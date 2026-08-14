// Command mcp-gateway is a policy-enforcing reverse proxy (sidecar) for MCP
// (Model Context Protocol) servers. It normalizes SSE, Streamable HTTP, and
// plain HTTP traffic into a common event model, applies a YAML default-deny
// policy, optionally redacts dangerous parameters, forwards or blocks the
// request, and emits a JSON-lines audit stream for SIEM ingestion.
//
// Usage:
//
//	mcp-gateway --policy policy.yaml --upstream http://localhost:8090 \
//	            --listen :9090 --audit-log /var/log/mcp/audit.log \
//	            --violations-log /var/log/mcp/violations.log
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"crypto/tls"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/console"
	"github.com/antigravity/mcp-gateway/pkg/identity"
	"github.com/antigravity/mcp-gateway/pkg/metrics"
	"github.com/antigravity/mcp-gateway/pkg/policy"
	"github.com/antigravity/mcp-gateway/pkg/server"
	"github.com/antigravity/mcp-gateway/pkg/webhooks"
)

// multiStringFlag is a repeatable command-line flag (one --team-policy per
// team layer). Using flag.Var instead of a raw []string keeps the CLI
// self-documenting (`go run ./cmd/mcp-gateway -h`).
type multiStringFlag []string

func (m *multiStringFlag) String() string { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	var (
		policyPath    = flag.String("policy", "policy.yaml", "path to the YAML policy file")
		upstream      = flag.String("upstream", "http://localhost:8090", "target MCP server URL")
		listen        = flag.String("listen", ":9090", "address the gateway listens on")
		auditLog      = flag.String("audit-log", "", "path to audit.log (JSON-lines); empty = stdout)")
		violationsLog = flag.String("violations-log", "", "path to violations.log; required when policy contains deny rules")
		logPrefix     = flag.String("log-prefix", "mcpgw", "prefix for structured log lines")
		consoleAddr     = flag.String("console", "", "address for the triage console UI/API (e.g. :9091); empty = disabled")
		consoleUsers    = flag.String("console-users", "", "path to users.yaml (static console credentials); empty = console data API refuses everything")
		consoleJWT      = flag.String("console-jwt-secret", "", "HMAC secret for console session JWTs; required with --console-users")
		configPath      = flag.String("config", "", "path to config.yaml (webhooks/alerting); empty = webhooks disabled")
		orgPolicyPath   = flag.String("org-policy", "", "path to org_policy.yaml (Stage 4 hierarchy base layer); activates multi-tenant mode")
		upstreamAlias   = flag.String("upstream-alias", "upstream", "aud claim / alias for upstream identity attestations")
		signingKeyPath  = flag.String("identity-signing-key", "", "path to PKCS#8 Ed25519 private key PEM (upstream attestation; empty = disabled)")
	)
	var teamPolicyPaths multiStringFlag
	flag.Var(&teamPolicyPaths, "team-policy", "path to a team_policy.yaml; repeatable for multi-team hierarchies")
	flag.Parse()

	if (*consoleUsers != "") != (*consoleJWT != "") {
		log.Fatalf("%s: --console-users and --console-jwt-secret must be provided together", *logPrefix)
	}

	// Stage 3 / Ticket 17 + Stage 4 / Ticket 19: the policy manager owns the
	// hot-swap surface. ValidateInitial is fail-closed: a broken policy at
	// boot means the gateway refuses to start, exactly like the single-load
	// path. --org-policy activates the multi-tenant hierarchy (fail-closed
	// merge — a shadowed org invariant rejects the whole hierarchy).
	var pm *policy.PolicyManager
	var err error
	if *orgPolicyPath != "" {
		pm, err = policy.NewHierarchyManager(*orgPolicyPath, []string(teamPolicyPaths))
		if err != nil {
			log.Fatalf("%s: invalid policy hierarchy: %v", *logPrefix, err)
		}
		log.Printf("%s: multi-tenant hierarchy loaded (org %s, %d team layers)",
			*logPrefix, *orgPolicyPath, len(teamPolicyPaths))
	} else {
		pm, err = policy.NewPolicyManager(*policyPath)
		if err != nil {
			log.Fatalf("%s: invalid policy: %v", *logPrefix, err)
		}
	}

	auditWriter, err := openAuditWriters(*auditLog, *violationsLog, *logPrefix)
	if err != nil {
		log.Fatalf("%s: audit initialization failed: %v", *logPrefix, err)
	}
	defer auditWriter.Close()

	var webhookCfg webhooks.Config
	if *configPath != "" {
		webhookCfg, err = webhooks.Load(*configPath)
		if err != nil {
			log.Fatalf("%s: invalid config: %v", *logPrefix, err)
		}
	}

	coll := metrics.NewCollector()

	if *consoleAddr != "" {
		startConsole(*consoleAddr, *consoleUsers, *consoleJWT, *violationsLog, pm, auditWriter, coll, *logPrefix)
	}

	stopWebhooks := startWebhooks(webhookCfg, auditWriter, *logPrefix)
	defer func() {
		for _, s := range stopWebhooks {
			s.Stop()
		}
	}()

	// Stage 3 / Ticket 14: JWT binding. A nil validator is the Stage 2
	// backward-compatible mode — config.yaml drives the opt-in.
	var tv *identity.TokenValidator
	if webhookCfg.Token.PEM != "" || webhookCfg.Token.JWKSURL != "" {
		tv, err = identity.NewTokenValidator(identity.TokenConfig(
			webhookCfg.Token))
		if err != nil {
			log.Fatalf("%s: invalid token config: %v", *logPrefix, err)
		}
		log.Printf("%s: token-bound identity enabled (aud=%q)",
			*logPrefix, webhookCfg.Token.Audience)
	}

	// Stage 3 / Ticket 16: per-identity rate limiting.
	limiter := server.NewLimiter(webhookCfg.RateLimit)
	if limiter.Enabled() {
		log.Printf("%s: rate limiting enabled (%d rps, burst %d)",
			*logPrefix, webhookCfg.RateLimit.RequestsPerSecond,
			webhookCfg.RateLimit.Burst)
	}

	gw := &server.Gateway{
		Evaluator:      policy.NewEvaluator(pm.Policy()),
		Audit:          auditWriter,
		Upstream:       *upstream,
		TokenValidator: tv,
		Limiter:        limiter,
		Metrics:        coll,
	}

	// Stage 3 / Ticket 17: zero-downtime policy reload. A goroutine polls
	// the policy file every 2 seconds and atomically swaps the evaluator's
	// policy pointer; SIGHUP forces a re-read even when the timestamp is
	// unchanged (edit-in-place edits that preserve mtime).
	go runHotReload(pm, gw, *logPrefix)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           gw,
		ReadHeaderTimeout: 10 * time.Second, // harden against slowloris
	}

	// Stage 6 / Ticket 21: upstream identity attestation. A non-Ed25519
	// signing key is a startup hard failure — never a silent passthrough,
	// because an unsigned X-Mcpgw-Identity header is worthless against
	// network-hopping spoofing.
	if *signingKeyPath != "" {
		pemBytes, readErr := os.ReadFile(*signingKeyPath)
		if readErr != nil {
			log.Fatalf("%s: identity signing key unreadable: %v", *logPrefix, readErr)
		}
		key, keyErr := identity.ParseSigningKey(pemBytes)
		if keyErr != nil {
			log.Fatalf("%s: %v", *logPrefix, keyErr)
		}
		gw.IdentitySigner = &key
		gw.UpstreamAlias = *upstreamAlias
		log.Printf("%s: upstream identity attestation enabled (alias %q)",
			*logPrefix, *upstreamAlias)
	}

	// Stage 3 / Ticket 15: mTLS transport. When enabled, the listener is
	// wrapped so only clients presenting a certificate signed by the
	// configured CA can even open a TCP handshake visible to the proxy.
	if webhookCfg.TLS.Enabled {
		tlsCfg, tlsErr := identity.BuildTLSConfig(webhookCfg.TLS)
		if tlsErr != nil {
			log.Fatalf("%s: invalid tls config: %v", *logPrefix, tlsErr)
		}
		ln, lnErr := tls.Listen("tcp", *listen, tlsCfg)
		if lnErr != nil {
			log.Fatalf("%s: cannot listen: %v", *logPrefix, lnErr)
		}
		srv.Addr = ""
		errCh := make(chan error, 1)
		go func() {
			log.Printf("%s: listening on %s with mTLS (trust domain %s, upstream %s, policy %s)",
				*logPrefix, *listen, webhookCfg.TLS.TrustDomain, *upstream, *policyPath)
			errCh <- srv.Serve(ln)
		}()
		setupShutdown(srv, errCh, *logPrefix)
	} else {
		errCh := make(chan error, 1)
		go func() {
			log.Printf("%s: listening on %s (upstream %s, policy %s)",
				*logPrefix, *listen, *upstream, *policyPath)
			errCh <- srv.ListenAndServe()
		}()
		setupShutdown(srv, errCh, *logPrefix)
	}
}

func setupShutdown(srv *http.Server, errCh chan error, prefix string) {
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-shutdownCh:
		log.Printf("%s: signal %s received, draining", prefix, sig)
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("%s: server error: %v", prefix, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("%s: shutdown error: %v", prefix, err)
	}
	log.Printf("%s: stopped", prefix)
}

func startConsole(addr, usersPath, jwtSecret, violationsPath string, pm *policy.PolicyManager, w *audit.Writer, coll *metrics.Collector, prefix string) {
	ing := console.NewIngester(0, 0)
	var srv *console.Server
	if usersPath != "" {
		f, err := os.Open(usersPath)
		if err != nil {
			log.Fatalf("%s: console users file unreadable: %v", prefix, err)
		}
		defer f.Close()
		users, err := console.LoadUsersFile(f)
		if err != nil {
			log.Fatalf("%s: invalid console users file: %v", prefix, err)
		}
		srv = console.NewServerWithAuth(ing, users, []byte(jwtSecret))
		srv.Exporter = console.NewExporter(ing, violationsPath)
		log.Printf("%s: console RBAC enabled (%d console users), forensic export bound to %s",
			prefix, len(users), violationsPath)
	} else {
		srv = console.NewServer(ing)
	}
	srv.Policy = pm.Policy()
	srv.Metrics = coll
	bridge := &console.ConsoleObserver{Ingester: ing, Server: srv}
	w.RegisterObserver(bridge)
	audit.RegisterQuarantineNotifier(bridge)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("%s: console listening on %s", prefix, addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("%s: console server error: %v", prefix, err)
		}
	}()
}

// openAuditWriters returns a Writer backed by real files (or stdout/err for
// audit when no path is given). The violations log always gets 0o600
// permissions when it is a file.
func openAuditWriters(auditPath, violationsPath, prefix string) (*audit.Writer, error) {
	af := os.Stdout
	if auditPath != "" {
		f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("audit log: %w", err)
		}
		af = f
	}
	var vf = os.Stderr
	if violationsPath != "" {
		f, err := os.OpenFile(violationsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("violations log: %w", err)
		}
		vf = f
	}
	return audit.NewWriterTo(af, vf), nil
}

// noopStopper is the lifecycle placeholder for stateless observers.
type noopStopper struct{}

func (n *noopStopper) Stop() {}

// startWebhooks attaches the Slack/PagerDuty alerting observers to the audit
// writer. Both observers run off the critical path: Observe never blocks the
// proxy goroutine, and durable delivery is handled by background workers
// with retries and a dead-letter queue.
// runHotReload polls the policy file and force-swaps on SIGHUP. It only
// ever upgrades the evaluator — a failed reload leaves the last known
// good policy in place and logs the diff for triage.
func runHotReload(pm *policy.PolicyManager, gw *server.Gateway, prefix string) {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sighup:
			log.Printf("%s: SIGHUP received, forcing policy reload", prefix)
			res := pm.ForceReload()
			reportReload(prefix, res)
			gw.Evaluator = policy.NewEvaluator(pm.Policy())
		case <-ticker.C:
			res := pm.Reload()
			if res.Swapped {
				reportReload(prefix, res)
				gw.Evaluator = policy.NewEvaluator(pm.Policy())
			}
		}
	}
}

func reportReload(prefix string, res policy.ReloadResult) {
	if res.Error != nil {
		log.Printf("%s: policy reload rejected (fail-steady): %v", prefix, res.Error)
		return
	}
	log.Printf("%s: policy reloaded: %d rules (was %d)", prefix,
		res.NewRules, res.OldRules)
}

func startWebhooks(cfg webhooks.Config, w *audit.Writer, prefix string) []interface {
	Stop()
} {
	if cfg.Webhooks.Slack.Enabled && cfg.Webhooks.Slack.URL == "" {
		log.Fatalf("%s: slack is enabled but webhooks.slack.url is empty (startup hard-fail)", prefix)
	}
	if cfg.Webhooks.PagerDuty.Enabled && cfg.Webhooks.PagerDuty.RoutingKey == "" {
		log.Fatalf("%s: pagerduty is enabled but webhooks.pagerduty.routing_key is empty (startup hard-fail)", prefix)
	}
	var stoppers []interface{ Stop() }
	if cfg.Webhooks.Slack.Enabled {
	slack, err := webhooks.NewSlackObserver(cfg.Webhooks.Slack.URL, "")
		if err != nil {
			log.Fatalf("%s: slack observer init failed: %v", prefix, err)
		}
		w.RegisterObserver(slack)
		stoppers = append(stoppers, slack)
		log.Printf("%s: slack webhook observer registered", prefix)
	}
	if cfg.Webhooks.PagerDuty.Enabled {
		pd := webhooks.NewPagerDutyObserver(cfg.Webhooks.PagerDuty.RoutingKey)
		w.RegisterObserver(pd)
		// PagerDuty is stateless (rate-limited fire-and-forget) so it has
		// nothing to drain on shutdown — wrap it with a no-op stopper so
		// the lifecycle loop stays uniform.
		stoppers = append(stoppers, &noopStopper{})
		log.Printf("%s: pagerduty observer registered", prefix)
	}
	return stoppers
}

