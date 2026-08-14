package server

import (
	"bytes"
	"fmt"
	"io"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/enforcement"
	"github.com/antigravity/mcp-gateway/pkg/identity"
	"github.com/antigravity/mcp-gateway/pkg/metrics"
	"github.com/antigravity/mcp-gateway/pkg/policy"
	"github.com/antigravity/mcp-gateway/pkg/transport"
)

// Gateway is the heart of the sidecar: it binds the transport normalizer,
// the policy evaluator, the redaction rewriter, and the audit writer into a
// single reverse-proxy handler.
type Gateway struct {
	Evaluator policy.Evaluator
	Audit     *audit.Writer
	Upstream  string // target MCP server URL (scheme + host + port)

	// --- Stage 3 (Production Hardening) — all optional, nil is safe.
	// TokenValidator binds identity to a cryptographically verified JWT.
	// When set, any request carrying an Authorization header that fails
	// validation is rejected with HTTP 401 before policy evaluation.
	TokenValidator *identity.TokenValidator

	// Limiter protects the upstream from runaway agents. When set,
	// exceeded budgets return HTTP 429 with a Retry-After header.
	Limiter *Limiter

	// Metrics feeds the Prometheus exposition surface.
	Metrics *metrics.Collector
	// --- Stage 6 (Upstream Zero-Trust) — optional, nil is safe.
	// IdentitySigner attests the verified caller identity onto every
	// forwarded upstream request (X-Mcpgw-Identity, 30s Ed25519 JWT).
	// When set, UpstreamAlias becomes the aud claim.
	IdentitySigner *identity.SigningKey
	UpstreamAlias  string
}

// jsonResponse writes a compact JSON body with the given status code.
func jsonResponse(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprint(w, body)
}

// ServeHTTP implements the full decision loop:
//
//	normalize → evaluate → rewrite(if deny_with_redact) → forward or deny → audit
//
// The original request body is preserved verbatim for upstream forwarding
// AND for quarantine: nothing is ever read destructively.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Stage 3 / Ticket 14: bind identity to a verified JWT. An Authorization
	// header is now proof, not a claim — a failed signature is an
	// authentication failure (401), never a policy question.
	if g.TokenValidator != nil && r.Header.Get("Authorization") != "" {
		tokenHash, err := g.TokenValidator.Validate(r.Header.Get("Authorization"))
		if err != nil {
			g.writeAuthAudit(r, err)
			if g.Metrics != nil {
				g.Metrics.IncRequest("invalid_token")
			}
			jsonResponse(w, http.StatusUnauthorized,
				`{"error":"invalid_token","reason":"signature or claims validation failed"}`)
			return
		}
		r = requestWithTokenHash(r, tokenHash)
	}

	// Stage 3 / Ticket 15: mTLS-derived identity. The leaf certificate's
	// SPIFFE URI SAN is the only acceptable machine identity under mTLS.
	if tlsState := tlsStateOf(r); tlsState != nil {
		r = requestWithMTLSSubject(r, tlsState, "")
	}

	// Stage 3 / Ticket 16: per-identity rate budget. Rate-limited calls
	// are audited but never escalate to PagerDuty (default
	// IncludeInAlerts=false).
	if g.Limiter != nil && g.Limiter.Enabled() {
		fp := Fingerprint(transport.ExtractIdentity(r, ""))
		allowed, retryAfter := g.Limiter.Allow(fp, 0)
		if !allowed {
			if g.Audit != nil {
				msg := &core.MCPMessage{
					ReceivedAt:     time.Now().UTC(),
					Transport:      transport.DetectTransport(r),
					SourceAddr:     r.RemoteAddr,
					CallerIdentity: transport.ExtractIdentity(r, ""),
				}
				decision := policy.Decision{
					Action:        policy.ActionDeny,
					MatchedRuleID: "RATE_LIMITED",
					Reason:        "request budget exceeded",
				}
				g.Audit.RecordDecision(msg, decision, 0)
			}
			if g.Metrics != nil {
				g.Metrics.IncRateLimited(fp)
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
			jsonResponse(w, http.StatusTooManyRequests,
				`{"error":"rate_limited","reason":"request budget exceeded"}`)
			return
		}
	}

	msg, bodyReader, err := transport.NormalizeRequest(r)
	if err != nil {
		g.writeMalformedAudit(r, err)
		jsonResponse(w, http.StatusBadRequest,
			fmt.Sprintf(`{"error":"bad_request","reason":%q}`, err.Error()))
		return
	}

	decision := g.Evaluator.Evaluate(&msg)
	latencyNs := time.Since(start).Nanoseconds()

	if g.Metrics != nil {
		g.Metrics.IncRequest(string(decision.Action))
		g.Metrics.ObserveLatency(time.Duration(latencyNs))
		if decision.Action == policy.ActionDeny || decision.Action == policy.ActionDenyRedact {
			g.Metrics.IncViolation(decision.MatchedRuleID, Fingerprint(msg.CallerIdentity))
		}
	}

	switch decision.Action {
	case policy.ActionAllow, policy.ActionAllowAll:
		g.Audit.RecordDecision(&msg, decision, latencyNs)
		g.forward(w, r, bodyReader)
		return

	case policy.ActionDenyRedact:
		// Find the matched rule to obtain RedactKeys.
		rule := g.findRule(decision.MatchedRuleID)
		if rule != nil {
			clean, rwErr := enforcement.Rewrite(&msg, decision, rule)
			if rwErr != nil || clean != nil {
				if clean != nil {
					bodyReader = bytes.NewReader(clean)
				}
				// Note: rewrite failure degrades to plain deny to avoid
				// forwarding an unverifiable payload.
				if rwErr != nil && clean == nil {
					g.Audit.RecordDecision(&msg, decision, latencyNs)
					jsonResponse(w, http.StatusForbidden,
						fmt.Sprintf(`{"error":"denied","rule_id":%q,"reason":"redaction failure"}`, decision.MatchedRuleID))
					return
				}
			}
		}
		g.Audit.RecordDecision(&msg, decision, latencyNs)
		g.forward(w, r, bodyReader)
		return

	default: // ActionDeny
		g.Audit.RecordDecision(&msg, decision, latencyNs)
		jsonResponse(w, http.StatusForbidden,
			fmt.Sprintf(`{"error":"denied","rule_id":%q,"reason":%q}`,
				decision.MatchedRuleID, decision.Reason))
	}
}

// forward proxies the request to the upstream MCP server. The path and
// query are preserved; the host becomes the upstream host; the body is the
// (possibly redacted) reader returned by the decision loop.
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, bodyReader io.Reader) {
	target := g.Upstream + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bodyReader)
	if err != nil {
		jsonResponse(w, http.StatusBadGateway,
			fmt.Sprintf(`{"error":"upstream_error","reason":%q}`, err.Error()))
		return
	}
	// Preserve transport-neutral headers; strip hop-by-hop headers.
	// NOTE: Content-Length is deliberately NOT copied from the inbound
	// request — after redaction the body is shorter, and a stale
	// Content-Length causes upstream EOF errors. http.NewRequestWithContext
	// sets the correct length from the reader automatically.
	for _, h := range []string{"Accept", "Content-Type", "Mcp-Protocol-Version", "Mcp-Session-Id"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	// Stage 6 / Ticket 21: upstream identity injection. The gateway signs the
	// verified caller identity (spiffe://… or token-sha256:…) into a 30s
	// Ed25519 JWT on X-Mcpgw-Identity so the upstream can enforce
	// row-level security on attested claims. Requests that cleared
	// enforcement carry the attestation; anything reaching the upstream
	// directly can only present an unsigned, worthless header.
	if g.IdentitySigner != nil {
		sub := identity.IdentityClaim(
			r.Header.Get("X-Mcpgw-Token-Hash"),
			r.Header.Get("X-Mcpgw-Mtls-Subject"),
		)
		if jwt, err := g.IdentitySigner.MintIdentityJWT(sub, g.UpstreamAlias); err == nil {
			req.Header.Set(identity.IdentityHeader, jwt)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		jsonResponse(w, http.StatusBadGateway,
			fmt.Sprintf(`{"error":"upstream_unreachable","reason":%q}`, err.Error()))
		return
	}
	defer resp.Body.Close()

	// Mirror upstream status and headers onto the gateway's response.
	for k, vv := range resp.Header {
		// Never leak the upstream transport's identity headers downstream.
		lower := strings.ToLower(k)
		if lower == "content-encoding" || lower == "transfer-encoding" || lower == "connection" {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// findRule looks up a rule by its stable ID for post-decision detail
// (redaction keys, reason). Returns nil if the evaluator's decision could
// not be mapped (e.g., PRE_FLIGHT_UNIDENTIFIED) — callers handle nil.
func (g *Gateway) findRule(id string) *policy.Rule {
	concrete, ok := g.Evaluator.(*policy.DefaultEvaluator)
	if !ok {
		return nil
	}
	// Evaluator exposes its policy only via the concrete type.
	pol := concrete.Policy()
	for i := range pol.Rules {
		if pol.Rules[i].ID == id {
			return &pol.Rules[i]
		}
	}
	return nil
}

// requestWithTokenHash returns a shallow copy of the request with the
// verified JWT hash injected into the identity header slot, so the
// transport normalizer downstream can attach it to CallerIdentity.
func requestWithTokenHash(r *http.Request, tokenHash string) *http.Request {
	r2 := new(http.Request)
	*r2 = *r
	r2.Header = r.Header.Clone()
	r2.Header.Set("X-Mcpgw-Token-Hash", tokenHash)
	return r2
}

// requestWithMTLSSubject returns a shallow copy of the request with the
// SPIFFE-derived identity header set. The trust domain argument filters
// out-of-domain certificates to an empty identity (deny by pre-flight).
func requestWithMTLSSubject(r *http.Request, state *tls.ConnectionState, trustDomain string) *http.Request {
	r2 := new(http.Request)
	*r2 = *r
	r2.Header = r.Header.Clone()
	r2.Header.Set("X-Mcpgw-Mtls-Subject", identity.CallerMTLSSubject(state, trustDomain))
	return r2
}

// tlsStateOf returns the TLS connection state if the request arrived
// over a verified TLS channel, nil otherwise.
func tlsStateOf(r *http.Request) *tls.ConnectionState {
	if r.TLS == nil {
		return nil
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS
}

// writeAuthAudit records a failed JWT validation so SIEM teams can see
// identity spoofing attempts that never reached policy evaluation.
func (g *Gateway) writeAuthAudit(r *http.Request, err error) {
	if g.Audit == nil {
		return
	}
	msg := &core.MCPMessage{
		ReceivedAt:     time.Now().UTC(),
		Transport:      transport.DetectTransport(r),
		SourceAddr:     r.RemoteAddr,
		CallerIdentity: transport.ExtractIdentity(r, ""),
	}
	decision := policy.Decision{
		Action:        policy.ActionDeny,
		MatchedRuleID: "INVALID_TOKEN",
		Reason:        err.Error(),
	}
	g.Audit.RecordDecision(msg, decision, 0)
}

// writeMalformedAudit records a parse-failure event so SIEM teams can see
// traffic that never became a decision.
func (g *Gateway) writeMalformedAudit(r *http.Request, err error) {
	if g.Audit == nil {
		return
	}
	msg := &core.MCPMessage{
		ReceivedAt:     time.Now().UTC(),
		Transport:      transport.DetectTransport(r),
		SourceAddr:     r.RemoteAddr,
		CallerIdentity: transport.ExtractIdentity(r, ""),
	}
	decision := policy.Decision{
		Action:        policy.ActionDeny,
		MatchedRuleID: "MALFORMED_REQUEST",
		Reason:        err.Error(),
	}
	g.Audit.RecordDecision(msg, decision, 0)
}
