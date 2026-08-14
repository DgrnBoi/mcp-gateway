package console

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/gitops"
	"github.com/antigravity/mcp-gateway/pkg/metrics"
	"github.com/antigravity/mcp-gateway/pkg/policy"
)

//go:embed ui
var uiFS embed.FS

// Server is the embedded visibility console: a REST API over the ingester
// plus a statically embedded vanilla-HTML/JS dashboard (no build pipeline,
// no npm tree — every byte is auditable next to the engine).
type Server struct {
	Ingester *Ingester
	Policy   *policy.Policy // nil disables GitOps rule suggestion (defense in depth: no guessing)
	Metrics  *metrics.Collector // nil disables the /metrics endpoint
	Exporter *Exporter // nil disables the forensic export endpoint
	Users    UsersFile // nil disables RBAC: every API request is refused
	JWTSect  []byte    // signing secret for console session tokens
	subs     map[chan []byte]struct{}
	subsMu   sync.RWMutex
}

// NewServer creates the console server. Use NewServerWithAuth when the
// gateway was started with --console-users and --console-jwt-secret so
// the console enforces the Stage 5 role matrix; otherwise the console
// refuses every API request with 403 rather than serving data openly.
func NewServer(ing *Ingester) *Server {
	return &Server{Ingester: ing, subs: make(map[chan []byte]struct{})}
}

// NewServerWithAuth wires the console with JWT session auth and the
// admin/analyst/auditor role matrix (Ticket 20).
func NewServerWithAuth(ing *Ingester, users UsersFile, jwtSecret []byte) *Server {
	return &Server{Ingester: ing, Users: users, JWTSect: jwtSecret, subs: make(map[chan []byte]struct{})}
}

// Router returns the HTTP handler wired to the console routes. The gateway
// mounts this under its own mux (e.g. path prefix "/_console").
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/_console/api/auth/login", s.handleLogin)
	mux.Handle("/_console/api/audit", s.guard(http.HandlerFunc(s.handleAudit), RoleAdmin, RoleAnalyst))
	mux.Handle("/_console/api/violations/", s.guard(http.HandlerFunc(s.handleViolations), RoleAdmin, RoleAnalyst))
	mux.Handle("/_console/api/export", s.guard(http.HandlerFunc(s.handleExport), RoleAdmin, RoleAnalyst))
	mux.Handle("/_console/api/events/stream", s.guard(http.HandlerFunc(s.handleStream), RoleAdmin, RoleAnalyst, RoleAuditor))
	mux.Handle("/_console/api/rules/suggest", s.guard(http.HandlerFunc(s.handleSuggestRule), RoleAdmin))
	// Ticket 18: Prometheus exposition. Defense in depth: a nil collector
	// means the endpoint is unreachable, not a 404-generator.
	if s.Metrics != nil {
		mux.HandleFunc("/_console/metrics", s.handleMetrics)
	}
	// Static UI: the embedded FS root is the parent of "ui/", so scope the
	// file server to that subtree and strip the console prefix.
	uiRoot, err := fs.Sub(uiFS, "ui")
	if err != nil {
		panic("console ui embed missing: " + err.Error())
	}
	mux.Handle("/_console/", http.StripPrefix("/_console/", http.FileServer(http.FS(uiRoot))))
	return mux
}

// guard applies the per-route role matrix. With no UsersFile/JWTSect the
// middleware refuses everything with 403 — open console access is never
// silently permitted.
func (s *Server) guard(handler http.Handler, allowed ...string) http.Handler {
	return RequireRole(s.Users, s.JWTSect, allowed...)(handler)
}

// handleLogin exchanges static credentials for a console session JWT.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Username == "" || req.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	token, err := Login(s.Users, s.JWTSect, req.Username, req.Password)
	if err != nil {
		// Fixed-time comparison would be better; the HMAC verify in
		// extractClaims is constant-time on the signature itself.
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// handleExport is the RBAC-guarded dispatcher for the forensic gzip
// export (Ticket 21). Without an Exporter the endpoint is unreachable —
// never a 404-generator, never a silent data source.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if s.Exporter == nil {
		http.Error(w, "forensic export not configured", http.StatusServiceUnavailable)
		return
	}
	s.Exporter.HandleExport(w, r)
}

// handleMetrics serves the Prometheus exposition for the gateway's data
// plane. Content-Type is text/plain with version 0.0.4 to match the
// exposition format spec.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	if s.Metrics == nil {
		http.Error(w, "metrics not enabled", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", `text/plain; version=0.0.4; charset=utf-8`)
	fmt.Fprint(w, s.Metrics.Expose())
}

// Notify pushes an event to all SSE subscribers. The gateway calls it from
// an observer implementation (see handler wiring in cmd/mcp-gateway).
func (s *Server) Notify(entryJSON []byte) {
	s.subsMu.RLock()
	for ch := range s.subs {
		select {
		case ch <- entryJSON:
		default: // drop instead of blocking a slow subscriber
		}
	}
	s.subsMu.RUnlock()
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	offset, limit := parseInt(q.Get("offset"), 0), parseInt(q.Get("limit"), 100)
	if limit > 200 {
		limit = 200
	}
	events := s.Ingester.AuditSnapshot(offset, limit)
	if events == nil {
		events = []audit.AuditEntry{} // never respond with null
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (s *Server) handleViolations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	qid := strings.TrimPrefix(r.URL.Path, "/_console/api/violations/")
	if qid == "" || strings.Contains(qid, "/") {
		http.Error(w, "missing quarantine_id", http.StatusBadRequest)
		return
	}
	rawParams, ruleID, ok := s.Ingester.Quarantine(qid)
	if !ok || rawParams == "" {
		http.Error(w, "quarantine payload not available (expired or unknown)", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"quarantine_id": qid, "rule_id": ruleID, "raw_params": json.RawMessage(rawParams),
	})
}

// handleStream is an SSE endpoint so the dashboard renders live events.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan []byte, 64)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// keep-alive comment per SSE spec
	fmt.Fprint(w, ": keepalive\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// handleSuggestRule is the deny-first GitOps suggestion endpoint (Ticket 13).
// It takes a quarantine ID, reconstructs the violation from the ingester,
// and emits a minimal ADR-002-conformant rule fragment that TIGHTENS
// enforcement around what the attacker attempted. There is deliberately no
// one-click allow: generating an allow rule requires an analyst to accept
// the escalation risk explicitly via X-GitOps-Opt-In: allow, which carries
// a mandatory analyst reason in X-GitOps-Reason.
func (s *Server) handleSuggestRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	qid := q.Get("quarantine_id")
	if qid == "" {
		http.Error(w, "missing quarantine_id", http.StatusBadRequest)
		return
	}
	rawParams, ruleID, ok := s.Ingester.Quarantine(qid)
	if !ok {
		http.Error(w, "quarantine entry not found (expired or unknown)", http.StatusNotFound)
		return
	}
	entry, ok := s.Ingester.LookupEntryByQuarantineID(qid)
	if !ok {
		http.Error(w, "audit entry not found for quarantine_id", http.StatusNotFound)
		return
	}

	optIn := r.Header.Get("X-GitOps-Opt-In")
	reason := r.Header.Get("X-GitOps-Reason")

	var patch gitops.RulePatch
	var err error
	if strings.EqualFold(optIn, "allow") {
		if strings.TrimSpace(reason) == "" {
			http.Error(w, "X-GitOps-Opt-In: allow requires a non-empty X-GitOps-Reason (analyst consent)", http.StatusBadRequest)
			return
		}
		patch, err = gitops.AllowRule(entry, reason)
	} else {
		// Secure default: every violation generates tighter enforcement,
		// never an allowance. The payload is the quarantined raw params.
		if s.Policy == nil {
			http.Error(w, "gitops suggestion disabled: gateway started without a loaded policy", http.StatusServiceUnavailable)
			return
		}
		patch, err = gitops.Generate(gitops.Request{
			Entry: entry, Payload: rawParams, Mode: gitops.DenyMode,
		}, s.Policy)
	}
	if err != nil {
		http.Error(w, "suggestion failed: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// generated_rule is YAML, not JSON: serializing it as a plain string
	// keeps the response itself valid JSON for the dashboard and CI
	// consumers. Treat it as an opaque code fragment.
	json.NewEncoder(w).Encode(map[string]any{
		"rule_id":      patch.RuleID,
		"generated_rule": patch.YAML,
		"recommendation": patch.Recommend,
		"safety_note":   patch.SafetyNote,
		"source_rule":   ruleID,
	})
}

func parseInt(s string, fallback int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n < 0 {
		return fallback
	}
	return n
}

// The API serializes pkg/audit.AuditEntry verbatim, so the console stream
// is byte-for-byte identical to the SIEM audit.log schema.
