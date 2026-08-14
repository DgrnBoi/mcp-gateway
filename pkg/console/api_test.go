package console

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
)

// --- RBAC-aware test helpers (Stage 5, Ticket 20) ----------------------------
// The console enforces per-route role checks; tests must mint and attach JWTs
// instead of hitting unguarded routes.

func newTestServerRBAC(t *testing.T) (*Server, *Ingester, []byte) {
	t.Helper()
	ing := NewIngester(100, 0)
	secret := []byte("test-console-secret")
	users := UsersFile{
		"admin-t":  userEntry{Username: "admin-t", PasswordHash: hashPassword("p"), Role: RoleAdmin},
		"analyst-t": userEntry{Username: "analyst-t", PasswordHash: hashPassword("p"), Role: RoleAnalyst},
	}
	srv := NewServerWithAuth(ing, users, secret)
	return srv, ing, secret
}

func tokenFor(t *testing.T, srv *Server, secret []byte, user string) string {
	t.Helper()
	tok, err := Login(srv.Users, secret, user, "p")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func withAuth(r *http.Request, token string) *http.Request {
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// --- pre-existing API surface tests (now run through the RBAC guard) ----------

func TestAPI_AuditPagination_NeverNull(t *testing.T) {
	srv, ing, secret := newTestServerRBAC(t)
	admin := tokenFor(t, srv, secret, "admin-t")
	ing.Observe(audit.AuditEntry{CorrelationID: "req-1", Tool: "t1", Action: "allow", RuleID: "R-001", LatencyNs: 1})
	ing.Observe(audit.AuditEntry{CorrelationID: "req-2", Tool: "t2", Action: "deny", RuleID: "R-002", LatencyNs: 2, QuarantineID: "Q-000001"})

	req := withAuth(httptest.NewRequest(http.MethodGet, "/_console/api/audit?offset=0&limit=10", nil), admin)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var events []audit.AuditEntry
	if err := json.NewDecoder(rec.Body).Decode(&events); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	// oldest first
	if events[0].CorrelationID != "req-1" || events[1].CorrelationID != "req-2" {
		t.Fatalf("order wrong: %+v", events)
	}
}

func TestAPI_EmptyAudit_RespondsEmptyArray(t *testing.T) {
	srv, _, secret := newTestServerRBAC(t)
	analyst := tokenFor(t, srv, secret, "analyst-t")
	req := withAuth(httptest.NewRequest(http.MethodGet, "/_console/api/audit", nil), analyst)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.TrimSpace(body) != "[]" {
		t.Fatalf("empty audit must return [], got %q", body)
	}
}

func TestAPI_Violations_404WhenMissing(t *testing.T) {
	srv, ing, secret := newTestServerRBAC(t)
	admin := tokenFor(t, srv, secret, "admin-t")
	ing.StoreQuarantinePayload("Q-000001", "R-003", `{"arguments":{}}`)

	req := withAuth(httptest.NewRequest(http.MethodGet, "/_console/api/violations/Q-000001", nil), admin)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("known quarantine: status %d", rec.Code)
	}

	req = withAuth(httptest.NewRequest(http.MethodGet, "/_console/api/violations/Q-999999", nil), admin)
	rec = httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown quarantine must 404: status %d", rec.Code)
	}
}

func TestAPI_Violations_RawParamsReturned(t *testing.T) {
	srv, ing, secret := newTestServerRBAC(t)
	admin := tokenFor(t, srv, secret, "admin-t")
	want := `{"name":"execute_query","arguments":{"sql":"DROP TABLE users;"}}`
	ing.StoreQuarantinePayload("Q-000001", "R-004", want)

	req := withAuth(httptest.NewRequest(http.MethodGet, "/_console/api/violations/Q-000001", nil), admin)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	var got map[string]any
	json.NewDecoder(rec.Body).Decode(&got)
	raw, ok := got["raw_params"]
	if !ok {
		t.Fatalf("raw_params missing: %v", got)
	}
	// raw_params is embedded verbatim JSON; the decoded value is a nested
	// object regardless of whether the body carried it as a string or struct.
	encoded, _ := json.Marshal(raw)
	if !strings.Contains(string(encoded), "DROP TABLE") {
		t.Fatalf("raw_params missing injected payload: %q", encoded)
	}
	if got["rule_id"] != "R-004" {
		t.Fatalf("rule_id wrong: %v", got["rule_id"])
	}
}

func TestAPI_UIAndStreamRouteServed(t *testing.T) {
	srv, _, secret := newTestServerRBAC(t)
	router := srv.Router()

	// The UI shell is static and publicly served; the API is what is gated.
	req := httptest.NewRequest(http.MethodGet, "/_console/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("UI must serve 200: status %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "Triage Console") {
		t.Fatal("UI index.html not served correctly")
	}

	// SSE stream: ResponseRecorder implements http.Flusher, so the handler
	// serves the keepalive heartbeat. A bounded context keeps the test fast,
	// and closing the body's response ends the goroutine promptly.
	auditor := tokenFor(t, srv, secret, "analyst-t")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req = withAuth(httptest.NewRequest(http.MethodGet, "/_console/api/events/stream", nil).WithContext(ctx), auditor)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	streamBody := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(streamBody, ": keepalive") {
		t.Fatalf("SSE stream must serve keepalive (status %d, body %q)", rec.Code, streamBody)
	}
}

func TestBridge_ObservePushesToIngestionAndStream(t *testing.T) {
	srv, ing, _ := newTestServerRBAC(t)
	bridge := &ConsoleObserver{Ingester: ing, Server: srv}

	// Observe feeds the event store and SSE fan-out (quarantine payloads
	// arrive via audit.ForwardQuarantine → Bridge.Quarantined instead).
	e := audit.AuditEntry{CorrelationID: "req-bridge", Tool: "t", Action: "deny", RuleID: "R-001", LatencyNs: 5, QuarantineID: "Q-000001"}
	bridge.Observe(e)
	if ing.Count() != 1 {
		t.Fatal("observer did not ingest")
	}

	bridge.Quarantined("Q-000001", "R-001", `{"arguments":{}}`)
	raw, _, ok := ing.Quarantine("Q-000001")
	if !ok || raw == "" {
		t.Fatalf("quarantine payload missing via Quarantined bridge")
	}
}

// --- new RBAC surface checks (Stage 5, Ticket 20) ----------------------------

func TestAPI_AuditorDeniedFromQuarantinePayloads(t *testing.T) {
	_, _, _ = newTestServerRBAC(t)
	// Build a server whose only user is an auditor, so no analyst/admin token
	// can accidentally pass the matrix below.
	ing2 := NewIngester(100, 0)
	secret2 := []byte("test-console-secret-2")
	users2 := UsersFile{
		"auditor-t": userEntry{Username: "auditor-t", PasswordHash: hashPassword("p"), Role: RoleAuditor},
	}
	srv2 := NewServerWithAuth(ing2, users2, secret2)
	ing2.StoreQuarantinePayload("Q-000002", "R-005", `{"secret":"do-not-leak"}`)
	tok, err := Login(users2, secret2, "auditor-t", "p")
	if err != nil {
		t.Fatal(err)
	}
	req := withAuth(httptest.NewRequest(http.MethodGet, "/_console/api/violations/Q-000002", nil), tok)
	rec := httptest.NewRecorder()
	srv2.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor must be 403 on quarantine payloads: status %d", rec.Code)
	}
}
