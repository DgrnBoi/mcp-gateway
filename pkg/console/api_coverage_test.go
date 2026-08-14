package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/metrics"
	"github.com/antigravity/mcp-gateway/pkg/policy"
)

// TestAPI_Metrics_NoCollectorConfigured verifies the metrics endpoint
// is deliberately unreachable (404, not 503) when the gateway was started
// without --metrics: no partial attack surface is exposed.
func TestAPI_Metrics_NoCollectorConfigured(t *testing.T) {
	srv, _, secret := newTestServerRBAC(t)
	admin := tokenFor(t, srv, secret, "admin-t")

	req := withAuth(httptest.NewRequest(http.MethodGet, "/_console/metrics", nil), admin)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("metrics without collector must be 404: %d", w.Code)
	}
}

// TestAPI_Metrics_WithCollector verifies the exposition path serves the
// collector output when the gateway was started with --metrics.
func TestAPI_Metrics_WithCollector(t *testing.T) {
	srv, _, secret := newTestServerRBAC(t)
	admin := tokenFor(t, srv, secret, "admin-t")
	srv.Metrics = metrics.NewCollector()

	req := withAuth(httptest.NewRequest(http.MethodGet, "/_console/metrics", nil), admin)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("metrics with collector: %d want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("exposition content type: %q", ct)
	}
	if !strings.Contains(w.Body.String(), "mcpgw_violations_total") {
		t.Errorf("exposition must contain gateway metrics: %q", w.Body.String())
	}
}

// TestAPI_SuggestRule_DenyModeDefault verifies an admin generates a
// tighten-only rule (deny_mode) when no opt-in header is supplied.
func TestAPI_SuggestRule_DenyModeDefault(t *testing.T) {
	srv, ing, secret := newTestServerRBAC(t)
	admin := tokenFor(t, srv, secret, "admin-t")
	seedQuarantine(ing, t)
	srv.Policy = denyDefaultPolicy()

	qid := "Q-test-1"
	req := withAuth(httptest.NewRequest(http.MethodPost, "/_console/api/rules/suggest?quarantine_id="+qid, nil), admin)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("admin deny-mode suggestion must succeed: %d %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if _, ok := body["generated_rule"]; !ok {
		t.Errorf("response must carry generated_rule: %v", body)
	}
}

// TestAPI_SuggestRule_OptInAllowRequiresReason verifies the escalation
// gate: minting an allow rule demands an explicit analyst reason.
func TestAPI_SuggestRule_OptInAllowRequiresReason(t *testing.T) {
	srv, ing, secret := newTestServerRBAC(t)
	admin := tokenFor(t, srv, secret, "admin-t")
	seedQuarantine(ing, t)

	qid := "Q-test-1"
	req := withAuth(httptest.NewRequest(http.MethodPost, "/_console/api/rules/suggest?quarantine_id="+qid, nil), admin)
	req.Header.Set("X-GitOps-Opt-In", "allow")
	// Deliberately NO X-GitOps-Reason — the escalation must be refused.
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Error("allow opt-in without a reason must be rejected")
	}
}

// TestAPI_SuggestRule_OptInAllowWithReason verifies the happy path for
// the dangerous escalation: allow rules require both the opt-in header
// and a non-empty analyst reason.
func TestAPI_SuggestRule_OptInAllowWithReason(t *testing.T) {
	srv, ing, secret := newTestServerRBAC(t)
	admin := tokenFor(t, srv, secret, "admin-t")
	seedQuarantine(ing, t)

	qid := "Q-test-1"
	req := withAuth(httptest.NewRequest(http.MethodPost, "/_console/api/rules/suggest?quarantine_id="+qid, nil), admin)
	req.Header.Set("X-GitOps-Opt-In", "allow")
	req.Header.Set("X-GitOps-Reason", "false positive during scheduled scan")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("allow with reason must succeed: %d %s", w.Code, w.Body.String())
	}
}

// TestAPI_SuggestRule_AnalystForbidden verifies analysts cannot trigger
// rule generation even when they can inspect the same quarantine payload.
func TestAPI_SuggestRule_AnalystForbidden(t *testing.T) {
	srv, ing, secret := newTestServerRBAC(t)
	analyst := tokenFor(t, srv, secret, "analyst-t")
	seedQuarantine(ing, t)
	qid := "Q-test-1"

	req := withAuth(httptest.NewRequest(http.MethodPost, "/_console/api/rules/suggest?quarantine_id="+qid, nil), analyst)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("analyst must be forbidden from rule generation: %d", w.Code)
	}
}

// seedQuarantine pushes one quarantine-worthy decision through the
// ingester and persists its raw params, mirroring the enforcement path.
func seedQuarantine(ing *Ingester, t *testing.T) {
	t.Helper()
	ing.Observe(audit.AuditEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		CorrelationID: "c-test-1",
		Transport:     string(core.TransportStreamableHTTP),
		Identity:      core.CallerIdentity{ClientID: "intruder-agent"},
		Tool:          "export_database",
		Action:        string(policy.ActionDenyRedact),
		RuleID:        "R-001",
		Reason:        "sensitive tool outside policy scope",
		QuarantineID:  "Q-test-1",
	})
	ing.StoreQuarantinePayload("Q-test-1", "R-001", `{"db":"hr","scope":"all"}`)
}

// denyDefaultPolicy returns the smallest valid policy for GitOps
// generation: a default-deny baseline with one deny rule.
func denyDefaultPolicy() *policy.Policy {
	return &policy.Policy{
		DefaultAction: policy.ActionDeny,
		Rules: []policy.Rule{{
			ID: "R-001",
			AgentMatch: policy.AgentMatch{ClientID: "any-agent"},
			ToolMatch:  policy.ToolMatch{Name: "export_database"},
			Action:     policy.ActionDenyRedact,
			Reason:     "baseline deny for database export",
		}},
		PolicyLayer: "org",
	}
}

var _ = strings.NewReader
