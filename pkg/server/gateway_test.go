package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/policy"
)

// stubUpstream records what the gateway actually forwarded and replies
// with a canned tools/call response.
func stubUpstream(t *testing.T) (*httptest.Server, *received) {
	rec := &received{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.body = string(body)
		rec.path = r.URL.RequestURI()
		rec.method = r.Method
		rec.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":42,"result":{"content":[{"type":"text","text":"OK"}]}}`))
	}))
	return s, rec
}

type received struct {
	mu     sync.Mutex
	body   string
	path   string
	method string
}

func (r *received) snapshot() (string, string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body, r.path, r.method
}

const referencePolicyYAML = `
default_action: deny
rules:
  - id: R-001
    agent:
      client_id: sales-copilot
    tool:
      name: search_contacts
    action: allow
  - id: R-003
    agent:
      client_id: sales-copilot
    tool:
      name: export_contacts_bulk
    action: deny
    reason: bulk export forbidden
  - id: R-004
    agent:
      client_id: etl-worker
    tool:
      name: execute_query
    action: deny_with_redact
    redact_keys:
      - sql
    reason: ad-hoc SQL blocked
`

func newGateway(t *testing.T, upstreamURL string) (*Gateway, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	p, err := policy.Load(strings.NewReader(referencePolicyYAML))
	if err != nil {
		t.Fatalf("reference policy failed to load: %v", err)
	}
	eval := policy.NewEvaluator(p)
	var abuf, vbuf bytes.Buffer
	w := audit.NewWriterTo(&abuf, &vbuf)
	return &Gateway{Evaluator: eval, Audit: w, Upstream: upstreamURL}, &abuf, &vbuf
}

func postJSON(t *testing.T, gw *Gateway, clientID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if clientID != "" {
		req.Header.Set("X-Client-Id", clientID)
	}
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)
	return rr
}

func TestGateway_Allow_ForwardsVerbatim(t *testing.T) {
	upstream, rec := stubUpstream(t)
	defer upstream.Close()
	gw, _, _ := newGateway(t, upstream.URL)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_contacts","arguments":{"q":"alice"}},"id":42}`
	rr := postJSON(t, gw, "sales-copilot", body)

	if rr.Code != http.StatusOK {
		t.Errorf("allowed call must reach upstream: status %d", rr.Code)
	}
	got, _, _ := rec.snapshot()
	if got != body {
		t.Errorf("upstream must receive the ORIGINAL payload:\ngot  %s\nwant %s", got, body)
	}
}

func TestGateway_Deny_Returns403AndQuarantines(t *testing.T) {
	upstream, _ := stubUpstream(t)
	defer upstream.Close()
	gw, abuf, vbuf := newGateway(t, upstream.URL)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"export_contacts_bulk","arguments":{}},"id":7}`
	rr := postJSON(t, gw, "sales-copilot", body)

	if rr.Code != http.StatusForbidden {
		t.Errorf("denied call must return 403, got %d (upstream must NOT be reached)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"rule_id":"R-003"`) {
		t.Error("403 body must name the matched rule")
	}
	if !strings.Contains(vbuf.String(), "export_contacts_bulk") {
		t.Error("denied payload must be quarantined to violations.log")
	}
	if strings.Count(abuf.String(), `"quarantine_id"`) != 1 {
		t.Error("exactly one audit line with quarantine_id expected")
	}
}

func TestGateway_DenyWithRedact_ForwardsCleanedPayload(t *testing.T) {
	upstream, rec := stubUpstream(t)
	defer upstream.Close()
	gw, abuf, vbuf := newGateway(t, upstream.URL)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_query","arguments":{"sql":"DROP TABLE users;","readonly":true}},"id":9}`
	rr := postJSON(t, gw, "etl-worker", body)

	if rr.Code != http.StatusOK {
		t.Errorf("redacted call must still succeed: status %d", rr.Code)
	}
	got, _, _ := rec.snapshot()
	if strings.Contains(got, `"sql"`) {
		t.Error("upstream received the redacted key — redaction did not take effect")
	}
	if !strings.Contains(got, `"readonly":true`) {
		t.Error("safe key was removed — over-redaction")
	}
	if !strings.Contains(abuf.String(), `"quarantine_id":"Q-000001"`) {
		t.Error("redacted action must carry a quarantine_id in audit.log")
	}
	// But the violations log holds the ORIGINAL with the sql.
	if !strings.Contains(vbuf.String(), "DROP TABLE users") {
		t.Error("original malicious payload not quarantined")
	}
}

func TestGateway_UnidentifiedCaller_DeniedBeforeRules(t *testing.T) {
	upstream, _ := stubUpstream(t)
	defer upstream.Close()
	gw, abuf, _ := newGateway(t, upstream.URL)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_contacts","arguments":{}},"id":1}`
	rr := postJSON(t, gw, "", body) // no X-Client-Id — anonymous

	if rr.Code != http.StatusForbidden {
		t.Errorf("anonymous caller must be denied, got %d", rr.Code)
	}
	if !strings.Contains(abuf.String(), "PRE_FLIGHT_UNIDENTIFIED") {
		t.Error("audit must show the pre-flight deny, not a rule match")
	}
}

func TestGateway_AllowThenRedactSequenceIDs(t *testing.T) {
	upstream, _ := stubUpstream(t)
	defer upstream.Close()
	gw, abuf, vbuf := newGateway(t, upstream.URL)

	postJSON(t, gw, "sales-copilot",
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"export_contacts_bulk","arguments":{}},"id":1}`)
	postJSON(t, gw, "etl-worker",
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_query","arguments":{"sql":"x"}},"id":2}`)

	// Q-000001 (deny) then Q-000002 (redact), both in both logs.
	if !strings.Contains(abuf.String(), `"quarantine_id":"Q-000001"`) ||
		!strings.Contains(abuf.String(), `"quarantine_id":"Q-000002"`) {
		t.Error("sequential quarantine IDs missing from audit.log")
	}
	if strings.Count(vbuf.String(), "\n") != 2 {
		t.Errorf("violations.log must hold 2 entries, has %d", strings.Count(vbuf.String(), "\n"))
	}
}

func TestGateway_MalformedBody_Returns400AndLogs(t *testing.T) {
	upstream, _ := stubUpstream(t)
	defer upstream.Close()
	gw, abuf, _ := newGateway(t, upstream.URL)

	rr := postJSON(t, gw, "sales-copilot", `this is not json`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed body: want 400, got %d", rr.Code)
	}
	if !strings.Contains(abuf.String(), "MALFORMED_REQUEST") {
		t.Error("malformed requests must still appear in the audit stream")
	}
	_ = os.DevNull // ensure os import usage guard stays honest
}

// End-to-end with the real sql_injection.json adversarial fixture.
func TestGateway_SqlInjectionFixture_EndToEnd(t *testing.T) {
	upstream, rec := stubUpstream(t)
	defer upstream.Close()

	// Fixture targets read_customer_data, which is NOT in the reference policy,
	// so under default-deny the malicious payload is blocked at the tool level.
	gw, abuf, vbuf := newGateway(t, upstream.URL)
	fixture, err := os.ReadFile("../../tests/adversarial/attacks/sql_injection.json")
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	var fixtureMap map[string]json.RawMessage
	json.Unmarshal(fixture, &fixtureMap)
	fixtureMap["id"] = json.RawMessage(`99`)
	body, _ := json.Marshal(fixtureMap)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("X-Client-Id", "sales-copilot")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("sql_injection fixture must be denied, got %d", rr.Code)
	}
	if !strings.Contains(vbuf.String(), "1 OR 1=1") {
		t.Error("attack payload not quarantined for forensics")
	}
	if !strings.Contains(abuf.String(), "PRE_FLIGHT_UNIDENTIFIED") && !strings.Contains(abuf.String(), "DEFAULT_deny") {
		t.Error("fixture denial missing from audit.log")
	}
	if _, path, _ := rec.snapshot(); path != "" {
		t.Error("upstream must never see a denied request")
	}
}

func TestGateway_SSEPath_DetectedAndRouted(t *testing.T) {
	upstream, rec := stubUpstream(t)
	defer upstream.Close()
	gw, _, _ := newGateway(t, upstream.URL)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_contacts","arguments":{"q":"b"}},"id":3}`
	req := httptest.NewRequest(http.MethodPost, "/message?session_id=abc", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-Id", "sales-copilot")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("SSE message-channel call should be allowed: %d", rr.Code)
	}
	if _, path, _ := rec.snapshot(); path != "/message?session_id=abc" {
		t.Errorf("upstream path must be preserved: got %q", path)
	}
}
