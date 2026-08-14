package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/policy"
)

func newDenyMessage() *core.MCPMessage {
	return &core.MCPMessage{
		ReceivedAt:  time.Date(2026, 8, 12, 14, 32, 0, 123000000, time.UTC),
		Transport:   "streamable_http",
		SourceAddr:  "10.0.0.5:44120",
		UpstreamURL: "crm.internal/mcp",
		Method:      "tools/call",
		ID:          "42",
		RawParams:   json.RawMessage(`{"name":"delete_employee","arguments":{"employee_id":"12345","force":true}}`),
		CallerIdentity: core.CallerIdentity{
			ClientID:    "hr-agent-prod",
			MTLSSubject: "spiffe://internal/hr-agent",
			TokenHash:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			UserAgent:   "Claude Desktop 1.0",
		},
		ToolCall: &core.ToolCallView{ToolName: "delete_employee"},
	}
}

func TestWriter_AllowEntry(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriterTo(&buf, nil)
	msg := newDenyMessage()
	msg.ToolCall.ToolName = "search_contacts"
	qid := w.RecordDecision(msg, policy.Decision{Action: policy.ActionAllow, MatchedRuleID: "R-001", Reason: "policy match"}, 2536)

	if qid != "" {
		t.Error("allow decisions must NOT emit a quarantine_id")
	}
	var entry AuditEntry
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("audit line is not valid JSON: %v", err)
	}
	if entry.Tool != "search_contacts" || entry.Action != "allow" || entry.LatencyNs != 2536 {
		t.Errorf("audit entry malformed: %+v", entry)
	}
}

func TestWriter_DenyEmitsQuarantine(t *testing.T) {
	var abuf, vbuf bytes.Buffer
	w := NewWriterTo(&abuf, &vbuf)
	qid := w.RecordDecision(newDenyMessage(), policy.Decision{Action: policy.ActionDeny, MatchedRuleID: "R-003", Reason: "bulk export forbidden"}, 4000)

	if qid != "Q-000001" {
		t.Errorf("quarantine sequence broken: got %q", qid)
	}
	var audit AuditEntry
	json.Unmarshal(bytes.TrimSpace(abuf.Bytes()), &audit)
	if audit.QuarantineID != "Q-000001" {
		t.Error("audit line missing quarantine_id for deny action")
	}
	var viol ViolationEntry
	json.Unmarshal(bytes.TrimSpace(vbuf.Bytes()), &viol)
	if viol.QuarantineID != "Q-000001" || viol.RuleID != "R-003" {
		t.Errorf("violation entry mismatch: %+v", viol)
	}
	// The quarantined payload is the ORIGINAL, verbatim params.
	if !strings.Contains(string(viol.OriginalRawParams), "12345") {
		t.Error("quarantine lost the original payload")
	}
}

func TestWriter_DenyWithRedactSequence(t *testing.T) {
	var abuf, vbuf bytes.Buffer
	w := NewWriterTo(&abuf, &vbuf)

	// First denial: Q-000001
	w.RecordDecision(newDenyMessage(), policy.Decision{Action: policy.ActionDeny, MatchedRuleID: "R-003"}, 4000)
	// Second denial-with-redact must get the NEXT sequence number.
	qid2 := w.RecordDecision(newDenyMessage(), policy.Decision{Action: policy.ActionDenyRedact, MatchedRuleID: "R-004"}, 3000)
	if qid2 != "Q-000002" {
		t.Errorf("sequence must increment across both log streams: got %q", qid2)
	}
	// Two lines in violations.log.
	if lines := strings.Count(vbuf.String(), "\n"); lines != 2 {
		t.Errorf("violations.log should have 2 entries, has %d", lines)
	}
}

func TestWriter_ConcurrentSafety(t *testing.T) {
	var abuf, vbuf safeBuffer
	w := NewWriterTo(&abuf, &vbuf)
	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			w.RecordDecision(newDenyMessage(), policy.Decision{Action: policy.ActionDeny, MatchedRuleID: "R-003"}, 100)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
	if lines := strings.Count(abuf.String(), "\n"); lines != 100 {
		t.Errorf("expected 100 audit lines, got %d (lost writes or corruption)", lines)
	}
}

// safeBuffer lets bytes.Buffer satisfy io.Writer across goroutines in the test.
type safeBuffer struct {
	bytes.Buffer
	mu sync.Mutex
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Buffer.Write(p)
}

func TestNewWriter_FileRoundTripAndClose(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir+"/audit.log", dir+"/violations.log")
	if err != nil {
		t.Fatal(err)
	}
	qid := w.RecordDecision(&core.MCPMessage{
		ReceivedAt:     time.Now().UTC(),
		CallerIdentity: core.CallerIdentity{ClientID: "agent-1"},
		RawParams:      json.RawMessage(`{"sql":"DROP"}`),
	}, policy.Decision{Action: policy.ActionDeny, MatchedRuleID: "R-001"}, 0)
	if qid == "" {
		t.Fatal("denied decision must produce a quarantine ID")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(dir + "/audit.log")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"action":"deny"`) {
		t.Errorf("audit line missing action: %s", audit)
	}
	v, err := os.ReadFile(dir + "/violations.log")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(v), qid) || !strings.Contains(string(v), "DROP") {
		t.Errorf("violation line missing: %s", v)
	}
}

func TestNewWriter_InMemoryNoQuarantineFile(t *testing.T) {
	af, vf := &bytes.Buffer{}, &bytes.Buffer{}
	w := NewWriterTo(af, vf)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	qid := w.RecordDecision(&core.MCPMessage{
		ReceivedAt:     time.Now().UTC(),
		CallerIdentity: core.CallerIdentity{ClientID: "agent-1"},
	}, policy.Decision{Action: policy.ActionDeny}, 0)
	// No violations file → quarantine ID is still minted (the entry is
	// recorded) but nothing is written to the violations stream.
	if qid == "" {
		t.Fatal("quarantine ID must be minted even without a violations file")
	}
	if vf.Len() != 0 {
		t.Error("violations buffer must stay empty without a violations writer")
	}
}

func TestCorrelationID_BothBranches(t *testing.T) {
	if got := correlationID(&core.MCPMessage{ID: "42"}); got != "req-42" {
		t.Errorf("with message ID: %q", got)
	}
	if got := correlationID(&core.MCPMessage{ReceivedAt: time.UnixMilli(1000)}); got != "req-1000" {
		t.Errorf("without message ID: %q", got)
	}
}

// panickingObserver proves a misbehaving observer never takes down the
// enforcement path: its panic is caught, and the audit line still ships.
type panickingObserver struct{}

func (p panickingObserver) Observe(entry AuditEntry) { panic("observer panic") }

func TestObserveSafe_PanicGuard(t *testing.T) {
	af := &bytes.Buffer{}
	w := NewWriterTo(af, nil)
	w.RegisterObserver(panickingObserver{})
	w.RecordDecision(&core.MCPMessage{
		ReceivedAt:     time.Now().UTC(),
		CallerIdentity: core.CallerIdentity{ClientID: "agent-1"},
	}, policy.Decision{Action: policy.ActionAllow, MatchedRuleID: "ALLOWED"}, 0)
	if !strings.Contains(af.String(), "ALLOWED") {
		t.Error("panic in observer must not drop the audit line")
	}
}

type notifying struct{ fn func(string, string, string) }

func (n *notifying) Quarantined(quarantineID, ruleID, rawParams string) { n.fn(quarantineID, ruleID, rawParams) }

func TestQuarantineNotifier_ForwardedAfterQuarantine(t *testing.T) {
	vf := &bytes.Buffer{}
	w := NewWriterTo(nil, vf)
	var seen struct {
		mu    sync.Mutex
		raw   string
		rule  string
		qid   string
		calls int
	}
	n := &notifying{fn: func(qid, ruleID, rawParams string) {
		seen.mu.Lock()
		seen.raw, seen.rule, seen.qid, seen.calls = rawParams, ruleID, qid, seen.calls+1
		seen.mu.Unlock()
	}}
	RegisterQuarantineNotifier(n)
	defer RegisterQuarantineNotifier(nil)

	w.RecordDecision(&core.MCPMessage{
		ReceivedAt:     time.Now().UTC(),
		CallerIdentity: core.CallerIdentity{ClientID: "agent-1"},
		RawParams:      json.RawMessage(`{"payload":"x"}`),
	}, policy.Decision{Action: policy.ActionDenyRedact, MatchedRuleID: "R-002"}, 0)

	seen.mu.Lock()
	defer seen.mu.Unlock()
	if seen.calls != 1 {
		t.Fatalf("notifier calls: %d", seen.calls)
	}
	if seen.raw != `{"payload":"x"}` || seen.rule != "R-002" {
		t.Errorf("notifier payload wrong: raw=%q rule=%q qid=%q", seen.raw, seen.rule, seen.qid)
	}
}
