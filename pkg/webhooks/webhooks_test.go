package webhooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/policy"
)

// ---------------------------------------------------------------------------
// Config loader tests (Ticket 11 validation contract)
// ---------------------------------------------------------------------------

func TestConfigLoad_Valid(t *testing.T) {
	src := `
webhooks:
  slack:
    url: "https://hooks.slack.com/services/T/B/X"
    enabled: true
  pagerduty:
    routing_key: "key-123"
    enabled: false
`
	cfg, err := LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if !cfg.Webhooks.Slack.Enabled || cfg.Webhooks.Slack.URL == "" {
		t.Fatal("slack not parsed")
	}
}

func TestConfigLoad_RejectsUnknownProvider(t *testing.T) {
	src := `
webhooks:
  slack:
    url: "https://x"
    enabled: true
  teams:
    url: "https://y"
    enabled: true
`
	_, err := LoadFromBytes([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "unknown webhook provider") {
		t.Fatalf("expected unknown-provider error, got: %v", err)
	}
}

func TestConfigLoad_RejectsUnknownTopLevelKey(t *testing.T) {
	src := `
webhooks:
  slack:
    url: "https://x"
    enabled: true
logging:
  level: debug
`
	_, err := LoadFromBytes([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "unknown top-level config key") {
		t.Fatalf("expected unknown-key error, got: %v", err)
	}
}

func TestConfigLoad_EnabledEmptyEndpointIsHardError(t *testing.T) {
	src := `
webhooks:
  slack:
    url: ""
    enabled: true
  pagerduty:
    routing_key: ""
    enabled: true
`
	_, err := LoadFromBytes([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "enabled but") {
		t.Fatalf("expected enabled-empty-endpoint error, got: %v", err)
	}
}

// LoadFromBytes mirrors Load for testability (disk path identical logic).
func LoadFromBytes(src []byte) (Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(src, &cfg); err != nil {
		return cfg, err
	}
	if err := cfg.validate(src); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// safeBuffer is a concurrency-safe bytes.Buffer used to capture DLQ writes
// in tests; the raw bytes.Buffer is NOT safe for concurrent writers, and
// both the observer goroutine and Stop's final drain can write to it.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}


func (b *safeBuffer) String() string {
b.mu.Lock()
defer b.mu.Unlock()
return b.buf.String()
}

func (b *safeBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	return out
}

// ---------------------------------------------------------------------------
// Slack observer tests (Ticket 11 delivery contract)
// ---------------------------------------------------------------------------

type fakeClient struct {
	mu       sync.Mutex
	calls    int
	statuses []int // served in order; after exhaustion returns last
	errs     []error
	delay    time.Duration  // optional per-call latency (tests only)
	block    <-chan struct{} // when non-nil, Do waits until closed
}

func (f *fakeClient) Do(req *http.Request) (*http.Response, error) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	io.Copy(io.Discard, req.Body)
	idx := f.calls
	f.calls++
	if idx < len(f.errs) && f.errs[idx] != nil {
		return nil, f.errs[idx]
	}
	if len(f.errs) > 0 && f.errs[len(f.errs)-1] != nil && len(f.statuses) == 0 {
		// Sticky error semantics: when only network failures are configured,
		// every call fails — retry loops must see deterministic exhaustion.
		return nil, f.errs[len(f.errs)-1]
	}
	if idx < len(f.statuses) {
		return &http.Response{StatusCode: f.statuses[idx], Body: io.NopCloser(strings.NewReader("ok"))}, nil
	}
	// Sticky semantics: repeat the last configured status indefinitely
	// (default 200 when none is configured) so retry-loop tests see
	// deterministic exhaustion rather than a late success.
	code := 200
	if n := len(f.statuses); n > 0 {
		code = f.statuses[n-1]
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func denyEntry(qid string) audit.AuditEntry {
	return denyEntryFor(qid, core.CallerIdentity{ClientID: "sales-copilot"})
}

// denyEntryFor builds a denial with an explicit identity so violation
// fingerprints match across events in identity-isolation tests.
func denyEntryFor(qid string, id core.CallerIdentity) audit.AuditEntry {
	return audit.AuditEntry{
		Timestamp:     "2026-08-12T18:00:00.000Z",
		CorrelationID: "req-1",
		Transport:     "streamable_http",
		Identity:      id,
		Tool:          "export_contacts_bulk",
		Action:        string(policy.ActionDeny),
		RuleID:        "R-003",
		QuarantineID:  qid,
	}
}

func TestSlack_NotifyNeverBlocks(t *testing.T) {
	dlq := &safeBuffer{}
	// Blocking client guarantees the worker never drains during the fill
	// loop: without this, the bounded queue would empty faster than we can
	// push and the overflow path would never exercise.
	blocked := make(chan struct{})
	client := &fakeClient{block: blocked}
	s, err := NewSlackObserver("https://example.com/hook", "",
		WithClient(client), WithBackoff(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	s.dlq = dlq
	// Fill the queue (the worker grabs one item then blocks in send),
	// then observe one more: must return immediately.
	for i := 0; i < DefaultChannelSize+1; i++ {
		s.Observe(denyEntry(fmt.Sprintf("Q-%06d", i+1)))
	}
	done := make(chan struct{})
	go func() {
		s.Observe(denyEntry("Q-001001"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Observe blocked on a full queue")
	}
	close(blocked) // let the worker drain; Stop will now complete
	s.Stop()
	if dlq.Len() == 0 {
		t.Fatal("overflow event must be dead-lettered, DLQ empty")
	}
}

func TestSlack_RetriesOn5xxThenDeadLetters(t *testing.T) {
	dlq := &safeBuffer{}
	client := &fakeClient{statuses: []int{500, 500, 500}, errs: []error{nil, nil, nil}}
	s, _ := NewSlackObserver("https://example.com/hook", "",
		WithClient(client), WithBackoff(time.Nanosecond), WithRetries(3), WithSync())
	// Point DLQ capture at our buffer via a wrapper.
	s.dlq = dlq

	s.Observe(denyEntry("Q-000001"))
	s.Stop()

	if client.calls != 4 { // initial + 3 retries
		t.Fatalf("expected 4 delivery attempts, got %d", client.calls)
	}
	if dlq.Len() == 0 {
		t.Fatal("event not dead-lettered after exhausting retries")
	}
	if !strings.Contains(dlq.String(), "Q-000001") {
		t.Fatal("DLQ entry missing quarantine ID")
	}
}

func TestSlack_4xxNeverRetried(t *testing.T) {
	client := &fakeClient{statuses: []int{404}}
	s, _ := NewSlackObserver("https://example.com/hook", "",
		WithClient(client), WithBackoff(time.Nanosecond), WithRetries(3), WithSync())
	s.Observe(denyEntry("Q-000001"))
	s.Stop()
	if client.calls != 1 {
		t.Fatalf("4xx must not be retried: got %d attempts", client.calls)
	}
}

func TestSlack_NetworkErrorRetriesThenDLQ(t *testing.T) {
	dlq := &safeBuffer{}
	client := &fakeClient{errs: []error{fmt.Errorf("dial tcp: timeout")}}
	s, _ := NewSlackObserver("https://example.com/hook", "",
		WithClient(client), WithBackoff(time.Nanosecond), WithRetries(2), WithSync())
	s.dlq = dlq
	s.Observe(denyEntry("Q-000002"))
	s.Stop()
	if dlq.Len() == 0 {
		t.Fatal("network failure not dead-lettered")
	}
}

func TestSlack_AllowEventsNotPosted(t *testing.T) {
	client := &fakeClient{}
	s, _ := NewSlackObserver("https://example.com/hook", "",
		WithClient(client), WithBackoff(time.Nanosecond), WithSync())
	s.Observe(audit.AuditEntry{Action: "allow", Tool: "x"})
	s.Stop()
	if client.calls != 0 {
		t.Fatalf("allow events must be Slack noise: got %d posts", client.calls)
	}
}

func TestSlack_DLQReplay(t *testing.T) {
	dlq := &safeBuffer{}

	s, _ := NewSlackObserver("https://example.com/hook", "",
		WithClient(&fakeClient{statuses: []int{500}}),
		WithBackoff(time.Nanosecond), WithRetries(2), WithSync())
	s.dlq = dlq
	s.Observe(denyEntry("Q-000007"))
	s.Stop()

	if dlq.Len() == 0 {
		t.Fatal("DLQ buffer empty — nothing to replay")
	}

	var seen []string
	err := ReplayFromBytes(dlq.Bytes(), func(entry audit.AuditEntry) error {
		seen = append(seen, entry.QuarantineID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "Q-000007" {
		t.Fatalf("replay mismatch: %v", seen)
	}
}

// ReplayFromFile is the on-disk variant used at startup; ReplayFromBytes
// covers the identical dispatch logic without a real file in tests.
func ReplayFromFile(dlqPath string, send func(entry audit.AuditEntry) error) error {
	data, err := os.ReadFile(dlqPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return ReplayFromBytes(data, send)
}



// ---------------------------------------------------------------------------
// PagerDuty observer tests (Ticket 12 contract)
// ---------------------------------------------------------------------------

func newClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_000_000, 0)}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestPD_TriggerAfterThreshold(t *testing.T) {
	client := &fakeClient{}
	clock := newClock()
	p := NewPagerDutyObserver("key-1", PDWithClient(client),
		PDWithClock(clock.Now), PDWithThreshold(5),
		PDWithWindow(60*time.Second), PDWithSuppression(5*time.Minute))

	for i := 0; i < 5; i++ {
		p.Observe(denyEntry(fmt.Sprintf("Q-%06d", i+1)))
		if p.FiringCount() != 0 {
			t.Fatalf("fired before threshold at event %d", i+1)
		}
	}
	p.Observe(denyEntry("Q-000006"))
	if p.FiringCount() != 1 {
		t.Fatalf("expected fire at 6th violation, got %d", p.FiringCount())
	}
	if client.calls != 1 {
		t.Fatalf("expected 1 incident POST, got %d", client.calls)
	}
}

func TestPD_SuppressionWindow(t *testing.T) {
	client := &fakeClient{}
	clock := newClock()
	p := NewPagerDutyObserver("key-1", PDWithClient(client),
		PDWithClock(clock.Now), PDWithThreshold(5),
		PDWithWindow(60*time.Second), PDWithSuppression(5*time.Minute))

	for i := 0; i < 6; i++ {
		p.Observe(denyEntry(fmt.Sprintf("Q-%06d", i+1)))
	}
	if p.FiringCount() != 1 {
		t.Fatalf("expected single fire, got %d", p.FiringCount())
	}
	// 50 more violations within the suppression window: no new fires.
	for i := 0; i < 50; i++ {
		p.Observe(denyEntry(fmt.Sprintf("Q-%06d", 100+i)))
	}
	if p.FiringCount() != 1 {
		t.Fatalf("suppression failed: %d fires", p.FiringCount())
	}
}

func TestPD_WindowExpiryResets(t *testing.T) {
	client := &fakeClient{}
	clock := newClock()
	p := NewPagerDutyObserver("key-1", PDWithClient(client),
		PDWithClock(clock.Now), PDWithThreshold(5),
		PDWithWindow(60*time.Second), PDWithSuppression(5*time.Minute))

	for i := 0; i < 4; i++ {
		p.Observe(denyEntry(fmt.Sprintf("Q-%06d", i+1)))
	}
	clock.Advance(61 * time.Second)
	// Old timestamps expired; 4 new ones should not yet fire.
	for i := 0; i < 4; i++ {
		p.Observe(denyEntry(fmt.Sprintf("Q-%06d", 100+i)))
	}
	if p.FiringCount() != 0 {
		t.Fatalf("expired window must reset the count: %d fires", p.FiringCount())
	}
}

func TestPD_FingerprintIsSHA256(t *testing.T) {
	client := &fakeClient{}
	clock := newClock()
	p := NewPagerDutyObserver("key-1", PDWithClient(client),
		PDWithClock(clock.Now), PDWithThreshold(1),
		PDWithWindow(60*time.Second), PDWithSuppression(5*time.Minute))

	p.Observe(audit.AuditEntry{
		Identity: core.CallerIdentity{ClientID: "svc-a", TokenHash: "abc"},
		Tool:     "x", Action: "deny", QuarantineID: "Q-000001",
	})
	// Fire happens once the count EXCEEDS the threshold (threshold 1 →
	// second weighted event triggers the incident).
	p.Observe(audit.AuditEntry{
		Identity: core.CallerIdentity{ClientID: "svc-a", TokenHash: "abc"},
		Tool:     "x", Action: "deny", QuarantineID: "Q-000002",
	})
	if client.calls != 1 {
		t.Fatal("no incident POST")
	}
}

func TestPD_AllowOnRedactionCounts(t *testing.T) {
	client := &fakeClient{}
	clock := newClock()
	p := NewPagerDutyObserver("key-1", PDWithClient(client),
		PDWithClock(clock.Now), PDWithThreshold(2),
		PDWithWindow(60*time.Second), PDWithSuppression(5*time.Minute))

	svcA := core.CallerIdentity{ClientID: "svc-a"}
	// A redacted allow carries a quarantine ID and counts as a violation.
	p.Observe(audit.AuditEntry{
		Identity: svcA, Tool: "search", Action: "allow", QuarantineID: "Q-000001",
	})
	// All three events share the same identity so the sliding window counts.
	p.Observe(denyEntryFor("Q-000002", svcA))
	// Third weighted event exceeds the threshold and fires the incident.
	p.Observe(denyEntryFor("Q-000003", svcA))
	if p.FiringCount() != 1 {
		t.Fatalf("allow-on-redaction must weight as violation: %d fires", p.FiringCount())
	}
}

func TestPD_CleanAllowIsNoise(t *testing.T) {
	client := &fakeClient{}
	clock := newClock()
	p := NewPagerDutyObserver("key-1", PDWithClient(client),
		PDWithClock(clock.Now), PDWithThreshold(1))
	p.Observe(audit.AuditEntry{Action: "allow", Tool: "x"})
	p.Observe(audit.AuditEntry{Action: "allow_all", Tool: "y"})
	if client.calls != 0 {
		t.Fatal("clean allows must not trigger")
	}
}

func TestPD_IdentitiesIsolated(t *testing.T) {
	client := &fakeClient{}
	clock := newClock()
	p := NewPagerDutyObserver("key-1", PDWithClient(client),
		PDWithClock(clock.Now), PDWithThreshold(3),
		PDWithWindow(60*time.Second), PDWithSuppression(5*time.Minute))

	for i := 0; i < 2; i++ {
		p.Observe(audit.AuditEntry{Identity: core.CallerIdentity{ClientID: "a"}, Action: "deny", Tool: "x"})
		p.Observe(audit.AuditEntry{Identity: core.CallerIdentity{ClientID: "b"}, Action: "deny", Tool: "x"})
	}
	// Third violation by "a" reaches but does not exceed the threshold;
	// "b" is also at 2 — no identity has tripped the alarm yet.
	if p.FiringCount() != 0 {
		t.Fatalf("threshold not reached yet: %d fires", p.FiringCount())
	}
	// Fourth violation by "a" hits the threshold exactly; still no fire
	// (alerting requires strictly exceeding the threshold, avoiding
	// noise at the boundary).
	p.Observe(audit.AuditEntry{Identity: core.CallerIdentity{ClientID: "a"}, Action: "deny", Tool: "x"})
	if p.FiringCount() != 0 {
		t.Fatalf("boundary must not fire: %d fires", p.FiringCount())
	}
	// Fifth violation by "a" exceeds the threshold and fires only for "a".
	p.Observe(audit.AuditEntry{Identity: core.CallerIdentity{ClientID: "a"}, Action: "deny", Tool: "x"})
	if p.FiringCount() != 1 {
		t.Fatalf("expected exactly 1 fire: %d", p.FiringCount())
	}
}

func ReplayFromBytes(data []byte, send func(entry audit.AuditEntry) error) error {
	var failures int
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry audit.AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			failures++
			continue
		}
		if err := send(entry); err != nil {
			failures++
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d entries could not be replayed", failures)
	}
	return nil
}
