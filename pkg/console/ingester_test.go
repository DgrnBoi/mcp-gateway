package console

import (
	"testing"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
)

func entry(id, tool, action, qid string) audit.AuditEntry {
	return audit.AuditEntry{
		Timestamp:     time.Now().UTC().Add(-1 * time.Second).Format(audit.RFC3339Milli),
		CorrelationID: "req-" + id, Transport: "streamable_http",
		Tool: tool, Action: action, RuleID: "R-001", LatencyNs: 1000,
		QuarantineID: qid,
	}
}

func TestIngester_ObservePush(t *testing.T) {
	ing := NewIngester(10, 0)
	e := entry("1", "search_contacts", "allow", "")
	ing.Observe(e)
	if got := ing.Count(); got != 1 {
		t.Fatalf("expected 1 event, got %d", got)
	}
	snap := ing.AuditSnapshot(0, 10)
	if len(snap) != 1 || snap[0].Tool != "search_contacts" {
		t.Fatalf("snapshot wrong: %+v", snap)
	}
}

func TestIngester_RingWrapsAndKeepsOrder(t *testing.T) {
	ing := NewIngester(5, 0)
	for i := 1; i <= 8; i++ {
		ing.Observe(entry(string(rune('0'+i)), "t", "allow", ""))
	}
	snap := ing.AuditSnapshot(0, 10)
	if len(snap) != 5 {
		t.Fatalf("expected 5 retained events, got %d", len(snap))
	}
	// oldest retained first: events 4..8
	if snap[0].CorrelationID != "req-4" || snap[4].CorrelationID != "req-8" {
		t.Fatalf("ordering broken: first=%s last=%s", snap[0].CorrelationID, snap[4].CorrelationID)
	}
}

func TestIngester_QuarantineMapAndTTL(t *testing.T) {
	ing := NewIngester(10, 5*time.Millisecond)
	ing.StoreQuarantinePayload("Q-000001", "R-003", `{"name":"x","arguments":{"sql":"DROP"}}`)

	raw, ruleID, ok := ing.Quarantine("Q-000001")
	if !ok || ruleID != "R-003" || raw == "" {
		t.Fatalf("quarantine retrieval failed: %q %q %v", raw, ruleID, ok)
	}
	time.Sleep(10 * time.Millisecond)
	if _, _, ok = ing.Quarantine("Q-000001"); ok {
		t.Fatal("expired quarantine should not be retrievable")
	}
	ing.StoreQuarantinePayload("Q-000002", "R-004", `{"readonly":true}`)
	ing.Prune()
	if raw, _, ok := ing.Quarantine("Q-000002"); !ok || raw == "" {
		t.Fatalf("fresh quarantine pruned incorrectly: %q %v", raw, ok)
	}
}

func TestIngester_ConcurrentObservers(t *testing.T) {
	ing := NewIngester(10_000, 0)
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(id int) {
			for i := 0; i < 500; i++ {
				ing.Observe(entry(string(rune('A'+id%26))+string(rune('0'+i%10)), "t", "allow", ""))
			}
			done <- struct{}{}
		}(g)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if got := ing.Count(); got != 4000 {
		t.Fatalf("lost events under concurrency: expected 4000, got %d", got)
	}
}

func TestIngester_SnapshotBounds(t *testing.T) {
	ing := NewIngester(10, 0)
	for i := 1; i <= 3; i++ {
		ing.Observe(entry(string(rune('0'+i)), "t", "allow", ""))
	}
	if got := ing.AuditSnapshot(99, 10); len(got) != 0 {
		t.Fatal("out-of-range offset must return empty")
	}
	if got := ing.AuditSnapshot(0, -1); len(got) != 0 {
		t.Fatal("non-positive limit must return empty")
	}
}
