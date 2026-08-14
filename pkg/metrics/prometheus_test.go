package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestCollector_ViolationCounter(t *testing.T) {
	c := NewCollector()
	c.IncViolation("R-001", "fp-a")
	c.IncViolation("R-001", "fp-a")
	c.IncViolation("R-002", "fp-b")

	body := c.Expose()
	if !strings.Contains(body, `mcpgw_violations_total{rule_id="R-001", identity="fp-a"} 2`) {
		t.Fatalf("expected 2 violations for R-001|fp-a:\n%s", body)
	}
	if !strings.Contains(body, `mcpgw_violations_total{rule_id="R-002", identity="fp-b"} 1`) {
		t.Fatal("expected 1 violation for R-002|fp-b")
	}
}

func TestCollector_RequestCounter(t *testing.T) {
	c := NewCollector()
	c.IncRequest("deny")
	c.IncRequest("deny")
	c.IncRequest("allow")
	body := c.Expose()
	if !strings.Contains(body, `mcpgw_requests_total{action="deny"} 2`) {
		t.Fatal("expected deny=2")
	}
	if !strings.Contains(body, `mcpgw_requests_total{action="allow"} 1`) {
		t.Fatal("expected allow=1")
	}
}

func TestCollector_RateLimitedCounter(t *testing.T) {
	c := NewCollector()
	c.IncRateLimited("fp-a")
	c.IncViolation("R-001", "fp-a")
	body := c.Expose()
	if !strings.Contains(body, `mcpgw_rate_limited_total{identity="fp-a"} 1`) {
		t.Fatal("expected rate_limited counter present")
	}
	if !strings.Contains(body, "mcpgw_violations_total") {
		t.Fatal("violations must still be exposed alongside rate limits")
	}
}

func TestCollector_HistogramAccumulates(t *testing.T) {
	c := NewCollector()
	c.ObserveLatency(1 * time.Millisecond) // 0.001s
	c.ObserveLatency(3 * time.Millisecond) // 0.003s
	c.ObserveLatency(20 * time.Millisecond) // 0.02s

	body := c.Expose()
	lines := strings.Split(body, "\n")
	find := func(prefix string) string {
		for _, l := range lines {
			if strings.HasPrefix(l, prefix) {
				return l
			}
		}
		return ""
	}
	// 0.001 <= 0.001 → bucket 0.001 gets 1; 0.003 ≤ 0.005 gets it etc.
	if find(`mcpgw_evaluate_latency_seconds_bucket{le="0.001"}`) != `mcpgw_evaluate_latency_seconds_bucket{le="0.001"} 1` {
		t.Fatalf("le=0.001 line wrong: %s", find(`mcpgw_evaluate_latency_seconds_bucket{le="0.001"}`))
	}
	if find(`mcpgw_evaluate_latency_seconds_count`) != "mcpgw_evaluate_latency_seconds_count 3" {
		t.Fatalf("count line wrong: %s", find(`mcpgw_evaluate_latency_seconds_count`))
	}
	if find(`mcpgw_evaluate_latency_seconds_sum`) != "mcpgw_evaluate_latency_seconds_sum 0.024" {
		t.Fatalf("sum line wrong: %s", find(`mcpgw_evaluate_latency_seconds_sum`))
	}
	if !strings.Contains(body, `mcpgw_evaluate_latency_seconds_bucket{le="+Inf"} 3`) {
		t.Fatal("+Inf bucket must equal count")
	}
}

func TestCollector_OutputIsDeterministic(t *testing.T) {
	c := NewCollector()
	c.IncViolation("R-B", "fp-2")
	c.IncViolation("R-A", "fp-1")
	a := c.Expose()
	b := c.Expose()
	if a != b {
		t.Fatal("exposition must be deterministic across calls")
	}
	// Lexicographic ordering: R-A before R-B.
	i := strings.Index(a, "R-A")
	j := strings.Index(a, "R-B")
	if i >= j {
		t.Fatal("labels must be lexicographically ordered")
	}
}

func TestCollector_Concurrent(t *testing.T) {
	c := NewCollector()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					c.IncViolation("R-001", "fp")
					c.IncRequest("deny")
					c.ObserveLatency(time.Microsecond)
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		_ = c.Expose()
	}
	close(done)
	body := c.Expose()
	if !strings.Contains(body, "mcpgw_violations_total") {
		t.Fatal("concurrent counters must survive")
	}
}
