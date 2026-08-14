package metrics

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Collector is the Stage 3 telemetry surface (Ticket 18). It exposes
// standard Prometheus counters and a latency histogram through a
// hand-rolled text exposition so the gateway keeps its zero-import
// supply chain (no third-party prometheus/client dependency).
type Collector struct {
	mu            sync.Mutex
	violations    map[string]int64 // "rule_id|identity" → count
	requests      map[string]int64 // action → count
	rateLimited   map[string]int64 // identity → count
	histCount     int64
	histSum       float64
	histBuckets   []float64
	bucketCounts  []int64
}

// DefaultBuckets are the evaluator latency buckets in seconds.
var DefaultBuckets = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
}

// NewCollector creates a collector with the default latency buckets.
func NewCollector() *Collector {
	return &Collector{
		violations:  make(map[string]int64),
		requests:    make(map[string]int64),
		rateLimited: make(map[string]int64),
		histBuckets: DefaultBuckets,
		bucketCounts: make([]int64, len(DefaultBuckets)+1),
	}
}

// IncViolation records a policy violation keyed by rule ID and the
// attacking identity fingerprint.
func (c *Collector) IncViolation(ruleID, identity string) {
	c.mu.Lock()
	c.violations[ruleID+"|"+identity]++
	c.mu.Unlock()
}

// IncRequest records an enforcement decision.
func (c *Collector) IncRequest(action string) {
	c.mu.Lock()
	c.requests[action]++
	c.mu.Unlock()
}

// IncRateLimited records a 429 event for the identity. By design these
// never flow into PagerDuty (see Ticket 16) but operators still want
// the counter in dashboards.
func (c *Collector) IncRateLimited(identity string) {
	c.mu.Lock()
	c.rateLimited[identity]++
	c.mu.Unlock()
}

// ObserveLatency adds a duration to the evaluator latency histogram.
func (c *Collector) ObserveLatency(d time.Duration) {
	sec := d.Seconds()
	c.mu.Lock()
	c.histCount++
	c.histSum += sec
	for i, bound := range c.histBuckets {
		if sec <= bound {
			c.bucketCounts[i]++
		}
	}
	c.bucketCounts[len(c.histBuckets)]++ // +Inf
	c.mu.Unlock()
}

// handler is the shared exposition logic; Expose and the console
// handler both use it.
func (c *Collector) render() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var sb strings.Builder

	writeCounter := func(name, help string, labels []string, values map[string]int64) {
		sb.WriteString("# HELP ")
		sb.WriteString(name)
		sb.WriteString(" ")
		sb.WriteString(help)
		sb.WriteString("\n# TYPE ")
		sb.WriteString(name)
		sb.WriteString(" counter\n")
		// Deterministic ordering so alerting diff-checks stay stable.
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts := strings.SplitN(k, "|", 2)
			sb.WriteString(name)
			writeLabels(&sb, labels, parts)
			fmt.Fprintf(&sb, " %d\n", values[k])
		}
		sb.WriteString("\n")
	}

	writeCounter("mcpgw_violations_total",
		"Policy violations by rule id and identity fingerprint.",
		[]string{"rule_id", "identity"}, c.violations)
	writeCounter("mcpgw_requests_total",
		"Enforcement decisions by action.",
		[]string{"action"}, c.requests)
	writeCounter("mcpgw_rate_limited_total",
		"HTTP 429 responses emitted by identity.",
		[]string{"identity"}, c.rateLimited)

	// Histogram exposition.
	sb.WriteString("# HELP mcpgw_evaluate_latency_seconds Evaluator decision latency.\n")
	sb.WriteString("# TYPE mcpgw_evaluate_latency_seconds histogram\n")
	for i, bound := range c.histBuckets {
		fmt.Fprintf(&sb, "mcpgw_evaluate_latency_seconds_bucket{le=\"%g\"} %d\n", bound, c.bucketCounts[i])
	}
	fmt.Fprintf(&sb, "mcpgw_evaluate_latency_seconds_bucket{le=\"+Inf\"} %d\n", c.bucketCounts[len(c.histBuckets)])
	fmt.Fprintf(&sb, "mcpgw_evaluate_latency_seconds_sum %s\n", formatFloat(c.histSum))
	fmt.Fprintf(&sb, "mcpgw_evaluate_latency_seconds_count %d\n", c.histCount)
	return sb.String()
}

func writeLabels(sb *strings.Builder, labels []string, parts []string) {
	sb.WriteByte('{')
	for i, label := range labels {
		if i > 0 {
			sb.WriteString(", ")
		}
		value := ""
		if i < len(parts) {
			value = parts[i]
		}
		fmt.Fprintf(sb, "%s=%q", label, value)
	}
	sb.WriteByte('}')
}

// formatFloat renders a float without scientific notation for stable
// Prometheus parsing.
func formatFloat(f float64) string {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return fmt.Sprintf("%g", f)
	}
	s := fmt.Sprintf("%.6f", f)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}

// Expose returns the full Prometheus text exposition.
func (c *Collector) Expose() string {
	return c.render()
}
