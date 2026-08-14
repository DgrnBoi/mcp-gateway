package webhooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
)

// DefaultWindow is the sliding-window span for violation counting.
const DefaultWindow = 60 * time.Second

// DefaultThreshold fires a PagerDuty incident when exceeded.
const DefaultThreshold = 5

// DefaultSuppressionWindow mutes re-alerts for the same identity after fire.
const DefaultSuppressionWindow = 5 * time.Minute

// HTTPClient abstracts the transport so tests inject a deterministic client.
type PDHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// NowFunc supplies time so the sliding window is deterministically testable.
type NowFunc func() time.Time

// PagerDutyObserver raises incidents only for identities that accumulate
// weighted violations above the threshold inside a sliding window.
//
// Fingerprint contract: the dedup key is SHA-256(ClientID|TokenHash|
// MTLSSubject) — bounded length, collision-safe, and safe for PagerDuty's
// dedup field. The canonical debug string ClientID|TokenHash|MTLSSubject is
// included in the incident description for human triage.
type PagerDutyObserver struct {
	routingKey string
	logPrefix  string
	client     PDHTTPClient
	now        NowFunc
	window            time.Duration
	threshold         int
	suppressionWindow time.Duration

	mu          sync.Mutex
	events      map[string][]time.Time // fingerprint -> window timestamps
	suppress    map[string]time.Time   // fingerprint -> suppression deadline
	fired    int                    // number of incidents raised (test/helper)
}

// PDOption applies a constructor setting.
type PDOption func(*PagerDutyObserver)

// WithClient injects the HTTP client (tests only).
func PDWithClient(c PDHTTPClient) PDOption {
	return func(p *PagerDutyObserver) { p.client = c }
}

// WithClock injects the time provider (tests only).
func PDWithClock(f NowFunc) PDOption {
	return func(p *PagerDutyObserver) { p.now = f }
}

// WithThreshold replaces the fire threshold (tests only).
func PDWithThreshold(n int) PDOption {
	return func(p *PagerDutyObserver) { p.threshold = n }
}

// WithWindow replaces the sliding window (tests only).
func PDWithWindow(d time.Duration) PDOption {
	return func(p *PagerDutyObserver) { p.window = d }
}

// WithSuppression replaces the post-fire mute (tests only).
func PDWithSuppression(d time.Duration) PDOption {
	return func(p *PagerDutyObserver) { p.suppressionWindow = d }
}

// NewPagerDutyObserver creates the observer with wall-clock defaults.
func NewPagerDutyObserver(routingKey string, opts ...PDOption) *PagerDutyObserver {
	p := &PagerDutyObserver{
		routingKey: routingKey,
		logPrefix:  "mcpgw",
		client:     http.DefaultClient,
		now:               time.Now,
		window:            DefaultWindow,
		threshold:         DefaultThreshold,
		suppressionWindow: DefaultSuppressionWindow,
		events:     make(map[string][]time.Time),
		suppress:   make(map[string]time.Time),
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Observe implements audit.Observer. Only weighted violation events count;
// a fire calls the PagerDuty Events v2 API once per suppression window.
func (p *PagerDutyObserver) Observe(entry audit.AuditEntry) {
	w := eventWeight(entry)
	if w == 0 {
		return
	}

	fingerprint, display := fingerprintOf(entry)
	now := p.now()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Prune expired timestamps from the sliding window.
	ts := make([]time.Time, 0, len(p.events[fingerprint]))
	for _, t := range p.events[fingerprint] {
		if now.Sub(t) < p.window {
			ts = append(ts, t)
		}
	}
	ts = append(ts, now)
	p.events[fingerprint] = ts

	if len(ts) <= p.threshold {
		return
	}
	if deadline, ok := p.suppress[fingerprint]; ok && now.Before(deadline) {
		return
	}


	p.fire(display, fingerprint, entry)
	p.suppress[fingerprint] = now.Add(p.suppressionWindow)
}

// FiringCount exposes incident count for tests; not concurrency-protected
// beyond the lock used at fire time.
func (p *PagerDutyObserver) FiringCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fired
}

// --- private ---

// eventWeight scores an enforcement decision for alerting purposes.
// allow, allow_all, and malformed decisions are noise; violations count.
func eventWeight(entry audit.AuditEntry) int {
	switch entry.Action {
	case "deny", "deny_with_redact":
		return 1
	case "allow":
		// An allow decision that carried a quarantine ID is an
		// allow-on-redaction incident signal (see ADR amendment on Ticket 12).
		if entry.QuarantineID != "" {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// fingerprintOf returns the SHA-256 dedup key and the human-readable string.
func fingerprintOf(entry audit.AuditEntry) (string, string) {
	display := identityDisplay(entry.Identity)
	sum := sha256.Sum256([]byte(display))
	return fmt.Sprintf("%x", sum), display
}

func (p *PagerDutyObserver) fire(display, fingerprint string, entry audit.AuditEntry) {
	p.fired++
	if p.client == nil {
		return
	}
	// Log the incident fire so operators can see escalation in the gateway
	// log without waiting on the PD API response.
	fmt.Printf("%s: pagerduty incident fired for %s (dedup %s)\n",
		p.logPrefix, display, fingerprint[:12]+"...")

	payload, err := json.Marshal(map[string]any{
		"routing_key":  p.routingKey,
		"event_action": "trigger",
		"dedup_key":    fingerprint,
		"payload": map[string]any{
			"summary":  fmt.Sprintf("MCP agent %s tripped %d violations in %s", display, p.threshold, p.window),
			"severity": "critical",
			"source":   "mcp-gateway",
			"component": entry.Tool,
			"custom_details": map[string]string{
				"identity_display": display,
				"latest_tool":      entry.Tool,
				"latest_rule":      entry.RuleID,
				"timestamp":        entry.Timestamp,
			},
		},
	})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost,
		"https://events.pagerduty.com/v2/enqueue",
		bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}
