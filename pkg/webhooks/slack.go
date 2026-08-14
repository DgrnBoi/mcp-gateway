package webhooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/core"
)

// DefaultChannelSize is the bounded handoff between Notify (critical path)
// and the delivery worker.
const DefaultChannelSize = 1000

// DefaultMaxRetries is the delivery attempt ceiling before dead-lettering.
const DefaultMaxRetries = 3

// DefaultBaseBackoff is the starting backoff before the first retry.
const DefaultBaseBackoff = 500 * time.Millisecond

// HTTPClient abstracts the transport so tests inject a deterministic client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DeadLetterWriter abstracts DLQ output so tests capture writes.
type DeadLetterWriter interface {
	Write(p []byte) (n int, err error)
}

// SlackObserver pushes enforcement decisions to a Slack incoming webhook.
//
// Decoupling contract: Notify always pushes to a bounded channel and
// returns immediately; if the channel is full, the event is dead-lettered
// rather than blocking the gateway's critical path. A dedicated worker
// retries transient failures with exponential backoff and ultimately
// persists the entry to the DLQ so alert loss is never silent.
type SlackObserver struct {
	url      string
	queue    chan audit.AuditEntry
	dlq      DeadLetterWriter
	client   HTTPClient
	baseBack time.Duration
	retries  int
	stopped  chan struct{}
	done     chan struct{}
	dlqmu    sync.Mutex
	sync     bool // tests only: deliver synchronously in Observe
}

// SlackOption applies a constructor setting.
type SlackOption func(*SlackObserver)

// WithClient injects the HTTP client (tests only).
func WithClient(c HTTPClient) SlackOption {
	return func(s *SlackObserver) { s.client = c }
}

// WithBackoff replaces the backoff base (tests only).
func WithBackoff(d time.Duration) SlackOption {
	return func(s *SlackObserver) { s.baseBack = d }
}

// WithRetries replaces the retry ceiling (tests only).
func WithRetries(n int) SlackOption {
	return func(s *SlackObserver) { s.retries = n }
}

// WithSync disables the worker goroutine and delivers synchronously in
// Observe. Production MUST NOT use this; it exists so the delivery logic
// can be exercised deterministically in tests.
func WithSync() SlackOption {
	return func(s *SlackObserver) { s.sync = true }
}

// NewSlackObserver opens the DLQ file and starts the delivery worker.
// url is the Slack incoming webhook URL from config.yaml.
func NewSlackObserver(url, dlqPath string, opts ...SlackOption) (*SlackObserver, error) {
	var dlq DeadLetterWriter
	if dlqPath != "" {
		f, err := os.OpenFile(dlqPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("opening dead-letter log: %w", err)
		}
		dlq = f
	}

	s := &SlackObserver{
		url:      url,
		queue:    make(chan audit.AuditEntry, DefaultChannelSize),
		dlq:      dlq,
		client:   http.DefaultClient,
		baseBack: DefaultBaseBackoff,
		retries:  DefaultMaxRetries,
		stopped:  make(chan struct{}),
		done:     make(chan struct{}),
	}
	for _, o := range opts {
		o(s)
	}
	if !s.sync {
		go s.worker()
	} else {
		close(s.done)
	}
	return s, nil
}

// Observe is the audit.Observer entry point. It never blocks and never
// panics: a full queue or a DLQ write failure is swallowed after best effort.
func (s *SlackObserver) Observe(entry audit.AuditEntry) {
	if s.sync {
		s.deliver(entry)
		return
	}
	select {
	case s.queue <- entry:
	default:
		// Queue full — the gateway must not wait. Dead-letter the event.
		s.deadLetter(entry, "queue_full")
	}
}

// Stop drains the queue one final time and waits for the worker to exit.
func (s *SlackObserver) Stop() {
	select {
	case <-s.stopped:
		return
	default:
	}
	close(s.stopped)
	s.drainOnce()
	<-s.done
}

// ReplayFrom scans a DLQ file, re-dispatches every entry, and truncates on
// success. It supports the "restart and flush what we couldn't send"
// durability guarantee. Call before starting workers; not thread-safe.
func ReplayFrom(dlqPath string, send func(entry audit.AuditEntry) error) error {
	if dlqPath == "" {
		return nil
	}
	data, err := os.ReadFile(dlqPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
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
		return fmt.Errorf("%d DLQ entries could not be replayed", failures)
	}
	return os.WriteFile(dlqPath, nil, 0o600)
}

// --- private ---

func (s *SlackObserver) worker() {
	defer close(s.done)
	for {
		select {
		case <-s.stopped:
			// Shutdown contract: flush anything still queued before exiting
			// so Stop() returns only after queued events are processed.
			s.drainOnce()
			return
		case entry := <-s.queue:
			s.deliver(entry)
		}
	}
}

// drainOnce empties the channel in the non-blocking path so Stop() waits
// until queued events are processed.
func (s *SlackObserver) drainOnce() {
	for {
		select {
		case entry := <-s.queue:
			s.deliver(entry)
		default:
			return
		}
	}
}

func (s *SlackObserver) deliver(entry audit.AuditEntry) {
	lastErr := s.send(entry)
	if lastErr == nil {
		return
	}
	if _, ok := lastErr.(*permanentError); ok {
		// 4xx: never retry — the webhook URL is dead or misconfigured.
		s.deadLetter(entry, lastErr.Error())
		return
	}
	for attempt := 1; attempt <= s.retries; attempt++ {
		time.Sleep(s.baseBack * (1 << (attempt - 1)))
		lastErr = s.send(entry)
		if lastErr == nil {
			return
		}
		if _, ok := lastErr.(*permanentError); ok {
			s.deadLetter(entry, lastErr.Error())
			return
		}
	}
	s.deadLetter(entry, lastErr.Error())
}

// send posts the Slack payload. 5xx and network errors are transient;
// anything else (4xx — e.g. a dead webhook URL) fails permanently.
func (s *SlackObserver) send(entry audit.AuditEntry) error {
	payload, err := slackPayload(entry)
	if err != nil {
		return nil // unsendable payload: don't retry, don't DLQ spam
	}
	if payload == nil {
		return nil // event filtered out (e.g. clean allows): no delivery
	}
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err // network failure: transient
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 500 {
		return fmt.Errorf("slack HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return &permanentError{code: resp.StatusCode} // never retry
	}
	return nil
}

// permanentError marks 4xx responses so retries skip them and the entry is
// DLQ'd immediately after one attempt instead of three futile ones.
type permanentError struct{ code int }

func (e *permanentError) Error() string {
	return fmt.Sprintf("slack HTTP %d (permanent)", e.code)
}

// deadLetter appends the entry to the DLQ with a failure note. File DLQ
// keeps alert-loss durable and replayable; a one-line stderr summary keeps
// operators aware even when nobody reads the log directory.
func (s *SlackObserver) deadLetter(entry audit.AuditEntry, cause string) {
	line, err := json.Marshal(struct {
		audit.AuditEntry
		Reason string `json:"dead_letter_reason"`
	}{entry, cause})
	if err != nil {
		return
	}
	line = append(line, '\n')
	if s.dlq != nil {
		s.dlqmu.Lock()
		_, _ = s.dlq.Write(line)
		s.dlqmu.Unlock()
	}
	fmt.Fprintf(os.Stderr, "mcpgw: dead-lettered slack event q=%s cause=%s\n",
		entry.QuarantineID, cause)
}

// slackPayload builds the incoming-webhook payload for a violation event.
func slackPayload(entry audit.AuditEntry) ([]byte, error) {
	if entry.Action != "deny" && entry.Action != "deny_with_redact" {
		return nil, nil // Slack is violation-focused; other events are noise
	}
	return json.Marshal(map[string]string{
		"text": fmt.Sprintf("MCP Gateway violation: %s called %s -> %s (rule %s, %s)",
			identityDisplay(entry.Identity), entry.Tool, entry.Action,
			entry.RuleID, entry.Timestamp),
	})
}

// identityDisplay renders the canonical debug string
// ClientID|TokenHash|MTLSSubject used for fingerprints and alerts.
func identityDisplay(id core.CallerIdentity) string {
	return fmt.Sprintf("%s|%s|%s", id.ClientID, id.TokenHash, id.MTLSSubject)
}
