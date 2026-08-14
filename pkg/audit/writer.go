package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/policy"
)

// RFC3339Milli is time.RFC3339Nano truncated to millisecond precision,
// the format mandated by the audit contract spec (e.g. 2026-08-12T14:32:00.123Z).
const RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"

// AuditEntry is one line of audit.log (SIEM ingestion), per the contract spec.
type AuditEntry struct {
	Timestamp     string              `json:"timestamp"`
	CorrelationID string              `json:"correlation_id"`
	Transport     string              `json:"transport"`
	Identity      core.CallerIdentity `json:"identity"`
	Tool          string              `json:"tool,omitempty"`
	Action        string              `json:"action"`
	RuleID        string              `json:"rule_id"`
	Reason        string              `json:"reason"`
	LatencyNs     int64               `json:"latency_ns"`
	QuarantineID  string              `json:"quarantine_id,omitempty"`
}

// ViolationEntry is one line of violations.log (high-security quarantine).
type ViolationEntry struct {
	QuarantineID      string          `json:"quarantine_id"`
	Timestamp         string          `json:"timestamp"`
	RuleID            string          `json:"rule_id"`
	OriginalRawParams json.RawMessage `json:"original_raw_params"`
}

// Observer is the push-model hook registered on the audit Writer. Observers
// are notified SYNCHRONOUSLY on the gateway's critical path for every
// enforcement decision, so implementations must be fast and must not panic;
// the Writer recovers from observer panics to protect the data plane.
type Observer interface {
	Observe(entry AuditEntry)
}

// Writer appends JSON-lines entries to two append-only log files.
// Concurrency-safe; a single writer instance is shared per gateway.
type Writer struct {
	mu             sync.Mutex
	auditFile      io.Writer
	violationsFile io.Writer
	quarantineSeq  uint64
	observers      []Observer
}

// NewWriter creates a Writer. nil paths skip that log (testing/separation).
func NewWriter(auditPath, violationsPath string) (*Writer, error) {
	var af, vf io.Writer
	var err error
	if auditPath != "" {
		af, err = os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, fmt.Errorf("opening audit log: %w", err)
		}
	}
	if violationsPath != "" {
		vf, err = os.OpenFile(violationsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("opening violations log: %w", err)
		}
	}
	return &Writer{auditFile: af, violationsFile: vf}, nil
}

// Close flushes and closes the underlying writers when they are files
// (io.Closer). It is a no-op for in-memory test writers.
func (w *Writer) Close() error {
	var firstErr error
	for _, c := range []io.Closer{closerOf(w.auditFile), closerOf(w.violationsFile)} {
		if c != nil {
			if err := c.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// closerOf returns an io.Closer only when the writer is a file that the
// Writer owns — os.Stdout/os.Stderr must NOT be closed by the library.
func closerOf(w io.Writer) io.Closer {
	f, ok := w.(*os.File)
	if !ok {
		return nil
	}
	if f == os.Stdout || f == os.Stderr {
		return nil
	}
	return f
}

// NewWriterTo is the in-memory testing constructor.
func NewWriterTo(af, vf io.Writer) *Writer {
	return &Writer{auditFile: af, violationsFile: vf}
}

// RecordDecision writes one enforcement decision to audit.log and, if the
// action was deny or deny_with_redact, quarantines the verbatim payload to
// violations.log, returning the quarantine ID (or "").
func (w *Writer) RecordDecision(
	msg *core.MCPMessage,
	decision policy.Decision,
	latencyNs int64,
) (quarantineID string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	ts := time.Now().UTC().Format(RFC3339Milli)
	tool := ""
	if msg.ToolCall != nil {
		tool = msg.ToolCall.ToolName
	}
	entry := AuditEntry{
		Timestamp:     ts,
		CorrelationID: correlationID(msg),
		Transport:     string(msg.Transport),
		Identity:      msg.CallerIdentity,
		Tool:          tool,
		Action:        string(decision.Action),
		RuleID:        decision.MatchedRuleID,
		Reason:        decision.Reason,
		LatencyNs:     latencyNs,
	}

	if decision.Action == policy.ActionDeny || decision.Action == policy.ActionDenyRedact {
		w.quarantineSeq++
		entry.QuarantineID = fmt.Sprintf("Q-%06d", w.quarantineSeq)
		quarantineID = entry.QuarantineID
		if w.violationsFile != nil && len(msg.RawParams) > 0 {
			v := ViolationEntry{
				QuarantineID:      quarantineID,
				Timestamp:         ts,
				RuleID:            decision.MatchedRuleID,
				OriginalRawParams: msg.RawParams,
			}
			line, _ := json.Marshal(v)
			fmt.Fprintf(w.violationsFile, "%s\n", line)
			// Forward the quarantined payload to registered observers
			// (e.g. the visibility console) via the quarantine notifier.
			ForwardQuarantine(quarantineID, decision.MatchedRuleID, string(msg.RawParams))
		}
	}

	if w.auditFile != nil {
		line, _ := json.Marshal(entry)
		fmt.Fprintf(w.auditFile, "%s\n", line)
	}

	// Push to observers AFTER the durable logs so a slow or failing observer
	// can never cause audit-line loss on the critical path.
	for _, o := range w.observers {
		observeSafe(o, entry)
	}
	return quarantineID
}

// RegisterObserver attaches an observer to the push stream. Registration
// before the gateway starts serving is assumed (no lock needed at runtime).
func (w *Writer) RegisterObserver(o Observer) {
	w.observers = append(w.observers, o)
}

// observeSafe calls the observer inside a panic guard: a misbehaving
// observer must never take down the gateway's enforcement path.
func observeSafe(o Observer, entry AuditEntry) {
	defer func() { recover() }()
	o.Observe(entry)
}

// QuarantineNotifier is the quarantine-side hook registered by interested
// consumers (e.g. the visibility console). It is invoked after each
// quarantine line is written to violations.log. Keeping it in pkg/audit
// avoids an import cycle: consumers import audit, never the reverse.
type QuarantineNotifier interface {
	Quarantined(quarantineID, ruleID, rawParams string)
}

var quarantineNotifier func(quarantineID, ruleID, rawParams string)
var quarantineNotifierMu sync.RWMutex

// RegisterQuarantineNotifier installs the quarantine forwarder.
func RegisterQuarantineNotifier(n QuarantineNotifier) {
	quarantineNotifierMu.Lock()
	quarantineNotifier = func(qid, ruleID, rawParams string) { n.Quarantined(qid, ruleID, rawParams) }
	quarantineNotifierMu.Unlock()
}

// ForwardQuarantine is invoked by RecordDecision after writing a quarantine
// line. Nil notifier is a safe no-op.
func ForwardQuarantine(quarantineID, ruleID, rawParams string) {
	quarantineNotifierMu.RLock()
	f := quarantineNotifier
	quarantineNotifierMu.RUnlock()
	if f != nil {
		f(quarantineID, ruleID, rawParams)
	}
}

// correlationID derives a stable ID from the message for log correlation.
func correlationID(msg *core.MCPMessage) string {
	if msg.ID != "" {
		return "req-" + msg.ID
	}
	return fmt.Sprintf("req-%d", msg.ReceivedAt.UnixMilli())
}
