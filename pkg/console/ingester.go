package console

import (
	"sync"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
)

const (
	// DefaultCapacity is the ring-buffer size mandated by the Stage 2 plan
	// (last 10,000 events for instant UI loading).
	DefaultCapacity = 10_000
	// DefaultQuarantineTTL caps how long quarantined payloads stay in memory.
	DefaultQuarantineTTL = 30 * time.Minute
)

// Ingester is the console's in-memory event store. It implements
// audit.Observer (synchronous push from the Writer) and stores:
//   - a ring buffer of the last N AuditEntries (oldest entries are overwritten
//     once full — the UI loads recent history instantly, and full history
//     remains in the durable audit.log for SIEM)
//   - a quarantine map: quarantine_id -> quarantined payload, TTL-pruned
type Ingester struct {
	mu       sync.Mutex
	capacity int
	head     int // index of the newest entry (0-based ring slot)
	count    int // entries currently in the buffer
	ring     []audit.AuditEntry

	qmu        sync.Mutex
	quarantine map[string]violationRecord
	qttl       time.Duration
}

type violationRecord struct {
	RawParams string    `json:"raw_params"`
	RuleID    string    `json:"rule_id"`
	ExpiresAt time.Time `json:"-"`
}

// NewIngester creates a console event store with the given capacity and
// quarantine TTL (use 0 for the defaults).
func NewIngester(capacity int, ttl time.Duration) *Ingester {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if ttl <= 0 {
		ttl = DefaultQuarantineTTL
	}
	return &Ingester{
		capacity:   capacity,
		ring:       make([]audit.AuditEntry, capacity),
		quarantine: make(map[string]violationRecord),
		qttl:       ttl,
	}
}

// Observe implements audit.Observer. Called synchronously on the gateway's
// critical path: bounded work only (ring write + map insert), no I/O.
func (i *Ingester) Observe(entry audit.AuditEntry) {
	i.mu.Lock()
	i.ring[i.head] = entry
	i.head = (i.head + 1) % i.capacity
	if i.count < i.capacity {
		i.count++
	}
	i.mu.Unlock()

	if entry.QuarantineID != "" && entry.Timestamp != "" {
		if t, err := time.Parse(audit.RFC3339Milli, entry.Timestamp); err == nil {
			i.storeQuarantine(entry, t)
		}
	}
}

// storeQuarantine keeps the verbatim quarantine available for inspection.
// Quarantine payloads live on violations.log forever; the map is a
// convenience index only, hence the TTL cap.
func (i *Ingester) storeQuarantine(entry audit.AuditEntry, ts time.Time) {
	// Raw params are not present in the AuditEntry; the verbatim payload
	// arrives via StoreQuarantinePayload (ForwardQuarantine) which may race
	// with this marker insert — never clobber a payload with an empty one.
	i.qmu.Lock()
	if existing, present := i.quarantine[entry.QuarantineID]; !present || existing.RawParams == "" {
		i.quarantine[entry.QuarantineID] = violationRecord{
			RawParams: "", ExpiresAt: ts.Add(i.qttl),
		}
	}
	i.qmu.Unlock()
}

// StoreQuarantinePayload attaches the verbatim quarantined payload (from
// violations.log or the gateway's quarantine path) to the in-memory index.
func (i *Ingester) StoreQuarantinePayload(qid, ruleID, rawParams string) {
	i.qmu.Lock()
	defer i.qmu.Unlock()
	i.quarantine[qid] = violationRecord{
		RawParams: rawParams, RuleID: ruleID, ExpiresAt: time.Now().Add(i.qttl),
	}
}

// AuditSnapshot returns a page of events. offset=0 is the OLDEST retained
// event; the newest is at count-1. Out-of-range offsets return an empty page.
func (i *Ingester) AuditSnapshot(offset, limit int) []audit.AuditEntry {
	i.mu.Lock()
	count, head, capacity := i.count, i.head, i.capacity
	ring := i.ring
	i.mu.Unlock()

	if limit <= 0 || offset < 0 || offset >= count {
		return nil
	}
	if offset+limit > count {
		limit = count - offset
	}
	out := make([]audit.AuditEntry, limit)
	for n := 0; n < limit; n++ {
		// oldest retained slot = (head - count + offset) mod capacity
		idx := (head - count + offset + n + capacity*2) % capacity
		out[n] = ring[idx]
	}
	return out
}

// Count returns the current number of retained events (ring buffer load).
func (i *Ingester) Count() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.count
}

// LookupEntryByQuarantineID returns the audit entry that produced the
// quarantine payload so the GitOps generator can bind its suggested rule
// to the exact attacking identity. Entries rotate out of the ring buffer
// like every other record, so suggestion only works while the entry is
// still retained.
func (i *Ingester) LookupEntryByQuarantineID(qid string) (audit.AuditEntry, bool) {
	events := i.AuditSnapshot(0, i.Capacity())
	for n := len(events) - 1; n >= 0; n-- {
		if events[n].QuarantineID == qid {
			return events[n], true
		}
	}
	return audit.AuditEntry{}, false
}

// Capacity exposes the ring-buffer capacity (for pagination boundaries).
func (i *Ingester) Capacity() int {
	return i.capacity
}

// Quarantine returns the quarantined payload for a quarantine ID, or an
// empty string when the ID is unknown or TTL-expired.
func (i *Ingester) Quarantine(qid string) (rawParams string, ruleID string, ok bool) {
	i.qmu.Lock()
	defer i.qmu.Unlock()
	rec, present := i.quarantine[qid]
	if !present {
		return "", "", false
	}
	if time.Now().After(rec.ExpiresAt) {
		delete(i.quarantine, qid)
		return "", "", false
	}
	return rec.RawParams, rec.RuleID, true
}

// Prune removes TTL-expired quarantine entries; cheap, called by a periodic
// timer (e.g. every 5 minutes). Panics from this path never reach observers.
func (i *Ingester) Prune() {
	now := time.Now()
	i.qmu.Lock()
	defer i.qmu.Unlock()
	for qid, rec := range i.quarantine {
		if now.After(rec.ExpiresAt) {
			delete(i.quarantine, qid)
		}
	}
}
