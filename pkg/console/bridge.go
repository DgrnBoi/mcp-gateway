package console

import (
	"encoding/json"

	"github.com/antigravity/mcp-gateway/pkg/audit"
)

// ConsoleObserver is the audit.Observer implementation that feeds the
// visibility console. Every enforcement decision is:
//   - pushed to the in-memory event store (ring buffer + quarantine map)
//   - broadcast over the SSE stream for the live dashboard
//
// Observe runs synchronously on the gateway's critical path, so both steps
// are bounded: the ingester is O(1) and Notify uses non-blocking fan-out.
type ConsoleObserver struct {
	Ingester *Ingester
	Server   *Server
}

// Observe implements audit.Observer.
func (c *ConsoleObserver) Observe(entry audit.AuditEntry) {
	c.Ingester.Observe(entry)
	data, err := json.Marshal(entry)
	if err != nil {
		return // never break the critical path over a serialization failure
	}
	c.Server.Notify(data)
}

// Quarantined implements audit.QuarantineNotifier for the ingester: the
// Writer forwards quarantine payloads after writing violations.log, and the
// console keeps its in-memory retrieval map in sync.
func (c *ConsoleObserver) Quarantined(quarantineID, ruleID, rawParams string) {
	c.Ingester.StoreQuarantinePayload(quarantineID, ruleID, rawParams)
}
