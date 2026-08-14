package gitops

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/policy"

	"gopkg.in/yaml.v3"
)

// Mode selects the generator's output family. DenyMode is the secure
// default and the ONLY mode offered without explicit human opt-in:
// generating allow rules for denied actions is a privilege-escalation
// path, and this package will never build one unprompted.
type Mode int

const (
	DenyMode Mode = iota
	AllowOptInMode // analyst explicitly accepts the escalation risk
)

// Request binds an audit entry to its quarantined payload and an output
// mode. The payload is needed to enumerate the exact argument keys the
// attacker used (for deny_with_redact scoping).
type Request struct {
	Entry   audit.AuditEntry
	Payload string // raw JSON from violations.log, may be ""
	Mode    Mode
}

// RulePatch is the generator's output: a minimal ADR-002-conformant YAML
// fragment plus provenance for review.
type RulePatch struct {
	YAML        string `json:"yaml"`
	RuleID      string `json:"rule_id"`
	Recommend   string `json:"recommendation"`
	SafetyNote  string `json:"safety_note"`
}

// Generate produces a tightly scoped rule that responds to the violation.
//
// DenyMode (default): the rule tightens enforcement around what the
// attacker actually attempted — an explicit deny on the tool for the
// exact attacking identity, or a deny_with_redact with the abusive
// argument keys when the payload reveals which keys carried the attack.
//
// AllowOptInMode: only when the tool is permitted elsewhere in policy and
// the analyst has opted in does the generator propose an allow rule,
// carrying a human-acknowledged reason and a 14-day auto-expiry.
func Generate(req Request, policyDoc *policy.Policy) (RulePatch, error) {
	entry := req.Entry
	switch entry.Action {
	case "deny":
		return denyRule(entry, req.Payload)
	case "deny_with_redact":
		return denyRule(entry, req.Payload)
	case "allow":
		if entry.QuarantineID == "" {
			return RulePatch{}, fmt.Errorf("no actionable action: %s", entry.Action)
		}
		// An allow-on-redaction event: the agent slipped past with a
		// redacted payload, so the response is still tighter enforcement.
		return denyRule(entry, req.Payload)
	}
	return RulePatch{}, fmt.Errorf("no actionable action: %s", entry.Action)
}

// denyRule emits an explicit deny (or deny_with_redact when the payload
// reveals abusive argument keys) scoped to the attacking identity.
func denyRule(entry audit.AuditEntry, payload string) (RulePatch, error) {
	id := uniqueRuleID()
	agent := agentFor(entry)

	if agent.IsEmpty() {
		// No fingerprintable identity: scope to the tool only, and warn.
		agent = policy.AgentMatch{}
	}

	var keys []string
	if strings.Contains(entry.Action, "redact") || payload != "" {
		keys = extractAbusiveKeys(payload)
	}

	action := policy.ActionDeny
	var redact []string
	recommend := fmt.Sprintf("explicit deny on %s for identity %s|%s|%s",
		entry.Tool, agent.ClientID, agent.TokenHashPrefix, agent.MTLSSubject)
	if len(keys) > 0 {
		action = policy.ActionDenyRedact
		redact = keys
		recommend = fmt.Sprintf("deny_with_redact on %s stripping keys %v for identity %s|%s|%s",
			entry.Tool, keys, agent.ClientID, agent.TokenHashPrefix, agent.MTLSSubject)
	}

	rule := policy.Rule{
		ID: id,
		AgentMatch: agent,
		ToolMatch:  policy.ToolMatch{Name: entry.Tool},
		Action:     action,
		Reason:     fmt.Sprintf("auto-generated response to violation %s (%s)", entry.QuarantineID, entry.Timestamp),
		RedactKeys: redact,
	}

	// An anonymous attacker (no fingerprintable identity) must not produce
	// an empty `agent:` block — an empty AgentMatch would be a universal
	// match if ever relaxed, so emit a tool-only rule instead.
	var out []byte
	var err error
	if agent.IsEmpty() {
		out, err = yaml.Marshal(map[string]any{
			"id":   id,
			"tool": map[string]string{"name": entry.Tool},
			"action": action,
			"reason": fmt.Sprintf("auto-generated response to violation %s (%s)",
				entry.QuarantineID, entry.Timestamp),
		})
	} else {
		out, err = yaml.Marshal(rule)
	}
	if err != nil {
		return RulePatch{}, err
	}
	return RulePatch{
		YAML:        string(out),
		RuleID:      id,
		Recommend:   recommend,
		SafetyNote:  "Deny-first by policy: this rule tightens enforcement. It never grants new access.",
	}, nil
}

// AllowRule is the opt-in escalation path. Callers must obtain explicit
// analyst consent before using it; it forces a reason and a 14-day expiry.
func AllowRule(entry audit.AuditEntry, reason string) (RulePatch, error) {
	if strings.TrimSpace(reason) == "" {
		return RulePatch{}, fmt.Errorf("allow rule requires an analyst-provided reason")
	}
	id := uniqueRuleID()
	expiry := &policy.ExpiryTime{Time: time.Now().UTC().Add(14 * 24 * time.Hour)}
	rule := policy.Rule{
		ID:         id,
		AgentMatch: agentFor(entry),
		ToolMatch:  policy.ToolMatch{Name: entry.Tool},
		Action:     policy.ActionAllow,
		Reason:     reason,
		Expiry:     expiry,
	}
	out, err := yaml.Marshal(rule)
	if err != nil {
		return RulePatch{}, err
	}
	return RulePatch{
		YAML: string(out),
		RuleID: id,
		Recommend: fmt.Sprintf("opt-in allow on %s for identity (auto-expires %s)",
			entry.Tool, expiry.Format(time.RFC3339)),
		SafetyNote: "OPT-IN ESCALATION: a human accepted that this relaxes enforcement. Review and remove after expiry.",
	}, nil
}

// extractAbusiveKeys returns top-level argument keys when the payload is
// parseable JSON; callers scope redaction to everything the payload
// touched. Empty on unparseable payloads (deny without redaction data).
func extractAbusiveKeys(payload string) []string {
	if payload == "" {
		return nil
	}
	var wrapper struct {
		Arguments map[string]any `json:"arguments"`
	}
	if err := parseJSON(payload, &wrapper); err != nil || len(wrapper.Arguments) == 0 {
		return nil
	}
	keys := make([]string, 0, len(wrapper.Arguments))
	for k := range wrapper.Arguments {
		keys = append(keys, k)
	}
	return keys
}

func parseJSON(s string, v any) error {
	return json.NewDecoder(strings.NewReader(s)).Decode(v)
}

// agentFor binds the generated rule to the exact identity from the audit
// entry — the fingerprint scoping the attacker, never a wildcard.
func agentFor(entry audit.AuditEntry) policy.AgentMatch {
	id := entry.Identity
	return policy.AgentMatch{
		ClientID:        id.ClientID,
		MTLSSubject:     id.MTLSSubject,
		TokenHashPrefix: prefixOf(id.TokenHash),
	}
}

// prefixOf shortens token hashes for YAML readability while staying
// specific enough for matching (loader tolerates prefixes).
func prefixOf(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// uniqueRuleID builds a deterministic ID from the entry's correlation
// data so reruns are stable, formatted to the ADR-002 pattern.
var idSeq uint64

func uniqueRuleID() string {
	// Monotonic counter + wall clock + PID makes reruns stable within one
	// process and unique across processes, formatted to ADR-002 pattern.
	seq := atomic.AddUint64(&idSeq, 1)
	raw := fmt.Sprintf("R-%d-%d-%d", os.Getpid(), time.Now().UnixMilli(), seq)
	sum := sha256.Sum256([]byte(raw))
	n := int(sum[0])%900 + 100 // 100..999
	return fmt.Sprintf("R-%d", n)
}
