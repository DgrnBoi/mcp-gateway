package policy

import (
	"github.com/antigravity/mcp-gateway/pkg/core"
)

// Decision represents the final outcome of the policy evaluation.
type Decision struct {
	Action        Action
	MatchedRuleID string
	Reason        string
}

// Action is the enforcement outcome for a rule.
type Action string

const (
	ActionAllow      Action = "allow"
	ActionDeny       Action = "deny"
	ActionDenyRedact Action = "deny_with_redact" // matches YAML "deny_with_redact" (ADR-002)
	ActionAllowAll   Action = "allow_all"
)

// AgentMatch selects which agents a rule applies to.
// Invariant (FIX #1): at least one field MUST be set; an empty AgentMatch
// is a loader-level validation error, never silently-universal.
type AgentMatch struct {
	ClientID        string `yaml:"client_id"`
	MTLSSubject     string `yaml:"mtls_subject"`
	UserAgent       string `yaml:"user_agent"`
	TokenHashPrefix string `yaml:"token_hash_prefix"`
}

// IsEmpty reports whether the match has no identity criteria at all.
// Loader validation must reject empty AgentMatches; Evaluate must also
// defend against them because a security gateway is defense-in-depth.
func (m AgentMatch) IsEmpty() bool {
	return m.ClientID == "" && m.MTLSSubject == "" &&
		m.UserAgent == "" && m.TokenHashPrefix == ""
}

// ToolMatch selects which tools a rule applies to.
type ToolMatch struct {
	Name string `yaml:"name"`
}

// Rule is a single allow/deny policy rule.
type Rule struct {
	ID         string     `yaml:"id"`
	AgentMatch AgentMatch `yaml:"agent"`
	ToolMatch  ToolMatch  `yaml:"tool"`
	Action     Action     `yaml:"action"`
	Reason     string     `yaml:"reason,omitempty"`
	// RedactKeys lists argument keys to strip when Action is deny_with_redact.
	RedactKeys []string `yaml:"redact_keys,omitempty"`
	// ServerAlias names the upstream MCP server this rule targets (loader field).
	ServerAlias string `yaml:"server_alias,omitempty"`
	// Expiry, when set, makes an allow_all rule auto-revoke (loader field).
	Expiry *ExpiryTime `yaml:"expires_at,omitempty"`
}

// Policy is the full loaded policy document.
type Policy struct {
	DefaultAction Action `yaml:"default_action"`
	Rules         []Rule `yaml:"rules"`
	// PolicyLayer marks which hierarchy tier this document belongs to.
	// "org" (the central baseline) or "team" (a specific unit's allowances).
	// Required for hierarchical merging (Ticket 19); unknown values are
	// rejected at load time.
	PolicyLayer string `yaml:"policy_layer,omitempty"`
}

// Evaluator is the pure-Go transport-agnostic interface for evaluating MCP messages.
type Evaluator interface {
	Evaluate(msg *core.MCPMessage) Decision
}

type DefaultEvaluator struct {
	policy *Policy
}

func NewEvaluator(p *Policy) *DefaultEvaluator {
	return &DefaultEvaluator{policy: p}
}

// Policy returns the evaluator's loaded policy. Used by the server layer to
// look up matched rules (e.g., redaction keys) after evaluation.
func (e *DefaultEvaluator) Policy() *Policy {
	return e.policy
}

// Evaluate applies the top-to-bottom first-match rules to the normalized message.
//
// FIX #1 (critical): messages with NO identity are denied BEFORE rule walking,
// so an empty CallerIdentity can never match anything, and an empty AgentMatch
// can never become a universal allow.
//
// FIX #2: the default decision's MatchedRuleID is derived from the actual
// default action, so audit logs never contradict themselves.
func (e *DefaultEvaluator) Evaluate(msg *core.MCPMessage) Decision {
	// Pre-flight identity gate. An entirely unidentified caller never
	// enters the rule walk — no rule can "rescue" it.
	if isIdentityEmpty(msg.CallerIdentity) {
		return Decision{
			Action:        ActionDeny,
			MatchedRuleID: "PRE_FLIGHT_UNIDENTIFIED",
			Reason:        "no identity presented (no client_id, mTLS subject, or token)",
		}
	}

	for _, rule := range e.policy.Rules {
		// Defense in depth: skip any rule whose agent match is empty.
		// Loader validation should reject these, but evaluation never
		// trusts the loader alone.
		if rule.AgentMatch.IsEmpty() {
			continue
		}
		if !matchAgent(rule.AgentMatch, msg.CallerIdentity) {
			continue
		}

		// If the rule specifies a tool match, but this isn't a tool call, skip.
		if rule.ToolMatch.Name != "" {
			if msg.ToolCall == nil {
				continue
			}
			if !matchTool(rule.ToolMatch, msg.ToolCall) {
				continue
			}
		}
		return Decision{
			Action:        rule.Action,
			MatchedRuleID: rule.ID,
			Reason:        rule.Reason,
		}
	}
	return Decision{
		Action:        e.policy.DefaultAction,
		MatchedRuleID: "DEFAULT_" + string(e.policy.DefaultAction),
	}
}

// isIdentityEmpty reports whether the caller presented zero identity claims.
func isIdentityEmpty(c core.CallerIdentity) bool {
	return c.ClientID == "" && c.MTLSSubject == "" &&
		c.TokenHash == "" && c.UserAgent == ""
}

// matchAgent requires every non-empty field of the rule's AgentMatch to
// equal the corresponding field of the caller. Empty rule fields are
// wildcards; an all-empty rule field set is rejected by IsEmpty above.
func matchAgent(match AgentMatch, caller core.CallerIdentity) bool {
	if match.ClientID != "" && match.ClientID != caller.ClientID {
		return false
	}
	if match.MTLSSubject != "" && match.MTLSSubject != caller.MTLSSubject {
		return false
	}
	if match.TokenHashPrefix != "" && !hasPrefix(caller.TokenHash, match.TokenHashPrefix) {
		return false
	}
	if match.UserAgent != "" && match.UserAgent != caller.UserAgent {
		return false
	}
	return true
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func matchTool(match ToolMatch, tool *core.ToolCallView) bool {
	if match.Name != "" && match.Name != tool.ToolName {
		return false
	}
	return true
}
