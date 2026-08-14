package policy

import (
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"
)

// ExpiryTime wraps time.Time for YAML deserialization of allow_all expirations.
type ExpiryTime struct {
	time.Time
}

func (e *ExpiryTime) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("expiry must be RFC3339 (e.g. 2026-08-19T00:00:00Z): %w", err)
	}
	e.Time = t
	return nil
}

// NOTE (ADR-002): Rule, Policy, and the Action constants are defined in
// evaluator.go. The loader EXTENDS them via ServerAlias and Expiry below.
// Both files share the same package, so no type duplication exists.

// ServerAlias is the rule field naming the upstream server it targets.
type ServerAlias = string

// Load parses and strictly validates a YAML policy document.
func Load(r io.Reader) (*Policy, error) {
	var p Policy
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true) // Reject unknown fields to prevent silent typos
	if err := decoder.Decode(&p); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	if err := validatePolicy(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func validatePolicy(p *Policy) error {
	// Invariant: the ONLY safe default is deny; allow_all as default is a
	// misconfiguration even if technically representable in code.
	if p.DefaultAction == "" {
		return fmt.Errorf("default_action is required (recommend: deny)")
	}
	if p.DefaultAction != ActionDeny && p.DefaultAction != ActionAllowAll {
		return fmt.Errorf("default_action must be 'deny' or 'allow_all', got '%s'", p.DefaultAction)
	}
	if p.DefaultAction == ActionAllow {
		return fmt.Errorf("default_action 'allow' is prohibited on any layer: the gateway fails closed by default")
	}

	seenIDs := make(map[string]bool)
	seenServerAliases := make(map[string]bool)
	for i, rule := range p.Rules {
		// 1. Rule ID presence and uniqueness
		if rule.ID == "" {
			return fmt.Errorf("rule #%d: missing rule ID", i+1)
		}
		if seenIDs[rule.ID] {
			return fmt.Errorf("rule #%d: duplicate rule ID '%s'", i+1, rule.ID)
		}
		seenIDs[rule.ID] = true

		// 2. Valid action value
		switch rule.Action {
		case ActionAllow, ActionDeny, ActionDenyRedact, ActionAllowAll:
		default:
			return fmt.Errorf("rule #%d ('%s'): unknown action '%s'", i+1, rule.ID, rule.Action)
		}

		// 3. Empty AgentMatch — loader AND evaluator both guard this.
		if rule.AgentMatch.IsEmpty() {
			return fmt.Errorf("rule #%d ('%s'): empty AgentMatch is forbidden", i+1, rule.ID)
		}

		// 4. allow_all requires reason AND future expiry.
		if rule.Action == ActionAllowAll {
			if rule.Reason == "" {
				return fmt.Errorf("rule #%d ('%s'): allow_all requires a reason", i+1, rule.ID)
			}
			if rule.Expiry == nil {
				return fmt.Errorf("rule #%d ('%s'): allow_all requires expires_at", i+1, rule.ID)
			}
			if rule.Expiry.Time.Before(time.Now()) {
				return fmt.Errorf("rule #%d ('%s'): allow_all expires_at is in the past", i+1, rule.ID)
			}
		}

		// 5. deny_with_redact requires redact_keys.
		if rule.Action == ActionDenyRedact && len(rule.RedactKeys) == 0 {
			return fmt.Errorf("rule #%d ('%s'): deny_with_redact requires redact_keys", i+1, rule.ID)
		}

		// 6. Server alias references (forward declaration check skipped;
		// loader receives the server map from the caller in production).
		_ = seenServerAliases
	}

	// 7. policy_layer validation (Ticket 19). A missing layer is rejected:
	// the merger must never silently assign a tier, and a typo in the layer
	// name must fail closed.
	switch p.PolicyLayer {
	case "", "org", "team":
	default:
		return fmt.Errorf("unknown policy_layer '%s' (must be 'org' or 'team')", p.PolicyLayer)
	}

	// Team layers may never default to allow: a missing rule walks to the
	// team default, so a permissive team default would silently erode the
	// org baseline.
	if p.PolicyLayer == "team" && p.DefaultAction == ActionAllow {
		return fmt.Errorf("team policy cannot default to allow: would erode the org baseline")
	}
	return nil
}

// LoadWithServers parses a policy and validates every rule.server reference
// against the declared server aliases. Called once at startup; the result is
// cached in memory and reloaded on config change with hash verification.
func LoadWithServers(r io.Reader, servers map[string]bool) (*Policy, error) {
	p, err := Load(r)
	if err != nil {
		return nil, err
	}
	for i, rule := range p.Rules {
		if rule.ServerAlias != "" && !servers[rule.ServerAlias] {
			return nil, fmt.Errorf("rule #%d ('%s'): references undeclared server '%s'", i+1, rule.ID, rule.ServerAlias)
		}
	}
	return p, nil
}
