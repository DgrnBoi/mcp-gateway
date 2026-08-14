package policy

import (
	"strings"
	"testing"
)

const validPolicy = `
default_action: deny
rules:
  - id: R-001
    agent:
      client_id: sales-copilot
    tool:
      name: search_contacts
    action: allow
  - id: R-002
    agent:
      client_id: etl-worker
    tool:
      name: execute_query
    action: deny_with_redact
    redact_keys:
      - sql
    reason: ad-hoc SQL blocked
  - id: R-003
    agent:
      client_id: human-admin
    tool:
      name: "*"
    action: allow_all
    reason: migration window
    expires_at: "2099-01-01T00:00:00Z"
`

func load(t *testing.T, s string) (*Policy, error) {
	t.Helper()
	return Load(strings.NewReader(s))
}

func TestLoader_ValidPolicy(t *testing.T) {
	p, err := load(t, validPolicy)
	if err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if len(p.Rules) != 3 {
		t.Errorf("want 3 rules, got %d", len(p.Rules))
	}
	if p.Rules[1].Action != ActionDenyRedact || len(p.Rules[1].RedactKeys) != 1 {
		t.Error("deny_with_redact rule not parsed correctly")
	}
}

func TestLoader_RejectsEmptyAgentMatch(t *testing.T) {
	doc := strings.Replace(validPolicy, "    agent:\n      client_id: sales-copilot\n", "", 1)
	_, err := load(t, doc)
	if err == nil {
		t.Error("POLICY ENGINE INCOMPLETE: empty AgentMatch was ACCEPTED — the critical auth-bypass would still be configurable")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestLoader_RejectsDuplicateIDs(t *testing.T) {
	doc := validPolicy + `
  - id: R-001
    agent:
      client_id: another
    tool:
      name: x
    action: deny
    reason: dup test
`
	_, err := load(t, doc)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("want duplicate-ID rejection, got err=%v", err)
	}
}

func TestLoader_AllowAllRequiresReasonAndExpiry(t *testing.T) {
	doc := `
default_action: deny
rules:
  - id: R-X
    agent:
      client_id: admin
    tool:
      name: y
    action: allow_all
`
	_, err := load(t, doc)
	if err == nil {
		t.Error("allow_all without reason+expiry was accepted")
	}
}

func TestLoader_AllowAllPastExpiryRejected(t *testing.T) {
	doc := `
default_action: deny
rules:
  - id: R-X
    agent:
      client_id: admin
    tool:
      name: y
    action: allow_all
    reason: oops
    expires_at: "2020-01-01T00:00:00Z"
`
	_, err := load(t, doc)
	if err == nil {
		t.Error("allow_all with past expiry was accepted")
	}
}

func TestLoader_DenyWithRedactRequiresKeys(t *testing.T) {
	doc := `
default_action: deny
rules:
  - id: R-X
    agent:
      client_id: worker
    tool:
      name: z
    action: deny_with_redact
    reason: no keys
`
	_, err := load(t, doc)
	if err == nil {
		t.Error("deny_with_redact without redact_keys was accepted")
	}
}

func TestLoader_RejectsUnknownFields(t *testing.T) {
	doc := validPolicy + `
  - id: R-Z
    agent:
      client_id: x
    toool:          # typo: unknown field, should be rejected by KnownFields(true)
      name: y
    action: deny
    reason: typo test
`
	_, err := load(t, doc)
	if err == nil {
		t.Error("unknown field 'toool' was silently accepted — typos would create invisible open rules")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestLoader_RejectsUnknownAction(t *testing.T) {
	doc := validPolicy + `
  - id: R-Z
    agent:
      client_id: x
    tool:
      name: y
    action: deny_all_please
    reason: bogus action
`
	_, err := load(t, doc)
	if err == nil {
		t.Error("unknown action was accepted")
	}
}

// LoadWithServers validates server alias references.
func TestLoader_RejectsUndeclaredServer(t *testing.T) {
	doc := `
default_action: deny
rules:
  - id: R-S
    agent:
      client_id: x
    tool:
      name: y
    action: deny
    server_alias: ghost-server
    reason: undeclared server
`
	_, err := LoadWithServers(strings.NewReader(doc), map[string]bool{"crm-server": true})
	if err == nil {
		t.Error("rule referencing undeclared server was accepted")
	}
}
