package gitops

import (
	"strings"
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/policy"

	"gopkg.in/yaml.v3"
)

func viEntry(action string, qid string) audit.AuditEntry {
	return audit.AuditEntry{
		Timestamp:     "2026-08-12T18:00:00.000Z",
		CorrelationID: "req-violation",
		Transport:     "streamable_http",
		Identity: core.CallerIdentity{
			ClientID: "sales-copilot", TokenHash: "sha256tokenabcdef1234567890",
		},
		Tool:         "export_contacts_bulk",
		Action:       action,
		RuleID:       "R-003",
		QuarantineID: qid,
	}
}

// ---------------------------------------------------------------------------
// Deny-first generation (Ticket 13 secure default)
// ---------------------------------------------------------------------------

func TestGenerate_DenyModeProducesDenyRule(t *testing.T) {
	patch, err := Generate(Request{Entry: viEntry("deny", "Q-000001")}, &policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(patch.YAML, "action: deny") {
		t.Fatalf("deny-mode rule must be a deny, got:\n%s", patch.YAML)
	}
	if !strings.Contains(patch.YAML, "export_contacts_bulk") {
		t.Fatal("rule must be scoped to the offending tool")
	}
	if !strings.Contains(patch.YAML, "sales-copilot") {
		t.Fatal("rule must be scoped to the attacking identity")
	}
	if !strings.HasPrefix(patch.RuleID, "R-") || len(patch.RuleID) != 5 {
		t.Fatalf("rule ID must follow ADR-002 pattern, got %q", patch.RuleID)
	}
	if patch.SafetyNote == "" {
		t.Fatal("patch must carry an explicit safety note")
	}
	// Round-trip: the patch must parse back into a valid Rule.
	var rule policy.Rule
	if err := yaml.Unmarshal([]byte(patch.YAML), &rule); err != nil {
		t.Fatalf("generated YAML failed to parse: %v", err)
	}
	if rule.ToolMatch.Name != "export_contacts_bulk" || rule.Action != policy.ActionDeny {
		t.Fatal("round-tripped rule lost tool/action scoping")
	}
}

func TestGenerate_RedactPayloadScopesRedactKeys(t *testing.T) {
	payload := `{"arguments": {"sql": "SELECT * FROM users", "limit": 10}}`
	patch, err := Generate(Request{
		Entry:   viEntry("deny_with_redact", "Q-000002"),
		Payload: payload,
	}, &policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(patch.YAML, "action: deny_with_redact") {
		t.Fatalf("deny_with_redact violation must propose deny_with_redact, got:\n%s", patch.YAML)
	}
	if !strings.Contains(patch.YAML, "sql") || !strings.Contains(patch.YAML, "limit") {
		t.Fatalf("redact_keys must cover every argument key in the payload: %s", patch.YAML)
	}
}

func TestGenerate_EmptyPayloadFallsBackToDeny(t *testing.T) {
	patch, err := Generate(Request{
		Entry:   viEntry("deny_with_redact", "Q-000003"),
		Payload: "",
	}, &policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(patch.YAML, "action: deny") {
		t.Fatalf("unparseable payload must fall back to a plain deny: %s", patch.YAML)
	}
}

func TestGenerate_AnonymousIdentityWarnsAndToolOnly(t *testing.T) {
	entry := audit.AuditEntry{
		Timestamp: "2026-08-12T18:00:00.000Z", Transport: "streamable_http",
		Identity: core.CallerIdentity{}, Tool: "export_contacts_bulk",
		Action: "deny", QuarantineID: "Q-000004",
	}
	patch, err := Generate(Request{Entry: entry}, &policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(patch.YAML, "export_contacts_bulk") {
		t.Fatalf("rule must still scope to the tool: %s", patch.YAML)
	}
	// No client_id line means the rule is tool-scoped only (identity unknown).
	if strings.Contains(patch.YAML, "client_id") {
		t.Fatal("anonymous identity must not fabricate a client_id criterion")
	}
}

func TestGenerate_AllowOnRedactionStillTightens(t *testing.T) {
	// An allow decision that carried a quarantine ID is a redaction
	// incident, not a success: the generated response must tighten
	// enforcement, never acknowledge the access.
	patch, err := Generate(Request{
		Entry: audit.AuditEntry{
			Timestamp: "2026-08-12T18:00:00.000Z", Transport: "streamable_http",
			Identity: core.CallerIdentity{ClientID: "sales-copilot"},
			Tool: "export_contacts_bulk", Action: "allow", QuarantineID: "Q-000005",
		},
	}, &policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(patch.YAML, "action: allow") {
		t.Fatalf("allow-on-redaction must never generate an allow rule: %s", patch.YAML)
	}
	if patch.SafetyNote == "" {
		t.Fatal("safety note missing")
	}
}

func TestGenerate_CleanAllowUnactionable(t *testing.T) {
	_, err := Generate(Request{
		Entry: audit.AuditEntry{Action: "allow", Tool: "x"},
	}, &policy.Policy{})
	if err == nil {
		t.Fatal("a clean allow carries no violation context: must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Opt-in escalation path (analyst consent guardrails)
// ---------------------------------------------------------------------------

func TestAllowRule_RequiresReason(t *testing.T) {
	_, err := AllowRule(viEntry("allow_all", "Q-000006"), "")
	if err == nil {
		t.Fatal("empty reason must be rejected")
	}
	_, err = AllowRule(viEntry("allow_all", "Q-000007"), "   ")
	if err == nil {
		t.Fatal("whitespace-only reason must be rejected")
	}
}

func TestAllowRule_ExpiresAndDocumentsEscalation(t *testing.T) {
	patch, err := AllowRule(viEntry("allow_all", "Q-000008"), "temp access for sales migration")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(patch.YAML, "action: allow") {
		t.Fatalf("opt-in rule must be an allow: %s", patch.YAML)
	}
	if !strings.Contains(patch.YAML, "expires_at") {
		t.Fatalf("opt-in rule must carry a 14-day auto-expiry: %s", patch.YAML)
	}
	if !strings.Contains(patch.Recommend, "auto-expires") {
		t.Fatal("recommendation must flag the auto-expiry")
	}
	if !strings.Contains(patch.SafetyNote, "OPT-IN ESCALATION") {
		t.Fatal("safety note must warn that this relaxes enforcement")
	}
}
