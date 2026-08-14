package policy

import (
	"encoding/json"
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/core"
)

// testPolicy mirrors examples/policy.yaml R-001..R-004 style rules,
// including an allow rule for read_customer_data so the sql_injection
// fixture's "allowed tool" story is true.
var testPolicy = &Policy{
	DefaultAction: ActionDeny,
	Rules: []Rule{
		{ID: "R-001", AgentMatch: AgentMatch{ClientID: "sales-copilot"}, ToolMatch: ToolMatch{Name: "search_contacts"}, Action: ActionAllow},
		{ID: "R-002", AgentMatch: AgentMatch{ClientID: "sales-copilot"}, ToolMatch: ToolMatch{Name: "get_contact"}, Action: ActionAllow},
		{ID: "R-003", AgentMatch: AgentMatch{ClientID: "sales-copilot"}, ToolMatch: ToolMatch{Name: "export_contacts_bulk"}, Action: ActionDeny, Reason: "bulk export forbidden"},
		{ID: "R-004", AgentMatch: AgentMatch{ClientID: "etl-worker"}, ToolMatch: ToolMatch{Name: "execute_query"}, Action: ActionDenyRedact, RedactKeys: []string{"sql"}, Reason: "ad-hoc SQL blocked"},
		{ID: "R-005", AgentMatch: AgentMatch{ClientID: "sales-copilot"}, ToolMatch: ToolMatch{Name: "read_customer_data"}, Action: ActionAllow},
	},
}

func TestEvaluator_Allow(t *testing.T) {
	e := NewEvaluator(testPolicy)
	msg := &core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "sales-copilot"},
		ToolCall:       &core.ToolCallView{ToolName: "search_contacts"},
	}
	d := e.Evaluate(msg)
	if d.Action != ActionAllow || d.MatchedRuleID != "R-001" {
		t.Errorf("want allow/R-001, got %s/%s", d.Action, d.MatchedRuleID)
	}
}

func TestEvaluator_DefaultDeny(t *testing.T) {
	e := NewEvaluator(testPolicy)
	msg := &core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "sales-copilot"},
		ToolCall:       &core.ToolCallView{ToolName: "some_unknown_tool"},
	}
	d := e.Evaluate(msg)
	if d.Action != ActionDeny || d.MatchedRuleID != "DEFAULT_deny" {
		t.Errorf("want deny/DEFAULT_deny, got %s/%s", d.Action, d.MatchedRuleID)
	}
}

// FIX #2 regression: default action label must match the action.
func TestEvaluator_AllowAllDefault_Consistent(t *testing.T) {
	p := &Policy{DefaultAction: ActionAllowAll, Rules: testPolicy.Rules}
	e := NewEvaluator(p)
	msg := &core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "unknown-agent"},
		ToolCall:       &core.ToolCallView{ToolName: "anything"},
	}
	d := e.Evaluate(msg)
	if d.Action != ActionAllowAll {
		t.Fatalf("action should be allow_all, got %s", d.Action)
	}
	if d.MatchedRuleID != "DEFAULT_allow_all" {
		t.Errorf("matched rule id is %q — want DEFAULT_allow_all; audit log must not contradict the action", d.MatchedRuleID)
	}
}

// FIX #1 regression: an empty AgentMatch must NEVER become a universal allow.
func TestEvaluator_EmptyAgentMatch_NeverMatches(t *testing.T) {
	p := &Policy{
		DefaultAction: ActionDeny,
		Rules: []Rule{
			{ID: "R-BAD", AgentMatch: AgentMatch{}, ToolMatch: ToolMatch{Name: "export_contacts_bulk"}, Action: ActionAllow},
		},
	}
	e := NewEvaluator(p)
	msg := &core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "anonymous"},
		ToolCall:       &core.ToolCallView{ToolName: "export_contacts_bulk"},
	}
	d := e.Evaluate(msg)
	if d.Action == ActionAllow {
		t.Error("empty AgentMatch still matches — the critical auth-bypass is not fixed")
	}
}

// FIX #1 regression: an unidentified caller is denied before rule walking.
func TestEvaluator_UnidentifiedCaller_PreFlightDeny(t *testing.T) {
	e := NewEvaluator(testPolicy)
	msg := &core.MCPMessage{
		CallerIdentity: core.CallerIdentity{}, // nothing presented
		ToolCall:       &core.ToolCallView{ToolName: "search_contacts"},
	}
	d := e.Evaluate(msg)
	if d.Action != ActionDeny {
		t.Errorf("unidentified caller must be denied, got %s", d.Action)
	}
	if d.MatchedRuleID != "PRE_FLIGHT_UNIDENTIFIED" {
		t.Errorf("want PRE_FLIGHT_UNIDENTIFIED, got %s", d.MatchedRuleID)
	}
}

// deny_with_redact smoke test (redaction mechanics move to enforcement later).
func TestEvaluator_DenyWithRedact_MatchesRule(t *testing.T) {
	e := NewEvaluator(testPolicy)
	msg := &core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "etl-worker"},
		ToolCall:       &core.ToolCallView{ToolName: "execute_query"},
	}
	d := e.Evaluate(msg)
	if d.Action != ActionDenyRedact || d.MatchedRuleID != "R-004" {
		t.Errorf("want deny_with_redact/R-004, got %s/%s", d.Action, d.MatchedRuleID)
	}
}

// sql_injection.json fixture story check: under the reference policy,
// read_customer_data IS allowed for sales-copilot, so the malicious
// payload story (allowed tool, bad argument) is now truthful.
func TestEvaluator_SqlInjectionFixture(t *testing.T) {
	fixture := `{
	  "jsonrpc": "2.0",
	  "method": "tools/call",
	  "params": {
		"name": "read_customer_data",
		"arguments": {
		  "customer_id": "1 OR 1=1; DROP TABLE users;"
		}
	  },
	  "id": 2
	}`
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(fixture), &raw); err != nil {
		t.Fatalf("fixture is not valid JSON-RPC: %v", err)
	}
	e := NewEvaluator(testPolicy)
	msg := &core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "sales-copilot"},
		ToolCall:       &core.ToolCallView{ToolName: "read_customer_data"},
		Method:         "tools/call",
	}
	d := e.Evaluate(msg)
	if d.Action != ActionAllow {
		t.Errorf("fixture story requires the tool to be ALLOWED (payload is the problem, not the tool). Got %s/%s", d.Action, d.MatchedRuleID)
	}
}

// BenchmarkEvaluator_WorstCase tests the 5ms latency gate by simulating a policy
// with 200 mismatching rules, forcing the evaluator to walk the entire list
// before hitting the default deny. (Submitted by orchestrator; verified by coder.)
func BenchmarkEvaluator_WorstCase(b *testing.B) {
	rules := make([]Rule, 200)
	for i := 0; i < 200; i++ {
		rules[i] = Rule{
			ID:         "R-MISMATCH",
			AgentMatch: AgentMatch{ClientID: "wrong-client"},
			ToolMatch:  ToolMatch{Name: "wrong_tool"},
			Action:     ActionAllow,
		}
	}
	p := &Policy{
		DefaultAction: ActionDeny,
		Rules:         rules,
	}
	eval := NewEvaluator(p)
	msg := &core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "target-client"},
		ToolCall:       &core.ToolCallView{ToolName: "target_tool"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Evaluate(msg)
	}
}
