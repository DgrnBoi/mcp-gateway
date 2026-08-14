package enforcement

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/policy"
)

func mustRawParams(t *testing.T, s string) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		t.Fatalf("bad raw params fixture: %v", err)
	}
	return raw
}

func TestRewrite_StripsRedactKeys(t *testing.T) {
	msg := &core.MCPMessage{
		Method: "tools/call",
		ToolCall: &core.ToolCallView{
			ToolName: "execute_query",
			Args:     map[string]interface{}{"sql": "DROP TABLE users;", "readonly": true},
		},
		RawParams: mustRawParams(t, `{"name":"execute_query","arguments":{"sql":"DROP TABLE users;","readonly":true}}`),
	}
	decision := policy.Decision{Action: policy.ActionDenyRedact, MatchedRuleID: "R-004", Reason: "ad-hoc SQL blocked"}
	rule := &policy.Rule{RedactKeys: []string{"sql"}}

	clean, err := Rewrite(msg, decision, rule)
	if err != nil {
		t.Fatalf("rewrite failed: %v", err)
	}
	s := string(clean)
	if strings.Contains(s, `"sql"`) {
		t.Error("redacted key 'sql' still present in forwarded payload")
	}
	if !strings.Contains(s, `"readonly":true`) {
		t.Error("allowed key 'readonly' was removed — over-redaction")
	}
	// Original must remain intact on the message for quarantine.
	if !strings.Contains(string(msg.RawParams), "DROP TABLE users") {
		t.Error("original RawParams was mutated — quarantine evidence lost")
	}
}

func TestRewrite_NoRewriteForAllowedActions(t *testing.T) {
	msg := &core.MCPMessage{Method: "tools/call", ToolCall: &core.ToolCallView{ToolName: "x"}, RawParams: mustRawParams(t, `{"name":"x","arguments":{}}`)}
	decision := policy.Decision{Action: policy.ActionAllow, MatchedRuleID: "R-001"}
	rule := &policy.Rule{RedactKeys: []string{"anything"}}

	clean, err := Rewrite(msg, decision, rule)
	if err != nil || clean != nil {
		t.Error("allow decision should produce no rewrite output")
	}
}

func TestRewrite_EmptyRedactKeys(t *testing.T) {
	msg := &core.MCPMessage{Method: "tools/call", ToolCall: &core.ToolCallView{ToolName: "x"}, RawParams: mustRawParams(t, `{"name":"x","arguments":{"a":1}}`)}
	decision := policy.Decision{Action: policy.ActionDenyRedact, MatchedRuleID: "R-X"}
	rule := &policy.Rule{RedactKeys: []string{}}

	clean, err := Rewrite(msg, decision, rule)
	if err != nil {
		t.Fatalf("rewrite failed: %v", err)
	}
	// No keys to strip: original params forwarded verbatim.
	if !strings.Contains(string(clean), `"a":1`) {
		t.Error("payload changed despite empty redact list")
	}
}
