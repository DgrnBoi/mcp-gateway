package enforcement

import (
	"encoding/json"

	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/policy"
)

// Rewrite applies deny_with_redact semantics: it strips every key listed in
// the matched rule's RedactKeys from the tool-call arguments, returning the
// cleaned JSON-RPC params ready for upstream forwarding.
//
// The original, unredacted payload is preserved on the message via
// msg.RawParams for quarantine routing — nothing in this function deletes it.
func Rewrite(msg *core.MCPMessage, decision policy.Decision, rule *policy.Rule) ([]byte, error) {
	if decision.Action != policy.ActionDenyRedact {
		return nil, nil // no rewrite needed; forward as-is
	}
	if msg.ToolCall == nil || len(msg.RawParams) == 0 {
		return nil, nil // nothing addressable to rewrite
	}

	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(msg.RawParams, &params); err != nil {
		return nil, err
	}
	if params.Arguments == nil {
		return msg.RawParams, nil
	}

	for _, key := range rule.RedactKeys {
		delete(params.Arguments, key)
	}

	clean, err := json.Marshal(struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}{Name: params.Name, Arguments: params.Arguments})
	if err != nil {
		return nil, err
	}
	return clean, nil
}
