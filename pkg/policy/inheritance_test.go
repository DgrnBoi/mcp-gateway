package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/core"
	"gopkg.in/yaml.v3"
)

func orgDoc(t *testing.T, rules []Rule, defaultAction Action) *Policy {
	t.Helper()
	p := &Policy{PolicyLayer: "org", DefaultAction: defaultAction, Rules: rules}
	if err := validatePolicy(p); err != nil {
		t.Fatalf("org fixture invalid: %v", err)
	}
	return p
}

func teamDoc(t *testing.T, rules []Rule, defaultAction Action) *Policy {
	t.Helper()
	p := &Policy{PolicyLayer: "team", DefaultAction: defaultAction, Rules: rules}
	if err := validatePolicy(p); err != nil {
		t.Fatalf("team fixture invalid: %v", err)
	}
	return p
}

func TestHierarchy_PrecedenceWalk(t *testing.T) {
	org := orgDoc(t, []Rule{
		{ID: "ORG-D1", AgentMatch: AgentMatch{ClientID: "finance-agent"}, ToolMatch: ToolMatch{"run_sql"}, Action: ActionDeny},
		{ID: "ORG-A1", AgentMatch: AgentMatch{ClientID: "hr-agent"}, ToolMatch: ToolMatch{"lookup_employee"}, Action: ActionAllow},
	}, ActionDeny)

	team := teamDoc(t, []Rule{
		{ID: "TEAM-D1", AgentMatch: AgentMatch{ClientID: "sales-agent"}, ToolMatch: ToolMatch{"send_email"}, Action: ActionDeny},
		{ID: "TEAM-A1", AgentMatch: AgentMatch{ClientID: "sales-agent"}, ToolMatch: ToolMatch{"lookup_lead"}, Action: ActionAllow},
	}, ActionDeny)

	h, err := Merge(org, team)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	ev := NewHierarchyEvaluator(h)

	cases := []struct {
		name     string
		msg      *core.MCPMessage
		wantAct  Action
		wantRule string
	}{
		{
			name: "org deny invariant wins over team allow",
			msg: &core.MCPMessage{
				CallerIdentity: core.CallerIdentity{ClientID: "sales-agent"},
				ToolCall:       &core.ToolCallView{ToolName: "run_sql"},
			},
				wantAct: ActionDeny, wantRule: "ORG_DENY_INVARIANT:ORG-D1",
		},
		{
			name: "team deny blocks team member tool",
			msg: &core.MCPMessage{
				CallerIdentity: core.CallerIdentity{ClientID: "sales-agent"},
				ToolCall:       &core.ToolCallView{ToolName: "send_email"},
			},
				wantAct: ActionDeny, wantRule: "TEAM_DENY:TEAM-D1",
		},
		{
			name: "team allow passes team member tool",
			msg: &core.MCPMessage{
				CallerIdentity: core.CallerIdentity{ClientID: "sales-agent"},
				ToolCall:       &core.ToolCallView{ToolName: "lookup_lead"},
			},
				wantAct: ActionAllow, wantRule: "TEAM_ALLOW:TEAM-A1",
		},
		{
			name: "org allow passes matching agent",
			msg: &core.MCPMessage{
				CallerIdentity: core.CallerIdentity{ClientID: "hr-agent"},
				ToolCall:       &core.ToolCallView{ToolName: "lookup_employee"},
			},
				wantAct: ActionAllow, wantRule: "ORG_ALLOW:ORG-A1",
		},
		{
			name: "unmatched caller walks to default",
			msg: &core.MCPMessage{
				CallerIdentity: core.CallerIdentity{ClientID: "marketing-agent"},
				ToolCall:       &core.ToolCallView{ToolName: "post_tweet"},
			},
				wantAct: ActionDeny, wantRule: "DEFAULT_deny",
		},
		{
			name: "unidentified caller pre-flight deny",
			msg: &core.MCPMessage{
				CallerIdentity: core.CallerIdentity{},
				ToolCall:       &core.ToolCallView{ToolName: "lookup_lead"},
			},
				wantAct: ActionDeny, wantRule: "PRE_FLIGHT_UNIDENTIFIED",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ev.Evaluate(c.msg)
			if got.Action != c.wantAct || got.MatchedRuleID != c.wantRule {
				t.Errorf("got %s/%s, want %s/%s", got.Action, got.MatchedRuleID, c.wantAct, c.wantRule)
			}
		})
	}
}

func TestHierarchy_TeamDefaultPerRequest(t *testing.T) {
	org := orgDoc(t, []Rule{
		{ID: "ORG-A1", AgentMatch: AgentMatch{ClientID: "known-agent"}, ToolMatch: ToolMatch{"tools"}, Action: ActionAllow},
	}, ActionDeny)
	team := teamDoc(t, nil, ActionAllowAll)
	// team default allow_all should NOT apply to unknown callers who bind no
	// org scope? Per spec: callers matching an org identity scope get the
	// org default; ALL OTHER callers get the team default. A caller that
	// binds no org scope receives the team default:
	h, err := Merge(org, team)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	got := NewHierarchyEvaluator(h).Evaluate(&core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "unknown-agent"},
		ToolCall:       &core.ToolCallView{ToolName: "anything"},
	})
	if got.Action != ActionAllowAll || got.MatchedRuleID != "DEFAULT_allow_all" {
		t.Errorf("unscoped caller should get team default, got %s/%s", got.Action, got.MatchedRuleID)
	}
	// But a caller inside the org allow scope gets the ORG default even if
	// the team default is looser:
	got = NewHierarchyEvaluator(h).Evaluate(&core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "known-agent"},
		ToolCall:       &core.ToolCallView{ToolName: "other"},
	})
	if got.Action != ActionDeny || got.MatchedRuleID != "DEFAULT_deny" {
		t.Errorf("org-scoped caller should get org default, got %s/%s", got.Action, got.MatchedRuleID)
	}
}

func TestHierarchy_UniversalOrgDeny(t *testing.T) {
	org := orgDoc(t, []Rule{
		{ID: "ORG-U1", AgentMatch: AgentMatch{ClientID: "any-agent"}, ToolMatch: ToolMatch{"admin_reset"}, Action: ActionDeny},
	}, ActionDeny)
	team := teamDoc(t, []Rule{
		{ID: "TEAM-A1", AgentMatch: AgentMatch{ClientID: "any-client"}, ToolMatch: ToolMatch{"admin_reset"}, Action: ActionAllow},
	}, ActionDeny)
	h, err := Merge(org, team)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	got := NewHierarchyEvaluator(h).Evaluate(&core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "rogue-agent"},
		ToolCall:       &core.ToolCallView{ToolName: "admin_reset"},
	})
	// Universal org deny (step 5) precedes team allows (step 3) only for
	// identity-erased org denies; the universal deny is checked AFTER org
	// allows but BEFORE default resolution, and it binds this caller:
	if got.Action != ActionDeny || !strings.HasPrefix(got.MatchedRuleID, "ORG_UNIVERSAL_DENY") {
		t.Errorf("universal org deny must bind, got %s/%s", got.Action, got.MatchedRuleID)
	}
}

func TestMerge_ShadowedInvariantRejected(t *testing.T) {
	org := orgDoc(t, []Rule{
		{ID: "ORG-D1", AgentMatch: AgentMatch{ClientID: "finance-agent"}, ToolMatch: ToolMatch{"run_sql"}, Action: ActionDeny},
	}, ActionDeny)
	team := teamDoc(t, []Rule{
		{ID: "TEAM-A1", AgentMatch: AgentMatch{ClientID: "finance-agent"}, ToolMatch: ToolMatch{"run_sql"}, Action: ActionAllow},
	}, ActionDeny)
	if _, err := Merge(org, team); !errors.Is(err, ErrShadowedInvariant) {
		t.Fatalf("expected ErrShadowedInvariant, got %v", err)
	}
}

func TestMerge_ShadowRejectedOnTokenHashPrefixOverlap(t *testing.T) {
	org := orgDoc(t, []Rule{
		{ID: "ORG-D1", AgentMatch: AgentMatch{TokenHashPrefix: "sha256:ab"}, ToolMatch: ToolMatch{"run_sql"}, Action: ActionDeny},
	}, ActionDeny)
	team := teamDoc(t, []Rule{
		{ID: "TEAM-A1", AgentMatch: AgentMatch{TokenHashPrefix: "sha256:abc123"}, ToolMatch: ToolMatch{"run_sql"}, Action: ActionAllow},
	}, ActionDeny)
	if _, err := Merge(org, team); !errors.Is(err, ErrShadowedInvariant) {
		t.Fatalf("expected prefix-overlap shadow rejection, got %v", err)
	}
}

func TestMerge_NonOverlappingTeamAllowAccepted(t *testing.T) {
	org := orgDoc(t, []Rule{
		{ID: "ORG-D1", AgentMatch: AgentMatch{ClientID: "finance-agent"}, ToolMatch: ToolMatch{"run_sql"}, Action: ActionDeny},
	}, ActionDeny)
	team := teamDoc(t, []Rule{
		{ID: "TEAM-A1", AgentMatch: AgentMatch{ClientID: "marketing-agent"}, ToolMatch: ToolMatch{"post_tweet"}, Action: ActionAllow},
	}, ActionDeny)
	h, err := Merge(org, team)
	if err != nil {
		t.Fatalf("non-overlapping allow must merge: %v", err)
	}
	if len(h.teamAllows) != 1 {
		t.Errorf("expected one team allow, got %d", len(h.teamAllows))
	}
}

func TestMerge_DuplicateRuleIDAcrossLayersRejected(t *testing.T) {
	org := orgDoc(t, []Rule{
		{ID: "DUP", AgentMatch: AgentMatch{ClientID: "a"}, ToolMatch: ToolMatch{"t"}, Action: ActionDeny},
	}, ActionDeny)
	team := teamDoc(t, []Rule{
		{ID: "DUP", AgentMatch: AgentMatch{ClientID: "b"}, ToolMatch: ToolMatch{"u"}, Action: ActionAllow},
	}, ActionDeny)
	_, err := Merge(org, team)
	if _, ok := err.(*DuplicateLayerRuleIDError); !ok {
		t.Fatalf("expected DuplicateLayerRuleIDError, got %v", err)
	}
}

func TestMerge_TeamAllowAllRejected(t *testing.T) {
	org := orgDoc(t, nil, ActionDeny)
	team := teamDoc(t, []Rule{
		{ID: "BAD", AgentMatch: AgentMatch{ClientID: "a"}, Action: ActionAllowAll,
			Reason: "temp", Expiry: mustExpiry("2099-01-01T00:00:00Z")},
	}, ActionDeny)
	_, err := Merge(org, team)
	if err == nil || !strings.Contains(err.Error(), "allow_all") {
		t.Fatalf("team allow_all must be rejected, got %v", err)
	}
}

func TestMerge_UnknownLayerRejected(t *testing.T) {
	p := &Policy{PolicyLayer: "contractor", DefaultAction: ActionDeny}
	_, err := Merge(orgDoc(t, nil, ActionDeny), p)
	if _, ok := err.(*UnknownPolicyLayerError); !ok {
		t.Fatalf("expected UnknownPolicyLayerError, got %v", err)
	}
}

func TestMerge_OrgDocumentRequired(t *testing.T) {
	if _, err := Merge(nil); err == nil {
		t.Fatal("expected error for missing org document")
	}
}

func TestLoadHierarchy_MultiDocumentStream(t *testing.T) {
	stream := `policy_layer: org
default_action: deny
rules:
  - {id: O1, agent: {client_id: "finance-agent"}, tool: {name: "run_sql"}, action: deny}
---
policy_layer: team
default_action: deny
rules:
  - {id: T1, agent: {client_id: "sales-agent"}, tool: {name: "lookup_lead"}, action: allow}
`
	_ = mustExpiry
	h, err := LoadHierarchy(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(h.orgDenies) != 1 || len(h.teamAllows) != 1 {
		t.Errorf("unexpected tier partition: orgDenies=%d teamAllows=%d", len(h.orgDenies), len(h.teamAllows))
	}
}

func TestLoadHierarchy_MissingOrgRejected(t *testing.T) {
	stream := `policy_layer: team
default_action: deny
rules: []
`
	_ = mustExpiry
	if _, err := LoadHierarchy(strings.NewReader(stream)); err == nil {
		t.Fatal("expected rejection for team-only stream")
	}
}

func TestLoadHierarchy_OrgDefaultAllowRejected(t *testing.T) {
	stream := `policy_layer: org
default_action: allow
rules: []
`
	_ = mustExpiry
	if _, err := LoadHierarchy(strings.NewReader(stream)); err == nil {
		t.Fatal("org default allow must be rejected by the loader")
	}
}

func TestLoadHierarchy_MultipleOrgDocsRejected(t *testing.T) {
	stream := `policy_layer: org
default_action: deny
rules: []
---
policy_layer: org
default_action: deny
rules: []
`
	_ = mustExpiry
	if _, err := LoadHierarchy(strings.NewReader(stream)); err == nil {
		t.Fatal("multiple org documents must be rejected")
	}
}

func mustExpiry(s string) *ExpiryTime {
	var e ExpiryTime
	if err := e.UnmarshalYAML(strNode(s)); err != nil {
		panic("test fixture expiry: " + err.Error())
	}
	return &e
}

// strNode wraps a raw string into a yaml.Node for direct ExpiryTime parsing.
func strNode(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}
