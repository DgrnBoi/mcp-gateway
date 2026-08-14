package policy

import (
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/core"
)

// --- Stage 4 / Ticket 19: scope collision and matching internals -------------

func TestScopesOverlap_UniversalOrgCollidesWithEverything(t *testing.T) {
	// A truly universal org scope (no fields set) collides with any team scope.
	if !scopesOverlap(AgentMatch{}, AgentMatch{ClientID: "sales-agent"}) {
		t.Error("universal org scope must collide with any team scope")
	}
	if !scopesOverlap(AgentMatch{}, AgentMatch{MTLSSubject: "spiffe://corp/team"}) {
		t.Error("universal org scope must collide with mTLS-scoped teams")
	}
}

func TestScopesOverlap_NamedClientCollidesWithWildcardTeam(t *testing.T) {
	// org names a client; team says "all my clients" — still a collision.
	if !scopesOverlap(
		AgentMatch{ClientID: "hr-agent"},
		AgentMatch{MTLSSubject: "spiffe://corp/team"}) {
		t.Error("named org client must collide with an otherwise-empty team match")
	}
}

func TestScopesOverlap_DistinctClientsDoNotCollide(t *testing.T) {
	if scopesOverlap(
		AgentMatch{ClientID: "hr-agent"},
		AgentMatch{ClientID: "sales-agent"}) {
		t.Error("distinct named clients must not collide")
	}
}

func TestScopesOverlap_TokenHashPrefixRequiresPrefixMatch(t *testing.T) {
	if !scopesOverlap(
		AgentMatch{TokenHashPrefix: "abc"},
		AgentMatch{TokenHashPrefix: "abcdef"}) {
		t.Error("team prefix extending org prefix must collide")
	}
	if scopesOverlap(
		AgentMatch{TokenHashPrefix: "abc"},
		AgentMatch{TokenHashPrefix: "xyz"}) {
		t.Error("unrelated prefixes must not collide")
	}
}

func TestScopesOverlap_MTLSSubject(t *testing.T) {
	if !scopesOverlap(AgentMatch{MTLSSubject: "spiffe://corp/hr"}, AgentMatch{}) {
		t.Error("org mTLS subject must collide with a wildcard team")
	}
	if scopesOverlap(AgentMatch{MTLSSubject: "spiffe://corp/hr"}, AgentMatch{MTLSSubject: "spiffe://corp/sales"}) {
		t.Error("distinct SPIFFE IDs must not collide")
	}
	if !scopesOverlap(AgentMatch{MTLSSubject: "spiffe://corp/hr"}, AgentMatch{MTLSSubject: "spiffe://corp/hr"}) {
		t.Error("identical SPIFFE IDs must collide")
	}
}

func TestToolsOverlap_EmptyScopeOverlapsEverything(t *testing.T) {
	if !toolsOverlap(ToolMatch{}, ToolMatch{Name: "x"}) ||
		!toolsOverlap(ToolMatch{Name: "x"}, ToolMatch{}) {
		t.Error("empty tool scope must overlap everything")
	}
	if !toolsOverlap(ToolMatch{Name: "delete_employee"}, ToolMatch{Name: "delete_employee"}) {
		t.Error("identical tool names must overlap")
	}
	if toolsOverlap(ToolMatch{Name: "delete_employee"}, ToolMatch{Name: "search_contacts"}) {
		t.Error("distinct tool names must not overlap")
	}
}

func TestMatchesOrgScope_AnyAgentDoesNotBindScope(t *testing.T) {
	h := &Hierarchy{
		univDenies: []Rule{{AgentMatch: AgentMatch{ClientID: "any-agent"}}},
		orgAllows:  []Rule{{AgentMatch: AgentMatch{ClientID: "any-agent"}}},
	}
	// A caller that only matches universal rules is NOT org-scoped: they
	// must be able to fall through to the team default.
	if matchesOrgScope(h, core.CallerIdentity{ClientID: "sales-agent"}) {
		t.Error("universal any-agent rules must not place a caller in the org scope")
	}
	// A caller bound by a named org allow IS org-scoped.
	h2 := &Hierarchy{orgAllows: []Rule{{AgentMatch: AgentMatch{ClientID: "hr-agent"}}}}
	if !matchesOrgScope(h2, core.CallerIdentity{ClientID: "hr-agent"}) {
		t.Error("named org allow must bind the caller to the org scope")
	}
}

func TestMatchAgent_HasPrefixEdgeCases(t *testing.T) {
	cases := []struct {
		hash, prefix string
		want         bool
	}{
		{"abc123def", "abc123", true},   // hash longer than prefix
		{"abc123", "abc123", true},      // exact match
		{"abc12", "abc123", false},      // hash shorter than prefix
		{"xyz123", "abc123", false},     // mismatch
		{"abc123", "", true},            // empty prefix is wildcard
	}
	for _, c := range cases {
		if got := hasPrefix(c.hash, c.prefix); got != c.want {
			t.Errorf("hasPrefix(%q,%q)=%v want %v", c.hash, c.prefix, got, c.want)
		}
	}
}

func TestMatchAgent_EveryFieldMustMatch(t *testing.T) {
	match := AgentMatch{
		ClientID:         "hr-agent",
		MTLSSubject:      "spiffe://corp/hr",
		TokenHashPrefix:  "deadbeef",
		UserAgent:        "mcp-client/1.0",
	}
	ok := core.CallerIdentity{
		ClientID:         "hr-agent",
		MTLSSubject:      "spiffe://corp/hr",
		TokenHash:        "deadbeef1234",
		UserAgent:        "mcp-client/1.0",
	}
	if !matchAgent(match, ok) {
		t.Error("fully matching identity must pass")
	}
	bad := ok
	bad.UserAgent = "curl/8"
	if matchAgent(match, bad) {
		t.Error("mismatched user agent must fail")
	}
	short := ok
	short.TokenHash = "dead"
	if matchAgent(match, short) {
		t.Error("truncated token hash must fail the prefix check")
	}
}
