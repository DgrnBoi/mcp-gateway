package policy

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/antigravity/mcp-gateway/pkg/core"
	"gopkg.in/yaml.v3"
)

// ErrShadowedInvariant is returned when a team-layer allow would collide
// with an org-layer deny (same identity scope AND tool scope). A team must
// never silently erode the central baseline: the whole hierarchy is
// rejected instead (fail-closed, Ticket 19).
var ErrShadowedInvariant = errors.New("team rule shadows an org deny invariant")

// UnknownPolicyLayerError is returned for documents with an unrecognized
// policy_layer value.
type UnknownPolicyLayerError struct{ Layer string }

func (e *UnknownPolicyLayerError) Error() string {
	return fmt.Sprintf("unknown policy_layer '%s' (must be 'org' or 'team')", e.Layer)
}

// DuplicateLayerRuleIDError is returned when two layers declare the same
// rule ID. Rule IDs must be globally unique across the hierarchy so audit
// logs remain unambiguous about which tier decided.
type DuplicateLayerRuleIDError struct{ ID string }

func (e *DuplicateLayerRuleIDError) Error() string {
	return fmt.Sprintf("duplicate rule ID '%s' across policy layers", e.ID)
}

// Hierarchy is the merged multi-layer enforcement view: an org baseline
// plus zero or more team allowances. Built by Merge (see below); evaluated
// by the HierarchyEvaluator in strict precedence order.
type Hierarchy struct {
	orgDefault  Action
	teamDefault Action
	orgDenies   []Rule // identity scope erased: universal for the tool
	orgAllows   []Rule // identity scope retained
	univDenies  []Rule // client_id: any-agent universal denies
	teamDenies  []Rule
	teamAllows  []Rule
}

// orgScopeErased produces a copy of the rule whose agent match is the
// universal "any identity" scope: an org deny invariant locks the tool for
// every agent, closing the empty-agent bypass (FIX #1).
func orgScopeErased(r Rule) Rule {
	return Rule{
		ID:         r.ID,
		Action:     r.Action,
		Reason:     r.Reason,
		RedactKeys: r.RedactKeys,
		ToolMatch:  r.ToolMatch,
		// ClientID/MTLSSubject/UserAgent/TokenHashPrefix intentionally zero:
		// matchAgent with an all-empty AgentMatch is skipped in Evaluate,
		// so universal org denies are handled as a dedicated walk step.
	}
}

// Merge builds a Hierarchy from one org document and any number of team
// documents. Strict precedence, fail-closed:
//   - every document's policy_layer is checked ("org"/"team", else rejected)
//   - duplicate rule IDs across layers are rejected
//   - a team allow whose identity AND tool scope collide with an org deny
//     raises ErrShadowedInvariant (the whole hierarchy is rejected)
//   - allow_all is an org-layer-only escape hatch (team layers cannot mint
//     them), and org default_action: allow is only permitted on org docs
//
// Exactly one org document is required; team documents are optional.
func Merge(org *Policy, teams ...*Policy) (*Hierarchy, error) {
	if org == nil {
		return nil, errors.New("Merge: org policy is required")
	}
	if err := layerOf(org, "org"); err != nil {
		return nil, err
	}

	seenIDs := make(map[string]bool, len(org.Rules))
	for _, r := range org.Rules {
		seenIDs[r.ID] = true
	}

	h := &Hierarchy{
		orgDefault:  org.DefaultAction,
		teamDefault: org.DefaultAction, // base fallback before any team layer
	}

	for _, team := range teams {
		if err := layerOf(team, "team"); err != nil {
			return nil, err
		}
		// The team-layer default becomes this layer's default while the layer
		// is in effect; the merge keeps the LAST team document's default
		// (document order), with the org default as base. The default applies
		// to the layer as a whole, not to any individual rule.
		h.teamDefault = team.DefaultAction
		for _, r := range team.Rules {
			if seenIDs[r.ID] {
				return nil, &DuplicateLayerRuleIDError{ID: r.ID}
			}
			seenIDs[r.ID] = true

			switch r.Action {
			case ActionDeny, ActionDenyRedact:
				h.teamDenies = append(h.teamDenies, r)
				// team-layer default becomes this layer's default while the
				// layer is in effect; the merge keeps the LAST team document's
				// default (document order), with the org default as base.
				h.teamDefault = team.DefaultAction
			case ActionAllow:
				if r.Action == ActionAllow {
					if err := checkShadow(org, r); err != nil {
						return nil, fmt.Errorf("rule '%s': %w", r.ID, err)
					}
					h.teamAllows = append(h.teamAllows, r)
				}
			case ActionAllowAll:
				// Team layers cannot mint escape hatches; only the org tier
				// holds the allow_all mechanism.
				return nil, fmt.Errorf("rule '%s': allow_all is an org-layer-only escape hatch", r.ID)
			}
		}
	}

	// Partition the org rules into deny invariants, allows, and universal denies.
	for _, r := range org.Rules {
		switch r.Action {
		case ActionDeny, ActionDenyRedact:
			if r.AgentMatch.ClientID == "any-agent" && isScopeUniversalExceptClientID(r.AgentMatch) {
				h.univDenies = append(h.univDenies, r)
			} else {
				h.orgDenies = append(h.orgDenies, orgScopeErased(r))
			}
		case ActionAllow:
			h.orgAllows = append(h.orgAllows, r)
		case ActionAllowAll:
			// Org-tier escape hatch: treated as an org allow during the walk,
			// with the loader's reason/expiry contract already validated.
			h.orgAllows = append(h.orgAllows, r)
		}
	}
	return h, nil
}

// layerOf rejects a document whose policy_layer is not the expected value.
func layerOf(p *Policy, want string) error {
	if p.PolicyLayer == "" {
		return &UnknownPolicyLayerError{Layer: "(missing)"}
	}
	if p.PolicyLayer != want {
		return &UnknownPolicyLayerError{Layer: p.PolicyLayer}
	}
	return nil
}

// isScopeUniversal reports whether the agent match binds no identity claim,
// i.e. the rule applies to every caller.
func isScopeUniversal(m AgentMatch) bool {
	return m.ClientID == "" && m.MTLSSubject == "" &&
		m.UserAgent == "" && m.TokenHashPrefix == ""
}

// isScopeUniversalExceptClientID reports a scope that is universal apart
// from the reserved "any-agent" client_id sentinel used for universal org
// denies. The loader forbids empty AgentMatch rules, so universality is
// encoded this way instead.
func isScopeUniversalExceptClientID(m AgentMatch) bool {
	return (m.ClientID == "" || m.ClientID == "any-agent") &&
		m.MTLSSubject == "" && m.UserAgent == "" && m.TokenHashPrefix == ""
}

// checkShadow raises ErrShadowedInvariant when the team allow's identity
// AND tool scope collide with an org deny. Identity scope collides when the
// team rule's match is a subset-or-equal of the org rule's scope: an org
// deny that names a client_id shadows any team allow for the same client;
// an org deny with universal scope shadows everything.
func checkShadow(org *Policy, teamAllow Rule) error {
	for _, orgDeny := range org.Rules {
		if orgDeny.Action != ActionDeny && orgDeny.Action != ActionDenyRedact {
			continue
		}
		if scopesOverlap(orgDeny.AgentMatch, teamAllow.AgentMatch) && toolsOverlap(orgDeny.ToolMatch, teamAllow.ToolMatch) {
			return ErrShadowedInvariant
		}
	}
	return nil
}

// scopesOverlap is true when the org rule's scope could bind the team
// rule's scope: org universal scope overlaps everything; otherwise every
// non-empty org field must equal the team field it targets.
func scopesOverlap(orgMatch, teamMatch AgentMatch) bool {
	if isScopeUniversal(orgMatch) {
		return true
	}
	if orgMatch.ClientID != "" {
		if teamMatch.ClientID != "" {
			return orgMatch.ClientID == teamMatch.ClientID
		}
		// org names a client; team says "all my clients" — still collides
		// when the named client exists in the team's population.
		return true
	}
	if orgMatch.MTLSSubject != "" && (teamMatch.MTLSSubject == "" || orgMatch.MTLSSubject == teamMatch.MTLSSubject) {
		return true
	}
	if orgMatch.TokenHashPrefix != "" && strings.HasPrefix(teamMatch.TokenHashPrefix, orgMatch.TokenHashPrefix) {
		return true
	}
	if orgMatch.UserAgent != "" && (teamMatch.UserAgent == "" || orgMatch.UserAgent == teamMatch.UserAgent) {
		return true
	}
	return false
}

func toolsOverlap(orgTool, teamTool ToolMatch) bool {
	if orgTool.Name == "" || teamTool.Name == "" {
		return true
	}
	return orgTool.Name == teamTool.Name
}

// HierarchyEvaluator walks the merged tiers in the mandated precedence:
//  1. org deny invariants (universal per-tool, identity erased)
//  2. team denies (deny / deny_with_redact)
//  3. team allows
//  4. org allows (identity scope retained)
//  5. universal org denies (client_id: any-agent)
//  6. default: callers matching an org identity scope get the org default;
//     all others get the team default.
//
// The identity-empty pre-flight gate is preserved from DefaultEvaluator:
// an unidentified caller never enters the tier walk.
type HierarchyEvaluator struct{ h *Hierarchy }

// FlattenedRules returns every merged rule (all layers, all tiers) as a
// single slice — the display surface used by the console and GitOps
// generation, which present the hierarchy as one rule list.
func (h *Hierarchy) FlattenedRules() []Rule {
	rules := make([]Rule, 0,
		len(h.orgDenies)+len(h.teamDenies)+len(h.teamAllows)+len(h.orgAllows)+len(h.univDenies))
	rules = append(rules, h.orgDenies...)
	rules = append(rules, h.teamDenies...)
	rules = append(rules, h.teamAllows...)
	rules = append(rules, h.orgAllows...)
	rules = append(rules, h.univDenies...)
	return rules
}

func NewHierarchyEvaluator(h *Hierarchy) *HierarchyEvaluator {
	return &HierarchyEvaluator{h: h}
}

func (e *HierarchyEvaluator) Evaluate(msg *core.MCPMessage) Decision {
	if isIdentityEmpty(msg.CallerIdentity) {
		return Decision{
			Action:        ActionDeny,
			MatchedRuleID: "PRE_FLIGHT_UNIDENTIFIED",
			Reason:        "no identity presented (no client_id, mTLS subject, or token)",
		}
	}

	// 1. org deny invariants: tool match only, universal identity.
	for _, r := range e.h.orgDenies {
		if ruleApplies(r, msg, true) {
			return decisionFor(r, "ORG_DENY_INVARIANT")
		}
	}

	// 2. team denies.
	for _, r := range e.h.teamDenies {
		if ruleApplies(r, msg, false) {
			return decisionFor(r, "TEAM_DENY")
		}
	}

	// 3. team allows.
	for _, r := range e.h.teamAllows {
		if ruleApplies(r, msg, false) {
			return decisionFor(r, "TEAM_ALLOW")
		}
	}

	// 4. org allows (identity scope retained).
	for _, r := range e.h.orgAllows {
		if ruleApplies(r, msg, false) {
			return decisionFor(r, "ORG_ALLOW")
		}
	}

	// 5. universal org denies (client_id: any-agent). The loader forbids an
	// empty AgentMatch, so universality is expressed by the reserved
	// "any-agent" sentinel: when evaluating, these rules match every
	// identified caller by tool alone.
	for _, r := range e.h.univDenies {
		if ruleApplies(r, msg, true) {
			return decisionFor(r, "ORG_UNIVERSAL_DENY")
		}
	}

	// 6. default action: org-specific identity scope gets the org default,
	// unknown callers get the team default.
	if matchesOrgScope(e.h, msg.CallerIdentity) {
		return Decision{Action: e.h.orgDefault, MatchedRuleID: "DEFAULT_" + string(e.h.orgDefault)}
	}
	return Decision{Action: e.h.teamDefault, MatchedRuleID: "DEFAULT_" + string(e.h.teamDefault)}
}

// ruleApplies checks a merged-tier rule against a message. Universal-flagged
// org invariants skip the identity match entirely (their scope is erased).
func ruleApplies(r Rule, msg *core.MCPMessage, universal bool) bool {
	if !universal && !matchAgent(r.AgentMatch, msg.CallerIdentity) {
		return false
	}
	if r.ToolMatch.Name != "" {
		if msg.ToolCall == nil {
			return false
		}
		if !matchTool(r.ToolMatch, msg.ToolCall) {
			return false
		}
	}
	return true
}

func decisionFor(r Rule, prefix string) Decision {
	return Decision{Action: r.Action, MatchedRuleID: prefix + ":" + r.ID, Reason: r.Reason}
}

// matchesOrgScope reports whether the caller binds an org-tier identity
// scope. Crucially, a universal "any-agent" rule does NOT bind a scope:
// universal scopes erase identity, so only explicitly named clients
// (non-empty ClientID/MTLSSubject/TokenHashPrefix) place a caller inside
// the org tier. Without this, unknown callers would inherit the org
// default and could never reach the team default.
func matchesOrgScope(h *Hierarchy, c core.CallerIdentity) bool {
	for _, r := range h.orgAllows {
		if isScopeUniversal(r.AgentMatch) {
			continue
		}
		if matchAgent(r.AgentMatch, c) {
			return true
		}
	}
	for _, r := range h.univDenies {
		if isScopeUniversal(r.AgentMatch) {
			continue
		}
		if matchAgent(r.AgentMatch, c) {
			return true
		}
	}
	return false
}

// LoadHierarchy reads a multi-document YAML stream (org document first,
// team documents after, in any order; separated by `---`), validates every
// layer, and returns the merged hierarchy.
func LoadHierarchy(r io.Reader) (*Hierarchy, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var docs []*Policy
	for {
		var p Policy
		err := dec.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing policy stream: %w", err)
		}
		if err := validatePolicy(&p); err != nil {
			return nil, fmt.Errorf("policy document: %w", err)
		}
		docs = append(docs, &p)
	}
	if len(docs) == 0 {
		return nil, errors.New("empty policy stream")
	}
	var org *Policy
	var teams []*Policy
	for _, d := range docs {
		if d.PolicyLayer == "org" {
			if org != nil {
				return nil, errors.New("multiple org documents in the policy stream")
			}
			org = d
		} else {
			teams = append(teams, d)
		}
	}
	if org == nil {
		return nil, errors.New("no org-layer document in the policy stream")
	}
	return Merge(org, teams...)
}
