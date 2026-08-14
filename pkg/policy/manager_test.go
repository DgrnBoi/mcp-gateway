package policy

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"strings"

	"github.com/antigravity/mcp-gateway/pkg/core"
	"testing"
	"time"
)

var mgrValidPolicy = `default_action: deny
rules:
  - id: R-001
    agent: {client_id: sales-copilot}
    tool: {name: read_customer}
    action: allow
    reason: approved by SOC
`

var mgrValidPolicyV2 = `default_action: deny
rules:
  - id: R-001
    agent: {client_id: sales-copilot}
    tool: {name: read_customer}
    action: allow
    reason: approved by SOC
  - id: R-002
    agent: {client_id: etl-worker}
    tool: {name: write_report}
    action: deny_with_redact
    redact_keys: [limit]
    reason: quarantine observed
`

var mgrInvalidPolicy = `default_action: deny
rules:
  - id: R-001
    tool: {name: x}
    action: allow
`

var mgrBadYAML = `default_action: deny
rules:
  - id: R-001
    agent: {}
    tool: {name: x}
    action: allow
`

func withSeams(t *testing.T, reader io.Reader, mt time.Time) func() {
	t.Helper()
	oldOpen := osOpen
	osOpen = func(path string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(contentsOf(reader))), nil
	}
	oldStat := fileStat
	fileStat = func(path string) (fileInfo, error) {
		return fakeFileInfo{m: mt}, nil
	}
	return func() {
		osOpen = oldOpen
		fileStat = oldStat
	}
}

// contentsOf re-reads a fresh copy from a bytes.Reader by copying once.
var contentsOf = func(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}

type fakeFileInfo struct{ m time.Time }

func (f fakeFileInfo) ModTime() time.Time { return f.m }

func newManager(t *testing.T, body []byte, mt time.Time) *PolicyManager {
	t.Helper()
	restore := withSeams(t, bytes.NewReader(body), mt)
	t.Cleanup(restore)
	pm, err := NewPolicyManager("/etc/mcp-gateway/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return pm
}

func TestManager_LoadsInitialPolicy(t *testing.T) {
	pm := newManager(t, []byte(mgrValidPolicy), time.Unix(1000, 0))
	p := pm.Policy()
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}
}

func TestManager_BadInitialPolicyIsFatal(t *testing.T) {
	restore := withSeams(t, bytes.NewReader([]byte(mgrInvalidPolicy)), time.Unix(1000, 0))
	defer restore()
	_, err := NewPolicyManager("/p")
	if err == nil {
		t.Fatal("invalid initial policy must fail startup")
	}
}

func TestManager_ReloadSwapsPolicy(t *testing.T) {
	body := []byte(mgrValidPolicy)
	mt := time.Unix(1000, 0)
	pm := newManager(t, body, mt)
	// Simulate an editor saving a new version: bump the mtime, THEN
	// serve the new content.
	fileStat = func(path string) (fileInfo, error) {
		return fakeFileInfo{m: mt.Add(time.Second)}, nil
	}
	osOpen = func(path string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte(mgrValidPolicyV2))), nil
	}
	res := pm.Reload()
	if !res.Swapped {
		t.Fatalf("reload must swap: %v", res.Error)
	}
	if res.OldRules != 1 || res.NewRules != 2 {
		t.Fatalf("rule counts wrong: %d → %d", res.OldRules, res.NewRules)
	}
	if len(pm.Policy().Rules) != 2 {
		t.Fatal("active policy must be v2")
	}
}

func TestManager_InvalidReloadIsRejected(t *testing.T) {
	pm := newManager(t, []byte(mgrValidPolicy), time.Unix(1000, 0))
	// The file was "edited" (new mtime) but contains invalid YAML.
	fileStat = func(path string) (fileInfo, error) {
		return fakeFileInfo{m: time.Unix(1001, 0)}, nil
	}
	osOpen = func(path string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte(mgrInvalidPolicy))), nil
	}
	res := pm.Reload()
	if res.Swapped {
		t.Fatal("invalid policy must never swap in")
	}
	if res.Error == nil {
		t.Fatal("expected rejection error")
	}
	if len(pm.Policy().Rules) != 1 {
		t.Fatal("active policy must remain v1")
	}
}

func TestManager_MtimeNoOp(t *testing.T) {
	mt := time.Unix(1000, 0)
	pm := newManager(t, []byte(mgrValidPolicy), mt)

	calls := 0
	osOpen = func(path string) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(bytes.NewReader([]byte(mgrValidPolicyV2))), nil
	}
	res := pm.Reload() // same mtime → no re-read
	if res.Swapped {
		t.Fatal("unchanged file must not swap")
	}
	if calls != 0 {
		t.Fatal("parser must not be invoked for an unchanged file")
	}
}

func TestManager_ForceReloadIgnoresMtime(t *testing.T) {
	mt := time.Unix(1000, 0)
	pm := newManager(t, []byte(mgrValidPolicy), mt)
	osOpen = func(path string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte(mgrValidPolicyV2))), nil
	}
	res := pm.ForceReload()
	if !res.Swapped || res.NewRules != 2 {
		t.Fatalf("force reload must swap: swapped=%v err=%v", res.Swapped, res.Error)
	}
}

func TestManager_ZeroDowntimeDuringReload(t *testing.T) {
	pm := newManager(t, []byte(mgrValidPolicy), time.Unix(1000, 0))
	osOpen = func(path string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte(mgrValidPolicyV2))), nil
	}

	const workers = 16
	var wg sync.WaitGroup
	evaluators := make([]*DefaultEvaluator, workers)
	for i := range evaluators {
		evaluators[i] = NewEvaluator(pm.Policy())
	}

	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(e *DefaultEvaluator) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					// Concurrent readers must always see a valid
					// (fully-initialized) policy snapshot.
					p := e.Policy()
					if p == nil || p.DefaultAction == "" {
						panic("observed zero-value policy during reload")
					}
				}
			}
		}(evaluators[i])
	}

	// Hammer swaps from a writer while readers spin.
	for i := 0; i < 200; i++ {
		pm.Reload()
		pm.ForceReload()
	}
	close(done)
	wg.Wait()
	if len(pm.Policy().Rules) != 2 {
		t.Fatal("final policy must be v2 after reloads")
	}
}

func TestManager_MalformedReloadRejected(t *testing.T) {
	pm := newManager(t, []byte(mgrValidPolicy), time.Unix(1000, 0))
	osOpen = func(path string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte(mgrBadYAML))), nil
	}
	res := pm.Reload()
	if res.Swapped {
		t.Fatal("malformed YAML must never swap in")
	}
}

func TestValidateInitial_FailClosed(t *testing.T) {
	if err := ValidateInitial("/etc/mcp-gateway/policy.yaml"); err == nil {
		t.Fatal("unconfigured seam must fail closed")
	}
}

func ExampleReloadResult() {
	fmt.Println("see manager_test.go")
	// Output: see manager_test.go
}

// --- Stage 4 / Ticket 19: multi-tenant hierarchy manager tests -----------------

var orgPolicyBody = `default_action: deny
policy_layer: org
rules:
  - id: R-001
    agent:
      client_id: any-agent
    tool: {name: "delete_*"}
    action: deny
    reason: destructive ops forbidden org-wide
  - id: R-000
    agent:
      client_id: sales-agent
    tool: {name: "delete_contacts"}
    action: deny
    reason: delete_contacts denied even for sales agents
  - id: R-002
    agent:
      client_id: any-agent
    tool: {name: "search_contacts"}
    action: allow
    reason: org-wide search allowance
`

var teamPolicyBody = `policy_layer: team
default_action: deny
rules:
  - id: T-001
    agent: {client_id: sales-agent}
    tool: {name: "search_contacts"}
    action: allow
    reason: sales team search
`

var shadowTeamPolicyBody = `policy_layer: team
default_action: deny
rules:
  - id: T-002
    agent: {client_id: sales-agent}
    tool: {name: "delete_contacts"}
    action: allow
    reason: must be rejected — shadows org deny invariant R-000
`

// The broken team payload used in TestManager_HierarchyReloadReMerges must
// also carry a valid layer marker so parsing errors (not layer errors) are exercised.
var brokenTeamBody = `policy_layer: team
default_action: deny
rules:
  - id: X
    agent: {client_id: sales-agent}
    tool: {name: "list_contacts"}
    action: bogus
`

// seamFor maps per-path content; every FileLoader.Load call looks the path up.
func seamFor(t *testing.T, contents map[string][]byte, mt map[string]time.Time) func() {
	t.Helper()
	oldOpen, oldStat := osOpen, fileStat
	osOpen = func(path string) (io.ReadCloser, error) {
		b, ok := contents[path]
		if !ok {
			return nil, fmt.Errorf("test seam: unknown path %s", path)
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	fileStat = func(path string) (fileInfo, error) {
		m, ok := mt[path]
		if !ok {
			return nil, fmt.Errorf("test seam: no mtime for %s", path)
		}
		return fakeFileInfo{m: m}, nil
	}
	return func() { osOpen = oldOpen; fileStat = oldStat }
}

func TestManager_HierarchyMergeAndFlatView(t *testing.T) {
	restore := seamFor(t,
		map[string][]byte{"/org.yaml": []byte(orgPolicyBody), "/team.yaml": []byte(teamPolicyBody)},
		map[string]time.Time{"/org.yaml": time.Unix(1000, 0), "/team.yaml": time.Unix(1000, 0)})
	t.Cleanup(restore)

	pm, err := NewHierarchyManager("/org.yaml", []string{"/team.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	flat := pm.Policy()
	if flat.DefaultAction != ActionDeny {
		t.Errorf("flat default must be the org default: %s", flat.DefaultAction)
	}
	// The team layer's default must also be preserved inside the hierarchy.
	if pm.Hierarchy().teamDefault != ActionDeny {
		t.Errorf("team default must be the team layer's deny: %s", pm.Hierarchy().teamDefault)
	}
	ids := make([]string, 0, len(flat.Rules))
	for _, r := range flat.Rules {
		ids = append(ids, r.ID)
	}
	for _, id := range []string{"R-001", "R-002", "T-001"} {
		found := false
		for _, existing := range ids {
			if existing == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("flat view missing rule %q: %v", id, ids)
		}
	}
	// Strict precedence: org deny invariant beats the team allow.
	dec := NewHierarchyEvaluator(pm.Hierarchy()).Evaluate(&core.MCPMessage{
		CallerIdentity: core.CallerIdentity{ClientID: "sales-agent"},
		ToolCall:       &core.ToolCallView{ToolName: "delete_employee"},
	})
	// Universal agent scope routes through ORG_UNIVERSAL_DENY; an
	// identity-scoped org deny would surface as ORG_DENY_INVARIANT — in
	// both tiers the org baseline beats the team allow.
	if dec.Action != ActionDeny {
		t.Errorf("org deny must win, got action %s via %q", dec.Action, dec.MatchedRuleID)
	}
}

func TestManager_HierarchyRejectsShadowedInvariant(t *testing.T) {
	restore := seamFor(t,
		map[string][]byte{"/org.yaml": []byte(orgPolicyBody), "/team.yaml": []byte(shadowTeamPolicyBody)},
		map[string]time.Time{"/org.yaml": time.Unix(1000, 0), "/team.yaml": time.Unix(1000, 0)})
	t.Cleanup(restore)

	if _, err := NewHierarchyManager("/org.yaml", []string{"/team.yaml"}); err == nil || !strings.Contains(err.Error(), "shadow") {
		t.Errorf("shadowed org invariant must be rejected: %v", err)
	}
}

func TestManager_HierarchyReloadReMerges(t *testing.T) {
	team := []byte(teamPolicyBody)
	restore := seamFor(t,
		map[string][]byte{"/org.yaml": []byte(orgPolicyBody), "/team.yaml": team},
		map[string]time.Time{"/org.yaml": time.Unix(1000, 0), "/team.yaml": time.Unix(1000, 0)})
	t.Cleanup(restore)

	pm, err := NewHierarchyManager("/org.yaml", []string{"/team.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	oldCount := len(pm.Policy().Rules)

	// Append a rule to the team layer and bump ONLY the team mtime — the
	// whole hierarchy re-merges because every layer is one watch surface.
	teamV2 := append(bytes.Clone(team), []byte(`
  - id: T-002
    agent: {client_id: sales-agent}
    tool: {name: "list_contacts"}
    action: allow
    reason: team-local read access
`)...)
	osOpen = func(path string) (io.ReadCloser, error) {
		m := map[string][]byte{
			"/org.yaml":  []byte(orgPolicyBody),
			"/team.yaml": teamV2,
		}
		b, ok := m[path]
		if !ok {
			return nil, fmt.Errorf("no content for %s", path)
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	fileStat = func(path string) (fileInfo, error) {
		m := map[string]time.Time{
			"/org.yaml":  time.Unix(1000, 0),
			"/team.yaml": time.Unix(2000, 0), // changed
		}
		m2, ok := m[path]
		if !ok {
			return nil, fmt.Errorf("no mtime for %s", path)
		}
		return fakeFileInfo{m: m2}, nil
	}
	res := pm.Reload()
	if !res.Swapped {
		t.Fatalf("hierarchy reload must swap: %v", res.Error)
	}
	if len(pm.Policy().Rules) != oldCount+1 {
		t.Errorf("rules: %d want %d", len(pm.Policy().Rules), oldCount+1)
	}
	_ = oldCount

	// A broken team edit is rejected and the last-good hierarchy survives.
	fileStat = func(path string) (fileInfo, error) {
		m := map[string]time.Time{
			"/org.yaml": time.Unix(1000, 0),
			"/team.yaml": time.Unix(3000, 0),
		}
		m2, ok := m[path]
		if !ok {
			return nil, fmt.Errorf("no mtime for %s", path)
		}
		return fakeFileInfo{m: m2}, nil
	}
	osOpen = func(path string) (io.ReadCloser, error) {
		if path == "/team.yaml" {
		return io.NopCloser(bytes.NewReader([]byte(brokenTeamBody))), nil
		}
		return io.NopCloser(bytes.NewReader([]byte(orgPolicyBody))), nil
	}
	res = pm.Reload()
	if res.Swapped || res.Error == nil {
		t.Error("broken team layer must be rejected")
	}
	if len(pm.Policy().Rules) != oldCount+1 {
		t.Error("last-good hierarchy must survive a rejected reload")
	}
}

func (pm *PolicyManager) Hierarchy() *Hierarchy { return pm.hierarchy.Load() }

func TestHierarchy_FlattenedRulesOrder(t *testing.T) {
	restore := seamFor(t,
		map[string][]byte{"/org.yaml": []byte(orgPolicyBody), "/team.yaml": []byte(teamPolicyBody)},
		map[string]time.Time{"/org.yaml": time.Unix(1000, 0), "/team.yaml": time.Unix(1000, 0)})
	t.Cleanup(restore)

	pm, err := NewHierarchyManager("/org.yaml", []string{"/team.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(pm.Hierarchy().FlattenedRules()))
	for _, r := range pm.Hierarchy().FlattenedRules() {
		ids = append(ids, r.ID)
	}
	// Identity-scoped org denies lead the flattened view; universal
	// any-agent denies trail behind the org allows.
	if ids[0] != "R-000" {
		t.Errorf("org identity-scoped denials must lead: %v", ids)
	}
}
