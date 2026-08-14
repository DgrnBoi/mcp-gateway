package policy

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ReloadResult reports the outcome of a hot-reload attempt so the
// operator (and CI tooling) can see why a swap did or did not happen.
type ReloadResult struct {
	Swapped  bool
	Error    error
	OldRules int
	NewRules int
}

// FileLoader parses and validates a YAML policy document from a file
// path. It wraps the strict YAML loader (loader.go) so the manager can
// re-read the file on every reload attempt. Tests may swap osOpen to
// inject a fake filesystem.
type FileLoader struct{}

// Load parses the policy file at path with strict validation.
func (FileLoader) Load(path string) (*Policy, error) {
	f, err := osOpen(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

// osOpen is the production file-open seam; tests replace it to inject
// readers without touching disk.
var osOpen = func(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

// PolicyManager watches a policy file and hot-swaps the active policy
// behind an atomic pointer. Swaps are zero-downtime: in-flight requests
// continue against the snapshot they already hold, and the next request
// picks up the new policy with a single pointer read.
type PolicyManager struct {
	loader       FileLoader
	path         string
	policy       atomic.Pointer[Policy]
	mu           sync.Mutex // serializes Reload calls
	trackModTime bool       // false during ForceReload (SIGHUP)
	lastModTime  time.Time

	// Stage 4 / Ticket 19: multi-tenant policy hierarchy. When non-nil, the
	// manager watches the org layer AND every team layer as one atomic unit
	// and re-merges the whole hierarchy on reload. The org default action is
	// always presented as the flat policy's DefaultAction so downstream
	// components (console, GitOps generation) keep a single view.
	orgPath    string
	teamPaths  []string
	hierarchy  atomic.Pointer[Hierarchy]
}

// NewPolicyManager loads the policy once (validating it) and returns a
// manager ready for hot-reload. A bad initial policy is a fatal startup
// error — the gateway never runs with an invalid policy.
func NewPolicyManager(path string) (*PolicyManager, error) {
	p, err := FileLoader{}.Load(path)
	if err != nil {
		return nil, fmt.Errorf("initial policy load: %w", err)
	}
	pm := &PolicyManager{path: path, trackModTime: true}
	pm.policy.Store(p)
	if info, err := fileStat(path); err == nil {
		pm.lastModTime = info.ModTime()
	}
	return pm, nil
}

// Policy returns the currently active policy. Safe to call from any
// request goroutine: a single atomic pointer read.
func (pm *PolicyManager) Policy() *Policy {
	return pm.policy.Load()
}

// Reload re-parses the policy file and swaps it in only if it fully
// validates. Repeated calls with an unchanged file (same mtime) are
// no-ops, so a watcher loop can poll cheaply.
func (pm *PolicyManager) Reload() ReloadResult {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.reloadLocked()
}

// ForceReload ignores mtime tracking and always re-parses. This is the
// SIGHUP path: operators demand a re-load even when the file's mtime
// did not change (edit-in-place by editors, or ConfigMap rollouts that
// preserve timestamps).
func (pm *PolicyManager) ForceReload() ReloadResult {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.trackModTime = false
	res := pm.reloadLocked()
	pm.trackModTime = true
	return res
}

func (pm *PolicyManager) reloadLocked() ReloadResult {
	res := ReloadResult{}
	res.OldRules = len(pm.policy.Load().Rules)

	// Stage 4 / Ticket 19: when a hierarchy is loaded, every layer (org +
	// teams) is part of the watch surface — a change to any single team
	// file triggers a full re-merge, so partial rollouts can never leave
	// the evaluator between two policy versions.
	if pm.orgPath != "" {
		return pm.reloadHierarchyLocked(res)
	}

	if pm.trackModTime {
		info, err := fileStat(pm.path)
		if err == nil && !info.ModTime().After(pm.lastModTime) {
			return res // unchanged, nothing to do
		}
	}

	newPolicy, err := pm.loader.Load(pm.path)
	if err != nil {
		res.Error = fmt.Errorf("policy rejected: %w", err)
		log.Printf("mcpgw: hot-reload rejected — %v", res.Error)
		return res
	}
	pm.policy.Store(newPolicy)

	if info, err := fileStat(pm.path); err == nil {
		pm.lastModTime = info.ModTime()
	}
	res.Swapped = true
	res.NewRules = len(newPolicy.Rules)
	log.Printf("mcpgw: policy hot-swapped (%d → %d rules)", res.OldRules, res.NewRules)
	return res
}

// anyLayerChanged reports whether any layer (org or any team) has a newer
// mtime than the tracked baseline — every layer participates in the watch
// surface, so a team-only rollout still triggers a full re-merge.
func (pm *PolicyManager) anyLayerChanged() bool {
	for _, p := range append([]string{pm.orgPath}, pm.teamPaths...) {
		if info, err := fileStat(p); err == nil && info.ModTime().After(pm.lastModTime) {
			return true
		}
	}
	return false
}

// reloadHierarchyLocked re-parses every layer and re-merges the hierarchy.
// The swap is all-or-nothing: if any layer fails to parse or the merge
// detects a new shadowed invariant, the last-good hierarchy stays active
// and the rejection is logged for triage.
func (pm *PolicyManager) reloadHierarchyLocked(res ReloadResult) ReloadResult {
	if pm.trackModTime && !pm.anyLayerChanged() {
		return res // all layers unchanged, nothing to do
	}
	org, err := FileLoader{}.Load(pm.orgPath)
	if err != nil {
		res.Error = fmt.Errorf("org policy rejected: %w", err)
		log.Printf("mcpgw: hot-reload rejected — %v", res.Error)
		return res
	}
	teams := make([]*Policy, 0, len(pm.teamPaths))
	for _, tp := range pm.teamPaths {
		t, terr := FileLoader{}.Load(tp)
		if terr != nil {
			res.Error = fmt.Errorf("team policy %s rejected: %w", tp, terr)
			log.Printf("mcpgw: hot-reload rejected — %v", res.Error)
			return res
		}
		teams = append(teams, t)
	}
	newHierarchy, herr := Merge(org, teams...)
	if herr != nil {
		res.Error = fmt.Errorf("hierarchy merge rejected: %w", herr)
		log.Printf("mcpgw: hot-reload rejected — %v", res.Error)
		return res
	}
	pm.policy.Store(hierarchyAsPolicy(newHierarchy))
	pm.hierarchy.Store(newHierarchy)

	// Advance the tracked baseline only past genuinely newer mtimes; the
	// org layer's mtime is the canonical marker.
	if info, err := fileStat(pm.orgPath); err == nil && info.ModTime().After(pm.lastModTime) {
		pm.lastModTime = info.ModTime()
	}
	res.Swapped = true
	res.NewRules = len(newHierarchy.FlattenedRules())
	log.Printf("mcpgw: hierarchy hot-swapped (%d → %d rules, %d team layers)",
		res.OldRules, res.NewRules, len(pm.teamPaths))
	return res
}

// ValidateInitial verifies the policy file with the strict loader so
// main.go can fail closed at startup before the first request arrives.
func ValidateInitial(path string) error {
	_, err := FileLoader{}.Load(path)
	return err
}

// NewHierarchyManager binds a multi-tenant hierarchy (one org base layer,
// any number of team layers) to the hot-reload surface. Merge is
// fail-closed: a team allow that shadows an org deny invariant rejects the
// entire hierarchy at startup — the gateway never runs with a silently
// downgraded baseline.
func NewHierarchyManager(orgPath string, teamPaths []string) (*PolicyManager, error) {
	org, err := FileLoader{}.Load(orgPath)
	if err != nil {
		return nil, fmt.Errorf("org policy: %w", err)
	}
	teams := make([]*Policy, 0, len(teamPaths))
	for _, tp := range teamPaths {
		t, terr := FileLoader{}.Load(tp)
		if terr != nil {
			return nil, fmt.Errorf("team policy %s: %w", tp, terr)
		}
		teams = append(teams, t)
	}
	h, herr := Merge(org, teams...)
	if herr != nil {
		return nil, fmt.Errorf("hierarchy merge: %w", herr)
	}
	pm := &PolicyManager{
		path:        orgPath,
		policy:      atomic.Pointer[Policy]{},
		hierarchy:   atomic.Pointer[Hierarchy]{},
		trackModTime: true,
		orgPath:     orgPath,
		teamPaths:   teamPaths,
	}
	pm.policy.Store(hierarchyAsPolicy(h))
	pm.hierarchy.Store(h)
	if info, err := fileStat(orgPath); err == nil {
		pm.lastModTime = info.ModTime()
	}
	return pm, nil
}

// hierarchyAsPolicy renders the merged hierarchy as the single flat policy
// view used by components that were written before multi-tenant support
// (the console, GitOps generation, hot-reload rule counting).
func hierarchyAsPolicy(h *Hierarchy) *Policy {
	rules := make([]Rule, 0,
		len(h.orgDenies)+len(h.teamDenies)+len(h.teamAllows)+len(h.orgAllows)+len(h.univDenies))
	rules = append(rules, h.orgDenies...)
	rules = append(rules, h.teamDenies...)
	rules = append(rules, h.teamAllows...)
	rules = append(rules, h.orgAllows...)
	rules = append(rules, h.univDenies...)
	return &Policy{DefaultAction: h.orgDefault, Rules: rules}
}

// fileInfo is the mtime surface the reload tracker depends on; tests
// inject fake implementations via the fileStat seam.
type fileInfo interface {
ModTime() time.Time
}
