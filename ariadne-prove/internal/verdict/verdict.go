// Package verdict builds the compact reckless/trade-off/hardened readout
// described in docs/cli-contract.md. It is a thin grading layer over the
// existing deterministic pipeline (model.Report + the inventory collection);
// it adds no new collection passes and no new evidence.
package verdict

import (
	"sort"
	"strconv"
	"time"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

// SchemaVersion identifies the verdict JSON shape.
const SchemaVersion = "ariadne.verdict/v1"

// Verdict words.
const (
	WordReckless      = "reckless"
	WordTradeoffsOnly = "tradeoffs_only"
	WordHardened      = "hardened"
	WordNoAgentsFound = "no_agents_found"
)

// Exposure family IDs, in the reckless rendering order required by the
// contract: egress first, then secret, then MCP.
const (
	FamilyEgress = "data-egress-chain"
	FamilySecret = "prompt-injection-to-secret-canary"
	FamilyMCP    = "mutable-tool-launch-execution"
)

var recklessFamilyOrder = []string{FamilyEgress, FamilySecret, FamilyMCP}

// Verdict is the top-level document rendered by RenderReadout/RenderText and
// marshaled by RenderJSON. Field order and JSON tags follow the "Verdict
// JSON" section of docs/cli-contract.md exactly.
type Verdict struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Target        string            `json:"target"`
	Mode          string            `json:"mode"`
	VerdictWord   string            `json:"verdict"`
	Scanned       ScannedSummary    `json:"scanned"`
	Reckless      []RecklessFinding `json:"reckless"`
	Tradeoffs     []TradeoffLine    `json:"tradeoffs"`
	Hardened      []HardenedLine    `json:"hardened"`
	Inconclusive  int               `json:"inconclusive"`
	NextAction    string            `json:"next_action"`
	Limitations   []string          `json:"limitations"`
}

// ScannedSummary is the "what was found" line of the readout.
type ScannedSummary struct {
	Runtimes []string `json:"runtimes"`
	Surfaces int      `json:"surfaces"`
	Executed bool     `json:"executed"`
}

// EvidenceLocation is a single source:line pointer.
type EvidenceLocation struct {
	Source string `json:"source"`
	Line   int    `json:"line"`
}

// RecklessFinding is one screen-numbered reckless finding.
type RecklessFinding struct {
	ID           string                    `json:"id"`
	ExposureID   string                    `json:"exposure_id"`
	Title        string                    `json:"title"`
	Where        EvidenceLocation          `json:"where"`
	EvidenceRefs []model.EvidenceReference `json:"evidence_refs"`
	Why          string                    `json:"why"`
	Fix          string                    `json:"fix"`
	AttestedOnly []string                  `json:"attested_only"`
}

// TradeoffLine is one accepted, non-exposed capability line.
type TradeoffLine struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Source  string `json:"source"`
}

// HardenedLine is one enforced control working in the user's favor.
type HardenedLine struct {
	ID      string `json:"id"`
	Control string `json:"control"`
	Summary string `json:"summary"`
	Source  string `json:"source"`
}

// Build grades the given inventory collection and exposure report into a
// Verdict. It is pure and deterministic: given the same inputs it always
// produces the same output (stable ordering, no map-iteration leaks).
func Build(inventory model.InventoryReport, r model.Report, target string, mode string) Verdict {
	collection := inventory.Collection

	reckless := buildReckless(r.Exposures, collection)
	tradeoffs := buildTradeoffs(r.Exposures, collection)
	hardened := buildHardened(collection)

	inconclusive := 0
	for _, exposure := range r.Exposures {
		if exposure.Status == model.StatusInconclusive {
			inconclusive++
		}
	}

	word := WordNoAgentsFound
	switch {
	case len(reckless) > 0:
		word = WordReckless
	case len(tradeoffs) > 0:
		word = WordTradeoffsOnly
	case len(hardened) > 0 || len(collection.Runtimes) > 0:
		word = WordHardened
	}

	nextAction := "no action needed — rerun after config changes"
	if word == WordReckless {
		nextAction = "fix reckless:1, then rerun ariadne self"
	}

	return Verdict{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Target:        target,
		Mode:          mode,
		VerdictWord:   word,
		Scanned:       buildScanned(collection),
		Reckless:      reckless,
		Tradeoffs:     tradeoffs,
		Hardened:      hardened,
		Inconclusive:  inconclusive,
		NextAction:    nextAction,
		Limitations: []string{
			"Verdict is derived from configuration evidence only; nothing was executed.",
		},
	}
}

func buildScanned(collection model.Collection) ScannedSummary {
	runtimeSet := make(map[string]bool, len(collection.Runtimes))
	for _, rt := range collection.Runtimes {
		if rt.Kind == "" {
			continue
		}
		runtimeSet[rt.Kind] = true
	}
	runtimes := make([]string, 0, len(runtimeSet))
	for name := range runtimeSet {
		runtimes = append(runtimes, name)
	}
	sort.Strings(runtimes)
	return ScannedSummary{
		Runtimes: runtimes,
		Surfaces: len(collection.Surfaces),
		Executed: false,
	}
}

// buildReckless returns one finding per exposed ExposureResult, ordered
// egress, secret, then MCP per the contract's grading rules.
func buildReckless(exposures []model.ExposureResult, collection model.Collection) []RecklessFinding {
	byID := make(map[string]model.ExposureResult, len(exposures))
	for _, exposure := range exposures {
		byID[exposure.ID] = exposure
	}

	out := make([]RecklessFinding, 0, len(recklessFamilyOrder))
	n := 0
	for _, familyID := range recklessFamilyOrder {
		exposure, ok := byID[familyID]
		if !ok || exposure.Status != model.StatusExposed {
			continue
		}
		n++
		out = append(out, buildRecklessFinding(n, exposure, collection))
	}
	return out
}

func buildRecklessFinding(n int, exposure model.ExposureResult, collection model.Collection) RecklessFinding {
	refs := exposure.EvidenceReferences
	where := EvidenceLocation{}
	if len(refs) > 0 {
		where = EvidenceLocation{Source: refs[0].Source, Line: refs[0].LineStart}
	}
	extraRefs := refs
	if len(extraRefs) > 4 {
		extraRefs = extraRefs[:4]
	}

	return RecklessFinding{
		ID:           recklessID(n),
		ExposureID:   exposure.ID,
		Title:        recklessTitle(exposure),
		Where:        where,
		EvidenceRefs: nonNilEvidenceRefs(extraRefs),
		Why:          exposure.WhyItMatters,
		Fix:          recklessFix(exposure.ID, collection),
		AttestedOnly: attestedOnlyForFamily(exposure.ID, collection.Controls),
	}
}

func recklessID(n int) string {
	return "reckless:" + itoa(n)
}

// recklessTitle rewrites the exposure title in second person, naming the
// concrete risk. Canonical per family so screen output is stable.
func recklessTitle(exposure model.ExposureResult) string {
	switch exposure.ID {
	case FamilyEgress:
		return "Untrusted repo text can steer an agent that reads your secrets and can reach the internet"
	case FamilySecret:
		return "Untrusted repo instructions can steer your agent into reading secret-like files"
	case FamilyMCP:
		return "A mutable MCP package launcher can run unreviewed code on your machine"
	default:
		return exposure.Title
	}
}

// recklessFix returns the canonical, enforced-surface fix for the family.
// It never suggests a .ariadne/* declaration.
func recklessFix(exposureID string, collection model.Collection) string {
	switch exposureID {
	case FamilySecret:
		return `set "defaultMode": "default" and add deny rules for secret paths in .claude/settings.json (or codex requirements deny_read)`
	case FamilyMCP:
		return "pin the MCP package to an exact version in " + mcpSource(collection)
	case FamilyEgress:
		return "restrict network: codex requirements network_access = false, or deny WebFetch/WebSearch in .claude/settings.json"
	default:
		return ""
	}
}

// mcpSource returns the source path of the mutable MCP tool launcher, so the
// fix names the real file to edit rather than a placeholder. Falls back to a
// generic phrase when no source is recorded.
func mcpSource(collection model.Collection) string {
	for _, tool := range collection.Tools {
		if tool.ID == "tool:mcp-package-launch" && tool.Source != "" {
			return tool.Source
		}
	}
	for _, tool := range collection.Tools {
		if tool.Source != "" {
			return tool.Source
		}
	}
	return "your MCP config"
}

// familyControlPrefixes lists the control-kind prefixes considered relevant
// to each exposure family, used to derive attested_only. Kept simple and
// deterministic: substring match against control kind/ID suffix, not a
// security check — this only decides which attested controls to *surface*,
// never whether a finding closes.
var familyControlPrefixes = map[string][]string{
	FamilyEgress: {"egress", "output", "network"},
	FamilySecret: {"input", "deny"},
	FamilyMCP:    {"tool", "mcp"},
}

func attestedOnlyForFamily(exposureID string, controls []model.Control) []string {
	prefixes := familyControlPrefixes[exposureID]
	if len(prefixes) == 0 {
		return []string{}
	}
	seen := make(map[string]bool)
	var out []string
	for _, control := range controls {
		if control.Enforcement != model.EnforcementAttested {
			continue
		}
		if !controlMatchesFamily(control, prefixes) {
			continue
		}
		if seen[control.ID] {
			continue
		}
		seen[control.ID] = true
		out = append(out, control.ID)
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func controlMatchesFamily(control model.Control, prefixes []string) bool {
	for _, prefix := range prefixes {
		if hasWordPrefix(control.ID, "control:"+prefix) || hasWordPrefix(control.Kind, prefix) {
			return true
		}
	}
	return false
}

// hasWordPrefix reports whether s starts with prefix at a "word" boundary
// (i.e. prefix is the whole string, or is followed immediately by '-' or
// ':'). This avoids accidental prefix collisions like "inputx" matching
// "input" while still being a plain structural check, not a substring scan
// over arbitrary config text.
func hasWordPrefix(s, prefix string) bool {
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return false
	}
	if len(s) == len(prefix) {
		return true
	}
	next := s[len(prefix)]
	return next == '-' || next == ':'
}

// buildTradeoffs returns one line per accepted capability whose matching
// exposure family is not exposed, per the contract's fixed trade-off rules.
func buildTradeoffs(exposures []model.ExposureResult, collection model.Collection) []TradeoffLine {
	exposed := make(map[string]bool, len(exposures))
	for _, exposure := range exposures {
		if exposure.Status == model.StatusExposed {
			exposed[exposure.ID] = true
		}
	}

	type candidate struct {
		order   int
		summary string
		source  string
	}
	var candidates []candidate

	if !exposed[FamilyEgress] {
		if authority, ok := firstAuthority(collection.Authorities, "authority:external-communication"); ok {
			candidates = append(candidates, candidate{0, "an agent can reach the network — normal for installs and web lookups", authority.Source})
		}
	}
	if !exposed[FamilySecret] && !exposed[FamilyEgress] {
		if authority, ok := firstAuthority(collection.Authorities, "authority:file-read"); ok {
			candidates = append(candidates, candidate{1, "agents read your workspace — that is what a coding agent is for", authority.Source})
		}
	}
	if !exposed[FamilySecret] {
		if boundary, ok := firstBoundary(collection.Boundaries, "boundary:agent-private-context"); ok {
			candidates = append(candidates, candidate{2, "agent chat/history is stored locally", boundary.Source})
		}
	}
	if !exposed[FamilyMCP] {
		if tool, ok := firstTool(collection.Tools, "tool:mcp-package-launch"); ok {
			if control, ok := firstEnforcedControl(collection.Controls, "control:mcp-reviewed-pinned"); ok {
				candidates = append(candidates, candidate{3, "MCP tools configured and pinned", firstNonEmpty(control.Source, tool.Source)})
			}
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].order < candidates[j].order })

	out := make([]TradeoffLine, 0, len(candidates))
	for i, c := range candidates {
		out = append(out, TradeoffLine{ID: "tradeoff:" + itoa(i+1), Summary: c.summary, Source: c.source})
	}
	return out
}

// buildHardened returns one line per enforced control, deduped by control
// ID, sorted for determinism. The screen caps at 6; the JSON carries the
// full list.
func buildHardened(collection model.Collection) []HardenedLine {
	seen := make(map[string]model.Control)
	var order []string
	for _, control := range collection.Controls {
		if control.Enforcement != model.EnforcementEnforced {
			continue
		}
		if _, ok := seen[control.ID]; !ok {
			order = append(order, control.ID)
		}
		seen[control.ID] = control
	}
	sort.Strings(order)

	out := make([]HardenedLine, 0, len(order))
	for i, id := range order {
		control := seen[id]
		out = append(out, HardenedLine{
			ID:      "hardened:" + itoa(i+1),
			Control: control.ID,
			Summary: control.Summary,
			Source:  control.Source,
		})
	}
	return out
}

func firstAuthority(authorities []model.Authority, id string) (model.Authority, bool) {
	for _, a := range authorities {
		if a.ID == id {
			return a, true
		}
	}
	return model.Authority{}, false
}

func firstBoundary(boundaries []model.Boundary, id string) (model.Boundary, bool) {
	for _, b := range boundaries {
		if b.ID == id {
			return b, true
		}
	}
	return model.Boundary{}, false
}

func firstTool(tools []model.Tool, id string) (model.Tool, bool) {
	for _, t := range tools {
		if t.ID == id {
			return t, true
		}
	}
	return model.Tool{}, false
}

func firstEnforcedControl(controls []model.Control, id string) (model.Control, bool) {
	for _, c := range controls {
		if c.ID == id && c.Enforcement == model.EnforcementEnforced {
			return c, true
		}
	}
	return model.Control{}, false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func nonNilEvidenceRefs(in []model.EvidenceReference) []model.EvidenceReference {
	if in == nil {
		return []model.EvidenceReference{}
	}
	return in
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
