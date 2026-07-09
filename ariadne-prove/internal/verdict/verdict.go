// Package verdict builds the compact reckless/trade-off/hardened readout
// described in docs/cli-contract.md. It is a thin grading layer over the
// existing deterministic pipeline (model.Report + the inventory collection);
// it adds no new collection passes and no new evidence.
package verdict

import (
	"sort"
	"strconv"
	"strings"
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
	SchemaVersion       string                    `json:"schema_version"`
	GeneratedAt         time.Time                 `json:"generated_at"`
	Target              string                    `json:"target"`
	Mode                string                    `json:"mode"`
	VerdictWord         string                    `json:"verdict"`
	Scanned             ScannedSummary            `json:"scanned"`
	InfluenceProvenance []InfluenceProvenanceFact `json:"influence_provenance"`
	DefaultJudgments    []DefaultJudgment         `json:"default_judgments"`
	Reckless            []RecklessFinding         `json:"reckless"`
	Tradeoffs           []TradeoffLine            `json:"tradeoffs"`
	Hardened            []HardenedLine            `json:"hardened"`
	Inconclusive        int                       `json:"inconclusive"`
	NextAction          string                    `json:"next_action"`
	Limitations         []string                  `json:"limitations"`
}

// ScannedSummary is the "what was found" line of the readout.
type ScannedSummary struct {
	Runtimes []string `json:"runtimes"`
	Surfaces int      `json:"surfaces"`
	Executed bool     `json:"executed"`
}

// InfluenceProvenanceFact is a deterministic fact about how a trust input
// arrived. It is intentionally about location/arrival, not who authored it.
type InfluenceProvenanceFact struct {
	ID               string `json:"id"`
	TrustInputID     string `json:"trust_input_id"`
	Provenance       string `json:"provenance"`
	InstructionScope string `json:"instruction_scope"`
	Source           string `json:"source"`
	Summary          string `json:"summary"`
}

// DefaultJudgment records an interpretative grading default and the facts it
// weighed, so consumers can re-derive or override the verdict word.
type DefaultJudgment struct {
	Rule          string             `json:"rule"`
	Label         string             `json:"label"`
	ExposureID    string             `json:"exposure_id"`
	TrustInputIDs []string           `json:"trust_input_ids"`
	Basis         []JudgmentBasisRef `json:"basis"`
	Summary       string             `json:"summary"`
}

// JudgmentBasisRef names one deterministic fact considered by a judgment.
type JudgmentBasisRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// EvidenceLocation is a source pointer. Parsed evidence carries a positive
// line; metadata-only evidence is marked with Anchor "file" and has no line.
type EvidenceLocation struct {
	Source string `json:"source"`
	Line   int    `json:"line,omitempty"`
	Anchor string `json:"anchor,omitempty"`
}

// RecklessFinding is one screen-numbered reckless finding.
type RecklessFinding struct {
	ID                  string                    `json:"id"`
	ExposureID          string                    `json:"exposure_id"`
	Title               string                    `json:"title"`
	Where               EvidenceLocation          `json:"where"`
	EvidenceRefs        []model.EvidenceReference `json:"evidence_refs"`
	Why                 string                    `json:"why"`
	Fix                 string                    `json:"fix"`
	RelatedCapabilities []RelatedCapability       `json:"related_capabilities"`
	AttestedOnly        []string                  `json:"attested_only"`
}

// RelatedCapability is an observed trade-off candidate that was consumed by
// this finding's exposed path instead of rendering as a separate trade-off.
type RelatedCapability struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Runtime string `json:"runtime,omitempty"`
	Source  string `json:"source"`
	Summary string `json:"summary"`
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

	influenceProvenance := buildInfluenceProvenance(collection)
	defaultJudgments := buildDefaultJudgments(r.Exposures, collection, influenceProvenance)
	downgraded := downgradedExposureIDs(defaultJudgments)
	recklessExposures := effectiveRecklessExposures(r.Exposures, downgraded)
	capabilityBuckets := bucketCapabilities(recklessExposures, collection)
	reckless := buildReckless(recklessExposures, collection, capabilityBuckets.Related)
	tradeoffs := buildTradeoffs(defaultJudgments, collection, capabilityBuckets)
	hardened := buildHardened(collection)

	inconclusive := 0
	for _, exposure := range r.Exposures {
		if exposure.Status == model.StatusInconclusive {
			inconclusive++
		}
	}

	word := computeVerdictWord(len(reckless), len(tradeoffs), len(hardened), len(collection.Runtimes))

	nextAction := "no action needed — rerun after config changes"
	if word == WordReckless {
		nextAction = "fix reckless:1, then rerun ariadne self"
	}

	return Verdict{
		SchemaVersion:       SchemaVersion,
		GeneratedAt:         time.Now().UTC(),
		Target:              target,
		Mode:                mode,
		VerdictWord:         word,
		Scanned:             buildScanned(collection),
		InfluenceProvenance: influenceProvenance,
		DefaultJudgments:    defaultJudgments,
		Reckless:            reckless,
		Tradeoffs:           tradeoffs,
		Hardened:            hardened,
		Inconclusive:        inconclusive,
		NextAction:          nextAction,
		Limitations: []string{
			"Verdict is derived from configuration evidence only; nothing was executed.",
		},
	}
}

func computeVerdictWord(recklessCount, tradeoffCount, hardenedCount, runtimeCount int) string {
	switch {
	case recklessCount > 0:
		return WordReckless
	case tradeoffCount > 0:
		return WordTradeoffsOnly
	case runtimeCount > 0:
		return WordHardened
	default:
		// Enforced controls remain reported, but cannot harden an absent runtime.
		_ = hardenedCount
		return WordNoAgentsFound
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

const (
	homeScopeDefaultRule   = "home_scope_influence_not_untrusted_by_default"
	nestedScopeDefaultRule = "nested_instructions_scoped_by_default"
)

func buildInfluenceProvenance(collection model.Collection) []InfluenceProvenanceFact {
	out := make([]InfluenceProvenanceFact, 0, len(collection.TrustInputs))
	seen := map[string]bool{}
	for _, input := range collection.TrustInputs {
		provenance := input.Provenance
		if provenance == "" {
			provenance = model.TrustInputProvenanceUnknown
		}
		instructionScope := input.InstructionScope
		if instructionScope == "" {
			instructionScope = model.InstructionScopeUnknown
		}
		factID := "fact:" + input.ID
		if fact, ok := provenanceFactForInput(collection.Facts, input); ok {
			factID = fact.ID
		}
		key := factID + "|" + input.ID + "|" + input.Source + "|" + provenance + "|" + instructionScope
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, InfluenceProvenanceFact{
			ID:               factID,
			TrustInputID:     input.ID,
			Provenance:       provenance,
			InstructionScope: instructionScope,
			Source:           input.Source,
			Summary:          "Trust input provenance and instruction scope derived from deterministic surface location and arrival path.",
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source == out[j].Source {
			if out[i].TrustInputID == out[j].TrustInputID {
				return out[i].Provenance < out[j].Provenance
			}
			return out[i].TrustInputID < out[j].TrustInputID
		}
		return out[i].Source < out[j].Source
	})
	if out == nil {
		return []InfluenceProvenanceFact{}
	}
	return out
}

func provenanceFactForInput(facts []model.Fact, input model.TrustInput) (model.Fact, bool) {
	for _, fact := range facts {
		if fact.Source == input.Source && fact.Provenance == input.Provenance && fact.InstructionScope == input.InstructionScope {
			return fact, true
		}
	}
	for _, fact := range facts {
		if fact.Source == input.Source && fact.Provenance != "" {
			return fact, true
		}
	}
	return model.Fact{}, false
}

func buildDefaultJudgments(exposures []model.ExposureResult, collection model.Collection, provenanceFacts []InfluenceProvenanceFact) []DefaultJudgment {
	risky := riskyTrustInputs(collection)
	if len(risky) == 0 {
		return []DefaultJudgment{}
	}
	rule := ""
	judgedInputs := risky
	summary := ""
	switch {
	case allHomeScope(risky):
		rule = homeScopeDefaultRule
		summary = "Home-scope influence alone is treated as a trade-off by default; deterministic facts do not claim the file is safe or user-authored."
	default:
		judgedInputs = riskyUntrustedTrustInputs(risky)
		if len(judgedInputs) == 0 || !allNestedScope(judgedInputs) {
			return []DefaultJudgment{}
		}
		rule = nestedScopeDefaultRule
		summary = "Nested untrusted instructions are scoped by default; they become live influence for agents that work inside those directories."
	}
	byID := make(map[string]model.ExposureResult, len(exposures))
	for _, exposure := range exposures {
		byID[exposure.ID] = exposure
	}
	trustInputIDs := trustInputIDs(judgedInputs)
	basis := judgmentBasis(judgedInputs, provenanceFacts)
	var out []DefaultJudgment
	for _, familyID := range []string{FamilyEgress, FamilySecret} {
		exposure, ok := byID[familyID]
		if !ok || exposure.Status != model.StatusExposed {
			continue
		}
		out = append(out, DefaultJudgment{
			Rule:          rule,
			Label:         "default_judgment",
			ExposureID:    familyID,
			TrustInputIDs: trustInputIDs,
			Basis:         basis,
			Summary:       summary,
		})
	}
	if out == nil {
		return []DefaultJudgment{}
	}
	return out
}

func riskyTrustInputs(collection model.Collection) []model.TrustInput {
	var out []model.TrustInput
	for _, input := range collection.TrustInputs {
		if input.Risky {
			out = append(out, input)
		}
	}
	return out
}

func allHomeScope(inputs []model.TrustInput) bool {
	for _, input := range inputs {
		if input.Provenance != model.TrustInputProvenanceHomeScope {
			return false
		}
	}
	return true
}

func riskyUntrustedTrustInputs(inputs []model.TrustInput) []model.TrustInput {
	var out []model.TrustInput
	for _, input := range inputs {
		if input.Provenance != model.TrustInputProvenanceHomeScope {
			out = append(out, input)
		}
	}
	return out
}

func allNestedScope(inputs []model.TrustInput) bool {
	for _, input := range inputs {
		if input.InstructionScope != model.InstructionScopeNested {
			return false
		}
	}
	return true
}

func trustInputIDs(inputs []model.TrustInput) []string {
	seen := map[string]bool{}
	var out []string
	for _, input := range inputs {
		if input.ID == "" || seen[input.ID] {
			continue
		}
		seen[input.ID] = true
		out = append(out, input.ID)
	}
	sort.Strings(out)
	if out == nil {
		return []string{}
	}
	return out
}

func judgmentBasis(inputs []model.TrustInput, provenanceFacts []InfluenceProvenanceFact) []JudgmentBasisRef {
	inputSources := map[string]bool{}
	var out []JudgmentBasisRef
	seen := map[string]bool{}
	for _, input := range inputs {
		inputSources[input.ID+"|"+input.Source+"|"+input.Provenance+"|"+input.InstructionScope] = true
		addJudgmentBasis(&out, seen, JudgmentBasisRef{Kind: "trust_input", ID: input.ID})
	}
	for _, fact := range provenanceFacts {
		if !inputSources[fact.TrustInputID+"|"+fact.Source+"|"+fact.Provenance+"|"+fact.InstructionScope] {
			continue
		}
		addJudgmentBasis(&out, seen, JudgmentBasisRef{Kind: "fact", ID: fact.ID})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].ID < out[j].ID
		}
		return out[i].Kind < out[j].Kind
	})
	if out == nil {
		return []JudgmentBasisRef{}
	}
	return out
}

func addJudgmentBasis(out *[]JudgmentBasisRef, seen map[string]bool, ref JudgmentBasisRef) {
	key := ref.Kind + "|" + ref.ID
	if seen[key] {
		return
	}
	seen[key] = true
	*out = append(*out, ref)
}

func downgradedExposureIDs(judgments []DefaultJudgment) map[string]bool {
	out := make(map[string]bool, len(judgments))
	for _, judgment := range judgments {
		out[judgment.ExposureID] = true
	}
	return out
}

// effectiveRecklessExposures returns effectively exposed ExposureResults in
// the reckless rendering order required by the contract.
func effectiveRecklessExposures(exposures []model.ExposureResult, downgraded map[string]bool) []model.ExposureResult {
	byID := make(map[string]model.ExposureResult, len(exposures))
	for _, exposure := range exposures {
		byID[exposure.ID] = exposure
	}

	out := make([]model.ExposureResult, 0, len(recklessFamilyOrder))
	for _, familyID := range recklessFamilyOrder {
		exposure, ok := byID[familyID]
		if !ok || exposure.Status != model.StatusExposed || downgraded[familyID] {
			continue
		}
		out = append(out, exposure)
	}
	return out
}

// buildReckless returns one finding per effectively exposed ExposureResult.
func buildReckless(exposures []model.ExposureResult, collection model.Collection, related map[string][]RelatedCapability) []RecklessFinding {
	out := make([]RecklessFinding, 0, len(exposures))
	for i, exposure := range exposures {
		out = append(out, buildRecklessFinding(i+1, exposure, collection, related[exposure.ID]))
	}
	return out
}

func buildRecklessFinding(n int, exposure model.ExposureResult, collection model.Collection, related []RelatedCapability) RecklessFinding {
	refs := orderFindingEvidenceReferences(exposure.EvidenceReferences)
	where := EvidenceLocation{}
	if len(refs) > 0 {
		where = evidenceLocationFromRef(refs[0])
	}
	extraRefs := refs
	if len(extraRefs) > 4 {
		extraRefs = extraRefs[:4]
	}

	return RecklessFinding{
		ID:                  recklessID(n),
		ExposureID:          exposure.ID,
		Title:               recklessTitle(exposure),
		Where:               where,
		EvidenceRefs:        nonNilEvidenceRefs(extraRefs),
		Why:                 exposure.WhyItMatters,
		Fix:                 recklessFix(exposure.ID, refs, collection),
		RelatedCapabilities: nonNilRelatedCapabilities(related),
		AttestedOnly:        attestedOnlyForFamily(exposure.ID, collection.Controls),
	}
}

func orderFindingEvidenceReferences(refs []model.EvidenceReference) []model.EvidenceReference {
	if len(refs) == 0 {
		return refs
	}
	primary := -1
	for i, ref := range refs {
		if ref.Source != "" && ref.LineStart > 0 {
			primary = i
			break
		}
	}
	if primary < 0 {
		for i, ref := range refs {
			if ref.Source != "" && ref.Anchor == "file" {
				primary = i
				break
			}
		}
	}
	if primary <= 0 {
		return refs
	}
	out := make([]model.EvidenceReference, 0, len(refs))
	out = append(out, refs[primary])
	out = append(out, refs[:primary]...)
	out = append(out, refs[primary+1:]...)
	return out
}

func evidenceLocationFromRef(ref model.EvidenceReference) EvidenceLocation {
	location := EvidenceLocation{Source: ref.Source}
	if ref.LineStart > 0 {
		location.Line = ref.LineStart
		return location
	}
	if ref.Anchor == "file" {
		location.Anchor = "file"
	}
	return location
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

type recklessFixTarget struct {
	Runtime  string
	Source   string
	Kind     string
	Category string
}

// recklessFix returns an evidence-derived, enforced-surface fix. The runtime is
// resolved from the same first evidence reference that becomes finding.where,
// then used to select a same-runtime edit surface. It never suggests a
// .ariadne/* declaration.
func recklessFix(exposureID string, refs []model.EvidenceReference, collection model.Collection) string {
	target := recklessFixTargetFromEvidence(refs, collection)
	source := recklessFixSource(exposureID, target, collection)
	switch exposureID {
	case FamilySecret:
		switch target.Runtime {
		case "claude":
			return `set "defaultMode": "default" and add deny rules for secret paths in ` + source
		case "codex":
			return "add deny_read entries for secret paths in " + source
		case "gemini":
			return "restrict filesystem access and deny secret paths in " + source
		default:
			return "restrict secret-file reads in " + source
		}
	case FamilyMCP:
		return "pin the MCP package to an exact version in " + source
	case FamilyEgress:
		switch target.Runtime {
		case "claude":
			return "restrict network in " + source + ": deny WebFetch/WebSearch and avoid broad Bash egress"
		case "codex":
			return "set network_access = false in " + source
		case "gemini":
			return "disable external network access in " + source
		default:
			return "restrict external communication in " + source
		}
	default:
		return ""
	}
}

func recklessFixTargetFromEvidence(refs []model.EvidenceReference, collection model.Collection) recklessFixTarget {
	if len(refs) == 0 {
		return recklessFixTarget{}
	}
	ref := refs[0]
	if target, ok := fixTargetFromSurface(ref.Source, collection.Surfaces); ok {
		return target
	}
	if target, ok := fixTargetFromModelRef(ref, collection); ok {
		return target
	}
	return recklessFixTarget{Source: ref.Source}
}

func fixTargetFromSurface(source string, surfaces []model.Surface) (recklessFixTarget, bool) {
	if source == "" {
		return recklessFixTarget{}, false
	}
	for _, surface := range surfaces {
		if surface.Source != source {
			continue
		}
		return recklessFixTarget{
			Runtime:  ownerRuntimeForSurface(surface),
			Source:   surface.Source,
			Kind:     surface.Kind,
			Category: surface.Category,
		}, true
	}
	return recklessFixTarget{}, false
}

func fixTargetFromModelRef(ref model.EvidenceReference, collection model.Collection) (recklessFixTarget, bool) {
	switch ref.Kind {
	case "authority":
		for _, authority := range collection.Authorities {
			if authority.Source == ref.Source && authority.ID == ref.ID {
				return recklessFixTarget{Runtime: authority.Runtime, Source: authority.Source}, true
			}
		}
	case "tool":
		for _, tool := range collection.Tools {
			if tool.Source == ref.Source && tool.ID == ref.ID {
				return recklessFixTarget{Runtime: tool.Runtime, Source: tool.Source}, true
			}
		}
	case "trust-input", "trust_input":
		for _, input := range collection.TrustInputs {
			if input.Source == ref.Source && refMatchesTrustInput(ref, input) {
				return recklessFixTarget{Runtime: input.Runtime, Source: input.Source}, true
			}
		}
	case "runtime", "config":
		for _, runtime := range collection.Runtimes {
			if runtime.Source == ref.Source {
				return recklessFixTarget{Runtime: runtime.Kind, Source: runtime.Source}, true
			}
		}
	}
	if ref.Source == "" {
		return recklessFixTarget{}, false
	}
	return recklessFixTarget{Source: ref.Source}, true
}

func refMatchesTrustInput(ref model.EvidenceReference, input model.TrustInput) bool {
	return ref.ID == input.ID || ref.ID == "evidence:"+input.ID
}

func ownerRuntimeForSurface(surface model.Surface) string {
	switch surface.Kind {
	case "claude-md":
		return "claude"
	default:
		if surface.Runtime == "generic" {
			return ""
		}
		return surface.Runtime
	}
}

func recklessFixSource(exposureID string, target recklessFixTarget, collection model.Collection) string {
	if exposureID == FamilyMCP {
		return firstFixSource(target, "your MCP config")
	}
	if isRuntimeFixSurface(target) {
		return firstFixSource(target, "the runtime config that produced this finding")
	}
	if target.Runtime != "" {
		if source := sameRuntimeFixSurface(target.Runtime, collection.Surfaces); source != "" {
			return source
		}
	}
	return firstFixSource(target, "the runtime config that produced this finding")
}

func isRuntimeFixSurface(target recklessFixTarget) bool {
	if target.Source == "" || ariadneDeclarationTarget(target) {
		return false
	}
	for _, kind := range runtimeFixKinds(target.Runtime) {
		if target.Kind == kind {
			return true
		}
	}
	return false
}

func sameRuntimeFixSurface(runtime string, surfaces []model.Surface) string {
	for _, kind := range runtimeFixKinds(runtime) {
		for _, surface := range surfaces {
			if ownerRuntimeForSurface(surface) == runtime && surface.Kind == kind {
				return surface.Source
			}
		}
	}
	return ""
}

func runtimeFixKinds(runtime string) []string {
	switch runtime {
	case "claude":
		return []string{"claude-settings", "claude-local-settings"}
	case "codex":
		return []string{"codex-config", "codex-requirements"}
	case "gemini":
		return []string{"gemini-settings"}
	default:
		return nil
	}
}

func firstFixSource(target recklessFixTarget, fallback string) string {
	if target.Source != "" && !ariadneDeclarationTarget(target) {
		return target.Source
	}
	return fallback
}

func ariadneDeclarationTarget(target recklessFixTarget) bool {
	switch target.Kind {
	case "mcp-policy",
		"network-policy",
		"egress-policy",
		"agent-policy",
		"tool-policy",
		"delegation-policy",
		"input-policy",
		"identity-policy",
		"authorization-policy",
		"workload-policy",
		"resource-policy",
		"memory-policy",
		"integrity-policy",
		"observability-policy",
		"response-policy",
		"governance-policy",
		"output-policy",
		"supply-chain-policy":
		return true
	default:
		return false
	}
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

type capabilityCandidate struct {
	order           int
	id              string
	kind            string
	runtime         string
	source          string
	summary         string
	tradeoffSummary string
	tradeoffSource  string
}

type capabilityBuckets struct {
	Related    map[string][]RelatedCapability
	Unconsumed []capabilityCandidate
}

func bucketCapabilities(recklessExposures []model.ExposureResult, collection model.Collection) capabilityBuckets {
	candidates := capabilityCandidates(collection)
	out := capabilityBuckets{
		Related:    map[string][]RelatedCapability{},
		Unconsumed: make([]capabilityCandidate, 0, len(candidates)),
	}
	for _, exposure := range recklessExposures {
		out.Related[exposure.ID] = []RelatedCapability{}
	}
	for _, candidate := range candidates {
		owner := ""
		for _, exposure := range recklessExposures {
			if capabilityConsumedByExposure(candidate, exposure) {
				owner = exposure.ID
				break
			}
		}
		if owner == "" {
			out.Unconsumed = append(out.Unconsumed, candidate)
			continue
		}
		out.Related[owner] = append(out.Related[owner], relatedCapability(candidate))
	}
	return out
}

func capabilityCandidates(collection model.Collection) []capabilityCandidate {
	var candidates []capabilityCandidate
	for _, authority := range collection.Authorities {
		switch authority.ID {
		case "authority:external-communication":
			candidates = append(candidates, capabilityCandidate{
				order:           10,
				id:              authority.ID,
				kind:            "authority",
				runtime:         authority.Runtime,
				source:          authority.Source,
				summary:         authority.Summary,
				tradeoffSummary: "an agent can reach the network — normal for installs and web lookups",
				tradeoffSource:  authority.Source,
			})
		case "authority:file-read":
			candidates = append(candidates, capabilityCandidate{
				order:           11,
				id:              authority.ID,
				kind:            "authority",
				runtime:         authority.Runtime,
				source:          authority.Source,
				summary:         authority.Summary,
				tradeoffSummary: "agents read your workspace — that is what a coding agent is for",
				tradeoffSource:  authority.Source,
			})
		}
	}
	for _, boundary := range collection.Boundaries {
		if boundary.ID != "boundary:agent-private-context" {
			continue
		}
		candidates = append(candidates, capabilityCandidate{
			order:           12,
			id:              boundary.ID,
			kind:            "boundary",
			source:          boundary.Source,
			summary:         boundary.Summary,
			tradeoffSummary: "agent chat/history is stored locally",
			tradeoffSource:  boundary.Source,
		})
	}
	for _, tool := range collection.Tools {
		if tool.ID != "tool:mcp-package-launch" {
			continue
		}
		candidate := capabilityCandidate{
			order:   13,
			id:      tool.ID,
			kind:    "tool",
			runtime: tool.Runtime,
			source:  tool.Source,
			summary: tool.Summary,
		}
		if control, ok := firstEnforcedControl(collection.Controls, "control:mcp-reviewed-pinned"); ok {
			candidate.tradeoffSummary = "MCP tools configured and pinned"
			candidate.tradeoffSource = firstNonEmpty(control.Source, tool.Source)
		}
		candidates = append(candidates, candidate)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].order != candidates[j].order {
			return candidates[i].order < candidates[j].order
		}
		if candidates[i].id != candidates[j].id {
			return candidates[i].id < candidates[j].id
		}
		if candidates[i].runtime != candidates[j].runtime {
			return candidates[i].runtime < candidates[j].runtime
		}
		return candidates[i].source < candidates[j].source
	})
	if candidates == nil {
		return []capabilityCandidate{}
	}
	return candidates
}

func capabilityConsumedByExposure(candidate capabilityCandidate, exposure model.ExposureResult) bool {
	for _, ref := range exposure.EvidenceReferences {
		if evidenceRefMatchesCandidate(ref, candidate) {
			return true
		}
	}
	for _, edge := range exposure.PathEdges {
		if edgeConsumesCandidate(edge, candidate) {
			return true
		}
	}
	if candidate.kind != "authority" {
		for _, node := range exposure.PathNodes {
			if node == candidate.id {
				return true
			}
		}
	}
	return false
}

func evidenceRefMatchesCandidate(ref model.EvidenceReference, candidate capabilityCandidate) bool {
	if normalizedRefKind(ref.Kind) != candidate.kind {
		return false
	}
	if !refIDMatches(ref.ID, candidate.id) {
		return false
	}
	if ref.Source != "" && candidate.source != "" && ref.Source != candidate.source {
		return false
	}
	return true
}

func normalizedRefKind(kind string) string {
	switch kind {
	case "trust-input":
		return "trust_input"
	default:
		return kind
	}
}

func refIDMatches(refID, id string) bool {
	return refID == id || refID == "evidence:"+id
}

func edgeConsumesCandidate(edge string, candidate capabilityCandidate) bool {
	from, edgeType, to, ok := splitEdge(edge)
	if !ok {
		return false
	}
	switch candidate.kind {
	case "authority":
		if edgeType == "has_authority" && to == candidate.id && strings.HasPrefix(from, "runtime:") {
			return strings.TrimPrefix(from, "runtime:") == candidate.runtime
		}
		return false
	case "boundary":
		return from == candidate.id || to == candidate.id
	case "tool":
		return from == candidate.id || to == candidate.id
	default:
		return false
	}
}

func splitEdge(edge string) (string, string, string, bool) {
	parts := strings.Split(edge, "|")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func relatedCapability(candidate capabilityCandidate) RelatedCapability {
	return RelatedCapability{
		ID:      candidate.id,
		Kind:    candidate.kind,
		Runtime: candidate.runtime,
		Source:  candidate.source,
		Summary: candidate.summary,
	}
}

// buildTradeoffs returns one line per accepted capability not consumed by a
// reckless finding's exposed path. Home-scope-only default judgments also
// render here.
func buildTradeoffs(judgments []DefaultJudgment, collection model.Collection, buckets capabilityBuckets) []TradeoffLine {
	type candidate struct {
		order   int
		summary string
		sources []string
	}
	var candidates []candidate
	for _, judgment := range judgments {
		candidates = append(candidates, candidate{0, tradeoffSummaryForJudgment(judgment), []string{judgmentSource(judgment, collection)}})
	}
	for _, capability := range buckets.Unconsumed {
		if capability.tradeoffSummary == "" {
			continue
		}
		candidates = append(candidates, candidate{capability.order, capability.tradeoffSummary, []string{capability.tradeoffSource}})
	}

	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].order < candidates[j].order })

	type mergedCandidate struct {
		summary string
		sources []string
	}
	merged := map[string]*mergedCandidate{}
	var order []string
	for _, c := range candidates {
		key := tradeoffDedupeKey(c.summary)
		existing, ok := merged[key]
		if !ok {
			merged[key] = &mergedCandidate{summary: c.summary, sources: c.sources}
			order = append(order, key)
			continue
		}
		existing.sources = append(existing.sources, c.sources...)
	}

	out := make([]TradeoffLine, 0, len(order))
	for _, key := range order {
		c := merged[key]
		out = append(out, TradeoffLine{ID: "tradeoff:" + itoa(len(out)+1), Summary: c.summary, Source: mergeTradeoffSources(c.sources)})
	}
	return out
}

func tradeoffSummaryForJudgment(judgment DefaultJudgment) string {
	if judgment.Rule == nestedScopeDefaultRule {
		switch judgment.ExposureID {
		case FamilyEgress:
			return "nested instructions can steer agents that reach the network — held as a trade-off by default; they become live influence when agents work inside those directories"
		case FamilySecret:
			return "nested instructions can steer agents that read local files — held as a trade-off by default; they become live influence when agents work inside those directories"
		default:
			return "nested instructions can steer agents — held as a trade-off by default; they become live influence when agents work inside those directories"
		}
	}
	switch judgment.ExposureID {
	case FamilyEgress:
		return "your own home config can steer agents that reach the network — held as a trade-off by default; see default_judgments to override"
	case FamilySecret:
		return "your own home config can steer agents that read local files — held as a trade-off by default; see default_judgments to override"
	default:
		return "your own home config can steer agents — held as a trade-off by default; see default_judgments to override"
	}
}

func tradeoffDedupeKey(summary string) string {
	return strings.Join(strings.Fields(summary), " ")
}

func mergeTradeoffSources(sources []string) string {
	seen := map[string]bool{}
	out := make([]string, 0, len(sources))
	for _, source := range sources {
		source = strings.TrimSpace(source)
		if source == "" || seen[source] {
			continue
		}
		seen[source] = true
		out = append(out, source)
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}

func judgmentSource(judgment DefaultJudgment, collection model.Collection) string {
	for _, inputID := range judgment.TrustInputIDs {
		for _, input := range collection.TrustInputs {
			if input.ID == inputID && input.Source != "" && input.Risky && judgmentAppliesToInput(judgment.Rule, input) {
				return input.Source
			}
		}
	}
	return ""
}

func judgmentAppliesToInput(rule string, input model.TrustInput) bool {
	switch rule {
	case homeScopeDefaultRule:
		return input.Provenance == model.TrustInputProvenanceHomeScope
	case nestedScopeDefaultRule:
		return input.Provenance != model.TrustInputProvenanceHomeScope && input.InstructionScope == model.InstructionScopeNested
	default:
		return false
	}
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

func nonNilRelatedCapabilities(in []RelatedCapability) []RelatedCapability {
	if in == nil {
		return []RelatedCapability{}
	}
	return in
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
