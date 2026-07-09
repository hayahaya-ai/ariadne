package verdict_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/prove"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/verdict"
)

func realPathFixture(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", name))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func buildVerdict(t *testing.T, name string) verdict.Verdict {
	t.Helper()
	fixture := realPathFixture(t, name)
	inv, err := prove.RunInventory(prove.Options{Path: fixture, Mode: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := prove.RunPath(prove.Options{Path: fixture, Mode: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	return verdict.Build(inv, r, fixture, "repo")
}

func buildStoryVerdict(t *testing.T, name string) verdict.Verdict {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath"))
	if err != nil {
		t.Fatal(err)
	}
	run, err := prove.RunStoryAllWithInventory(prove.Options{StoryRoot: root, StoryID: name})
	if err != nil {
		t.Fatal(err)
	}
	return verdict.Build(run.Inventory, run.Report, run.Inventory.TargetPath, run.Report.Story.Mode)
}

func TestBuildCombinedRiskIsReckless(t *testing.T) {
	v := buildVerdict(t, "combined-risk")

	if v.VerdictWord != verdict.WordReckless {
		t.Fatalf("verdict = %s, want %s", v.VerdictWord, verdict.WordReckless)
	}
	if len(v.Reckless) == 0 {
		t.Fatalf("expected at least one reckless finding")
	}
	if v.Reckless[0].ExposureID != verdict.FamilyEgress {
		t.Fatalf("first reckless finding = %s, want %s (egress-first ordering)", v.Reckless[0].ExposureID, verdict.FamilyEgress)
	}
	for _, finding := range v.Reckless {
		if finding.Where.Source == "" {
			t.Fatalf("finding %s has empty where.source: %+v", finding.ID, finding)
		}
		if finding.Why == "" {
			t.Fatalf("finding %s has empty why: %+v", finding.ID, finding)
		}
		if finding.Fix == "" {
			t.Fatalf("finding %s has empty fix: %+v", finding.ID, finding)
		}
		if strings.Contains(finding.Fix, ".ariadne") {
			t.Fatalf("finding %s fix must never mention .ariadne: %q", finding.ID, finding.Fix)
		}
	}
}

func TestBuildSafeControlsIsNotReckless(t *testing.T) {
	v := buildVerdict(t, "safe-controls")

	if v.VerdictWord == verdict.WordReckless {
		t.Fatalf("verdict = %s, want not reckless", v.VerdictWord)
	}
	if len(v.Hardened) == 0 {
		t.Fatalf("expected non-empty hardened list")
	}
	for _, h := range v.Hardened {
		if h.Control == "control:ai-bom" {
			t.Fatalf("attested-only control:ai-bom must not appear in hardened: %+v", h)
		}
	}
}

func TestBuildTradeoffsOnlyFixtureIsNotReckless(t *testing.T) {
	v := buildVerdict(t, "tradeoffs-only")

	if v.VerdictWord == verdict.WordReckless {
		t.Fatalf("verdict = %s, want not reckless", v.VerdictWord)
	}
	if len(v.Tradeoffs) == 0 {
		t.Fatalf("expected at least one trade-off line")
	}
}

func TestBuildBucketsConsumedAndUnconsumedCapabilities(t *testing.T) {
	inventory := model.InventoryReport{Collection: model.Collection{
		Runtimes: []model.RuntimeEvidence{{ID: "runtime:claude", Kind: "claude"}},
		Authorities: []model.Authority{
			{ID: "authority:external-communication", Kind: "external-communication", Runtime: "claude", Source: ".claude/settings.json", Summary: "Claude can reach the network."},
			{ID: "authority:file-read", Kind: "file-read", Runtime: "claude", Source: ".claude/settings.json", Summary: "Claude can read workspace files."},
			{ID: "authority:file-read", Kind: "file-read", Source: "mcp.json", Summary: "MCP filesystem server can read configured files."},
		},
	}}
	report := model.Report{Exposures: []model.ExposureResult{{
		ID:     verdict.FamilyEgress,
		Status: model.StatusExposed,
		PathEdges: []string{
			"runtime:claude|has_authority|authority:external-communication",
			"runtime:claude|has_authority|authority:file-read",
		},
		EvidenceReferences: []model.EvidenceReference{{
			ID:     "authority:external-communication",
			Kind:   "authority",
			Source: ".claude/settings.json",
		}},
		WhyItMatters: "egress matters",
	}}}

	v := verdict.Build(inventory, report, "/tmp/target", "repo")

	if len(v.Reckless) != 1 {
		t.Fatalf("reckless findings = %d, want 1: %+v", len(v.Reckless), v.Reckless)
	}
	if !hasRelatedCapability(v.Reckless[0], "authority:external-communication", ".claude/settings.json") {
		t.Fatalf("egress finding should own consumed external communication: %+v", v.Reckless[0].RelatedCapabilities)
	}
	if !hasRelatedCapability(v.Reckless[0], "authority:file-read", ".claude/settings.json") {
		t.Fatalf("egress finding should own consumed Claude file-read: %+v", v.Reckless[0].RelatedCapabilities)
	}
	if len(v.Tradeoffs) != 1 || v.Tradeoffs[0].Source != "mcp.json" {
		t.Fatalf("unconsumed MCP file-read should be the only trade-off: %+v", v.Tradeoffs)
	}
}

func TestBuildTradeoffsDedupesRenderedCapabilityWithMergedSources(t *testing.T) {
	inventory := model.InventoryReport{Collection: model.Collection{
		Runtimes: []model.RuntimeEvidence{
			{ID: "runtime:claude", Kind: "claude"},
			{ID: "runtime:codex", Kind: "codex"},
		},
		Authorities: []model.Authority{
			{ID: "authority:external-communication", Kind: "external-communication", Runtime: "claude", Source: ".claude/settings.json", Summary: "Claude can reach the network."},
			{ID: "authority:external-communication", Kind: "external-communication", Runtime: "codex", Source: ".codex/config.toml", Summary: "Codex can reach the network."},
		},
	}}

	v := verdict.Build(inventory, model.Report{}, "/tmp/target", "repo")

	if got := countTradeoffSummary(v.Tradeoffs, "an agent can reach the network — normal for installs and web lookups"); got != 1 {
		t.Fatalf("network trade-off lines = %d, want 1: %+v", got, v.Tradeoffs)
	}
	if len(v.Tradeoffs) != 1 {
		t.Fatalf("trade-off lines = %d, want 1: %+v", len(v.Tradeoffs), v.Tradeoffs)
	}
	for _, source := range []string{".claude/settings.json", ".codex/config.toml"} {
		if !strings.Contains(v.Tradeoffs[0].Source, source) {
			t.Fatalf("deduped trade-off source should keep %s: %+v", source, v.Tradeoffs[0])
		}
	}
}

func TestBuildTradeoffsDoesNotDedupeDistinctCapabilitiesSharingSource(t *testing.T) {
	inventory := model.InventoryReport{Collection: model.Collection{
		Runtimes: []model.RuntimeEvidence{{ID: "runtime:codex", Kind: "codex"}},
		Authorities: []model.Authority{
			{ID: "authority:external-communication", Kind: "external-communication", Runtime: "codex", Source: ".codex/config.toml", Summary: "Codex can reach the network."},
			{ID: "authority:file-read", Kind: "file-read", Runtime: "codex", Source: ".codex/config.toml", Summary: "Codex can read workspace files."},
		},
	}}

	v := verdict.Build(inventory, model.Report{}, "/tmp/target", "repo")

	if len(v.Tradeoffs) != 2 {
		t.Fatalf("distinct trade-off lines = %d, want 2: %+v", len(v.Tradeoffs), v.Tradeoffs)
	}
	if countTradeoffSummary(v.Tradeoffs, "an agent can reach the network — normal for installs and web lookups") != 1 {
		t.Fatalf("missing network trade-off: %+v", v.Tradeoffs)
	}
	if countTradeoffSummary(v.Tradeoffs, "agents read your workspace — that is what a coding agent is for") != 1 {
		t.Fatalf("missing workspace-read trade-off: %+v", v.Tradeoffs)
	}
}

func TestBuildCombinedRiskKeepsOnlyUnconsumedTradeoffs(t *testing.T) {
	v := buildVerdict(t, "combined-risk")

	if len(v.Tradeoffs) != 1 {
		t.Fatalf("combined-risk tradeoffs = %d, want 1: %+v", len(v.Tradeoffs), v.Tradeoffs)
	}
	if v.Tradeoffs[0].Source != "mcp.json" {
		t.Fatalf("combined-risk trade-off should come from unconsumed MCP file-read: %+v", v.Tradeoffs)
	}
	for _, tradeoff := range v.Tradeoffs {
		if strings.Contains(tradeoff.Summary, "reach the network") {
			t.Fatalf("consumed external communication must not also render as trade-off: %+v", v.Tradeoffs)
		}
	}
	if !hasFindingRelatedCapability(v, verdict.FamilyEgress, "authority:external-communication", ".claude/settings.json") {
		t.Fatalf("egress finding should carry consumed external communication: %+v", v.Reckless)
	}
	if !hasFindingRelatedCapability(v, verdict.FamilyMCP, "tool:mcp-package-launch", "mcp.json") {
		t.Fatalf("MCP finding should carry consumed MCP tool launch: %+v", v.Reckless)
	}
}

func TestBuildUserHomeInstructionsOnlyAppliesDefaultJudgment(t *testing.T) {
	v := buildStoryVerdict(t, "user-home-instructions-only")

	if v.VerdictWord != verdict.WordTradeoffsOnly {
		t.Fatalf("verdict = %s, want %s", v.VerdictWord, verdict.WordTradeoffsOnly)
	}
	if len(v.Reckless) != 0 {
		t.Fatalf("home-scope-only influence should not render reckless findings: %+v", v.Reckless)
	}
	if len(v.DefaultJudgments) != 2 {
		t.Fatalf("default judgments = %d, want 2: %+v", len(v.DefaultJudgments), v.DefaultJudgments)
	}
	if !hasInfluenceProvenance(v, "GEMINI.md", "home_scope") {
		t.Fatalf("verdict should carry home-scope provenance fact: %+v", v.InfluenceProvenance)
	}
	for _, judgment := range v.DefaultJudgments {
		if judgment.Rule != "home_scope_influence_not_untrusted_by_default" || judgment.Label != "default_judgment" {
			t.Fatalf("unexpected default judgment identity: %+v", judgment)
		}
		if len(judgment.TrustInputIDs) == 0 || !hasBasisKind(judgment.Basis, "trust_input") || !hasBasisKind(judgment.Basis, "fact") {
			t.Fatalf("default judgment should cite trust input IDs and fact basis: %+v", judgment)
		}
	}
	for _, want := range []string{
		"your own home config can steer agents that reach the network — held as a trade-off by default; see default_judgments to override",
		"your own home config can steer agents that read local files — held as a trade-off by default; see default_judgments to override",
	} {
		if countTradeoffSummary(v.Tradeoffs, want) != 1 {
			t.Fatalf("missing plain default-judgment trade-off %q: %+v", want, v.Tradeoffs)
		}
	}
	for _, tradeoff := range v.Tradeoffs {
		if strings.Contains(tradeoff.Summary, "default-judgment") || strings.Contains(tradeoff.Summary, "non-home influence") {
			t.Fatalf("default judgment trade-off wording should be plain second-person language: %+v", tradeoff)
		}
	}
}

func TestBuildRepoCheckoutInfluenceUnderHomeStaysReckless(t *testing.T) {
	v := buildStoryVerdict(t, "repo-checkout-instructions-under-home")

	if v.VerdictWord != verdict.WordReckless {
		t.Fatalf("verdict = %s, want %s", v.VerdictWord, verdict.WordReckless)
	}
	if len(v.DefaultJudgments) != 0 {
		t.Fatalf("repo-checkout influence must not get home-scope default judgment: %+v", v.DefaultJudgments)
	}
	if !hasInfluenceProvenance(v, "checkout/GEMINI.md", "repo_checkout") {
		t.Fatalf("verdict should carry repo-checkout provenance fact: %+v", v.InfluenceProvenance)
	}
}

func TestRenderReadoutCombinedRisk(t *testing.T) {
	v := buildVerdict(t, "combined-risk")

	var buf bytes.Buffer
	if err := verdict.RenderReadout(&buf, v); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) > 40 {
		t.Fatalf("readout has %d lines, want <=40:\n%s", len(lines), out)
	}
	if !strings.Contains(out, "VERDICT: RECKLESS") {
		t.Fatalf("readout missing VERDICT: RECKLESS:\n%s", out)
	}
	if !strings.Contains(out, "RECKLESS ──") {
		t.Fatalf("readout missing RECKLESS section header:\n%s", out)
	}
	if !strings.Contains(out, "fix") {
		t.Fatalf("readout missing fix line:\n%s", out)
	}
	for _, line := range lines {
		if strings.Contains(line, "fix") && strings.Contains(line, ".ariadne") {
			t.Fatalf("fix line must never mention .ariadne: %q", line)
		}
	}
	if !strings.Contains(out, "Next:") {
		t.Fatalf("readout missing Next: line:\n%s", out)
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	v := buildVerdict(t, "combined-risk")

	var buf bytes.Buffer
	if err := verdict.RenderJSON(&buf, v); err != nil {
		t.Fatal(err)
	}
	var decoded verdict.Verdict
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.VerdictWord != v.VerdictWord {
		t.Fatalf("round-tripped verdict = %s, want %s", decoded.VerdictWord, v.VerdictWord)
	}
}

func TestRenderJSONArraysAreEmptyNotNull(t *testing.T) {
	v := buildVerdict(t, "tradeoffs-only")

	var buf bytes.Buffer
	if err := verdict.RenderJSON(&buf, v); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"reckless": []`) {
		t.Fatalf("expected empty reckless array (not null) in JSON:\n%s", out)
	}
	if strings.Contains(out, "null") {
		t.Fatalf("verdict JSON must never contain null arrays:\n%s", out)
	}
}

func TestRenderReadoutOmitsLineSuffixForFileLevelWhere(t *testing.T) {
	v := verdict.Verdict{
		VerdictWord: verdict.WordReckless,
		Scanned:     verdict.ScannedSummary{},
		Reckless: []verdict.RecklessFinding{{
			ID:         "reckless:1",
			ExposureID: verdict.FamilySecret,
			Title:      "Secret boundary is file-level only",
			Where:      verdict.EvidenceLocation{Source: ".env", Anchor: "file"},
			Why:        "Boundary contents are metadata-only.",
			Fix:        "restrict secret-file reads in runtime config",
		}},
		NextAction: "fix reckless:1, then rerun ariadne self",
	}

	var buf bytes.Buffer
	if err := verdict.RenderReadout(&buf, v); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, ".env:0") {
		t.Fatalf("file-level where must not render :0:\n%s", out)
	}
	if !strings.Contains(out, "where  .env") {
		t.Fatalf("file-level where should render source without line:\n%s", out)
	}
}

func TestBuildEgressControlsKeepsParsedWhereAndFileLevelBoundaryRef(t *testing.T) {
	v := buildVerdict(t, "egress-controls")
	if len(v.Reckless) == 0 {
		t.Fatalf("expected reckless findings")
	}
	for _, finding := range v.Reckless {
		if finding.Where.Line <= 0 || finding.Where.Anchor == "file" {
			t.Fatalf("finding should use parsed positive-line where when available: %+v", finding.Where)
		}
		foundFileAnchor := false
		for _, ref := range finding.EvidenceRefs {
			if ref.Source == ".env" {
				if ref.Anchor != "file" || ref.LineStart != 0 {
					t.Fatalf(".env ref should be explicit file-level without line: %+v", ref)
				}
				foundFileAnchor = true
			}
		}
		if !foundFileAnchor {
			t.Fatalf("finding missing .env file-level evidence ref: %+v", finding.EvidenceRefs)
		}
	}
}

func TestBuildInconclusiveExposuresAreCounted(t *testing.T) {
	v := buildVerdict(t, "repo-only-risk")
	if v.Inconclusive == 0 {
		t.Fatalf("expected at least one inconclusive exposure for repo-only-risk fixture")
	}
}

func hasInfluenceProvenance(v verdict.Verdict, source string, provenance string) bool {
	for _, fact := range v.InfluenceProvenance {
		if fact.Source == source && fact.Provenance == provenance && fact.ID != "" && fact.TrustInputID != "" {
			return true
		}
	}
	return false
}

func hasBasisKind(basis []verdict.JudgmentBasisRef, kind string) bool {
	for _, ref := range basis {
		if ref.Kind == kind && ref.ID != "" {
			return true
		}
	}
	return false
}

func hasFindingRelatedCapability(v verdict.Verdict, exposureID string, id string, source string) bool {
	for _, finding := range v.Reckless {
		if finding.ExposureID != exposureID {
			continue
		}
		return hasRelatedCapability(finding, id, source)
	}
	return false
}

func hasRelatedCapability(finding verdict.RecklessFinding, id string, source string) bool {
	for _, capability := range finding.RelatedCapabilities {
		if capability.ID == id && capability.Source == source {
			return true
		}
	}
	return false
}

func countTradeoffSummary(tradeoffs []verdict.TradeoffLine, summary string) int {
	count := 0
	for _, tradeoff := range tradeoffs {
		if tradeoff.Summary == summary {
			count++
		}
	}
	return count
}
