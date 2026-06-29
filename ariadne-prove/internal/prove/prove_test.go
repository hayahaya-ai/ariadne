package prove

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/report"
)

func TestGoldenStories(t *testing.T) {
	cases := []struct {
		id        string
		status    model.Status
		proofMode model.ProofMode
	}{
		{"local-agent-secret-exposed", model.StatusExposed, model.ProofSimulated},
		{"local-agent-secret-protected", model.StatusProtected, model.ProofSimulated},
		{"mutable-tool-launch-exposed", model.StatusExposed, model.ProofSimulated},
		{"mutable-tool-launch-protected", model.StatusProtected, model.ProofSimulated},
		{"data-egress-chain-exposed", model.StatusExposed, model.ProofSimulated},
		{"data-egress-chain-protected", model.StatusProtected, model.ProofSimulated},
		{"data-egress-chain-inconclusive", model.StatusInconclusive, model.ProofInferred},
		{"repo-risk-runtime-unknown", model.StatusInconclusive, model.ProofInferred},
		{"endpoint-risk-inferred", model.StatusExposed, model.ProofInferred},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			report, err := RunStory(Options{StoryRoot: storyRoot(t), StoryID: tc.id})
			if err != nil {
				t.Fatal(err)
			}
			if !report.Matched {
				t.Fatalf("story oracle mismatch: %v", report.Mismatches)
			}
			if report.Exposure.Status != tc.status {
				t.Fatalf("status = %s, want %s", report.Exposure.Status, tc.status)
			}
			if report.Exposure.ProofMode != tc.proofMode {
				t.Fatalf("proof mode = %s, want %s", report.Exposure.ProofMode, tc.proofMode)
			}
		})
	}
}

func TestProtectedStoryControlBreaksPath(t *testing.T) {
	r, err := RunStory(Options{StoryRoot: storyRoot(t), StoryID: "local-agent-secret-protected"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Graph.HasNode("control:deny-secret-read") {
		t.Fatalf("expected deny control node")
	}
	if !r.Graph.HasEdge("control:deny-secret-read|restricts|boundary:secret-like-file") {
		t.Fatalf("expected deny control to restrict secret boundary")
	}
	if r.Exposure.Observation.Status != model.ObservationBlocked {
		t.Fatalf("observation = %s, want blocked", r.Exposure.Observation.Status)
	}
}

func TestMCPProtectedStoryControlBreaksPath(t *testing.T) {
	r, err := RunStory(Options{StoryRoot: storyRoot(t), StoryID: "mutable-tool-launch-protected"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Graph.HasNode("control:mcp-reviewed-pinned") {
		t.Fatalf("expected reviewed/pinned MCP control node")
	}
	if !r.Graph.HasEdge("control:mcp-reviewed-pinned|restricts|tool:mcp-package-launch") {
		t.Fatalf("expected reviewed/pinned control to restrict MCP package launch")
	}
	if r.Exposure.Observation.Status != model.ObservationBlocked {
		t.Fatalf("observation = %s, want blocked", r.Exposure.Observation.Status)
	}
}

func TestRedactionDoesNotLeakCanaries(t *testing.T) {
	ids := []string{"local-agent-secret-exposed", "local-agent-secret-protected", "repo-risk-runtime-unknown", "data-egress-chain-exposed", "data-egress-chain-protected", "data-egress-chain-inconclusive"}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			r, err := RunStory(Options{StoryRoot: storyRoot(t), StoryID: id})
			if err != nil {
				t.Fatal(err)
			}
			jsonBlob, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var table bytes.Buffer
			if err := report.Render(&table, r, "table"); err != nil {
				t.Fatal(err)
			}
			combined := string(jsonBlob) + table.String()
			if strings.Contains(combined, "STORYLAB_FAKE_SECRET_DO_NOT_LEAK") {
				t.Fatalf("report leaked fake canary value")
			}
			if r.Redaction.CanaryValuesIncluded {
				t.Fatalf("canary values should never be included")
			}
		})
	}
}

func TestJSONReportContainsGraphEvidence(t *testing.T) {
	r, err := RunStory(Options{StoryRoot: storyRoot(t), StoryID: "local-agent-secret-exposed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Graph.Nodes) == 0 || len(r.Graph.Edges) == 0 {
		t.Fatalf("expected graph nodes and edges")
	}
	if len(r.Evidence) == 0 {
		t.Fatalf("expected evidence")
	}
	if r.SchemaVersion != model.SchemaVersion {
		t.Fatalf("schema version = %s, want %s", r.SchemaVersion, model.SchemaVersion)
	}
}

func TestGraphExportFormatsExposeVisualEdges(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "combined-risk")})
	if err != nil {
		t.Fatal(err)
	}
	var dot bytes.Buffer
	if err := report.Render(&dot, r, "dot"); err != nil {
		t.Fatal(err)
	}
	dotOut := dot.String()
	if !strings.Contains(dotOut, "digraph ariadne_graph") {
		t.Fatalf("dot output missing graph header:\n%s", dotOut)
	}
	if !strings.Contains(dotOut, `"trustinput:repo-instruction" -> "runtime:codex" [label="influences"]`) {
		t.Fatalf("dot output missing influence edge:\n%s", dotOut)
	}

	var mermaid bytes.Buffer
	if err := report.Render(&mermaid, r, "mermaid"); err != nil {
		t.Fatal(err)
	}
	mermaidOut := mermaid.String()
	if !strings.Contains(mermaidOut, "flowchart LR") {
		t.Fatalf("mermaid output missing flowchart header:\n%s", mermaidOut)
	}
	if !strings.Contains(mermaidOut, `-->|"influences"|`) {
		t.Fatalf("mermaid output missing influence edge:\n%s", mermaidOut)
	}
}

func TestScanGraphExportIncludesTargets(t *testing.T) {
	targetFile, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", "targets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := RunScan(Options{TargetsFile: targetFile})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := report.RenderScan(&out, r, "mermaid"); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	for _, target := range []string{"target: combined", "target: safe", "target: repo-only"} {
		if !strings.Contains(rendered, target) {
			t.Fatalf("scan graph missing %s:\n%s", target, rendered)
		}
	}
}

func TestJSONGraphsUseArraysForEmptyEdges(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "repo-only-risk")})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	out := string(blob)
	if strings.Contains(out, `"edges":null`) || strings.Contains(out, `"nodes":null`) {
		t.Fatalf("graph arrays must not serialize as null: %s", out)
	}
	if strings.Contains(out, `"path_edges":null`) || strings.Contains(out, `"path_nodes":null`) || strings.Contains(out, `"graph_edges":null`) {
		t.Fatalf("path and issue arrays must not serialize as null: %s", out)
	}
	if !strings.Contains(out, `"edges":[]`) {
		t.Fatalf("expected empty edge array in repo-only graph: %s", out)
	}
}

func TestRunPathCombinedRiskProducesMultipleExposurePaths(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "combined-risk")})
	if err != nil {
		t.Fatal(err)
	}
	if r.RunKind != "path" {
		t.Fatalf("run kind = %s, want path", r.RunKind)
	}
	assertExposure(t, r, "prompt-injection-to-secret-canary", model.StatusExposed)
	assertExposure(t, r, "mutable-tool-launch-execution", model.StatusExposed)
	assertExposure(t, r, "data-egress-chain", model.StatusExposed)
	if !r.Graph.HasEdge("trustinput:repo-instruction|influences|runtime:codex") {
		t.Fatalf("missing secret exposure graph edge")
	}
	if !r.Graph.HasEdge("tool:mcp-package-launch|grants|authority:local-code-execution") {
		t.Fatalf("missing MCP exposure graph edge")
	}
	if !r.Graph.HasEdge("authority:external-communication|reaches|boundary:external-destination") {
		t.Fatalf("missing data-egress external communication graph edge")
	}
}

func TestRunPathCombinedRiskPrioritizesHighRiskPaths(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "combined-risk")})
	if err != nil {
		t.Fatal(err)
	}
	if r.Interpretation.Mode != "deterministic" {
		t.Fatalf("interpretation mode = %q, want deterministic", r.Interpretation.Mode)
	}
	if r.Interpretation.Summary.Critical < 2 || r.Interpretation.Summary.High < 1 {
		t.Fatalf("expected critical and high issue counts, got %+v", r.Interpretation.Summary)
	}
	assertIssue(t, r.Interpretation.Issues, "builtin:large private impossible", "", "", false)
	assertIssue(t, r.Interpretation.Issues, "builtin:builtin-mutable-tool-launch:mutable-tool-launch-execution", model.SeverityCritical, model.PriorityP0, true)
	assertIssue(t, r.Interpretation.Issues, "builtin:builtin-data-egress-chain:data-egress-chain", model.SeverityCritical, model.PriorityP0, true)
	assertIssue(t, r.Interpretation.Issues, "builtin:builtin-secret-boundary-access:prompt-injection-to-secret-canary", model.SeverityHigh, model.PriorityP1, true)
}

func TestRunPathAppliesCustomDeterministicRules(t *testing.T) {
	rulesPath := filepath.Join(t.TempDir(), "rules.json")
	policy := `{
  "version": "ariadne.rules/v1",
  "rules": [
    {
      "id": "org-critical-mutable-tool",
      "title": "Org critical mutable tool path",
      "category": "org-policy",
      "severity": "critical",
      "priority": "p0",
      "disposition": "fix_now",
      "when": {
        "mode": "repo",
        "exposure_id": "mutable-tool-launch-execution",
        "exposure_status": "exposed",
        "has_edges": ["tool:mcp-package-launch|grants|authority:local-code-execution"],
        "missing_controls": ["control:mcp-reviewed-pinned"]
      },
      "rationale": "Organization policy requires mutable tool launch paths to be treated as critical.",
      "actions": ["Pin MCP packages", "Require reviewed MCP server definitions"]
    }
  ]
}`
	if err := os.WriteFile(rulesPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := RunPath(Options{Path: realPathFixture(t, "combined-risk"), RulesPath: rulesPath})
	if err != nil {
		t.Fatal(err)
	}
	issue := assertIssue(t, r.Interpretation.Issues, "custom:org-critical-mutable-tool:mutable-tool-launch-execution", model.SeverityCritical, model.PriorityP0, true)
	if issue.RuleSource != "custom" {
		t.Fatalf("rule source = %s, want custom", issue.RuleSource)
	}
	if !strings.Contains(strings.Join(issue.Actions, " "), "Pin MCP packages") {
		t.Fatalf("custom issue missing configured action: %+v", issue)
	}
}

func TestDataEgressChainProtectedStoryControlBreaksPath(t *testing.T) {
	r, err := RunStory(Options{StoryRoot: storyRoot(t), StoryID: "data-egress-chain-protected"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Graph.HasNode("control:network-restricted") {
		t.Fatalf("expected network restriction control node")
	}
	if !r.Graph.HasEdge("control:network-restricted|restricts|boundary:external-destination") {
		t.Fatalf("expected network restriction to restrict external destination")
	}
	if r.Exposure.Observation.Status != model.ObservationBlocked {
		t.Fatalf("observation = %s, want blocked", r.Exposure.Observation.Status)
	}
}

func TestRunPathSafeControlsBreakPaths(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "safe-controls")})
	if err != nil {
		t.Fatal(err)
	}
	assertExposure(t, r, "prompt-injection-to-secret-canary", model.StatusProtected)
	assertExposure(t, r, "mutable-tool-launch-execution", model.StatusProtected)
	if !r.Graph.HasEdge("control:deny-secret-read|restricts|boundary:secret-like-file") {
		t.Fatalf("missing deny-read control edge")
	}
	if !r.Graph.HasEdge("control:mcp-reviewed-pinned|restricts|tool:mcp-package-launch") {
		t.Fatalf("missing MCP control edge")
	}
}

func TestRunPathRepoOnlyRiskIsInconclusive(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "repo-only-risk")})
	if err != nil {
		t.Fatal(err)
	}
	assertExposure(t, r, "prompt-injection-to-secret-canary", model.StatusInconclusive)
}

func TestRunScanAggregatesMultipleTargets(t *testing.T) {
	targetFile, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", "targets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := RunScan(Options{TargetsFile: targetFile})
	if err != nil {
		t.Fatal(err)
	}
	if r.RunKind != "scan" {
		t.Fatalf("run kind = %s, want scan", r.RunKind)
	}
	if r.Summary.Targets != 3 || r.Summary.Completed != 3 || r.Summary.Errors != 0 {
		t.Fatalf("unexpected scan summary: %+v", r.Summary)
	}
	if r.Summary.Exposed == 0 || r.Summary.Protected == 0 || r.Summary.Inconclusive == 0 {
		t.Fatalf("expected exposed, protected, and inconclusive paths in scan summary: %+v", r.Summary)
	}
	if r.Interpretation.Summary.Total == 0 || r.Summary.Critical != r.Interpretation.Summary.Critical {
		t.Fatalf("scan summary did not aggregate deterministic issue priority: summary=%+v interpretation=%+v", r.Summary, r.Interpretation.Summary)
	}
	if len(r.Targets) != 3 {
		t.Fatalf("targets = %d, want 3", len(r.Targets))
	}
}

func TestInventoryDiscoversMessyAISurfaces(t *testing.T) {
	r, err := RunInventory(Options{Path: realPathFixture(t, "messy-ai-surfaces")})
	if err != nil {
		t.Fatal(err)
	}
	requireSurfaceKind(t, r.Collection.Surfaces, "claude-local-settings")
	requireSurfaceKind(t, r.Collection.Surfaces, "claude-mcp-config")
	requireSurfaceKind(t, r.Collection.Surfaces, "claude-command")
	requireSurfaceKind(t, r.Collection.Surfaces, "claude-private-context")
	requireSurfaceKind(t, r.Collection.Surfaces, "codex-config")
	requireSurfaceKind(t, r.Collection.Surfaces, "codex-agents-md")
	requireSurfaceKind(t, r.Collection.Surfaces, "nested-agents-md")
	requireSurfaceKind(t, r.Collection.Surfaces, "cursor-rules")
	requireSurfaceKind(t, r.Collection.Surfaces, "secret-like-file")
	for _, surface := range r.Collection.Surfaces {
		if strings.Contains(surface.Source, "node_modules/badpkg/AGENTS.md") {
			t.Fatalf("ignored node_modules instruction was discovered: %+v", surface)
		}
	}
	if len(r.Collection.Facts) < len(r.Collection.Surfaces) {
		t.Fatalf("expected facts for discovered surfaces, got %d facts for %d surfaces", len(r.Collection.Facts), len(r.Collection.Surfaces))
	}
	if !hasGraphNodeType(r.Graph, "command-hook") {
		t.Fatalf("expected command-hook surface node in graph")
	}
}

func TestInventoryRedactionDoesNotLeakPrivateSurfaceContent(t *testing.T) {
	r, err := RunInventory(Options{Path: realPathFixture(t, "messy-ai-surfaces")})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var table bytes.Buffer
	if err := report.RenderInventory(&table, r, "table"); err != nil {
		t.Fatal(err)
	}
	combined := string(blob) + table.String()
	for _, forbidden := range []string{
		"MESSY_REALPATH_FAKE_SECRET_DO_NOT_LEAK",
		"MESSY_PRIVATE_CONTEXT_FAKE_SECRET_DO_NOT_LEAK",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("inventory leaked private fixture value %q", forbidden)
		}
	}
}

func TestRunPathMessyAISurfacesProducesExposurePaths(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "messy-ai-surfaces")})
	if err != nil {
		t.Fatal(err)
	}
	assertExposure(t, r, "prompt-injection-to-secret-canary", model.StatusExposed)
	assertExposure(t, r, "mutable-tool-launch-execution", model.StatusExposed)
	if !r.Graph.HasEdge("runtime:claude|has_authority|authority:local-code-execution") {
		t.Fatalf("missing command/settings local execution authority edge")
	}
	if !hasGraphNodeType(r.Graph, "history-cache") {
		t.Fatalf("expected summarized private context surface in graph")
	}
	for _, exposure := range r.Exposures {
		if exposure.Status == model.StatusExposed && exposure.ProofMode != model.ProofInferred {
			t.Fatalf("real path exposure %s proof mode = %s, want inferred", exposure.ID, exposure.ProofMode)
		}
		if exposure.Status == model.StatusExposed && exposure.Observation.Status == model.ObservationSucceededInLab {
			t.Fatalf("real path exposure %s should not use lab observation status", exposure.ID)
		}
	}
}

func TestRunPathRedactionDoesNotLeakCanaries(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "combined-risk")})
	if err != nil {
		t.Fatal(err)
	}
	jsonBlob, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var table bytes.Buffer
	if err := report.Render(&table, r, "table"); err != nil {
		t.Fatal(err)
	}
	combined := string(jsonBlob) + table.String()
	if strings.Contains(combined, "REALPATH_FAKE_SECRET_DO_NOT_LEAK") {
		t.Fatalf("real path report leaked fake canary value")
	}
}

func TestTableReportIsFactFirst(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "combined-risk")})
	if err != nil {
		t.Fatal(err)
	}
	var table bytes.Buffer
	if err := report.Render(&table, r, "table"); err != nil {
		t.Fatal(err)
	}
	out := table.String()
	facts := strings.Index(out, "Facts:")
	graph := strings.Index(out, "Graph path:")
	classification := strings.Index(out, "Classification:")
	why := strings.Index(out, "Why it matters:")
	if facts < 0 || graph < 0 || classification < 0 || why < 0 {
		t.Fatalf("report missing fact-first sections:\n%s", out)
	}
	if !(facts < graph && graph < classification && classification < why) {
		t.Fatalf("report order is not facts -> graph -> classification -> why:\n%s", out)
	}
	if !strings.Contains(out, "Runtime observed: codex") {
		t.Fatalf("report did not include runtime fact:\n%s", out)
	}
	if !strings.Contains(out, "Trust input observed: repo-instruction") {
		t.Fatalf("report did not include trust-input fact:\n%s", out)
	}
	if !strings.Contains(out, "Authority modeled: file-read") {
		t.Fatalf("report did not include authority fact:\n%s", out)
	}
}

func TestDashboardReportContainsIssuesAndFactsDive(t *testing.T) {
	r, err := RunPath(Options{Path: realPathFixture(t, "combined-risk")})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := report.Render(&out, r, "html"); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	for _, want := range []string{
		"Ariadne Exposure Dashboard",
		"Issue Dashboard",
		"Exposure Paths",
		"Facts Dive",
		"Mutable tool launch can reach local code execution",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("dashboard missing %q:\n%s", want, rendered)
		}
	}
}

func storyRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "storylab"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func realPathFixture(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", name))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func assertExposure(t *testing.T, r model.Report, id string, status model.Status) {
	t.Helper()
	for _, exposure := range r.Exposures {
		if exposure.ID == id {
			if exposure.Status != status {
				t.Fatalf("exposure %s status = %s, want %s", id, exposure.Status, status)
			}
			return
		}
	}
	t.Fatalf("missing exposure %s in %+v", id, r.Exposures)
}

func assertIssue(t *testing.T, issues []model.Issue, id string, severity model.Severity, priority model.Priority, shouldExist bool) model.Issue {
	t.Helper()
	for _, issue := range issues {
		if issue.ID != id {
			continue
		}
		if !shouldExist {
			t.Fatalf("issue %s should not exist", id)
		}
		if issue.Severity != severity || issue.Priority != priority {
			t.Fatalf("issue %s severity/priority = %s/%s, want %s/%s", id, issue.Severity, issue.Priority, severity, priority)
		}
		return issue
	}
	if shouldExist {
		t.Fatalf("missing issue %s in %+v", id, issues)
	}
	return model.Issue{}
}

func requireSurfaceKind(t *testing.T, surfaces []model.Surface, kind string) {
	t.Helper()
	for _, surface := range surfaces {
		if surface.Kind == kind {
			return
		}
	}
	t.Fatalf("missing surface kind %s in %+v", kind, surfaces)
}

func hasGraphNodeType(g model.Graph, nodeType string) bool {
	for _, node := range g.Nodes {
		if node.Type == nodeType {
			return true
		}
	}
	return false
}
