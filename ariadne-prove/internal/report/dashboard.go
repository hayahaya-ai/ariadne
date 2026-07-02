package report

import (
	"fmt"
	"html"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

const dashboardFactLimit = 250

func renderReportDashboard(w io.Writer, r model.Report) error {
	title := "Ariadne Exposure Dashboard"
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	renderDashboardHeader(w, title, []kv{
		{"Target", firstNonEmpty(r.TargetPath, r.Story.ID, "not recorded")},
		{"Run kind", r.RunKind},
		{"Mode", r.Story.Mode},
		{"Agent", r.Story.Runtime},
	})
	renderZeroTrustDashboard(w, r.ZeroTrust)
	renderIssueDashboard(w, r.Interpretation, r.Graph, r.Evidence, r.Redaction)
	renderExposureSection(w, r.Exposures)
	renderFactsDive(w, r.Graph, r.Evidence, r.Warnings, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderScanDashboard(w io.Writer, r model.ScanReport) error {
	title := "Ariadne Fleet Exposure Dashboard"
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	renderDashboardHeader(w, title, []kv{
		{"Targets", fmt.Sprintf("%d completed / %d total", r.Summary.Completed, r.Summary.Targets)},
		{"Mode", r.Mode},
		{"Agent", r.Agent},
		{"Errors", fmt.Sprintf("%d", r.Summary.Errors)},
	})
	renderScanZeroTrustDashboard(w, r)
	renderIssueDashboard(w, r.Interpretation, model.Graph{}, nil, r.Redaction)
	renderScanTargetSection(w, r)
	renderScanFactsDive(w, r)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderInventoryDashboard(w io.Writer, r model.InventoryReport) error {
	title := "Ariadne Inventory"
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	renderDashboardHeaderWithSubtitle(w, title, "Fact-only AI surface discovery. No exposure classification is performed in this view.", []kv{
		{"Target", firstNonEmpty(r.TargetPath, "not recorded")},
		{"Mode", firstNonEmpty(r.Mode, "unknown")},
		{"Agent", firstNonEmpty(r.Agent, "unknown")},
		{"Run kind", firstNonEmpty(r.RunKind, "inventory")},
	})
	renderInventorySummaryDashboard(w, r)
	renderInventorySurfaceMapDashboard(w, r.SurfaceMap)
	renderInventorySurfacesDashboard(w, r.Collection.Surfaces)
	renderInventoryFactsDashboard(w, r.Collection.Facts)
	renderInventoryGraphDashboard(w, r.Graph)
	renderRunNotes(w, r.Warnings, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderInventorySummaryDashboard(w io.Writer, r model.InventoryReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Inventory Readout</h2><div class="subtle">Fact-only discovery: Ariadne has not classified exposure in this view.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"AI surfaces", fmt.Sprintf("%d", len(r.Collection.Surfaces))},
		{"Typed facts", fmt.Sprintf("%d", len(r.Collection.Facts))},
		{"Runtimes", fmt.Sprintf("%d", len(r.Collection.Runtimes))},
		{"Tools", fmt.Sprintf("%d", len(r.Collection.Tools))},
		{"Authorities", fmt.Sprintf("%d", len(r.Collection.Authorities))},
	})
	fmt.Fprintln(w, `</section>`)
}

func renderInventorySurfaceMapDashboard(w io.Writer, surfaceMap []model.SurfaceMap) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Runtime Surface Map</h2><div class="subtle">Source-backed runtime groups, handling modes, and modeled facts.</div></div></div>`)
	renderAssessSurfaceMapTable(w, surfaceMap)
	fmt.Fprintln(w, `</section>`)
}

func renderInventorySurfacesDashboard(w io.Writer, surfaces []model.Surface) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Discovered Surfaces</h2><div class="subtle">Observed files, directories, and bounded discovery decisions.</div></div></div>`)
	if len(surfaces) == 0 {
		fmt.Fprintln(w, `<div class="empty">No supported AI surfaces were discovered.</div>`)
		fmt.Fprintln(w, `</section>`)
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table class="compact-table">`)
	fmt.Fprintln(w, "<thead><tr><th>Source</th><th>Runtime</th><th>Category</th><th>Handling</th><th>Summary</th></tr></thead><tbody>")
	for _, surface := range surfaces {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="mono">%s</span></td>`, esc(surface.Source))
		fmt.Fprintf(w, `<td>%s</td>`, esc(surface.Runtime))
		fmt.Fprintf(w, `<td>%s</td>`, esc(surface.Category))
		fmt.Fprintf(w, `<td>%s</td>`, esc(surface.HandlingMode))
		fmt.Fprintf(w, `<td>%s</td>`, esc(surface.Summary))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, `</section>`)
}

func renderInventoryFactsDashboard(w io.Writer, facts []model.Fact) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Modeled Facts</h2><div class="subtle">Normalized facts emitted by parsers and safe summarizers.</div></div></div>`)
	if len(facts) == 0 {
		fmt.Fprintln(w, `<div class="empty">No deterministic facts were collected.</div>`)
		fmt.Fprintln(w, `</section>`)
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table class="compact-table">`)
	fmt.Fprintln(w, "<thead><tr><th>Source</th><th>Type</th><th>Runtime</th><th>Evidence</th><th>Redaction</th><th>Summary</th></tr></thead><tbody>")
	for _, fact := range facts {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="mono">%s</span></td>`, esc(firstNonEmpty(fact.Source, "not recorded")))
		fmt.Fprintf(w, `<td>%s</td>`, esc(fact.Type))
		fmt.Fprintf(w, `<td>%s</td>`, esc(firstNonEmpty(fact.Runtime, "not recorded")))
		fmt.Fprintf(w, `<td>%s</td>`, esc(fact.EvidenceGrade))
		fmt.Fprintf(w, `<td>%s</td>`, esc(fact.Redaction))
		fmt.Fprintf(w, `<td>%s</td>`, esc(fact.Summary))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, `</section>`)
}

func renderInventoryGraphDashboard(w io.Writer, graph model.Graph) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Graph Shape</h2><div class="subtle">Inventory graph nodes and edges available for downstream exposure evaluation.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Nodes", fmt.Sprintf("%d", len(graph.Nodes))},
		{"Edges", fmt.Sprintf("%d", len(graph.Edges))},
		{"Runtimes", fmt.Sprintf("%d", countNodes(graph, "runtime"))},
		{"Authorities", fmt.Sprintf("%d", countNodes(graph, "authority"))},
		{"Controls", fmt.Sprintf("%d", countNodes(graph, "control"))},
	})
	fmt.Fprintln(w, `</section>`)
}

func renderAssessDashboard(w io.Writer, r model.AssessReport) error {
	title := "Ariadne Assessment"
	if r.RunKind == "assess_scan" {
		title = "Ariadne Fleet Assessment"
	}
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	fields := []kv{
		{"Mode", firstNonEmpty(r.Mode, "unknown")},
		{"Agent", firstNonEmpty(r.Agent, "unknown")},
		{"Filter", firstNonEmpty(r.StatusFilter, "breaking")},
		{"Cases", fmt.Sprintf("%d", r.Summary.OperatorCases)},
	}
	if r.RunKind == "assess_scan" {
		fields[0] = kv{"Targets", fmt.Sprintf("%d completed / %d total", r.Summary.CompletedTargets, r.Summary.Targets)}
	} else {
		fields[0] = kv{"Target", firstNonEmpty(r.TargetPath, "not recorded")}
	}
	renderDashboardHeader(w, title, fields)
	renderAssessSummaryDashboard(w, r)
	renderAssessFirstActionDashboard(w, r.TargetPath, r.FirstAction)
	renderAssessClosureEvidenceDashboard(w, r.ClosureEvidence)
	renderAssessCaseNavigationDashboard(w, r.TopCases)
	renderAssessActiveCaseDashboard(w, r)
	renderControlOperatorCasesDashboard(w, r.TopCases)
	renderAssessArchitectureDashboard(w, r)
	renderAssessInventoryDashboard(w, r.Inventory)
	renderAssessCommandsDashboard(w, r.NextCommands)
	renderRunNotes(w, r.Warnings, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderArchitectureDashboard(w io.Writer, r model.ArchitectureReport) error {
	title := "Ariadne Zero Trust Architecture"
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	renderDashboardHeader(w, title, []kv{
		{"Target", firstNonEmpty(r.TargetPath, "not recorded")},
		{"Mode", firstNonEmpty(r.Mode, "unknown")},
		{"Agent", firstNonEmpty(r.Agent, "unknown")},
		{"Filter", firstNonEmpty(r.StatusFilter, "breaking")},
	})
	renderArchitectureSummaryDashboard(w, r)
	renderArchitectureCaseWorkflowDashboard(w, r.ClosureFamilies, controlVerificationCommandContext{RunKind: "case_board", Path: r.TargetPath, Mode: r.Mode, Agent: r.Agent, StatusFilter: r.StatusFilter})
	renderArchitectureFrameworkCoverageDashboard(w, r.FrameworkCoverage)
	renderArchitectureEvidencePlanDashboard(w, r.EvidencePlan)
	renderArchitectureClosureFamiliesDashboard(w, r.ClosureFamilies)
	renderArchitectureClosurePlanDashboard(w, r.ClosurePlan)
	renderArchitectureFlawTableDashboard(w, r.Flaws)
	renderZeroTrustBoundaryCoverageDashboard(w, r.BoundaryCoverage, 12)
	renderZeroTrustMaturity(w, r.Maturity)
	renderZeroTrustCoverage(w, r.EvidenceCoverage)
	renderRunNotes(w, nil, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderArchitectureScanDashboard(w io.Writer, r model.ArchitectureScanReport) error {
	title := "Ariadne Fleet Zero Trust Architecture"
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	renderDashboardHeader(w, title, []kv{
		{"Targets", fmt.Sprintf("%d completed / %d total", r.Summary.Completed, r.Summary.Targets)},
		{"Mode", firstNonEmpty(r.Mode, "unknown")},
		{"Agent", firstNonEmpty(r.Agent, "unknown")},
		{"Filter", firstNonEmpty(r.StatusFilter, "breaking")},
	})
	renderArchitectureScanSummaryDashboard(w, r)
	renderArchitectureCaseWorkflowDashboard(w, r.ClosureFamilies, controlVerificationCommandContext{RunKind: "case_board_scan", Mode: r.Mode, Agent: r.Agent, StatusFilter: r.StatusFilter})
	renderArchitectureFrameworkCoverageDashboard(w, r.FrameworkCoverage)
	renderArchitectureEvidencePlanDashboard(w, r.EvidencePlan)
	renderArchitectureClosureFamiliesDashboard(w, r.ClosureFamilies)
	renderArchitectureClosurePlanDashboard(w, r.ClosurePlan)
	renderZeroTrustBoundaryCoverageDashboard(w, r.BoundaryCoverage, 12)
	renderArchitectureFlawGroupsDashboard(w, r.Groups)
	renderArchitectureTargetsDashboard(w, r.Targets)
	renderRunNotes(w, nil, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderControlCatalogDashboard(w io.Writer, r model.ControlCatalogReport) error {
	title := "Ariadne Control Evidence Catalog"
	if r.RunKind == "control_catalog_scan" {
		title = "Ariadne Fleet Control Evidence Catalog"
	}
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	fields := []kv{
		{"Run kind", firstNonEmpty(r.RunKind, "control_catalog")},
		{"Mode", firstNonEmpty(r.Mode, "unknown")},
		{"Agent", firstNonEmpty(r.Agent, "unknown")},
		{"Filter", firstNonEmpty(r.StatusFilter, "breaking")},
	}
	if r.TargetPath != "" {
		fields[0] = kv{"Target", r.TargetPath}
	}
	if r.CaseFilter != "" {
		fields = append(fields, kv{"Case", r.CaseFilter})
	}
	renderDashboardHeader(w, title, fields)
	renderControlCatalogSummaryDashboard(w, r)
	renderControlOperatorCasesDashboard(w, r.OperatorCases)
	renderControlBreakPathWorkstreamsDashboard(w, r.Workstreams)
	renderControlVerificationTasksDashboard(w, r.VerificationTasks)
	renderControlCatalogFamiliesDashboard(w, r.Families)
	renderControlCatalogControlsDashboard(w, r.Controls, r.ProofSpecs)
	renderRunNotes(w, nil, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderControlCaseBoardDashboard(w io.Writer, r model.ControlCatalogReport) error {
	title := "Ariadne Operator Case Board"
	if r.RunKind == "case_board_scan" {
		title = "Ariadne Fleet Operator Case Board"
	}
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	fields := []kv{
		{"Run kind", firstNonEmpty(r.RunKind, "case_board")},
		{"Mode", firstNonEmpty(r.Mode, "unknown")},
		{"Agent", firstNonEmpty(r.Agent, "unknown")},
		{"Filter", firstNonEmpty(r.StatusFilter, "breaking")},
	}
	if r.TargetPath != "" {
		fields[0] = kv{"Target", r.TargetPath}
	}
	if r.CaseFilter != "" {
		fields = append(fields, kv{"Case", r.CaseFilter})
	}
	renderDashboardHeader(w, title, fields)
	renderCaseBoardSummaryDashboard(w, r)
	renderControlOperatorCasesDashboard(w, r.OperatorCases)
	renderCaseBoardEvidenceModelDashboard(w)
	renderRunNotes(w, nil, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderProofPlanDashboard(w io.Writer, r model.ProofPlanReport) error {
	title := "Ariadne Proof Plan"
	if r.RunKind == "proof_plan_scan" {
		title = "Ariadne Fleet Proof Plan"
	}
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	fields := []kv{
		{"Run kind", firstNonEmpty(r.RunKind, "proof_plan")},
		{"Mode", firstNonEmpty(r.Mode, "unknown")},
		{"Agent", firstNonEmpty(r.Agent, "unknown")},
		{"Filter", firstNonEmpty(r.StatusFilter, "breaking")},
	}
	if r.TargetPath != "" {
		fields[0] = kv{"Target", r.TargetPath}
	}
	if r.CaseFilter != "" {
		fields = append(fields, kv{"Case", r.CaseFilter})
	}
	renderDashboardHeader(w, title, fields)
	renderProofPlanSummaryDashboard(w, r)
	renderProofPlanCurrentActionDashboard(w, r)
	renderProofPlanWorkbenchDashboard(w, r)
	renderControlOperatorCasesDashboard(w, r.Cases)
	renderProofPlanPatchesDashboard(w, r.TargetPath, r.ProofPatches)
	renderProofPlanEvidenceDashboard(w, r.TargetPath, r.EvidenceReferences)
	renderProofPlanCommandsDashboard(w, r)
	renderProofPlanCompareDashboard(w, r)
	renderRunNotes(w, nil, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderCaseCompareDashboard(w io.Writer, r model.CaseCompareReport) error {
	title := "Ariadne Case Compare"
	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, `<html lang="en">`)
	renderDashboardHead(w, title)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, `<main class="shell">`)
	renderDashboardHeader(w, title, []kv{
		{"Run kind", firstNonEmpty(r.RunKind, "case_compare")},
		{"Before", firstNonEmpty(r.BeforeSource, "<before>")},
		{"After", firstNonEmpty(r.AfterSource, "<after>")},
		{"Cases", fmt.Sprintf("%d", r.Summary.Cases)},
	})
	renderCaseCompareSummaryDashboard(w, r)
	renderCaseCompareOutcomeDashboard(w, r.Outcome)
	renderCaseCompareCasesDashboard(w, r.Cases)
	renderRunNotes(w, nil, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

type kv struct {
	Key   string
	Value string
}

func renderDashboardHead(w io.Writer, title string) {
	fmt.Fprintf(w, "<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>%s</title>\n", esc(title))
	fmt.Fprintln(w, `<style>
:root {
  color-scheme: light;
  --bg: #f6f7f9;
  --panel: #ffffff;
  --panel-strong: #f0f3f7;
  --text: #17202a;
  --muted: #5d6b7a;
  --line: #d8dee7;
  --critical: #8f1d1d;
  --high: #b54708;
  --medium: #946200;
  --low: #286642;
  --info: #3c4d63;
  --accent: #155eef;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.45;
}
.shell {
  width: min(1440px, calc(100vw - 32px));
  margin: 0 auto;
  padding: 24px 0 40px;
}
.topbar {
  display: grid;
  grid-template-columns: minmax(280px, 1fr) repeat(4, minmax(120px, 190px));
  gap: 12px;
  align-items: stretch;
  margin-bottom: 16px;
}
.title {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 16px;
}
h1 {
  margin: 0 0 6px;
  font-size: 24px;
  line-height: 1.2;
  letter-spacing: 0;
}
h2 {
  margin: 0;
  font-size: 17px;
  line-height: 1.25;
  letter-spacing: 0;
}
h3 {
  margin: 0 0 8px;
  font-size: 14px;
  line-height: 1.25;
  letter-spacing: 0;
}
.subtle { color: var(--muted); }
.metric, .panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.metric {
  padding: 12px;
  min-width: 0;
}
.metric .label {
  color: var(--muted);
  font-size: 12px;
  margin-bottom: 4px;
}
.metric .value {
  font-weight: 700;
  overflow-wrap: anywhere;
}
.grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.panel {
  padding: 16px;
  margin-bottom: 16px;
  overflow: hidden;
}
.section-head {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: baseline;
  margin-bottom: 12px;
}
.table-wrap {
  width: 100%;
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: 8px;
}
table {
  width: 100%;
  min-width: 860px;
  border-collapse: collapse;
}
th, td {
  padding: 9px 10px;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--line);
}
th {
  background: var(--panel-strong);
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}
tr:last-child td { border-bottom: 0; }
.pill {
  display: inline-flex;
  align-items: center;
  min-height: 22px;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  white-space: nowrap;
}
.critical { color: #fff; background: var(--critical); }
.high { color: #fff; background: var(--high); }
.medium { color: #1f2937; background: #f6d471; }
.low { color: #fff; background: var(--low); }
.info { color: #fff; background: var(--info); }
.breaking { color: #fff; background: var(--critical); }
.controlled { color: #fff; background: var(--low); }
.unknown { color: #fff; background: var(--info); }
.not-observed { color: #1f2937; background: #d8dee7; }
.neutral { color: #374151; background: #eef2f7; }
.exposed { color: #fff; background: var(--critical); }
.protected { color: #fff; background: var(--low); }
.inconclusive { color: #1f2937; background: #d8dee7; }
.closed, .stayed-closed { color: #fff; background: var(--low); }
.reopened { color: #fff; background: var(--critical); }
.stayed-open { color: #1f2937; background: #f6d471; }
.changed { color: #fff; background: var(--info); }
.added { color: #fff; background: var(--accent); }
.removed { color: #374151; background: #eef2f7; }
.p0, .p1 { color: #fff; background: var(--accent); }
.p2, .p3, .p4 { color: #1f2937; background: #dbeafe; }
.list {
  margin: 0;
  padding-left: 18px;
}
.list li + li { margin-top: 4px; }
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 12px;
  overflow-wrap: anywhere;
}
.file-link {
  color: var(--accent);
  text-decoration: none;
  border-bottom: 1px solid transparent;
}
.file-link:hover {
  border-bottom-color: var(--accent);
}
.two-col {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 16px;
}
.code-block {
  margin: 8px 0 0;
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fbfcfd;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.patch-stack > div + div {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px solid var(--line);
}
.nav-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.case-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #fbfcfd;
  color: var(--text);
  text-decoration: none;
}
.case-chip:hover, .inline-link:hover {
  border-color: var(--accent);
}
.inline-link {
  display: inline-flex;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 6px 8px;
  color: var(--accent);
  text-decoration: none;
}
.compact-table {
  min-width: 520px;
}
tr:target {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}
.empty {
  color: var(--muted);
  border: 1px dashed var(--line);
  border-radius: 8px;
  padding: 14px;
  background: #fbfcfd;
}
@media (max-width: 980px) {
  .shell { width: min(100vw - 20px, 1440px); padding-top: 12px; }
  .topbar, .grid, .two-col { grid-template-columns: 1fr; }
}
</style>`)
	fmt.Fprintln(w, "</head>")
}

func renderDashboardHeader(w io.Writer, title string, fields []kv) {
	renderDashboardHeaderWithSubtitle(w, title, "Fact collection, graph-backed exposure paths, and selected priority interpretation.", fields)
}

func renderDashboardHeaderWithSubtitle(w io.Writer, title string, subtitle string, fields []kv) {
	fmt.Fprintln(w, `<section class="topbar">`)
	fmt.Fprintln(w, `<div class="title">`)
	fmt.Fprintf(w, "<h1>%s</h1>\n", esc(title))
	fmt.Fprintf(w, `<div class="subtle">%s</div>`, esc(subtitle))
	fmt.Fprintln(w, "</div>")
	for _, field := range fields {
		fmt.Fprintln(w, `<div class="metric">`)
		fmt.Fprintf(w, `<div class="label">%s</div>`, esc(field.Key))
		fmt.Fprintf(w, `<div class="value">%s</div>`, esc(field.Value))
		fmt.Fprintln(w, "</div>")
	}
	fmt.Fprintln(w, "</section>")
}

func renderAssessSummaryDashboard(w io.Writer, r model.AssessReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Assessment Readout</h2><div class="subtle">Single entry point: discovered surfaces, exposure posture, architecture breaks, and closure cases.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Architecture breaks", fmt.Sprintf("%d breaking / %d matching", r.Summary.BreakingArchitectureFlaws, r.Summary.ArchitectureFlaws)},
		{"Operator cases", fmt.Sprintf("%d", r.Summary.OperatorCases)},
		{"Missing hard barriers", fmt.Sprintf("%d", r.Summary.MissingHardBarrierControls)},
		{"Exposure paths", fmt.Sprintf("%d exposed / %d total", r.Summary.Exposed, r.Summary.ExposurePaths)},
		{"Top case", firstNonEmpty(r.Summary.TopCaseID, "none")},
	})
	if r.Summary.TopCaseNextStep != "" {
		fmt.Fprintf(w, `<div><strong>Start here:</strong> %s <span class="subtle">(%s)</span></div>`, esc(r.Summary.TopCaseNextStep), esc(r.Summary.TopCaseTitle))
	}
	fmt.Fprintln(w, `</section>`)
}

func renderAssessFirstActionDashboard(w io.Writer, root string, action model.AssessFirstAction) {
	if !action.Available {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>First Action</h2><div class="subtle">The highest-ranked operator action from deterministic case-board evidence.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Case", action.CaseID},
		{"Severity", strings.ToUpper(action.Severity)},
		{"State", firstNonEmpty(action.State, "open")},
		{"Evidence refs", fmt.Sprintf("%d", len(action.EvidenceReferences))},
		{"Proof surfaces", fmt.Sprintf("%d", len(action.ProofSurfaces))},
	})
	fmt.Fprintf(w, `<h3>%s</h3>`, esc(action.Title))
	if action.WhyFirst != "" {
		fmt.Fprintf(w, `<p>%s</p>`, esc(action.WhyFirst))
	}
	if action.NextStep != "" {
		fmt.Fprintf(w, `<p><strong>Next step:</strong> %s</p>`, esc(action.NextStep))
	}
	renderAssessCurrentActionPacketDashboard(w, root, action)
	renderAssessWorkflowDashboard(w, root, action.Workflow)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessCurrentActionPacketDashboard(w io.Writer, root string, action model.AssessFirstAction) {
	current := action.CurrentAction
	if !current.Available {
		return
	}
	evidenceRefs := current.EvidenceReferences
	if len(evidenceRefs) == 0 {
		evidenceRefs = action.EvidenceReferences
	}
	proofSurfaces := action.ProofSurfaces
	if current.Surface != "" && !contains(proofSurfaces, current.Surface) {
		proofSurfaces = append([]string{current.Surface}, proofSurfaces...)
	}
	rerunCommands := nonEmptyStrings(current.RerunCommand)
	if len(rerunCommands) == 0 {
		rerunCommands = action.RerunCommands
	}
	compareCommands := action.CompareCommands
	if len(compareCommands) == 0 && current.CompareCommand != "" {
		compareCommands = []string{current.CompareCommand}
	}
	successCriteria := current.SuccessCriteria
	if len(successCriteria) == 0 {
		successCriteria = action.SuccessCriteria
	}

	fmt.Fprintln(w, `<h3>Current Action Packet</h3>`)
	renderMetricRow(w, []kv{
		{"Step", firstNonEmpty(current.WorkflowStepTitle, "not recorded")},
		{"Control", firstNonEmpty(current.Control, "not recorded")},
		{"Proof surface", firstNonEmpty(current.Surface, "not recorded")},
		{"Proof patch", assessProofPatchMetric(current)},
		{"Evidence refs", fmt.Sprintf("%d", len(dedupeEvidenceReferences(evidenceRefs)))},
	})
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Current Action</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(assessCurrentActionHTMLLines(root, current)))
	fmt.Fprintln(w, `<h3>Evidence To Inspect</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, evidenceRefs, 6)))
	fmt.Fprintln(w, `<h3>Controls To Start With</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(action.StartingControls, 6)))
	fmt.Fprintln(w, `<h3>Proof Surfaces</h3>`)
	fmt.Fprintln(w, renderDashboardPathList(root, limitStrings(proofSurfaces, 6)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Proof To Add Or Verify</h3>`)
	fmt.Fprintln(w, `<div class="subtle">Proof Patch</div>`)
	fmt.Fprintln(w, renderDashboardHTMLList(assessCurrentProofHTMLLines(root, current)))
	fmt.Fprintln(w, `<h3>Accepted Evidence</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(assessCurrentEvidenceExampleHTMLLines(root, current, action.EvidenceExamples)))
	if current.PatchExportCommand != "" {
		fmt.Fprintln(w, `<h3>Export Suggested Files</h3>`)
		fmt.Fprintln(w, renderSmallList([]string{"Export suggested files: " + current.PatchExportCommand}))
	}
	fmt.Fprintln(w, `<h3>Rerun</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(rerunCommands, 3)))
	fmt.Fprintln(w, `<h3>Compare Loop</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(compareCommands, 3)))
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(successCriteria, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
}

func assessCurrentActionHTMLLines(root string, action model.AssessCurrentAction) []string {
	out := []string{}
	if action.WorkflowStepTitle != "" {
		out = append(out, "Step: "+esc(action.WorkflowStepTitle))
	}
	if action.Control != "" {
		out = append(out, "Control: "+esc(action.Control))
	}
	if action.Surface != "" {
		out = append(out, "Surface: "+dashboardFileRefHTML(root, action.Surface))
	}
	if action.Instruction != "" {
		out = append(out, "Instruction: "+esc(action.Instruction))
	}
	return out
}

func assessProofPatchMetric(action model.AssessCurrentAction) string {
	if action.ProofPatchIndex < 0 {
		return "none"
	}
	return fmt.Sprintf("#%d", action.ProofPatchIndex+1)
}

func assessCurrentProofHTMLLines(root string, action model.AssessCurrentAction) []string {
	if action.ProofPatch != nil {
		lines := []string{"Proof patch: " + dashboardControlProofPatchHTML(root, *action.ProofPatch)}
		lines = append(lines, proofPlanCurrentPatchHTMLLines(root, *action.ProofPatch, true, false)...)
		return lines
	}
	if action.ProofPatchIndex >= 0 {
		return []string{fmt.Sprintf("Proof patch: #%d", action.ProofPatchIndex+1)}
	}
	return []string{"No parser-recognized proof patch was returned for this action."}
}

func assessCurrentEvidenceExampleHTMLLines(root string, action model.AssessCurrentAction, examples []model.ControlEvidenceExample) []string {
	if action.EvidenceExample != nil {
		return []string{"Accepted evidence: " + dashboardControlEvidenceExampleHTML(root, *action.EvidenceExample)}
	}
	if action.EvidenceExampleIndex >= 0 {
		return []string{fmt.Sprintf("Accepted evidence: #%d", action.EvidenceExampleIndex+1)}
	}
	lines := make([]string, 0, len(examples))
	for _, example := range examples {
		lines = append(lines, "Accepted evidence: "+dashboardControlEvidenceExampleHTML(root, example))
	}
	if lines == nil {
		return []string{"No accepted evidence example was returned for this action."}
	}
	return limitStrings(lines, 2)
}

func nonEmptyStrings(values ...string) []string {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	if out == nil {
		return []string{}
	}
	return out
}

func renderAssessWorkflowDashboard(w io.Writer, root string, workflow []model.AssessWorkflowStep) {
	if len(workflow) == 0 {
		return
	}
	fmt.Fprintln(w, `<h3>Action Workflow</h3>`)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Step</th><th>Fact Source</th><th>Proof Or Command</th><th>Done When</th></tr></thead><tbody>")
	for i, step := range workflow {
		fmt.Fprintln(w, "<tr>")
		current := ""
		if step.Current {
			current = ` <span class="pill info">CURRENT</span>`
		}
		fmt.Fprintf(w, `<td><strong>%d. %s</strong>%s<div class="subtle">%s</div></td>`, i+1, esc(step.Title), current, esc(step.Summary))
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(assessWorkflowFactSourceHTMLLines(root, step)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(assessWorkflowProofCommandLines(step)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(step.SuccessCriteria, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func assessWorkflowFactSourceHTMLLines(root string, step model.AssessWorkflowStep) []string {
	var out []string
	out = append(out, proofPlanEvidenceReferenceHTMLLines(root, step.EvidenceReferences, 3)...)
	out = append(out, labeledLimitedLines("Control", step.StartingControls, 4)...)
	out = append(out, labeledLimitedHTMLLines(root, "Surface", step.ProofSurfaces, 4)...)
	if out == nil {
		return []string{}
	}
	return out
}

func labeledLimitedHTMLLines(root string, label string, values []string, limit int) []string {
	limited := limitStrings(values, limit)
	out := make([]string, 0, len(limited))
	for _, value := range limited {
		if strings.Contains(value, "additional item") {
			out = append(out, label+"s: "+esc(value))
			continue
		}
		out = append(out, label+": "+dashboardFileRefHTML(root, value))
	}
	return out
}

func labeledLimitedLines(label string, values []string, limit int) []string {
	limited := limitStrings(values, limit)
	out := make([]string, 0, len(limited))
	for _, value := range limited {
		if strings.Contains(value, "additional item") {
			out = append(out, label+"s: "+value)
			continue
		}
		out = append(out, label+": "+value)
	}
	return out
}

func assessWorkflowProofCommandLines(step model.AssessWorkflowStep) []string {
	var out []string
	for _, command := range limitStrings(step.Commands, 3) {
		out = append(out, command)
	}
	if out == nil {
		return []string{}
	}
	return out
}

func renderAssessClosureEvidenceDashboard(w io.Writer, closure model.AssessClosureEvidence) {
	if !assessClosureEvidenceHasData(closure) {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Closure Evidence</h2><div class="subtle">Controls Ariadne already observed, and whether they close the path or leave missing hard barriers.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Protected exposures", fmt.Sprintf("%d", closure.ProtectedExposurePaths)},
		{"Controlled flaws", fmt.Sprintf("%d", closure.ControlledArchitectureFlaws)},
		{"Partial flaws", fmt.Sprintf("%d", closure.PartialArchitectureFlaws)},
		{"Hard barriers", fmt.Sprintf("%d", len(closure.HardBarriersObserved))},
		{"Still missing", fmt.Sprintf("%d", len(closure.RemainingMissingHardBarriers))},
	})
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Closed By Hard Barrier</h3>`)
	renderAssessClosurePathTable(w, closure.ControlledPaths, true)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Partial Evidence</h3>`)
	renderAssessClosurePathTable(w, closure.PartialPaths, false)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessClosurePathTable(w io.Writer, items []model.AssessClosurePath, controlled bool) {
	if len(items) == 0 {
		fmt.Fprintln(w, `<div class="empty">No closure path evidence in this category.</div>`)
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table class="compact-table">`)
	if controlled {
		fmt.Fprintln(w, "<thead><tr><th>Path</th><th>Hard barriers observed</th><th>Evidence</th></tr></thead><tbody>")
	} else {
		fmt.Fprintln(w, "<thead><tr><th>Path</th><th>Observed controls</th><th>Still missing</th><th>Evidence</th></tr></thead><tbody>")
	}
	for _, item := range limitAssessClosurePaths(items, 5) {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(item.Title), esc(item.ID), esc(string(item.Status)))
		if controlled {
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.HardBarriersObserved, 5)))
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(evidenceReferenceLines(item.EvidenceReferences, 4)))
		} else {
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.PartialOrFrictionControls, 5)))
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.RemainingMissingHardBarriers, 5)))
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(evidenceReferenceLines(item.EvidenceReferences, 4)))
		}
		fmt.Fprintln(w, "</tr>")
	}
	if len(items) > 5 {
		colspan := 3
		if !controlled {
			colspan = 4
		}
		fmt.Fprintf(w, `<tr><td colspan="%d"><span class="subtle">%d more closure path(s) in JSON output.</span></td></tr>`, colspan, len(items)-5)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func renderAssessCaseNavigationDashboard(w io.Writer, cases []model.ControlOperatorCase) {
	if len(cases) == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Case Navigation</h2><div class="subtle">Jump from the assessment summary to the actionable case row.</div></div></div>`)
	fmt.Fprintln(w, `<div class="nav-row">`)
	for _, item := range cases {
		fmt.Fprintf(w, `<a class="case-chip" href="#%s"><span class="pill %s">%s</span><strong>#%d %s</strong><span class="subtle">%s</span></a>`,
			esc(dashboardAnchorID("case", item.ID)),
			cssClass(item.Severity),
			esc(strings.ToUpper(item.Severity)),
			item.Rank,
			esc(item.Title),
			esc(item.ID),
		)
	}
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessActiveCaseDashboard(w io.Writer, r model.AssessReport) {
	if len(r.TopCases) == 0 {
		fmt.Fprintln(w, `<section class="panel">`)
		fmt.Fprintln(w, `<div class="section-head"><div><h2>Active Case Workbench</h2><div class="subtle">No operator case matched this assessment filter.</div></div></div>`)
		fmt.Fprintln(w, `<div class="empty">No case is currently active. Change the status filter or inspect the architecture output for unknown and not-observed gaps.</div>`)
		fmt.Fprintln(w, `</section>`)
		return
	}
	item := r.TopCases[0]
	proofPlan := r.TopCaseProofPlan
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Active Case Workbench</h2><div class="subtle">Start with the highest-priority break path, then prove the hard barrier that closes it.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Case", fmt.Sprintf("#%d %s", item.Rank, item.ID)},
		{"Severity", strings.ToUpper(item.Severity)},
		{"State", firstNonEmpty(item.State, "open")},
		{"Missing controls", fmt.Sprintf("%d", item.ControlCount)},
		{"Affected flaws", fmt.Sprintf("%d", item.FlawCount)},
	})
	fmt.Fprintf(w, `<h3>%s</h3>`, esc(item.Title))
	fmt.Fprintf(w, `<div class="subtle">%s</div>`, esc(item.Question))
	if item.Finding != "" {
		fmt.Fprintf(w, `<p>%s</p>`, esc(item.Finding))
	}
	fmt.Fprintf(w, `<p><a class="inline-link" href="#%s">Jump To Case</a></p>`, esc(dashboardAnchorID("case", item.ID)))
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Current State</h3>`)
	fmt.Fprintf(w, `<div>%s</div>`, esc(item.StateReason))
	if item.PriorityReason != "" {
		fmt.Fprintf(w, `<div class="subtle">%s</div>`, esc(item.PriorityReason))
	}
	fmt.Fprintln(w, `<h3>Next Step</h3>`)
	fmt.Fprintf(w, `<div>%s</div>`, esc(item.NextStep))
	fmt.Fprintln(w, `<h3>Evidence To Inspect</h3>`)
	renderAssessEvidenceReferenceTable(w, item.EvidenceReferences, 6)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Controls To Start With</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(item.StartingControls, 6)))
	fmt.Fprintln(w, `<h3>Control Proof Recipe</h3>`)
	renderAssessControlProofRecipeTable(w, item)
	fmt.Fprintln(w, `<h3>Proof Surfaces</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(item.ProofSurfaces, 8)))
	if proofPlan != nil {
		fmt.Fprintln(w, `<h3>Top Case Proof Packet</h3>`)
		fmt.Fprintln(w, renderSmallList([]string{
			fmt.Sprintf("case: %s", firstNonEmpty(proofPlan.CaseFilter, item.ID)),
			fmt.Sprintf("evidence references: %d", proofPlan.Summary.EvidenceReferences),
			fmt.Sprintf("proof patches: %d", proofPlan.Summary.ProofPatches),
		}))
	}
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Rerun</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(assessCaseCommands(r.NextCommands, item), 4)))
	if proofPlan != nil && len(proofPlan.CompareCommands) > 0 {
		fmt.Fprintln(w, `<h3>Compare Loop</h3>`)
		fmt.Fprintln(w, renderSmallList(limitStrings(proofPlan.CompareCommands, 3)))
	}
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(item.SuccessCriteria, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessEvidenceReferenceTable(w io.Writer, refs []model.EvidenceReference, limit int) {
	refs = dedupeEvidenceReferences(refs)
	if len(refs) == 0 {
		fmt.Fprintln(w, `<div class="empty">No evidence references were returned for this case.</div>`)
		return
	}
	if limit <= 0 || limit > len(refs) {
		limit = len(refs)
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table class="compact-table">`)
	fmt.Fprintln(w, "<thead><tr><th>Source</th><th>Kind</th><th>Fact</th></tr></thead><tbody>")
	for i, ref := range refs[:limit] {
		source := firstNonEmpty(ref.Source, ref.ID, ref.Kind)
		fmt.Fprintf(w, `<tr id="%s">`, esc(dashboardAnchorID("evidence", fmt.Sprintf("%d-%s-%s", i+1, ref.ID, source))))
		fmt.Fprintf(w, `<td><span class="mono">%s</span></td>`, esc(source))
		fmt.Fprintf(w, `<td>%s</td>`, esc(ref.Kind))
		fmt.Fprintf(w, `<td>%s</td>`, esc(ref.Summary))
		fmt.Fprintln(w, "</tr>")
	}
	if len(refs) > limit {
		fmt.Fprintf(w, `<tr><td colspan="3"><span class="subtle">%d more evidence reference(s) in JSON output.</span></td></tr>`, len(refs)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func renderAssessControlProofRecipeTable(w io.Writer, item model.ControlOperatorCase) {
	if len(item.StartingControls) == 0 {
		fmt.Fprintln(w, `<div class="empty">No starting controls were returned for this case.</div>`)
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table class="compact-table">`)
	fmt.Fprintln(w, "<thead><tr><th>Control</th><th>Add or verify at</th><th>Accepted evidence</th><th>Proof patch</th></tr></thead><tbody>")
	for _, control := range limitStrings(item.StartingControls, 6) {
		examples := controlExamplesForControl(item.EvidenceExamples, control)
		patches := controlPatchesForControl(item.ProofPatches, control)
		surfaces := proofSurfacesForControl(item.ProofSurfaces, examples)
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="mono">%s</span></td>`, esc(control))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(surfaces, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(controlEvidenceExampleLines(examples, 2), 2)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(controlProofPatchLines(patches, 2), 2)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(item.StartingControls) > 6 {
		fmt.Fprintf(w, `<tr><td colspan="4"><span class="subtle">%d more starting control(s) in JSON output.</span></td></tr>`, len(item.StartingControls)-6)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func controlExamplesForControl(examples []model.ControlEvidenceExample, control string) []model.ControlEvidenceExample {
	var matched []model.ControlEvidenceExample
	for _, example := range examples {
		if strings.Contains(example.Summary, control) || strings.Contains(example.Example, control) {
			matched = append(matched, example)
		}
	}
	if matched != nil {
		return matched
	}
	return []model.ControlEvidenceExample{}
}

func controlPatchesForControl(patches []model.ControlProofPatch, control string) []model.ControlProofPatch {
	var matched []model.ControlProofPatch
	for _, patch := range patches {
		if patch.Control == control {
			matched = append(matched, patch)
		}
	}
	if matched != nil {
		return matched
	}
	return []model.ControlProofPatch{}
}

func proofSurfacesForControl(all []string, examples []model.ControlEvidenceExample) []string {
	var surfaces []string
	for _, example := range examples {
		if example.Surface != "" && !contains(surfaces, example.Surface) {
			surfaces = append(surfaces, example.Surface)
		}
	}
	if len(surfaces) > 0 {
		return surfaces
	}
	return limitStrings(all, 4)
}

func renderAssessInventoryDashboard(w io.Writer, inventory model.AssessInventory) {
	if inventory.Surfaces == 0 && inventory.Facts == 0 && inventory.GraphNodes == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>What Was Inspected</h2><div class="subtle">Inventory facts are collected before classification.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"AI surfaces", fmt.Sprintf("%d", inventory.Surfaces)},
		{"Typed facts", fmt.Sprintf("%d", inventory.Facts)},
		{"Graph nodes", fmt.Sprintf("%d", inventory.GraphNodes)},
		{"Graph edges", fmt.Sprintf("%d", inventory.GraphEdges)},
		{"Controls observed", fmt.Sprintf("%d", inventory.Controls)},
	})
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div><h3>Surface categories</h3>`)
	fmt.Fprintln(w, renderSmallList(assessCountLines(inventory.SurfaceCategories)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div><h3>Handling modes</h3>`)
	fmt.Fprintln(w, renderSmallList(assessCountLines(inventory.HandlingModes)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	if len(inventory.SurfaceMap) > 0 {
		fmt.Fprintln(w, `<h3>Runtime Surface Map</h3>`)
		renderAssessSurfaceMapTable(w, inventory.SurfaceMap)
	}
	fmt.Fprintln(w, `</section>`)
}

func renderAssessSurfaceMapTable(w io.Writer, items []model.SurfaceMap) {
	if len(items) == 0 {
		fmt.Fprintln(w, `<div class="empty">No runtime surface map was built.</div>`)
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table class="compact-table">`)
	fmt.Fprintln(w, "<thead><tr><th>Runtime</th><th>Handling</th><th>Source refs</th><th>Modeled facts</th><th>Limits</th></tr></thead><tbody>")
	for _, item := range items {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s scope</div><div class="mono">%d surface(s)</div></td>`, esc(item.Runtime), esc(item.Scope), item.SurfaceCount)
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(surfaceMapHandlingLines(item)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.SourceRefs, 6)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(surfaceMapFactLines(item)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Limitations, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func surfaceMapHandlingLines(item model.SurfaceMap) []string {
	return []string{
		fmt.Sprintf("parse: %d", item.Parsed),
		fmt.Sprintf("summarize: %d", item.Summarized),
		fmt.Sprintf("boundary: %d", item.BoundaryIndicators),
		fmt.Sprintf("skip: %d", item.Skipped),
	}
}

func surfaceMapFactLines(item model.SurfaceMap) []string {
	var out []string
	if len(item.Authorities) > 0 {
		out = append(out, "authorities: "+strings.Join(limitStrings(item.Authorities, 4), ", "))
	}
	if len(item.Tools) > 0 {
		out = append(out, "tools: "+strings.Join(limitStrings(item.Tools, 4), ", "))
	}
	if len(item.Controls) > 0 {
		out = append(out, "controls: "+strings.Join(limitStrings(item.Controls, 4), ", "))
	}
	if len(out) == 0 {
		out = append(out, "no authority/tool/control facts modeled")
	}
	return out
}

func renderAssessArchitectureDashboard(w io.Writer, r model.AssessReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Architecture Break Paths</h2><div class="subtle">Facts are grouped by the Zero Trust boundary they break or leave unproven.</div></div></div>`)
	switch {
	case r.Architecture != nil:
		if len(r.Architecture.Flaws) == 0 {
			fmt.Fprintln(w, `<div class="empty">No architecture flaws matched this status filter.</div>`)
			break
		}
		renderArchitectureFlawTable(w, r.Architecture.Flaws)
	case r.ArchitectureScan != nil:
		if len(r.ArchitectureScan.Groups) == 0 {
			fmt.Fprintln(w, `<div class="empty">No architecture flaw groups matched this status filter.</div>`)
			break
		}
		fmt.Fprintln(w, `<div class="table-wrap"><table>`)
		fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Architecture flaw</th><th>Status by target</th><th>Targets</th><th>Evidence anchors</th><th>Breaks when</th></tr></thead><tbody>")
		for _, group := range r.ArchitectureScan.Groups {
			fmt.Fprintln(w, "<tr>")
			fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(group.Severity), esc(strings.ToUpper(group.Severity)))
			fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div></td>`, esc(group.Title), esc(group.Principle), esc(group.ID))
			fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustSummaryPills(group.StatusCounts))
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(group.Targets, 8)))
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(group.EvidenceSources, 6)))
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(group.ControlEvidenceNeeded, 6)))
			fmt.Fprintln(w, "</tr>")
		}
		fmt.Fprintln(w, "</tbody></table></div>")
	default:
		fmt.Fprintln(w, `<div class="empty">No architecture report attached.</div>`)
	}
	fmt.Fprintln(w, `</section>`)
}

func renderAssessCommandsDashboard(w io.Writer, commands []string) {
	if len(commands) == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Next Commands</h2><div class="subtle">Rerun the same assessment, focus the top case, open the proof plan, or inspect the full proof catalog.</div></div></div>`)
	fmt.Fprintln(w, renderSmallList(commands))
	fmt.Fprintln(w, `</section>`)
}

func assessCountLines(items []model.AssessCount) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprintf("%s: %d", item.Name, item.Count))
	}
	if out == nil {
		return []string{"none"}
	}
	return out
}

func assessCaseCommands(commands []string, item model.ControlOperatorCase) []string {
	out := make([]string, 0, len(commands)+len(item.RerunCommands))
	for _, command := range commands {
		if strings.Contains(command, "ariadne cases ") || strings.Contains(command, "ariadne proofs ") || strings.Contains(command, "ariadne assess ") {
			out = append(out, command)
		}
	}
	for _, command := range item.RerunCommands {
		if !contains(out, command) {
			out = append(out, command)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}

func dashboardAnchorID(prefix, value string) string {
	var b strings.Builder
	seed := strings.ToLower(strings.TrimSpace(value))
	if seed == "" {
		seed = "item"
	}
	for _, r := range seed {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			if b.Len() > 0 {
				b.WriteByte('-')
			}
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		id = "item"
	}
	return prefix + "-" + id
}

func renderIssueDashboard(w io.Writer, interpretation model.Interpretation, graph model.Graph, evidence []model.Evidence, redaction model.RedactionInfo) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Issue Dashboard</h2><div class="subtle">Prioritized only after Ariadne facts connect into graph paths.</div></div>`)
	fmt.Fprintf(w, `<div class="subtle">%s</div>`, esc(interpretationMeta(interpretation)))
	fmt.Fprintln(w, "</div>")
	renderIssueMetrics(w, interpretation.Summary)
	if len(interpretation.Issues) == 0 {
		fmt.Fprintln(w, `<div class="empty">No prioritized issues were returned for this run.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	if !redaction.SensitivePathsIncluded {
		fmt.Fprintln(w, `<div class="empty">File references are redacted in this dashboard. Re-run with <span class="mono">--include-sensitive-paths</span> for an operator dashboard with exact local paths.</div>`)
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Priority</th><th>Severity</th><th>Issue</th><th>Status</th><th>Where to look</th><th>Evidence</th><th>Action</th></tr></thead><tbody>")
	for _, issue := range interpretation.Issues {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(issue.Priority)), esc(strings.ToUpper(string(issue.Priority))))
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(issue.Severity)), esc(strings.ToUpper(string(issue.Severity))))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div></td>`, esc(issue.Title), esc(issue.Rationale), esc(issue.ID))
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span><div class="subtle">%s</div></td>`, cssClass(string(issue.ExposureStatus)), esc(strings.ToUpper(string(issue.ExposureStatus))), esc(string(issue.Disposition)))
		fmt.Fprintf(w, `<td>%s</td>`, renderIssueReferences(issueReferences(issue, graph, evidence)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(issue.Signals))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(issue.Actions))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	renderInterpretationLimitations(w, interpretation)
	fmt.Fprintln(w, "</section>")
}

func renderZeroTrustDashboard(w io.Writer, z model.ZeroTrust) {
	if z.FrameworkVersion == "" {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Zero Trust Architecture</h2><div class="subtle">Architecture boundaries evaluated from deterministic facts and graph edges.</div></div>`)
	fmt.Fprintf(w, `<div class="subtle">%s</div>`, esc(z.FrameworkVersion))
	fmt.Fprintln(w, "</div>")
	renderMetricRow(w, []kv{
		{"Breaking", fmt.Sprintf("%d", z.Summary.Breaking)},
		{"Controlled", fmt.Sprintf("%d", z.Summary.Controlled)},
		{"Unknown", fmt.Sprintf("%d", z.Summary.Unknown)},
		{"Not observed", fmt.Sprintf("%d", z.Summary.NotObserved)},
		{"Checks", fmt.Sprintf("%d", z.Summary.Total)},
	})
	renderZeroTrustBoundaryCoverageDashboard(w, buildArchitectureBoundaryCoverage([]architectureCoverageInput{{
		TargetID:  "target",
		ZeroTrust: z,
	}}), 8)
	renderArchitectureFlawsDashboard(w, z)
	fmt.Fprintln(w, `<h3>Boundary Checks</h3>`)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Boundary</th><th>Finding</th><th>Evidence</th><th>Graph / Control</th><th>Next action</th></tr></thead><tbody>")
	for _, check := range z.Checks {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(check.Status)), esc(statusLabel(string(check.Status))))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(check.Boundary), esc(check.Principle), esc(check.ID), esc(check.Tier))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%s</div></td>`, esc(check.Finding), esc(check.DesignTest))
		fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustEvidence(check.Evidence))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(check.GraphEdges, 4)), renderControlLine(check.Controls))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(check.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	renderZeroTrustMaturity(w, z.Maturity)
	renderZeroTrustCoverage(w, z.Coverage)
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureFlawsDashboard(w io.Writer, z model.ZeroTrust) {
	if len(z.ArchitectureFlaws) == 0 {
		return
	}
	fmt.Fprintln(w, `<h3>Architecture Failure Map</h3>`)
	renderMetricRow(w, []kv{
		{"Breaking flaws", fmt.Sprintf("%d", z.ArchitectureSummary.Breaking)},
		{"Controlled flaws", fmt.Sprintf("%d", z.ArchitectureSummary.Controlled)},
		{"Unknown flaws", fmt.Sprintf("%d", z.ArchitectureSummary.Unknown)},
		{"Not observed", fmt.Sprintf("%d", z.ArchitectureSummary.NotObserved)},
		{"Flaw categories", fmt.Sprintf("%d", z.ArchitectureSummary.Total)},
	})
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Architecture flaw</th><th>Control test</th><th>Why it matters</th><th>Evidence</th><th>Graph / Observed control</th><th>Breaks when</th><th>Evidence surfaces / Next action</th></tr></thead><tbody>")
	for _, flaw := range z.ArchitectureFlaws {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span><div class="pill %s">%s</div></td>`, cssClass(string(flaw.Status)), esc(statusLabel(string(flaw.Status))), cssClass(flaw.Severity), esc(strings.ToUpper(flaw.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(flaw.Title), esc(flaw.Principle), esc(flaw.ID), esc(strings.Join(flaw.Boundaries, ", ")))
		fmt.Fprintf(w, `<td>%s</td>`, renderArchitectureControlTest(flaw.ControlTest))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%s</div></td>`, esc(flaw.Finding), esc(flaw.WhyItMatters))
		fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustEvidence(flaw.Evidence))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(flaw.GraphEdges, 4)), renderControlLine(flaw.Controls))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(flaw.ControlEvidenceNeeded, 6)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Next action</h3>%s</td>`, renderSmallList(limitStrings(flaw.EvidenceSurfaces, 4)), renderSmallList(limitStrings(flaw.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func renderArchitectureSummaryDashboard(w io.Writer, r model.ArchitectureReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Architecture Readout</h2><div class="subtle">Focused Zero Trust agent architecture results from deterministic facts, graph edges, and control evidence.</div></div>`)
	fmt.Fprintf(w, `<div class="subtle">%s</div>`, esc(r.FrameworkVersion))
	fmt.Fprintln(w, "</div>")
	renderMetricRow(w, []kv{
		{"Matching flaws", fmt.Sprintf("%d", r.Summary.Total)},
		{"Breaking", fmt.Sprintf("%d", r.Summary.Breaking)},
		{"Controlled", fmt.Sprintf("%d", r.Summary.Controlled)},
		{"Unknown", fmt.Sprintf("%d", r.Summary.Unknown)},
		{"Evidence gaps", fmt.Sprintf("%d", r.EvidenceCoverage.Gaps)},
	})
	renderMetricRow(w, []kv{
		{"Overall flaws", fmt.Sprintf("%d", r.OverallSummary.Total)},
		{"Overall breaking", fmt.Sprintf("%d", r.OverallSummary.Breaking)},
		{"Overall controlled", fmt.Sprintf("%d", r.OverallSummary.Controlled)},
		{"Overall unknown", fmt.Sprintf("%d", r.OverallSummary.Unknown)},
		{"Not observed", fmt.Sprintf("%d", r.OverallSummary.NotObserved)},
	})
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureCaseWorkflowDashboard(w io.Writer, families []model.ArchitectureClosureFamily, ctx controlVerificationCommandContext) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Operator Case Workflow</h2><div class="subtle">Move from architecture breakage to the case board and focused closure commands.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(families) == 0 {
		fmt.Fprintln(w, `<div class="empty">No operator cases were available for this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Entry point</th><th>Command</th><th>What it does</th></tr></thead><tbody>")
	fmt.Fprintf(w, "<tr><td><strong>Case board</strong></td><td><span class=\"mono\">%s</span></td><td>Shows all architecture break paths as operator cases.</td></tr>", esc(architectureCaseBoardCommand(ctx)))
	limit := len(families)
	if limit > 6 {
		limit = 6
	}
	for _, family := range families[:limit] {
		fmt.Fprintf(w, "<tr><td><strong>%s</strong><div class=\"subtle\">%s</div><div class=\"mono\">%s</div></td><td><span class=\"mono\">%s</span></td><td>%d control(s), %d flaw(s), %d target(s)</td></tr>",
			esc(family.Title),
			esc(strings.ToUpper(family.Severity)),
			esc(architectureCaseID(family)),
			esc(architectureCaseFocusCommand(ctx, family)),
			family.ControlCount,
			family.FlawCount,
			family.TargetCount,
		)
	}
	if len(families) > limit {
		fmt.Fprintf(w, `<tr><td colspan="3"><span class="subtle">%d more operator cases in cases output.</span></td></tr>`, len(families)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureFrameworkCoverageDashboard(w io.Writer, items []model.ArchitectureFrameworkArea) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Framework Coverage</h2><div class="subtle">How Ariadne maps the Zero Trust agent architecture guidance to deterministic checks, evidence anchors, and remaining gaps.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(items) == 0 {
		fmt.Fprintln(w, `<div class="empty">No framework coverage rows were returned for this run.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Framework area</th><th>Status by target</th><th>Checks</th><th>Evidence anchors</th><th>Flaws</th><th>Missing / next collector</th><th>Limitations</th></tr></thead><tbody>")
	for _, item := range items {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(item.Area), esc(item.Source), esc(item.ID), esc(item.Tier))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%d target(s)</div>%s</td>`, renderZeroTrustSummaryPills(item.StatusCounts), item.TargetCount, renderSmallList(limitStrings(item.Targets, 6)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.CheckIDs, 8)))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(item.EvidenceSources, 6)), renderControlLine(limitStrings(item.Controls, 5)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Flaws, 5)))
		fmt.Fprintf(w, `<td><h3>Control evidence needed</h3>%s<h3>Missing evidence</h3>%s<h3>Next collectors</h3>%s</td>`, renderSmallList(limitStrings(item.ControlEvidenceNeeded, 6)), renderSmallList(limitStrings(item.MissingEvidence, 5)), renderSmallList(limitStrings(item.NextCollectors, 3)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Limitations, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureFlawTableDashboard(w io.Writer, flaws []model.ZeroTrustArchitecture) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Architecture Failure Map</h2><div class="subtle">Each row states the boundary break, the evidence anchor, and the hard barrier needed to close it.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(flaws) == 0 {
		fmt.Fprintln(w, `<div class="empty">No architecture flaws matched this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	renderArchitectureFlawTable(w, flaws)
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureClosurePlanDashboard(w io.Writer, items []model.ArchitectureClosure) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Closure Plan</h2><div class="subtle">Missing hard barriers ranked by affected architecture flaws and targets.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(items) == 0 {
		fmt.Fprintln(w, `<div class="empty">No missing hard barriers were returned for this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Missing hard barrier</th><th>Impact</th><th>Flaws</th><th>Targets</th><th>Evidence anchors / references</th><th>Evidence surfaces / action</th></tr></thead><tbody>")
	for _, item := range items {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div></td>`, esc(item.Control), esc(strings.ReplaceAll(item.ControlTestResult, "_", " ")), esc(strings.Join(limitStrings(item.CheckIDs, 4), ", ")))
		fmt.Fprintf(w, `<td>%d flaw(s)<br>%d target(s)</td>`, item.FlawCount, item.TargetCount)
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Flaws, 5)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Targets, 8)))
		fmt.Fprintf(w, `<td><h3>Anchors</h3>%s<h3>References</h3>%s</td>`, renderSmallList(limitStrings(item.EvidenceSources, 6)), renderSmallList(evidenceReferenceLines(item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Actions</h3>%s</td>`, renderSmallList(limitStrings(item.EvidenceSurfaces, 5)), renderSmallList(limitStrings(item.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderControlCatalogSummaryDashboard(w io.Writer, r model.ControlCatalogReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Control Evidence Catalog</h2><div class="subtle">Missing hard barriers from the architecture closure plan, rewritten as operator proof requests.</div></div>`)
	fmt.Fprintln(w, "</div>")
	renderMetricRow(w, []kv{
		{"Missing controls", fmt.Sprintf("%d", r.Summary.Controls)},
		{"Critical", fmt.Sprintf("%d", r.Summary.Critical)},
		{"High", fmt.Sprintf("%d", r.Summary.High)},
		{"Medium", fmt.Sprintf("%d", r.Summary.Medium)},
		{"Affected flaws", fmt.Sprintf("%d", r.Summary.Flaws)},
	})
	renderMetricRow(w, []kv{
		{"Affected targets", fmt.Sprintf("%d", r.Summary.Targets)},
		{"Operator cases", fmt.Sprintf("%d", len(r.OperatorCases))},
		{"Workstreams", fmt.Sprintf("%d", len(r.Workstreams))},
		{"Proof specs", fmt.Sprintf("%d", len(r.ProofSpecs))},
		{"Verification tasks", fmt.Sprintf("%d", len(r.VerificationTasks))},
	})
	fmt.Fprintln(w, "</section>")
}

func renderCaseBoardSummaryDashboard(w io.Writer, r model.ControlCatalogReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Case Queue</h2><div class="subtle">Architecture break paths grouped into the smallest useful set of operator decisions.</div></div>`)
	fmt.Fprintln(w, "</div>")
	renderMetricRow(w, []kv{
		{"Open cases", fmt.Sprintf("%d", len(r.OperatorCases))},
		{"Missing controls", fmt.Sprintf("%d", r.Summary.Controls)},
		{"Critical controls", fmt.Sprintf("%d", r.Summary.Critical)},
		{"High controls", fmt.Sprintf("%d", r.Summary.High)},
		{"Affected flaws", fmt.Sprintf("%d", r.Summary.Flaws)},
	})
	renderMetricRow(w, []kv{
		{"Affected targets", fmt.Sprintf("%d", r.Summary.Targets)},
		{"Proof specs", fmt.Sprintf("%d", len(r.ProofSpecs))},
		{"Verification tasks", fmt.Sprintf("%d", len(r.VerificationTasks))},
		{"Workstreams", fmt.Sprintf("%d", len(r.Workstreams))},
		{"Filter", firstNonEmpty(r.StatusFilter, "breaking")},
	})
	fmt.Fprintln(w, "</section>")
}

func renderProofPlanSummaryDashboard(w io.Writer, r model.ProofPlanReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Proof Plan</h2><div class="subtle">Focused evidence patches and rerun criteria for closing selected operator cases.</div></div>`)
	fmt.Fprintln(w, "</div>")
	renderMetricRow(w, []kv{
		{"State", proofPlanState(r)},
		{"Cases", fmt.Sprintf("%d", r.Summary.Cases)},
		{"Proof patches", fmt.Sprintf("%d", r.Summary.ProofPatches)},
		{"Evidence refs", fmt.Sprintf("%d", r.Summary.EvidenceReferences)},
		{"Controls", fmt.Sprintf("%d", r.Summary.Controls)},
		{"Targets", fmt.Sprintf("%d", r.Summary.Targets)},
	})
	if r.CaseFilter != "" {
		fmt.Fprintf(w, `<div><strong>Focused case:</strong> <span class="mono">%s</span></div>`, esc(r.CaseFilter))
	}
	fmt.Fprintln(w, "</section>")
}

func renderCaseCompareSummaryDashboard(w io.Writer, r model.CaseCompareReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Compare Summary</h2><div class="subtle">Deterministic change readout from two Ariadne JSON artifacts.</div></div>`)
	fmt.Fprintln(w, "</div>")
	renderMetricRow(w, []kv{
		{"Closed", fmt.Sprintf("%d", r.Summary.Closed)},
		{"Reopened", fmt.Sprintf("%d", r.Summary.Reopened)},
		{"Stayed open", fmt.Sprintf("%d", r.Summary.StayedOpen)},
		{"Stayed closed", fmt.Sprintf("%d", r.Summary.StayedClosed)},
		{"Changed", fmt.Sprintf("%d", r.Summary.Changed)},
	})
	fmt.Fprintln(w, "</section>")
}

func renderCaseCompareOutcomeDashboard(w io.Writer, outcome model.CaseCompareOutcome) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Outcome</h2><div class="subtle">After-rerun state and next action derived from case facts.</div></div>`)
	fmt.Fprintln(w, "</div>")
	renderMetricRow(w, []kv{
		{"After open", fmt.Sprintf("%d", outcome.AfterOpen)},
		{"After closed", fmt.Sprintf("%d", outcome.AfterClosed)},
		{"After absent", fmt.Sprintf("%d", outcome.AfterAbsent)},
		{"Material changes", fmt.Sprintf("%d", outcome.MaterialChanges)},
		{"Cases", fmt.Sprintf("%d", outcome.TotalCases)},
	})
	fmt.Fprintf(w, `<h3>Summary</h3><div>%s</div>`, esc(firstNonEmpty(outcome.Summary, "No outcome summary recorded.")))
	fmt.Fprintf(w, `<h3>Next Action</h3><div>%s</div>`, esc(firstNonEmpty(outcome.NextAction, "No next action recorded.")))
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div><h3>Still Open After Rerun</h3>`)
	fmt.Fprintln(w, renderSmallList(caseCompareOutcomeCaseLines(outcome.ActionCases, 5)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div><h3>Closed After Rerun</h3>`)
	fmt.Fprintln(w, renderSmallList(caseCompareOutcomeCaseLines(outcome.ClosedCases, 5)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	if len(outcome.AbsentCases) > 0 {
		fmt.Fprintln(w, `<h3>Absent After Rerun</h3>`)
		fmt.Fprintln(w, renderSmallList(caseCompareOutcomeCaseLines(outcome.AbsentCases, 5)))
	}
	fmt.Fprintln(w, "</section>")
}

func renderCaseCompareCasesDashboard(w io.Writer, cases []model.CaseCompareResult) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Case Changes</h2><div class="subtle">State, control, proof patch, and evidence-reference deltas by case ID.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(cases) == 0 {
		fmt.Fprintln(w, `<div class="empty">No comparable cases were found.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Disposition</th><th>Case</th><th>State</th><th>Controls</th><th>Proof / evidence</th><th>After next step</th></tr></thead><tbody>")
	for _, item := range cases {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(item.Disposition), esc(strings.ToUpper(strings.ReplaceAll(item.Disposition, "_", " "))))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(firstNonEmpty(item.Title, item.ID)), esc(item.ID), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><h3>Before</h3><div>%s</div><div class="subtle">%s</div><h3>After</h3><div>%s</div><div class="subtle">%s</div></td>`, esc(item.BeforeState), esc(item.BeforeStateReason), esc(item.AfterState), esc(item.AfterStateReason))
		fmt.Fprintf(w, `<td><h3>Before</h3>%s<h3>After</h3>%s<h3>Added</h3>%s<h3>Removed</h3>%s</td>`, renderSmallList(item.BeforeControls), renderSmallList(item.AfterControls), renderSmallList(item.AddedControls), renderSmallList(item.RemovedControls))
		fmt.Fprintf(w, `<td><h3>Proof patches</h3><div>%d -> %d</div><h3>Evidence refs</h3><div>%d -> %d</div><h3>After evidence</h3>%s<h3>Added evidence</h3>%s<h3>Removed evidence</h3>%s</td>`,
			item.BeforeProofPatches,
			item.AfterProofPatches,
			item.BeforeEvidenceRefs,
			item.AfterEvidenceRefs,
			renderSmallList(evidenceReferenceLines(item.AfterEvidence, 3)),
			renderSmallList(evidenceReferenceLines(item.AddedEvidence, 3)),
			renderSmallList(evidenceReferenceLines(item.RemovedEvidence, 3)),
		)
		fmt.Fprintf(w, `<td>%s<h3>After rerun</h3>%s<h3>After compare loop</h3>%s</td>`,
			esc(firstNonEmpty(item.AfterNextStep, "none")),
			renderSmallList(limitStrings(item.AfterRerunCommands, 2)),
			renderSmallList(limitStrings(item.AfterCompareCommands, 3)),
		)
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func proofPlanState(r model.ProofPlanReport) string {
	if len(r.Cases) == 0 {
		return "no selected cases"
	}
	closed := 0
	open := 0
	for _, item := range r.Cases {
		if controlOperatorCaseIsClosed(item) {
			closed++
			continue
		}
		open++
	}
	if closed == len(r.Cases) {
		return "closed"
	}
	if open == len(r.Cases) {
		return "open"
	}
	return "mixed"
}

func renderProofPlanWorkbenchDashboard(w io.Writer, r model.ProofPlanReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Evidence Workbench</h2><div class="subtle">One loop per selected case: inspect the facts, add or verify parser-recognized evidence, rerun, then confirm the break path is closed.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(r.Cases) == 0 {
		fmt.Fprintln(w, `<div class="empty">No selected operator cases were returned for this proof plan.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Break path</th><th>Inspect facts</th><th>Add / verify evidence</th><th>Rerun gate</th></tr></thead><tbody>")
	limit := len(r.Cases)
	if limit > 6 {
		limit = 6
	}
	for _, item := range r.Cases[:limit] {
		controlLabel := "Missing hard barriers"
		if controlOperatorCaseIsClosed(item) {
			controlLabel = "Observed hard barriers"
		}
		fmt.Fprintf(w, `<tr id="%s">`, esc(dashboardAnchorID("workbench", item.ID)))
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span><h3>%s</h3><div class="mono">%s</div><div class="subtle">%s</div><h3>Next step</h3><div>%s</div></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)), esc(item.Title), esc(item.ID), esc(item.StateReason), esc(item.NextStep))
		fmt.Fprintf(w, `<td><h3>Evidence references</h3>%s<h3>Proof surfaces</h3>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(r.TargetPath, item.EvidenceReferences, 5)), renderDashboardPathList(r.TargetPath, limitStrings(item.ProofSurfaces, 6)))
		fmt.Fprintf(w, `<td><h3>%s</h3>%s<h3>Evidence payload</h3>%s</td>`, esc(controlLabel), renderSmallList(limitStrings(item.StartingControls, 5)), renderProofPatchPayloads(item.ProofPatches, 3))
		fmt.Fprintf(w, `<td><h3>Rerun</h3>%s<h3>Done when</h3>%s<h3>Limits</h3>%s</td>`, renderSmallList(limitStrings(item.RerunCommands, 3)), renderSmallList(limitStrings(item.SuccessCriteria, 4)), renderSmallList(limitStrings(item.Limitations, 2)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(r.Cases) > limit {
		fmt.Fprintf(w, `<tr><td colspan="4"><span class="subtle">%d more selected case(s) in JSON output.</span></td></tr>`, len(r.Cases)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderProofPlanCurrentActionDashboard(w io.Writer, r model.ProofPlanReport) {
	if len(r.Cases) == 0 && len(r.ProofPatches) == 0 && len(r.EvidenceReferences) == 0 {
		return
	}
	item, hasCase := firstProofPlanCase(r)
	patch, hasPatch := firstProofPlanPatch(r)
	refs := r.EvidenceReferences
	if hasCase && len(item.EvidenceReferences) > 0 {
		refs = item.EvidenceReferences
	}
	proofSurfaces := proofPatchSurfaceLines(r.ProofPatches)
	if hasCase && len(item.ProofSurfaces) > 0 {
		proofSurfaces = item.ProofSurfaces
	}
	rerunCommands := r.RerunCommands
	if hasCase && len(item.RerunCommands) > 0 {
		rerunCommands = item.RerunCommands
	}
	successCriteria := r.SuccessCriteria
	if hasCase && len(item.SuccessCriteria) > 0 {
		successCriteria = item.SuccessCriteria
	}

	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Current Action Packet</h2><div class="subtle">The focused proof loop, rendered from structured proof-plan facts.</div></div>`)
	fmt.Fprintln(w, "</div>")
	renderMetricRow(w, []kv{
		{"Case", firstNonEmpty(proofPlanActionCaseID(item, hasCase), r.CaseFilter, "none")},
		{"State", firstNonEmpty(proofPlanActionState(item, hasCase), proofPlanState(r))},
		{"Evidence refs", fmt.Sprintf("%d", len(dedupeEvidenceReferences(refs)))},
		{"Proof patches", fmt.Sprintf("%d", len(r.ProofPatches))},
		{"Proof surfaces", fmt.Sprintf("%d", len(proofSurfaces))},
	})
	if hasCase {
		fmt.Fprintf(w, `<h3>%s</h3>`, esc(controlOperatorCaseDisplayTitle(item)))
		if item.Question != "" {
			fmt.Fprintf(w, `<div class="subtle">%s</div>`, esc(item.Question))
		}
		if item.StateReason != "" {
			fmt.Fprintf(w, `<p><strong>Current state:</strong> %s</p>`, esc(item.StateReason))
		}
		if item.NextStep != "" {
			fmt.Fprintf(w, `<p><strong>Next step:</strong> %s</p>`, esc(item.NextStep))
		}
	}
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Evidence To Inspect</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(r.TargetPath, refs, 6)))
	if hasCase {
		fmt.Fprintln(w, `<h3>Controls To Start With</h3>`)
		fmt.Fprintln(w, renderSmallList(limitStrings(item.StartingControls, 6)))
	}
	fmt.Fprintln(w, `<h3>Proof Surfaces</h3>`)
	fmt.Fprintln(w, renderDashboardPathList(r.TargetPath, limitStrings(proofSurfaces, 6)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Proof To Add Or Verify</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(proofPlanCurrentPatchHTMLLines(r.TargetPath, patch, hasPatch, hasCase && controlOperatorCaseIsClosed(item))))
	if r.PatchExportCommand != "" {
		fmt.Fprintln(w, `<h3>Export Suggested Files</h3>`)
		fmt.Fprintln(w, renderSmallList([]string{r.PatchExportCommand}))
	}
	fmt.Fprintln(w, `<h3>Rerun</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(rerunCommands, 3)))
	fmt.Fprintln(w, `<h3>Compare Loop</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(r.CompareCommands, 3)))
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(successCriteria, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, "</section>")
}

func firstProofPlanCase(r model.ProofPlanReport) (model.ControlOperatorCase, bool) {
	if len(r.Cases) == 0 {
		return model.ControlOperatorCase{}, false
	}
	return r.Cases[0], true
}

func firstProofPlanPatch(r model.ProofPlanReport) (model.ControlProofPatch, bool) {
	if len(r.ProofPatches) == 0 {
		return model.ControlProofPatch{}, false
	}
	return r.ProofPatches[0], true
}

func proofPlanActionCaseID(item model.ControlOperatorCase, ok bool) string {
	if !ok {
		return ""
	}
	return item.ID
}

func proofPlanActionState(item model.ControlOperatorCase, ok bool) string {
	if !ok {
		return ""
	}
	return firstNonEmpty(item.State, "open")
}

func proofPlanEvidenceReferenceHTMLLines(root string, refs []model.EvidenceReference, limit int) []string {
	limited := dashboardEvidenceReferencesBySource(refs, limit)
	out := make([]string, 0, len(limited))
	for _, ref := range limited {
		out = append(out, dashboardEvidenceReferenceHTML(root, ref))
	}
	if out == nil {
		return []string{}
	}
	return out
}

func proofPlanCurrentPatchHTMLLines(root string, patch model.ControlProofPatch, ok bool, closed bool) []string {
	if !ok {
		if closed {
			return []string{"No proof patch is needed because Ariadne already observes the hard barrier for this case."}
		}
		return []string{"No parser-recognized proof patch was returned for this filter."}
	}
	out := []string{
		"Control: " + esc(firstNonEmpty(patch.Control, "not recorded")),
		"Surface: " + dashboardFileRefHTML(root, patch.Surface),
	}
	if patch.Operation != "" {
		out = append(out, "Operation: "+esc(patch.Operation))
	}
	if patch.Format != "" {
		out = append(out, "Format: "+esc(patch.Format))
	}
	for _, field := range limitStrings(controlProofPatchFieldLines(patch.Fields), 4) {
		out = append(out, "Field: "+esc(field))
	}
	if patch.Example != "" {
		out = append(out, "Example: "+esc(compactExample(patch.Example)))
	}
	return out
}

func renderCaseBoardEvidenceModelDashboard(w io.Writer) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Evidence Model</h2><div class="subtle">Why these cases are facts-first and how to move from case to closure.</div></div>`)
	fmt.Fprintln(w, "</div>")
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Layer</th><th>What Ariadne uses</th><th>Operator use</th></tr></thead><tbody>")
	rows := []struct {
		layer string
		fact  string
		use   string
	}{
		{"Evidence", "Observed files, parsed configs, graph edges, evidence references, and redaction metadata.", "Trace a case back to the source facts before deciding whether it matters."},
		{"Case", "Architecture flaws grouped by break path, affected targets, missing hard barriers, and proof surfaces.", "Pick the case that closes the most important path instead of chasing every control row."},
		{"Closure", "Parser-recognized indicators, proof patches, evidence examples, rerun commands, and done criteria.", "Add or verify evidence, rerun Ariadne, and confirm the case disappears or becomes controlled."},
	}
	for _, row := range rows {
		fmt.Fprintf(w, "<tr><td><strong>%s</strong></td><td>%s</td><td>%s</td></tr>", esc(row.layer), esc(row.fact), esc(row.use))
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderProofPlanPatchesDashboard(w io.Writer, root string, patches []model.ControlProofPatch) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Proof Patches</h2><div class="subtle">Parser-recognized evidence Ariadne can verify on the next run. These are not enforcement claims.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(patches) == 0 {
		fmt.Fprintln(w, `<div class="empty">No proof patches matched this filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Control</th><th>Surface</th><th>Fields</th><th>Example</th><th>Rerun / done when</th></tr></thead><tbody>")
	limit := len(patches)
	if limit > 16 {
		limit = 16
	}
	for _, patch := range patches[:limit] {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div></td>`, esc(patch.Control), esc(patch.Operation))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%s</div></td>`, dashboardFileRefHTML(root, patch.Surface), esc(patch.Format))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(controlProofPatchFieldLines(patch.Fields)))
		fmt.Fprintf(w, `<td><span class="mono">%s</span></td>`, esc(compactExample(patch.Example)))
		fmt.Fprintf(w, `<td><h3>Rerun</h3>%s<h3>Done when</h3>%s<h3>Limit</h3>%s</td>`, renderSmallList(limitStrings(patch.RerunCommands, 2)), renderSmallList(limitStrings(patch.SuccessCriteria, 3)), renderSmallList(limitStrings(patch.Limitations, 1)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(patches) > limit {
		fmt.Fprintf(w, `<tr><td colspan="5"><span class="subtle">%d more proof patch(es) in JSON output.</span></td></tr>`, len(patches)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderProofPlanEvidenceDashboard(w io.Writer, root string, refs []model.EvidenceReference) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Evidence References</h2><div class="subtle">Source facts that caused this proof request.</div></div>`)
	fmt.Fprintln(w, "</div>")
	refs = dedupeEvidenceReferences(refs)
	if len(refs) == 0 {
		fmt.Fprintln(w, `<div class="empty">No evidence references were returned for this proof plan.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, refs, 12)))
	fmt.Fprintln(w, "</section>")
}

func renderProofPlanCommandsDashboard(w io.Writer, r model.ProofPlanReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Rerun Commands</h2><div class="subtle">Run these after adding or verifying real control evidence.</div></div>`)
	fmt.Fprintln(w, "</div>")
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div><h3>Rerun</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(r.RerunCommands, 6)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div><h3>Export Suggested Files</h3>`)
	fmt.Fprintln(w, renderSmallList(nonEmptyStrings(r.PatchExportCommand)))
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(r.SuccessCriteria, 6)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, "</section>")
}

func renderProofPlanCompareDashboard(w io.Writer, r model.ProofPlanReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Compare Loop</h2><div class="subtle">Save a before proof plan, rerun after adding evidence, then compare both artifacts.</div></div>`)
	fmt.Fprintln(w, "</div>")
	fmt.Fprintln(w, renderSmallList(limitStrings(r.CompareCommands, 6)))
	fmt.Fprintln(w, "</section>")
}

func renderProofPatchPayloads(patches []model.ControlProofPatch, limit int) string {
	if len(patches) == 0 {
		return `<span class="subtle">none</span>`
	}
	if limit <= 0 || limit > len(patches) {
		limit = len(patches)
	}
	var b strings.Builder
	b.WriteString(`<div class="patch-stack">`)
	for _, patch := range patches[:limit] {
		b.WriteString(`<div>`)
		b.WriteString(`<strong>`)
		b.WriteString(esc(firstNonEmpty(patch.Control, "control")))
		b.WriteString(`</strong>`)
		if patch.Surface != "" {
			b.WriteString(` <span class="subtle">at</span> <span class="mono">`)
			b.WriteString(esc(patch.Surface))
			b.WriteString(`</span>`)
		}
		if patch.Operation != "" {
			b.WriteString(`<div class="subtle">`)
			b.WriteString(esc(patch.Operation))
			if patch.Format != "" {
				b.WriteString(` / `)
				b.WriteString(esc(patch.Format))
			}
			b.WriteString(`</div>`)
		}
		b.WriteString(renderSmallList(controlProofPatchFieldLines(patch.Fields)))
		if patch.Example != "" {
			b.WriteString(`<pre class="code-block mono">`)
			b.WriteString(esc(strings.TrimSpace(patch.Example)))
			b.WriteString(`</pre>`)
		}
		b.WriteString(`</div>`)
	}
	if len(patches) > limit {
		fmt.Fprintf(&b, `<div class="subtle">%d more proof patch(es) in JSON output.</div>`, len(patches)-limit)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func renderControlOperatorCasesDashboard(w io.Writer, cases []model.ControlOperatorCase) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Operator Cases</h2><div class="subtle">A smaller action layer that connects architecture breakage, evidence references, proof surfaces, proof patches, rerun criteria, and compare-loop commands.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(cases) == 0 {
		fmt.Fprintln(w, `<div class="empty">No operator cases were returned for this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Case</th><th>State / next step</th><th>Why it exists</th><th>Evidence references</th><th>Start with</th><th>Prove at / example</th><th>Rerun / done when</th></tr></thead><tbody>")
	limit := len(cases)
	if limit > 10 {
		limit = 10
	}
	for _, item := range cases[:limit] {
		fmt.Fprintf(w, `<tr id="%s">`, esc(dashboardAnchorID("case", item.ID)))
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div><div class="subtle">%d control(s), %d flaw(s), %d target(s)</div></td>`, esc(controlOperatorCaseDisplayTitle(item)), esc(item.ID), item.ControlCount, item.FlawCount, item.TargetCount)
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><h3>Priority</h3><div>%s</div><h3>Next step</h3><div>%s</div></td>`, esc(firstNonEmpty(item.State, "open")), esc(item.StateReason), esc(item.PriorityReason), esc(item.NextStep))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%s</div></td>`, esc(item.Question), esc(item.Finding))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(evidenceReferenceLines(item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderOperatorCaseStartCell(item))
		fmt.Fprintf(w, `<td><h3>Proof surfaces</h3>%s<h3>Proof patches</h3>%s<h3>Evidence examples</h3>%s</td>`, renderSmallList(limitStrings(item.ProofSurfaces, 6)), renderSmallList(controlProofPatchLines(item.ProofPatches, 2)), renderSmallList(controlEvidenceExampleLines(item.EvidenceExamples, 2)))
		fmt.Fprintf(w, `<td><h3>Rerun</h3>%s<h3>Compare loop</h3>%s<h3>Done when</h3>%s</td>`, renderSmallList(limitStrings(item.RerunCommands, 2)), renderSmallList(limitStrings(item.CompareCommands, 3)), renderSmallList(limitStrings(item.SuccessCriteria, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(cases) > limit {
		fmt.Fprintf(w, `<tr><td colspan="8"><span class="subtle">%d more operator cases in JSON output.</span></td></tr>`, len(cases)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderOperatorCaseStartCell(item model.ControlOperatorCase) string {
	out := renderSmallList(limitStrings(item.StartingControls, 5))
	taskIDs := strings.Join(limitStrings(item.StartingTaskIDs, 5), ", ")
	if taskIDs != "" {
		out += fmt.Sprintf(`<div class="mono">%s</div>`, esc(taskIDs))
	}
	return out
}

func renderControlBreakPathWorkstreamsDashboard(w io.Writer, workstreams []model.ControlBreakPathWorkstream) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Break-Path Workstreams</h2><div class="subtle">Capability areas that group many missing controls into a smaller set of architecture break-path decisions.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(workstreams) == 0 {
		fmt.Fprintln(w, `<div class="empty">No break-path workstreams were returned for this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Workstream</th><th>Impact</th><th>Starting controls</th><th>Evidence references</th><th>Where to prove this</th><th>Done when</th></tr></thead><tbody>")
	limit := len(workstreams)
	if limit > 12 {
		limit = 12
	}
	for _, item := range workstreams[:limit] {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(item.Title), esc(item.ID), esc(item.Rationale))
		fmt.Fprintf(w, `<td>%d control(s)<br>%d flaw(s)<br>%d target(s)</td>`, item.ControlCount, item.FlawCount, item.TargetCount)
		fmt.Fprintf(w, `<td>%s<div class="mono">%s</div></td>`, renderSmallList(limitStrings(item.StartingControls, 5)), esc(strings.Join(limitStrings(item.StartingTaskIDs, 5), ", ")))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(evidenceReferenceLines(item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.ProofSurfaces, 6)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.SuccessCriteria, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(workstreams) > limit {
		fmt.Fprintf(w, `<tr><td colspan="7"><span class="subtle">%d more workstreams in JSON output.</span></td></tr>`, len(workstreams)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderControlVerificationTasksDashboard(w io.Writer, tasks []model.ControlVerificationTask) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Verification Tasks</h2><div class="subtle">Operator tasks that explain what evidence to add or verify, where Ariadne will look, and how to rerun the check.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(tasks) == 0 {
		fmt.Fprintln(w, `<div class="empty">No verification tasks were returned for this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Task</th><th>Why</th><th>Evidence references</th><th>Add or verify at</th><th>Accepted indicators</th><th>Proof patch</th><th>Rerun / done when</th></tr></thead><tbody>")
	limit := len(tasks)
	if limit > 16 {
		limit = 16
	}
	for _, task := range tasks[:limit] {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(task.Severity), esc(strings.ToUpper(task.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div></td>`, esc(task.Control), esc(task.ID))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%s</div></td>`, esc(task.Question), esc(task.Why))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(evidenceReferenceLines(task.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(task.ProofSurfaces, 6)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(task.RecognizedIndicators, 8)))
		fmt.Fprintf(w, `<td><h3>Patch</h3>%s<h3>Examples</h3>%s</td>`, renderSmallList(controlProofPatchLines(task.ProofPatches, 2)), renderSmallList(controlEvidenceExampleLines(task.EvidenceExamples, 2)))
		fmt.Fprintf(w, `<td><h3>Rerun</h3>%s<h3>Done when</h3>%s</td>`, renderSmallList(limitStrings(task.RerunCommands, 2)), renderSmallList(limitStrings(task.SuccessCriteria, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(tasks) > limit {
		fmt.Fprintf(w, `<tr><td colspan="8"><span class="subtle">%d more verification tasks in JSON output.</span></td></tr>`, len(tasks)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderControlCatalogFamiliesDashboard(w io.Writer, items []model.ArchitectureClosureFamily) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Control Families</h2><div class="subtle">Capability areas ranked by the missing hard barriers needed to close architecture flaws.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(items) == 0 {
		fmt.Fprintln(w, `<div class="empty">No control families were returned for this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Capability family</th><th>Impact</th><th>Missing controls</th><th>Closes flaws</th><th>Where to prove this</th></tr></thead><tbody>")
	for _, item := range items {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div></td>`, esc(item.Title), esc(item.ID))
		fmt.Fprintf(w, `<td>%d control(s)<br>%d flaw(s)<br>%d target(s)</td>`, item.ControlCount, item.FlawCount, item.TargetCount)
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Controls, 8)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Flaws, 5)))
		fmt.Fprintf(w, `<td><h3>Proof surfaces</h3>%s<h3>Evidence anchors</h3>%s<h3>Evidence references</h3>%s</td>`, renderSmallList(limitStrings(item.EvidenceSurfaces, 6)), renderSmallList(limitStrings(item.EvidenceSources, 6)), renderSmallList(evidenceReferenceLines(item.EvidenceReferences, 4)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderControlCatalogControlsDashboard(w io.Writer, items []model.ArchitectureClosure, proofSpecs []model.ControlProofSpec) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Controls To Prove</h2><div class="subtle">Each row states the missing hard barrier, the flaw it closes, the evidence reference, and the proof surface Ariadne expects.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(items) == 0 {
		fmt.Fprintln(w, `<div class="empty">No missing hard-barrier controls matched this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	proofByControl := controlProofSpecsByControl(proofSpecs)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Missing hard barrier</th><th>Closes flaws</th><th>Targets</th><th>Evidence anchors / references</th><th>Where to prove this</th><th>Recognized indicators</th><th>What would prove it</th></tr></thead><tbody>")
	for _, item := range items {
		fmt.Fprintln(w, "<tr>")
		proof := proofByControl[item.Control]
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div></td>`, esc(item.Control), esc(strings.ReplaceAll(item.ControlTestResult, "_", " ")), esc(strings.Join(limitStrings(item.CheckIDs, 4), ", ")))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Flaws, 5)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Targets, 8)))
		fmt.Fprintf(w, `<td><h3>Anchors</h3>%s<h3>References</h3>%s</td>`, renderSmallList(limitStrings(item.EvidenceSources, 6)), renderSmallList(evidenceReferenceLines(item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.EvidenceSurfaces, 6)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(proof.RecognizedIndicators, 8)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Actions, 4)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureEvidencePlanDashboard(w io.Writer, items []model.ArchitectureEvidencePlan) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Evidence Plan</h2><div class="subtle">Evidence gaps grouped by the next collector needed to prove or clear a Zero Trust boundary.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(items) == 0 {
		fmt.Fprintln(w, `<div class="empty">No Zero Trust evidence gaps were returned for this run.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Next collector</th><th>Impact</th><th>Status</th><th>Boundaries</th><th>Targets</th><th>Missing evidence / why it matters</th></tr></thead><tbody>")
	for _, item := range items {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%s</strong></td>`, esc(item.NextCollector))
		fmt.Fprintf(w, `<td>%d gap(s)<br>%d target(s)</td>`, item.GapCount, item.TargetCount)
		fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustSummaryPills(item.StatusCounts))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Boundaries, 5)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Targets, 8)))
		fmt.Fprintf(w, `<td><h3>Missing evidence</h3>%s<h3>Why it matters</h3>%s</td>`, renderSmallList(limitStrings(item.MissingEvidence, 6)), renderSmallList(limitStrings(item.WhyItMatters, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureClosureFamiliesDashboard(w io.Writer, items []model.ArchitectureClosureFamily) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Closure Families</h2><div class="subtle">Missing hard barriers grouped into Zero Trust capability areas.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(items) == 0 {
		fmt.Fprintln(w, `<div class="empty">No closure families were returned for this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Capability family</th><th>Impact</th><th>Controls</th><th>Flaws</th><th>Targets</th><th>Evidence anchors / references</th><th>Evidence surfaces / action</th></tr></thead><tbody>")
	for _, item := range items {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div></td>`, esc(item.Title), esc(item.ID))
		fmt.Fprintf(w, `<td>%d control(s)<br>%d flaw(s)<br>%d target(s)</td>`, item.ControlCount, item.FlawCount, item.TargetCount)
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Controls, 8)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Flaws, 5)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Targets, 8)))
		fmt.Fprintf(w, `<td><h3>Anchors</h3>%s<h3>References</h3>%s</td>`, renderSmallList(limitStrings(item.EvidenceSources, 6)), renderSmallList(evidenceReferenceLines(item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Actions</h3>%s</td>`, renderSmallList(limitStrings(item.EvidenceSurfaces, 5)), renderSmallList(limitStrings(item.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureFlawTable(w io.Writer, flaws []model.ZeroTrustArchitecture) {
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Architecture flaw</th><th>Control test</th><th>Evidence anchors</th><th>Graph / observed controls</th><th>Breaks when</th><th>Evidence surfaces / next action</th></tr></thead><tbody>")
	for _, flaw := range flaws {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span><div class="pill %s">%s</div></td>`, cssClass(string(flaw.Status)), esc(statusLabel(string(flaw.Status))), cssClass(flaw.Severity), esc(strings.ToUpper(flaw.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div><div class="subtle">%s</div><div class="subtle">%s</div></td>`, esc(flaw.Title), esc(flaw.Principle), esc(flaw.ID), esc(strings.Join(flaw.Boundaries, ", ")), esc(flaw.Finding))
		fmt.Fprintf(w, `<td>%s</td>`, renderArchitectureControlTest(flaw.ControlTest))
		fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustEvidence(flaw.Evidence))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(flaw.GraphEdges, 4)), renderControlLine(flaw.Controls))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(flaw.ControlEvidenceNeeded, 6)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Next action</h3>%s</td>`, renderSmallList(limitStrings(flaw.EvidenceSurfaces, 5)), renderSmallList(limitStrings(flaw.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func renderZeroTrustBoundaryCoverageDashboard(w io.Writer, boundaries []model.ArchitectureBoundary, limit int) {
	if len(boundaries) == 0 {
		return
	}
	fmt.Fprintln(w, `<h3>Boundary Coverage Map</h3>`)
	var totals model.ZeroTrustSummary
	for _, boundary := range boundaries {
		totals.Total += boundary.StatusCounts.Total
		totals.Breaking += boundary.StatusCounts.Breaking
		totals.Controlled += boundary.StatusCounts.Controlled
		totals.Unknown += boundary.StatusCounts.Unknown
		totals.NotObserved += boundary.StatusCounts.NotObserved
	}
	renderMetricRow(w, []kv{
		{"Boundary checks", fmt.Sprintf("%d", totals.Total)},
		{"Breaking", fmt.Sprintf("%d", totals.Breaking)},
		{"Controlled", fmt.Sprintf("%d", totals.Controlled)},
		{"Unknown", fmt.Sprintf("%d", totals.Unknown)},
		{"Not observed", fmt.Sprintf("%d", totals.NotObserved)},
	})
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Boundary</th><th>Status by target</th><th>Evidence anchors</th><th>Missing / next collector</th><th>Control evidence needed</th></tr></thead><tbody>")
	if limit <= 0 || limit > len(boundaries) {
		limit = len(boundaries)
	}
	for _, boundary := range boundaries[:limit] {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(boundary.Boundary), esc(boundary.Principle), esc(boundary.CheckID), esc(boundary.DesignTest))
		fmt.Fprintf(w, `<td>%s</td>`, renderArchitectureBoundaryTargetPills(boundary))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(boundary.EvidenceSources, 5)))
		fmt.Fprintf(w, `<td><h3>Missing evidence</h3>%s<h3>Next collectors</h3>%s</td>`, renderSmallList(limitStrings(boundary.MissingEvidence, 5)), renderSmallList(limitStrings(boundary.NextCollectors, 3)))
		fmt.Fprintf(w, `<td><h3>Controls observed</h3>%s<h3>Evidence needed</h3>%s</td>`, renderSmallList(limitStrings(boundary.Controls, 5)), renderSmallList(limitStrings(boundary.ControlEvidenceNeeded, 6)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	if len(boundaries) > limit {
		fmt.Fprintf(w, `<div class="subtle">%d boundary coverage rows omitted from this HTML view. JSON output contains the full set.</div>`, len(boundaries)-limit)
	}
}

func renderZeroTrustMaturity(w io.Writer, maturity model.ZeroTrustMaturity) {
	if maturity.TargetTier == "" {
		return
	}
	fmt.Fprintln(w, `<h3>Foundation Maturity Requirements</h3>`)
	renderMetricRow(w, []kv{
		{"Evidence present", fmt.Sprintf("%d/%d", maturity.Summary.Met, maturity.Summary.Total)},
		{"Gaps", fmt.Sprintf("%d", maturity.Summary.Gaps)},
		{"Breaking", fmt.Sprintf("%d", maturity.Summary.Breaking)},
		{"Unknown", fmt.Sprintf("%d", maturity.Summary.Unknown)},
		{"Not observed", fmt.Sprintf("%d", maturity.Summary.NotObserved)},
		{"Hard barriers", fmt.Sprintf("%d", maturity.Summary.HardBarriers)},
		{"Friction only", fmt.Sprintf("%d", maturity.Summary.FrictionOnly)},
	})
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Capability</th><th>Control quality</th><th>Finding</th><th>Evidence</th><th>Missing / Action</th></tr></thead><tbody>")
	for _, req := range maturity.Requirements {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(req.Status)), esc(statusLabel(string(req.Status))))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div></td>`, esc(req.Capability), esc(req.Principle), esc(req.ID))
		fmt.Fprintf(w, `<td><span class="pill neutral">%s</span></td>`, esc(strings.ReplaceAll(req.ControlQuality, "_", " ")))
		fmt.Fprintf(w, `<td>%s</td>`, esc(req.Finding))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderZeroTrustEvidence(req.Evidence), renderControlLine(req.Controls))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(req.MissingEvidence), renderSmallList(limitStrings(req.Actions, 2)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func renderZeroTrustCoverage(w io.Writer, coverage model.ZeroTrustCoverage) {
	if coverage.Gaps == 0 {
		fmt.Fprintln(w, `<div class="empty">No Zero Trust evidence coverage gaps were returned for this run.</div>`)
		return
	}
	fmt.Fprintln(w, `<h3>Evidence Coverage Gaps</h3>`)
	renderMetricRow(w, []kv{
		{"Known", fmt.Sprintf("%d", coverage.Known)},
		{"Gaps", fmt.Sprintf("%d", coverage.Gaps)},
		{"Unknown", fmt.Sprintf("%d", coverage.Unknown)},
		{"Not observed", fmt.Sprintf("%d", coverage.NotObserved)},
		{"Next collectors", fmt.Sprintf("%d", coverage.Gaps)},
	})
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Boundary</th><th>Missing evidence</th><th>Why it matters</th><th>Next collector</th></tr></thead><tbody>")
	for _, gap := range coverage.GapDetails {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(gap.Status)), esc(statusLabel(string(gap.Status))))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div></td>`, esc(gap.Boundary), esc(gap.CheckID))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(gap.MissingEvidence))
		fmt.Fprintf(w, `<td>%s</td>`, esc(gap.WhyItMatters))
		fmt.Fprintf(w, `<td>%s</td>`, esc(gap.NextCollector))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func renderScanZeroTrustDashboard(w io.Writer, r model.ScanReport) {
	var total model.ZeroTrustSummary
	var architectureTotal model.ZeroTrustSummary
	byTarget := make([]kv, 0, len(r.Targets))
	coverageInputs := make([]architectureCoverageInput, 0, len(r.Targets))
	for _, target := range r.Targets {
		if target.Error != "" || target.Report.ZeroTrust.FrameworkVersion == "" {
			continue
		}
		s := target.Report.ZeroTrust.Summary
		a := target.Report.ZeroTrust.ArchitectureSummary
		total.Total += s.Total
		total.Breaking += s.Breaking
		total.Controlled += s.Controlled
		total.Unknown += s.Unknown
		total.NotObserved += s.NotObserved
		architectureTotal.Total += a.Total
		architectureTotal.Breaking += a.Breaking
		architectureTotal.Controlled += a.Controlled
		architectureTotal.Unknown += a.Unknown
		architectureTotal.NotObserved += a.NotObserved
		coverageInputs = append(coverageInputs, architectureCoverageInput{
			TargetID:  target.Target.ID,
			ZeroTrust: target.Report.ZeroTrust,
		})
		byTarget = append(byTarget, kv{
			Key:   target.Target.ID,
			Value: fmt.Sprintf("%d breaking flaws, %d controlled flaws, %d unknown flaws; %d breaking checks", a.Breaking, a.Controlled, a.Unknown, s.Breaking),
		})
	}
	if total.Total == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Zero Trust Architecture</h2><div class="subtle">Aggregated architecture-failure and boundary readout across scanned targets.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Breaking flaws", fmt.Sprintf("%d", architectureTotal.Breaking)},
		{"Controlled flaws", fmt.Sprintf("%d", architectureTotal.Controlled)},
		{"Unknown flaws", fmt.Sprintf("%d", architectureTotal.Unknown)},
		{"Breaking checks", fmt.Sprintf("%d", total.Breaking)},
		{"Checks", fmt.Sprintf("%d", total.Total)},
	})
	renderZeroTrustBoundaryCoverageDashboard(w, buildArchitectureBoundaryCoverage(coverageInputs), 10)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Target</th><th>Zero Trust readout</th></tr></thead><tbody>")
	for _, row := range byTarget {
		fmt.Fprintf(w, "<tr><td><strong>%s</strong></td><td>%s</td></tr>\n", esc(row.Key), esc(row.Value))
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureScanSummaryDashboard(w io.Writer, r model.ArchitectureScanReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Fleet Architecture Readout</h2><div class="subtle">Grouped Zero Trust architecture breakage across targets.</div></div>`)
	fmt.Fprintln(w, "</div>")
	renderMetricRow(w, []kv{
		{"Targets", fmt.Sprintf("%d", r.Summary.Targets)},
		{"Completed", fmt.Sprintf("%d", r.Summary.Completed)},
		{"Errors", fmt.Sprintf("%d", r.Summary.Errors)},
		{"Matching flaws", fmt.Sprintf("%d", r.Summary.MatchingFlaws)},
		{"Distinct flaws", fmt.Sprintf("%d", r.Summary.DistinctFlaws)},
	})
	renderMetricRow(w, []kv{
		{"Breaking", fmt.Sprintf("%d", r.Summary.Breaking)},
		{"Controlled", fmt.Sprintf("%d", r.Summary.Controlled)},
		{"Unknown", fmt.Sprintf("%d", r.Summary.Unknown)},
		{"Not observed", fmt.Sprintf("%d", r.Summary.NotObserved)},
		{"Boundary rows", fmt.Sprintf("%d", len(r.BoundaryCoverage))},
	})
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureFlawGroupsDashboard(w io.Writer, groups []model.ArchitectureFlawGroup) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Flaws By Target Coverage</h2><div class="subtle">Which architecture failure categories recur across the scanned targets.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(groups) == 0 {
		fmt.Fprintln(w, `<div class="empty">No architecture flaw groups matched this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Architecture flaw</th><th>Status by target</th><th>Control test</th><th>Targets</th><th>Evidence anchors</th><th>Breaks when</th><th>Evidence surfaces / action</th></tr></thead><tbody>")
	for _, group := range groups {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(group.Severity), esc(strings.ToUpper(group.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(group.Title), esc(group.Principle), esc(group.ID), esc(group.Tier))
		fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustSummaryPills(group.StatusCounts))
		fmt.Fprintf(w, `<td>%s</td>`, renderControlTestResults(group.ControlTestResults))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(group.Targets, 8)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(group.EvidenceSources, 6)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(group.ControlEvidenceNeeded, 6)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Actions</h3>%s</td>`, renderSmallList(limitStrings(group.EvidenceSurfaces, 5)), renderSmallList(limitStrings(group.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureTargetsDashboard(w io.Writer, targets []model.ArchitectureTargetReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Targets</h2><div class="subtle">Filtered architecture flaw counts for each target.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(targets) == 0 {
		fmt.Fprintln(w, `<div class="empty">No target results were returned.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Target</th><th>Path</th><th>Status</th><th>Matching flaws</th></tr></thead><tbody>")
	for _, target := range targets {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%s</strong></td>`, esc(target.Target.ID))
		fmt.Fprintf(w, `<td class="mono">%s</td>`, esc(target.Target.Path))
		if target.Error != "" {
			fmt.Fprintf(w, `<td><span class="pill critical">ERROR</span><div class="subtle">%s</div></td>`, esc(target.Error))
		} else {
			fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustSummaryPills(target.Summary))
		}
		fmt.Fprintf(w, `<td>%d</td>`, len(target.Flaws))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderZeroTrustEvidence(evidence []model.ZeroTrustEvidence) string {
	if len(evidence) == 0 {
		return `<span class="subtle">No direct evidence mapped.</span>`
	}
	var b strings.Builder
	b.WriteString(`<ul class="list">`)
	for _, item := range limitEvidence(evidence, 5) {
		b.WriteString("<li>")
		if item.Source != "" {
			b.WriteString(`<span class="mono">`)
			b.WriteString(esc(item.Source))
			b.WriteString(`</span>`)
		} else if item.ID != "" {
			b.WriteString(`<span class="mono">`)
			b.WriteString(esc(item.ID))
			b.WriteString(`</span>`)
		}
		b.WriteString(`<div class="subtle">`)
		b.WriteString(esc(strings.TrimSpace(item.Kind + " " + item.Summary)))
		b.WriteString(`</div></li>`)
	}
	b.WriteString("</ul>")
	return b.String()
}

func renderControlLine(controls []string) string {
	if len(controls) == 0 {
		return ""
	}
	return `<h3>Controls</h3>` + renderSmallList(controls)
}

func renderZeroTrustSummaryPills(summary model.ZeroTrustSummary) string {
	parts := []string{
		statusCountPill(model.ZeroTrustBreaking, summary.Breaking),
		statusCountPill(model.ZeroTrustControlled, summary.Controlled),
		statusCountPill(model.ZeroTrustUnknown, summary.Unknown),
		statusCountPill(model.ZeroTrustNotObserved, summary.NotObserved),
	}
	var out []string
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return `<span class="subtle">none</span>`
	}
	return strings.Join(out, "<br>")
}

func statusCountPill(status model.ZeroTrustStatus, count int) string {
	if count == 0 {
		return ""
	}
	return fmt.Sprintf(`<span class="pill %s">%d %s</span>`, cssClass(string(status)), count, esc(statusLabel(string(status))))
}

func renderControlTestResults(results map[string]int) string {
	if len(results) == 0 {
		return `<span class="subtle">none</span>`
	}
	keys := make([]string, 0, len(results))
	for key := range results {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(`<ul class="list">`)
	for _, key := range keys {
		b.WriteString("<li>")
		b.WriteString(esc(fmt.Sprintf("%s: %d", strings.ReplaceAll(key, "_", " "), results[key])))
		b.WriteString("</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func renderArchitectureControlTest(test model.ArchitectureControlTest) string {
	if test.Result == "" {
		return `<span class="subtle">No control test mapped.</span>`
	}
	var b strings.Builder
	b.WriteString(`<span class="pill neutral">`)
	b.WriteString(esc(strings.ReplaceAll(test.Result, "_", " ")))
	b.WriteString(`</span>`)
	if test.Summary != "" {
		b.WriteString(`<div class="subtle">`)
		b.WriteString(esc(test.Summary))
		b.WriteString(`</div>`)
	}
	if len(test.HardBarriersObserved) > 0 {
		b.WriteString(`<h3>Hard barriers</h3>`)
		b.WriteString(renderSmallList(limitStrings(test.HardBarriersObserved, 4)))
	}
	if len(test.PartialOrFrictionControls) > 0 {
		b.WriteString(`<h3>Partial/friction</h3>`)
		b.WriteString(renderSmallList(limitStrings(test.PartialOrFrictionControls, 4)))
	}
	if len(test.MissingHardBarriers) > 0 {
		b.WriteString(`<h3>Missing hard barriers</h3>`)
		b.WriteString(renderSmallList(limitStrings(test.MissingHardBarriers, 4)))
	}
	return b.String()
}

func limitStrings(items []string, limit int) []string {
	if len(items) <= limit {
		return items
	}
	out := append([]string{}, items[:limit]...)
	out = append(out, fmt.Sprintf("%d additional items in JSON", len(items)-limit))
	return out
}

func limitEvidence(items []model.ZeroTrustEvidence, limit int) []model.ZeroTrustEvidence {
	if len(items) <= limit {
		return items
	}
	out := append([]model.ZeroTrustEvidence{}, items[:limit]...)
	out = append(out, model.ZeroTrustEvidence{Kind: "summary", Summary: fmt.Sprintf("%d additional evidence items in JSON", len(items)-limit)})
	return out
}

func renderIssueMetrics(w io.Writer, summary model.IssueSummary) {
	metrics := []kv{
		{"Total", fmt.Sprintf("%d", summary.Total)},
		{"Critical", fmt.Sprintf("%d", summary.Critical)},
		{"High", fmt.Sprintf("%d", summary.High)},
		{"Fix Now", fmt.Sprintf("%d", summary.FixNow)},
		{"Controlled", fmt.Sprintf("%d", summary.Controlled)},
	}
	fmt.Fprintln(w, `<div class="grid">`)
	for _, metric := range metrics {
		fmt.Fprintln(w, `<div class="metric">`)
		fmt.Fprintf(w, `<div class="label">%s</div>`, esc(metric.Key))
		fmt.Fprintf(w, `<div class="value">%s</div>`, esc(metric.Value))
		fmt.Fprintln(w, "</div>")
	}
	fmt.Fprintln(w, "</div>")
}

type issueReference struct {
	Kind    string
	Summary string
	Source  string
}

func issueReferences(issue model.Issue, graph model.Graph, evidence []model.Evidence) []issueReference {
	refs := referencesFromGraphEdges(issue, graph, evidence)
	if len(refs) == 0 {
		refs = referencesFromCategory(issue, graph, evidence)
	}
	return limitReferences(uniqueReferences(refs), 8)
}

func referencesFromGraphEdges(issue model.Issue, graph model.Graph, evidence []model.Evidence) []issueReference {
	nodeByID := make(map[string]model.Node, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodeByID[node.ID] = node
	}
	evidenceByID := make(map[string]model.Evidence, len(evidence))
	for _, item := range evidence {
		if item.ID != "" && item.Source != "" {
			evidenceByID[item.ID] = item
		}
	}
	var refs []issueReference
	for _, wanted := range issue.GraphEdges {
		for _, edge := range graph.Edges {
			if edge.Key() != wanted {
				continue
			}
			for _, nodeID := range []string{edge.From, edge.To} {
				node, ok := nodeByID[nodeID]
				if !ok || node.Source == "" {
					continue
				}
				refs = append(refs, issueReference{Kind: node.Type, Summary: node.Label, Source: node.Source})
			}
			if item, ok := evidenceByID[edge.EvidenceID]; ok {
				refs = append(refs, issueReference{Kind: item.Kind, Summary: item.Summary, Source: item.Source})
			}
		}
	}
	return refs
}

func referencesFromCategory(issue model.Issue, graph model.Graph, evidence []model.Evidence) []issueReference {
	var refs []issueReference
	nodeTypes := categoryNodeTypes(issue)
	for _, node := range graph.Nodes {
		if node.Source == "" || !nodeMatchesCategory(issue, node, nodeTypes) {
			continue
		}
		refs = append(refs, issueReference{Kind: node.Type, Summary: node.Label, Source: node.Source})
	}
	for _, item := range evidence {
		if item.Source == "" || !categoryEvidenceMatches(issue, item) {
			continue
		}
		refs = append(refs, issueReference{Kind: item.Kind, Summary: item.Summary, Source: item.Source})
	}
	return refs
}

func categoryNodeTypes(issue model.Issue) []string {
	switch issue.Category {
	case "tool-surface", "local-code-execution":
		return []string{"mcp-tool-config", "tool", "command-hook", "plugin-skill"}
	case "private-context":
		return []string{"history-cache", "memory", "boundary"}
	case "secret-access":
		return []string{"runtime", "config", "boundary", "sensitive-boundary"}
	case "data-egress":
		return []string{"trust_input", "runtime", "config", "boundary", "control"}
	default:
		return nil
	}
}

func nodeMatchesCategory(issue model.Issue, node model.Node, nodeTypes []string) bool {
	if !contains(nodeTypes, node.Type) {
		return false
	}
	label := strings.ToLower(node.Label)
	switch issue.Category {
	case "private-context":
		return node.Type == "history-cache" || node.Type == "memory" || label == "agent-private-context"
	case "tool-surface", "local-code-execution":
		return node.Type == "mcp-tool-config" || node.Type == "tool" || node.Type == "command-hook" || node.Type == "plugin-skill"
	case "secret-access":
		return node.Type == "runtime" || node.Type == "config" || strings.Contains(label, "secret")
	case "data-egress":
		return node.Type == "trust_input" || node.Type == "runtime" || node.Type == "config" || node.Type == "control" || strings.Contains(label, "external") || strings.Contains(label, "secret")
	default:
		return true
	}
}

func categoryEvidenceMatches(issue model.Issue, item model.Evidence) bool {
	text := strings.ToLower(item.Kind + " " + item.Summary)
	switch issue.Category {
	case "tool-surface", "local-code-execution":
		return strings.Contains(text, "mcp") || strings.Contains(text, "tool") || strings.Contains(text, "command")
	case "private-context":
		return strings.Contains(text, "private") || strings.Contains(text, "history") || strings.Contains(text, "cache") || strings.Contains(text, "context")
	case "secret-access":
		return strings.Contains(text, "secret") || strings.Contains(text, "boundary") || strings.Contains(text, "config")
	case "data-egress":
		return strings.Contains(text, "external") || strings.Contains(text, "network") || strings.Contains(text, "trust") || strings.Contains(text, "boundary")
	default:
		return false
	}
}

func uniqueReferences(refs []issueReference) []issueReference {
	seen := map[string]bool{}
	var out []issueReference
	for _, ref := range refs {
		if ref.Source == "" {
			continue
		}
		key := ref.Kind + "|" + ref.Summary + "|" + ref.Source
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	return out
}

func limitReferences(refs []issueReference, limit int) []issueReference {
	if len(refs) <= limit {
		return refs
	}
	out := append([]issueReference{}, refs[:limit]...)
	out = append(out, issueReference{Kind: "more", Summary: fmt.Sprintf("%d additional references in Facts Dive / JSON", len(refs)-limit)})
	return out
}

func renderIssueReferences(refs []issueReference) string {
	if len(refs) == 0 {
		return `<span class="subtle">No direct source reference mapped. Use Facts Dive for supporting evidence.</span>`
	}
	var b strings.Builder
	b.WriteString(`<ul class="list">`)
	for _, ref := range refs {
		b.WriteString("<li>")
		if ref.Source != "" {
			b.WriteString(`<span class="mono">`)
			b.WriteString(esc(ref.Source))
			b.WriteString(`</span>`)
		}
		if ref.Kind != "" || ref.Summary != "" {
			b.WriteString(`<div class="subtle">`)
			b.WriteString(esc(strings.TrimSpace(ref.Kind + " " + ref.Summary)))
			b.WriteString(`</div>`)
		}
		b.WriteString("</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func interpretationMeta(interpretation model.Interpretation) string {
	parts := []string{"Mode: " + firstNonEmpty(interpretation.Mode, "not evaluated")}
	if interpretation.ReviewSource != "" {
		parts = append(parts, "Source: "+interpretation.ReviewSource)
	}
	if interpretation.RequestDigest != "" {
		digest := interpretation.RequestDigest
		if len(digest) > 12 {
			digest = digest[:12]
		}
		parts = append(parts, "Request: "+digest)
	}
	return strings.Join(parts, " | ")
}

func renderExposureSection(w io.Writer, exposures []model.ExposureResult) {
	if len(exposures) == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Exposure Paths</h2><div class="subtle">Supported paths Ariadne could classify from graph evidence.</div></div></div>`)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Path</th><th>Proof</th><th>Graph evidence</th><th>Evidence refs</th><th>Controls</th></tr></thead><tbody>")
	for _, exposure := range exposures {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(exposure.Status)), esc(strings.ToUpper(string(exposure.Status))))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div></td>`, esc(exposure.Title), esc(exposure.Observation.Summary), esc(exposure.ID))
		fmt.Fprintf(w, `<td>%s</td>`, esc(string(exposure.ProofMode)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(exposure.PathEdges))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(evidenceReferenceLines(exposure.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(exposure.ControlsBreakPath))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderScanTargetSection(w io.Writer, r model.ScanReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Targets</h2><div class="subtle">Per-target exposure and issue rollup.</div></div></div>`)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Target</th><th>Exposures</th><th>Prioritized issues</th><th>Status</th></tr></thead><tbody>")
	for _, target := range r.Targets {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div></td>`, esc(target.Target.ID), esc(target.Target.Path))
		if target.Error != "" {
			fmt.Fprintln(w, `<td colspan="2" class="subtle">Collection error</td>`)
			fmt.Fprintf(w, `<td>%s</td>`, esc(target.Error))
			fmt.Fprintln(w, "</tr>")
			continue
		}
		fmt.Fprintf(w, `<td>%s</td>`, renderExposureCounts(target.Report.Exposures))
		fmt.Fprintf(w, `<td>%d</td>`, len(target.Report.Interpretation.Issues))
		fmt.Fprintln(w, `<td>completed</td>`)
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderFactsDive(w io.Writer, graph model.Graph, evidence []model.Evidence, warnings []string, limitations []string) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Facts Dive</h2><div class="subtle">Raw deterministic evidence and graph shape behind the issues.</div></div></div>`)
	renderGraphSummary(w, graph)
	fmt.Fprintln(w, `<div class="two-col">`)
	renderGraphEdges(w, graph)
	renderEvidenceRows(w, evidence)
	fmt.Fprintln(w, "</div>")
	renderRunNotes(w, warnings, limitations)
	fmt.Fprintln(w, "</section>")
}

func renderScanFactsDive(w io.Writer, r model.ScanReport) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Facts Dive</h2><div class="subtle">Aggregated graph shape and run notes across scanned targets.</div></div></div>`)
	totalNodes := 0
	totalEdges := 0
	totalEvidence := 0
	for _, target := range r.Targets {
		totalNodes += len(target.Report.Graph.Nodes)
		totalEdges += len(target.Report.Graph.Edges)
		totalEvidence += len(target.Report.Evidence)
	}
	renderMetricRow(w, []kv{
		{"Graph nodes", fmt.Sprintf("%d", totalNodes)},
		{"Graph edges", fmt.Sprintf("%d", totalEdges)},
		{"Evidence rows", fmt.Sprintf("%d", totalEvidence)},
		{"Exposure paths", fmt.Sprintf("%d", r.Summary.ExposurePaths)},
		{"Limitations", fmt.Sprintf("%d", len(r.Limitations))},
	})
	renderRunNotes(w, r.Warnings, r.Limitations)
	fmt.Fprintln(w, "</section>")
}

func renderGraphSummary(w io.Writer, graph model.Graph) {
	renderMetricRow(w, []kv{
		{"Graph nodes", fmt.Sprintf("%d", len(graph.Nodes))},
		{"Graph edges", fmt.Sprintf("%d", len(graph.Edges))},
		{"Runtimes", fmt.Sprintf("%d", countNodes(graph, "runtime"))},
		{"Authorities", fmt.Sprintf("%d", countNodes(graph, "authority"))},
		{"Controls", fmt.Sprintf("%d", countNodes(graph, "control"))},
	})
}

func renderMetricRow(w io.Writer, metrics []kv) {
	fmt.Fprintln(w, `<div class="grid">`)
	for _, metric := range metrics {
		fmt.Fprintln(w, `<div class="metric">`)
		fmt.Fprintf(w, `<div class="label">%s</div>`, esc(metric.Key))
		fmt.Fprintf(w, `<div class="value">%s</div>`, esc(metric.Value))
		fmt.Fprintln(w, "</div>")
	}
	fmt.Fprintln(w, "</div>")
}

func renderGraphEdges(w io.Writer, graph model.Graph) {
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Graph Edges</h3>`)
	if len(graph.Edges) == 0 {
		fmt.Fprintln(w, `<div class="empty">No graph edges returned.</div>`)
		fmt.Fprintln(w, "</div>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>From</th><th>Edge</th><th>To</th></tr></thead><tbody>")
	for _, edge := range graph.Edges {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td class="mono">%s</td><td>%s</td><td class="mono">%s</td>`, esc(edge.From), esc(edge.Type), esc(edge.To))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div></div>")
}

func renderEvidenceRows(w io.Writer, evidence []model.Evidence) {
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Evidence</h3>`)
	if len(evidence) == 0 {
		fmt.Fprintln(w, `<div class="empty">No evidence rows returned.</div>`)
		fmt.Fprintln(w, "</div>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Kind</th><th>Grade</th><th>Summary</th><th>Source</th></tr></thead><tbody>")
	limit := len(evidence)
	if limit > dashboardFactLimit {
		limit = dashboardFactLimit
	}
	for _, item := range evidence[:limit] {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td>%s</td><td>%s</td><td>%s</td><td class="mono">%s</td>`, esc(item.Kind), esc(item.Grade), esc(item.Summary), esc(item.Source))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	if len(evidence) > limit {
		fmt.Fprintf(w, `<div class="subtle">%d evidence rows omitted from this HTML view. JSON output contains the full set.</div>`, len(evidence)-limit)
	}
	fmt.Fprintln(w, "</div>")
}

func renderRunNotes(w io.Writer, warnings []string, limitations []string) {
	if len(warnings) == 0 && len(limitations) == 0 {
		return
	}
	fmt.Fprintln(w, `<div class="two-col">`)
	if len(warnings) > 0 {
		fmt.Fprintln(w, `<div><h3>Warnings</h3>`)
		fmt.Fprintf(w, "%s", renderSmallList(warnings))
		fmt.Fprintln(w, "</div>")
	}
	if len(limitations) > 0 {
		fmt.Fprintln(w, `<div><h3>Limitations</h3>`)
		fmt.Fprintf(w, "%s", renderSmallList(limitations))
		fmt.Fprintln(w, "</div>")
	}
	fmt.Fprintln(w, "</div>")
}

func renderInterpretationLimitations(w io.Writer, interpretation model.Interpretation) {
	if len(interpretation.Limitations) == 0 {
		return
	}
	fmt.Fprintln(w, `<h3>Interpretation Limits</h3>`)
	fmt.Fprintf(w, "%s", renderSmallList(interpretation.Limitations))
}

func renderExposureCounts(exposures []model.ExposureResult) string {
	if len(exposures) == 0 {
		return `<span class="subtle">none</span>`
	}
	counts := map[model.Status]int{}
	for _, exposure := range exposures {
		counts[exposure.Status]++
	}
	var parts []string
	for _, status := range []model.Status{model.StatusExposed, model.StatusProtected, model.StatusInconclusive} {
		if counts[status] == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf(`<span class="pill %s">%d %s</span>`, cssClass(string(status)), counts[status], esc(string(status))))
	}
	return strings.Join(parts, " ")
}

func renderArchitectureBoundaryTargetPills(boundary model.ArchitectureBoundary) string {
	parts := []string{
		renderTargetStatusPill(model.ZeroTrustBreaking, boundary.BreakingTargets),
		renderTargetStatusPill(model.ZeroTrustControlled, boundary.ControlledTargets),
		renderTargetStatusPill(model.ZeroTrustUnknown, boundary.UnknownTargets),
		renderTargetStatusPill(model.ZeroTrustNotObserved, boundary.NotObservedTargets),
	}
	var out []string
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return `<span class="subtle">none</span>`
	}
	return strings.Join(out, "<br>")
}

func renderTargetStatusPill(status model.ZeroTrustStatus, targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	limited := limitStrings(targets, 5)
	return fmt.Sprintf(`<span class="pill %s">%d %s</span><div class="mono">%s</div>`, cssClass(string(status)), len(targets), esc(statusLabel(string(status))), esc(strings.Join(limited, ", ")))
}

func renderSmallList(items []string) string {
	if len(items) == 0 {
		return `<span class="subtle">none</span>`
	}
	var b strings.Builder
	b.WriteString(`<ul class="list">`)
	for _, item := range items {
		b.WriteString("<li>")
		b.WriteString(esc(item))
		b.WriteString("</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func renderDashboardHTMLList(items []string) string {
	if len(items) == 0 {
		return `<span class="subtle">none</span>`
	}
	var b strings.Builder
	b.WriteString(`<ul class="list">`)
	for _, item := range items {
		b.WriteString("<li>")
		b.WriteString(item)
		b.WriteString("</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func renderDashboardPathList(root string, items []string) string {
	if len(items) == 0 {
		return `<span class="subtle">none</span>`
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, dashboardFileRefHTML(root, item))
	}
	return renderDashboardHTMLList(out)
}

func dashboardEvidenceReferencesBySource(values []model.EvidenceReference, limit int) []model.EvidenceReference {
	values = dedupeEvidenceReferences(values)
	if len(values) == 0 {
		return []model.EvidenceReference{}
	}
	seen := map[string]bool{}
	compact := make([]model.EvidenceReference, 0, len(values))
	for _, value := range values {
		key := value.Source
		if key == "" {
			key = value.ID
		}
		if key == "" {
			key = value.Kind
		}
		if value.Target != "" {
			key = value.Target + "|" + key
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		compact = append(compact, value)
	}
	if limit <= 0 || limit > len(compact) {
		limit = len(compact)
	}
	out := append([]model.EvidenceReference{}, compact[:limit]...)
	if len(compact) > limit {
		out = append(out, model.EvidenceReference{
			Kind:    "summary",
			Summary: fmt.Sprintf("%d more evidence source(s) in JSON", len(compact)-limit),
		})
	}
	return out
}

func dashboardEvidenceReferenceHTML(root string, value model.EvidenceReference) string {
	source := value.Source
	if source == "" {
		source = value.ID
	}
	if source == "" {
		source = value.Kind
	}
	prefix := dashboardFileRefHTML(root, source)
	if value.Target != "" {
		prefix = esc(value.Target) + ": " + prefix
	}
	summary := strings.TrimSpace(value.Summary)
	if len(summary) > 120 {
		summary = summary[:117] + "..."
	}
	kind := strings.TrimSpace(value.Kind)
	if summary == "" || summary == source {
		if kind != "" {
			return fmt.Sprintf("%s [%s]", prefix, esc(kind))
		}
		return prefix
	}
	if kind != "" {
		return fmt.Sprintf("%s [%s] %s", prefix, esc(kind), esc(summary))
	}
	return prefix + " " + esc(summary)
}

func dashboardControlEvidenceExampleHTML(root string, example model.ControlEvidenceExample) string {
	line := dashboardFileRefHTML(root, example.Surface)
	if example.Summary != "" {
		if line != "" {
			line += ": "
		}
		line += esc(strings.TrimSpace(example.Summary))
	}
	if example.Example != "" {
		if line != "" {
			line += " "
		}
		line += "Example: " + esc(compactExample(example.Example))
	}
	return strings.TrimSpace(line)
}

func dashboardControlProofPatchHTML(root string, patch model.ControlProofPatch) string {
	line := strings.TrimSpace(patch.Surface)
	if line != "" {
		line = dashboardFileRefHTML(root, line)
	} else {
		line = esc(strings.TrimSpace(patch.Control))
	}
	var fields []string
	for _, field := range patch.Fields {
		fields = append(fields, esc(field.Name+"="+field.ValueJSON))
	}
	if len(fields) > 0 {
		line += " " + esc(patch.Operation) + " " + strings.Join(limitStrings(fields, 3), ", ")
	} else if patch.Operation != "" {
		line += " " + esc(patch.Operation)
	}
	if patch.Example != "" {
		line += " Example: " + esc(compactExample(patch.Example))
	}
	return strings.TrimSpace(line)
}

func dashboardFileRefHTML(root, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	href := dashboardFileHref(root, value)
	if href == "" {
		return fmt.Sprintf(`<span class="mono">%s</span>`, esc(value))
	}
	return fmt.Sprintf(`<a class="file-link mono" href="%s">%s</a>`, esc(href), esc(value))
}

func dashboardFileHref(root, value string) string {
	value = strings.TrimSpace(value)
	if !dashboardLooksLikeLocalPath(value) {
		return ""
	}
	path := value
	if !filepath.IsAbs(path) {
		root = strings.TrimSpace(root)
		if root == "" {
			return ""
		}
		path = filepath.Join(root, path)
	}
	path = filepath.Clean(path)
	if path == "." || path == string(filepath.Separator) {
		return ""
	}
	return (&url.URL{Scheme: "file", Path: path}).String()
}

func dashboardLooksLikeLocalPath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || strings.ContainsAny(value, "\n\r\t") {
		return false
	}
	if strings.Contains(value, " ") {
		return false
	}
	if strings.HasPrefix(value, "control:") ||
		strings.HasPrefix(value, "case:") ||
		strings.HasPrefix(value, "ztaf:") ||
		strings.HasPrefix(value, "runtime:") ||
		strings.HasPrefix(value, "boundary:") ||
		strings.HasPrefix(value, "authority:") ||
		strings.HasPrefix(value, "tool:") ||
		strings.HasPrefix(value, "config:") ||
		strings.HasPrefix(value, "evidence:") {
		return false
	}
	if filepath.IsAbs(value) {
		return true
	}
	if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return true
	}
	if strings.HasPrefix(value, ".") && value != "." && value != ".." {
		return true
	}
	if filepath.Base(value) == value && strings.Contains(value, ".") {
		return true
	}
	return strings.Contains(value, "/")
}

func countNodes(graph model.Graph, nodeType string) int {
	count := 0
	for _, node := range graph.Nodes {
		if node.Type == nodeType {
			count++
		}
	}
	return count
}

func cssClass(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "_", "-")
	var cleaned strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			cleaned.WriteRune(r)
		}
	}
	if cleaned.Len() == 0 {
		return "info"
	}
	return cleaned.String()
}

func esc(value string) string {
	return html.EscapeString(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
