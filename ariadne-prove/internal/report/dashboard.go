package report

import (
	"fmt"
	"html"
	"io"
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
	renderAssessInventoryDashboard(w, r.Inventory)
	renderControlOperatorCasesDashboard(w, r.TopCases)
	renderAssessArchitectureDashboard(w, r)
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
.two-col {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 16px;
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
	fmt.Fprintln(w, `<section class="topbar">`)
	fmt.Fprintln(w, `<div class="title">`)
	fmt.Fprintf(w, "<h1>%s</h1>\n", esc(title))
	fmt.Fprintln(w, `<div class="subtle">Fact collection, graph-backed exposure paths, and selected priority interpretation.</div>`)
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
	fmt.Fprintln(w, `</section>`)
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
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Next Commands</h2><div class="subtle">Rerun the same assessment, focus the top case, or inspect the full proof catalog.</div></div></div>`)
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
		{"Closure", "Parser-recognized indicators, evidence examples, rerun commands, and done criteria.", "Add or verify evidence, rerun Ariadne, and confirm the case disappears or becomes controlled."},
	}
	for _, row := range rows {
		fmt.Fprintf(w, "<tr><td><strong>%s</strong></td><td>%s</td><td>%s</td></tr>", esc(row.layer), esc(row.fact), esc(row.use))
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderControlOperatorCasesDashboard(w io.Writer, cases []model.ControlOperatorCase) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Operator Cases</h2><div class="subtle">A smaller action layer that connects architecture breakage, evidence references, proof surfaces, accepted evidence examples, and rerun criteria.</div></div>`)
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
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><strong>#%d %s</strong><div class="mono">%s</div><div class="subtle">%d control(s), %d flaw(s), %d target(s)</div></td>`, item.Rank, esc(item.Title), esc(item.ID), item.ControlCount, item.FlawCount, item.TargetCount)
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><h3>Priority</h3><div>%s</div><h3>Next step</h3><div>%s</div></td>`, esc(firstNonEmpty(item.State, "open")), esc(item.StateReason), esc(item.PriorityReason), esc(item.NextStep))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%s</div></td>`, esc(item.Question), esc(item.Finding))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(evidenceReferenceLines(item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s<div class="mono">%s</div></td>`, renderSmallList(limitStrings(item.StartingControls, 5)), esc(strings.Join(limitStrings(item.StartingTaskIDs, 5), ", ")))
		fmt.Fprintf(w, `<td><h3>Proof surfaces</h3>%s<h3>Evidence examples</h3>%s</td>`, renderSmallList(limitStrings(item.ProofSurfaces, 6)), renderSmallList(controlEvidenceExampleLines(item.EvidenceExamples, 2)))
		fmt.Fprintf(w, `<td><h3>Rerun</h3>%s<h3>Done when</h3>%s</td>`, renderSmallList(limitStrings(item.RerunCommands, 2)), renderSmallList(limitStrings(item.SuccessCriteria, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(cases) > limit {
		fmt.Fprintf(w, `<tr><td colspan="8"><span class="subtle">%d more operator cases in JSON output.</span></td></tr>`, len(cases)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
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
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Task</th><th>Why</th><th>Evidence references</th><th>Add or verify at</th><th>Accepted indicators</th><th>Evidence examples</th><th>Rerun / done when</th></tr></thead><tbody>")
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
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(controlEvidenceExampleLines(task.EvidenceExamples, 2)))
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
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Path</th><th>Proof</th><th>Graph evidence</th><th>Controls</th></tr></thead><tbody>")
	for _, exposure := range exposures {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(exposure.Status)), esc(strings.ToUpper(string(exposure.Status))))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div></td>`, esc(exposure.Title), esc(exposure.Observation.Summary), esc(exposure.ID))
		fmt.Fprintf(w, `<td>%s</td>`, esc(string(exposure.ProofMode)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(exposure.PathEdges))
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
