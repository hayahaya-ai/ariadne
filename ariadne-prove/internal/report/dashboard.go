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
	renderZeroTrustDashboard(w, r.TargetPath, r.ZeroTrust)
	renderIssueDashboard(w, r.Interpretation, r.Graph, r.Evidence, r.Redaction)
	renderExposureSection(w, r.TargetPath, r.Exposures)
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
	renderAssessOperatorRunbookDashboard(w, r)
	renderAssessSourceReferenceWorkbenchDashboard(w, r)
	renderAssessOperatorPacketDashboard(w, r)
	renderAssessOperatorWorkbenchDashboard(w, r)
	renderAssessCaseLifecycleDashboard(w, r.TargetPath, r.CaseLifecycle)
	renderAssessDecisionDashboard(w, r.TargetPath, r.Decision)
	renderAssessSignalQualityDashboard(w, r.TargetPath, r.SignalQuality)
	renderAssessSignalNoiseDashboard(w, r.TargetPath, r.SignalNoise)
	renderAssessLethalTrifectaDashboard(w, r.TargetPath, r.LethalTrifecta)
	renderAssessTriageDashboard(w, r.TargetPath, r.Triage)
	renderAssessClosurePlanDashboard(w, r.TargetPath, r.ClosurePlan)
	renderAssessFirstActionDashboard(w, r.TargetPath, r.FirstAction, r.ControlState)
	renderAssessClosureEvidenceDashboard(w, r.TargetPath, r.ClosureEvidence)
	renderAssessCaseNavigationDashboard(w, r.TopCases)
	renderAssessActiveCaseDashboard(w, r)
	renderControlOperatorCasesDashboard(w, r.TargetPath, r.TopCases)
	renderAssessArchitectureDashboard(w, r)
	renderAssessInventoryDashboard(w, r.Inventory)
	renderAssessCommandsDashboard(w, r.NextCommands)
	renderRunNotes(w, r.Warnings, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderAssessSourceReferenceWorkbenchDashboard(w io.Writer, r model.AssessReport) {
	workbench := r.SourceReferences
	if !workbench.Available || len(workbench.Rows) == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Source Reference Workbench</h2><div class="subtle">Exact files and lines to open first. These rows come from deterministic evidence references, not generated opinion.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Evidence refs", fmt.Sprintf("%d", len(workbench.Rows))},
		{"Local files", fmt.Sprintf("%d", workbench.LocalFiles)},
		{"Metadata-only", fmt.Sprintf("%d", workbench.MetadataOnly)},
		{"Top case", firstNonEmpty(r.Summary.TopCaseID, "none")},
		{"Filter", firstNonEmpty(r.StatusFilter, "breaking")},
	})
	if workbench.Summary != "" {
		fmt.Fprintf(w, `<p><strong>Readout:</strong> %s</p>`, esc(workbench.Summary))
	}
	renderAssessSourceReferenceRowTable(w, workbench.Rows, 12)
	fmt.Fprintln(w, `</section>`)
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
	renderArchitectureFrameworkCoverageDashboard(w, r.TargetPath, r.FrameworkCoverage)
	renderArchitectureEvidencePlanDashboard(w, r.EvidencePlan)
	renderArchitectureClosureFamiliesDashboard(w, r.TargetPath, r.ClosureFamilies)
	renderArchitectureClosurePlanDashboard(w, r.TargetPath, r.ClosurePlan)
	renderArchitectureFlawTableDashboard(w, r.TargetPath, r.Flaws)
	renderZeroTrustBoundaryCoverageDashboard(w, r.TargetPath, r.BoundaryCoverage, 12)
	renderZeroTrustMaturity(w, r.TargetPath, r.Maturity)
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
	renderArchitectureCaseWorkflowDashboard(w, r.ClosureFamilies, controlVerificationCommandContext{RunKind: "case_board_scan", TargetsFile: r.TargetsFile, Mode: r.Mode, Agent: r.Agent, StatusFilter: r.StatusFilter})
	renderArchitectureFrameworkCoverageDashboard(w, "", r.FrameworkCoverage)
	renderArchitectureEvidencePlanDashboard(w, r.EvidencePlan)
	renderArchitectureClosureFamiliesDashboard(w, "", r.ClosureFamilies)
	renderArchitectureClosurePlanDashboard(w, "", r.ClosurePlan)
	renderZeroTrustBoundaryCoverageDashboard(w, "", r.BoundaryCoverage, 12)
	renderArchitectureFlawGroupsDashboard(w, "", r.Groups)
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
	renderControlOperatorCasesDashboard(w, r.TargetPath, r.OperatorCases)
	renderControlBreakPathWorkstreamsDashboard(w, r.TargetPath, r.Workstreams)
	renderControlVerificationTasksDashboard(w, r.TargetPath, r.VerificationTasks)
	renderControlCatalogFamiliesDashboard(w, r.TargetPath, r.Families)
	renderControlCatalogControlsDashboard(w, r.TargetPath, r.Controls, r.ProofSpecs)
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
	renderControlOperatorCasesDashboard(w, r.TargetPath, r.OperatorCases)
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
	renderProofPlanWorkflowDashboard(w, r)
	renderProofPlanWorkbenchDashboard(w, r)
	renderControlOperatorCasesDashboard(w, r.TargetPath, r.Cases)
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
	renderCaseCompareDecisionDashboard(w, r.Decision)
	renderCaseCompareSummaryDashboard(w, r)
	renderCaseCompareOutcomeDashboard(w, r.Outcome)
	renderCaseCompareCasesDashboard(w, r.Cases)
	renderRunNotes(w, nil, r.Limitations)
	fmt.Fprintln(w, "</main>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func renderCaseCompareDecisionDashboard(w io.Writer, decision model.CaseCompareDecision) {
	if decision.Status == "" && decision.Headline == "" {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Compare Decision</h2><div class="subtle">Proof outcome derived from before and after Ariadne JSON artifacts.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Verdict", statusLabel(firstNonEmpty(decision.Status, "unknown"))},
		{"Top case", firstNonEmpty(decision.TopCaseID, "none")},
		{"Open after", fmt.Sprintf("%d", decision.AfterOpen)},
		{"Closed after", fmt.Sprintf("%d", decision.AfterClosed)},
		{"Proof patches", fmt.Sprintf("%d -> %d", decision.ProofPatchesBefore, decision.ProofPatchesAfter)},
	})
	if decision.Headline != "" {
		fmt.Fprintf(w, `<p><strong>Readout:</strong> %s</p>`, esc(decision.Headline))
	}
	if decision.BeforeState != "" || decision.AfterState != "" {
		fmt.Fprintf(w, `<p><strong>Case transition:</strong> %s -&gt; %s`, esc(firstNonEmpty(decision.BeforeState, "unknown")), esc(firstNonEmpty(decision.AfterState, "unknown")))
		if decision.TopCaseDisposition != "" {
			fmt.Fprintf(w, ` (%s)`, esc(readableToken(decision.TopCaseDisposition)))
		}
		fmt.Fprintln(w, `</p>`)
	}
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Added Controls</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.AddedControls))
	fmt.Fprintln(w, `<h3>Added Evidence Sources</h3>`)
	fmt.Fprintln(w, renderDashboardPathList("", decision.AddedEvidenceSources))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Open After Rerun</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.OpenCases))
	fmt.Fprintln(w, `<h3>Closed After Rerun</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.ClosedCases))
	fmt.Fprintln(w, `<h3>Next Action</h3>`)
	fmt.Fprintln(w, renderSmallList(nonEmptyStrings(decision.NextAction)))
	fmt.Fprintln(w, `<h3>Decision Limits</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.Limitations))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
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
.current { color: #fff; background: var(--accent); }
.pending { color: #1f2937; background: #f6d471; }
.completed { color: #fff; background: var(--low); }
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
.file-ref {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.copy-inline {
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
  color: var(--accent);
  font: inherit;
  font-size: 11px;
  font-weight: 700;
  padding: 3px 6px;
  cursor: pointer;
}
.copy-inline:hover {
  border-color: var(--accent);
}
.two-col {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 16px;
}
.action-callout {
  margin: 0 0 16px;
  padding: 14px;
  border-left: 4px solid var(--accent);
  background: #fbfcfd;
}
.action-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr);
  gap: 16px;
}
.action-label {
  margin-bottom: 4px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
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
.command-list {
  display: grid;
  gap: 8px;
}
.command-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
  align-items: start;
}
.command-row code {
  display: block;
  padding: 9px 10px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fbfcfd;
  overflow-wrap: anywhere;
}
.copy-command {
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
  color: var(--accent);
  font: inherit;
  font-size: 12px;
  font-weight: 700;
  padding: 8px 10px;
  cursor: pointer;
}
.copy-command:hover {
  border-color: var(--accent);
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
  .topbar, .grid, .two-col, .action-grid { grid-template-columns: 1fr; }
  .command-row { grid-template-columns: 1fr; }
}
</style>`)
	fmt.Fprintln(w, `<script>
document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-copy-command], [data-copy-value]");
  if (!button) return;
  var copyValue = button.getAttribute("data-command") || button.getAttribute("data-copy-value") || "";
  if (!copyValue) return;
  var done = function () {
    var previous = button.textContent;
    button.textContent = "Copied";
    setTimeout(function () { button.textContent = previous; }, 1200);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(copyValue).then(done).catch(function () {
      fallbackCopy(copyValue, done);
    });
    return;
  }
  fallbackCopy(copyValue, done);
});
function fallbackCopy(text, done) {
  var textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  try {
    if (document.execCommand("copy")) done();
  } catch (error) {
  }
  document.body.removeChild(textarea);
}
</script>`)
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
	closed := assessFirstActionClosed(r.FirstAction)
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Assessment Readout</h2><div class="subtle">Single entry point: discovered surfaces, exposure posture, architecture breaks, and closure cases.</div></div></div>`)
	if closed {
		renderMetricRow(w, []kv{
			{"Focused status", statusLabel(firstNonEmpty(r.Triage.Status, "controlled"))},
			{"Focused case", firstNonEmpty(r.Summary.TopCaseID, "none")},
			{"Missing barriers", fmt.Sprintf("%d", len(r.Triage.MissingHardBarriers))},
			{"Present barriers", fmt.Sprintf("%d", len(r.Triage.PresentHardBarriers))},
			{"Evidence refs", fmt.Sprintf("%d", len(dedupeEvidenceReferences(r.Triage.EvidenceReferences)))},
		})
	} else {
		renderMetricRow(w, []kv{
			{"Architecture breaks", fmt.Sprintf("%d breaking / %d matching", r.Summary.BreakingArchitectureFlaws, r.Summary.ArchitectureFlaws)},
			{"Operator cases", fmt.Sprintf("%d", r.Summary.OperatorCases)},
			{"Missing hard barriers", fmt.Sprintf("%d", r.Summary.MissingHardBarrierControls)},
			{"Exposure paths", fmt.Sprintf("%d exposed / %d total", r.Summary.Exposed, r.Summary.ExposurePaths)},
			{"Top case", firstNonEmpty(r.Summary.TopCaseID, "none")},
		})
	}
	if r.Summary.TopCaseNextStep != "" {
		label := "Start here"
		if closed {
			label = "Evidence state"
		}
		fmt.Fprintf(w, `<div><strong>%s:</strong> %s <span class="subtle">(%s)</span></div>`, esc(label), esc(r.Summary.TopCaseNextStep), esc(r.Summary.TopCaseTitle))
	}
	if r.CaseFilter != "" || r.ControlFilter != "" {
		fmt.Fprintf(w, `<div><strong>Focus:</strong> %s</div>`, esc(assessFocusSummary(r)))
	}
	fmt.Fprintln(w, `</section>`)
}

func renderAssessOperatorRunbookDashboard(w io.Writer, r model.AssessReport) {
	workbench := r.OperatorWorkbench
	runbook := workbench.Runbook
	if !runbook.Available {
		return
	}
	currentStep := runbook.CurrentStep
	if currentStep.ID == "" {
		return
	}
	nextStep := runbook.NextStep
	closed := runbook.Mode == "closed_case"
	subtitle := "Action-first view: open evidence, run the current proof step, and compare deterministic artifacts."
	if closed {
		subtitle = "Action-first view: inspect observed evidence and keep the focused case closed as the environment changes."
	}

	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintf(w, `<div class="section-head"><div><h2>Operator Runbook</h2><div class="subtle">%s</div></div></div>`, esc(subtitle))
	renderMetricRow(w, []kv{
		{"Current step", fmt.Sprintf("%d. %s", currentStep.Step, firstNonEmpty(currentStep.Title, currentStep.ID))},
		{"Case", firstNonEmpty(runbook.Case.ID, "not recorded")},
		{"State", firstNonEmpty(runbook.Case.State, "unknown")},
		{"Control", firstNonEmpty(runbook.CurrentControl, "not recorded")},
		{"Proof surface", firstNonEmpty(runbook.ProofSurface, "not recorded")},
	})
	renderAssessRunbookCurrentActionDashboard(w, r.TargetPath, runbook, currentStep, nextStep, r.NextCommands)
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Open First</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(r.TargetPath, runbook.OpenFirst, 5)))
	fmt.Fprintln(w, `<div class="subtle">The Source Reference Workbench below has exact rows, line labels, and inspect commands.</div>`)
	fmt.Fprintln(w, `<h3>Why This Case</h3>`)
	fmt.Fprintln(w, renderSmallList(runbook.WhyThisCase))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Do Next</h3>`)
	fmt.Fprintln(w, renderSmallList(assessRunbookStepLines(currentStep, nextStep)))
	fmt.Fprintln(w, `<h3>Files / Artifacts</h3>`)
	fmt.Fprintln(w, assessRunbookFilesArtifactsHTML(r.TargetPath, runbook.Files, runbook.Artifacts))
	fmt.Fprintln(w, `<h3>Commands</h3>`)
	fmt.Fprintln(w, renderCommandList(runbook.Commands))
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(runbook.DoneCriteria, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<h3>Closure Workflow</h3>`)
	fmt.Fprintln(w, renderSmallList(assessClosureLoopStepLines(runbook.ClosureWorkflow, 6)))
	fmt.Fprintln(w, `</section>`)
}

func renderAssessRunbookCurrentActionDashboard(w io.Writer, root string, runbook model.AssessOperatorRunbook, current model.AssessClosureLoopStep, next model.AssessClosureLoopStep, nextCommands []string) {
	commands := firstNonEmptyStrings(current.Commands, runbook.Commands)
	files := firstNonEmptyStrings(current.Files, runbook.Files)
	artifacts := firstNonEmptyStrings(current.Artifacts, runbook.Artifacts)
	doneCriteria := firstNonEmptyStrings(current.DoneCriteria, runbook.DoneCriteria)
	closureCommand := assessClosureCommandFromNextCommands(nextCommands)
	fmt.Fprintln(w, `<div class="action-callout">`)
	fmt.Fprintln(w, `<div class="action-grid">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<div class="action-label">Current Action</div>`)
	fmt.Fprintf(w, `<h3>%s</h3>`, esc(firstNonEmpty(current.Title, current.ID, "Current step")))
	if current.Summary != "" {
		fmt.Fprintf(w, `<p>%s</p>`, esc(current.Summary))
	}
	if runbook.CurrentControl != "" || runbook.ProofSurface != "" {
		fmt.Fprintln(w, renderSmallList(nonEmptyStrings(
			"Control: "+runbook.CurrentControl,
			"Proof surface: "+runbook.ProofSurface,
		)))
	}
	if next.ID != "" {
		fmt.Fprintf(w, `<p><strong>Next:</strong> %s</p>`, esc(firstNonEmpty(next.Title, next.ID)))
	}
	fmt.Fprintln(w, `<h3>Open these first</h3>`)
	renderAssessEvidenceReferenceTable(w, root, runbook.OpenFirst, 6)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<div class="action-label">Run / Save</div>`)
	if closureCommand != "" {
		fmt.Fprintln(w, `<h3>Create closure workspace</h3>`)
		fmt.Fprintln(w, renderCommandList([]string{closureCommand}))
	}
	fmt.Fprintln(w, `<h3>Current proof command</h3>`)
	fmt.Fprintln(w, renderCommandList(commands))
	fmt.Fprintln(w, `<h3>Files and artifacts</h3>`)
	fmt.Fprintln(w, assessRunbookFilesArtifactsHTML(root, files, artifacts))
	fmt.Fprintln(w, `<h3>Done when</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(doneCriteria, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
}

func assessRunbookStepLines(current model.AssessClosureLoopStep, next model.AssessClosureLoopStep) []string {
	lines := nonEmptyStrings(
		current.Title + ": " + current.Summary,
	)
	if next.ID != "" {
		lines = append(lines, next.Title+": "+next.Summary)
	}
	return lines
}

func assessRunbookFilesArtifactsHTML(root string, files []string, artifacts []string) string {
	step := model.AssessClosureLoopStep{Files: files, Artifacts: artifacts}
	out := assessClosureLoopFilesArtifactsHTML(root, step)
	if out == `<span class="subtle">none</span>` {
		return out
	}
	return out
}

func assessClosureLoopStepLines(steps []model.AssessClosureLoopStep, limit int) []string {
	var lines []string
	for _, step := range limitAssessClosureLoopSteps(steps, limit) {
		lines = append(lines, fmt.Sprintf("%d. %s (%s)", step.Step, firstNonEmpty(step.Title, step.ID), readableToken(step.Status)))
	}
	if limit > 0 && len(steps) > limit {
		lines = append(lines, fmt.Sprintf("%d additional step(s) in JSON output", len(steps)-limit))
	}
	if lines == nil {
		return []string{}
	}
	return lines
}

func limitAssessClosureLoopSteps(steps []model.AssessClosureLoopStep, limit int) []model.AssessClosureLoopStep {
	if limit <= 0 || len(steps) <= limit {
		return steps
	}
	return steps[:limit]
}

func renderAssessOperatorPacketDashboard(w io.Writer, r model.AssessReport) {
	packet := r.OperatorPacket
	if !packet.Available {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Operator Packet</h2><div class="subtle">Smallest source-backed handoff: start here, open these files, apply this proof loop, then compare.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Verdict", statusLabel(firstNonEmpty(packet.Status, "unknown"))},
		{"Case", firstNonEmpty(packet.CaseID, "not recorded")},
		{"Control", firstNonEmpty(packet.CurrentControl, "not recorded")},
		{"Proof surface", firstNonEmpty(packet.ProofSurface, "not recorded")},
		{"State", firstNonEmpty(packet.State, "unknown")},
	})
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Start Here</h3>`)
	fmt.Fprintln(w, renderSmallList(nonEmptyStrings(
		packet.CaseTitle+" ("+packet.CaseID+")",
		"Severity: "+strings.ToUpper(firstNonEmpty(packet.Severity, "unknown")),
		"Current step: "+firstNonEmpty(packet.CurrentStep, "not recorded"),
		packet.Headline,
	)))
	fmt.Fprintln(w, `<h3>Why Actionable</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(packet.WhyActionable, 4)))
	fmt.Fprintln(w, `<h3>Controls</h3>`)
	fmt.Fprintln(w, renderSmallList(nonEmptyStrings(
		"Missing: "+firstNonEmpty(strings.Join(limitStrings(packet.MissingControls, 6), "; "), "none"),
		"Observed: "+firstNonEmpty(strings.Join(limitStrings(packet.PresentControls, 5), "; "), "none"),
		"Targets: "+firstNonEmpty(strings.Join(limitStrings(packet.TargetControls, 6), "; "), "none"),
	)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Evidence To Open</h3>`)
	renderAssessEvidenceReferenceTable(w, r.TargetPath, packet.EvidenceToOpen, 6)
	fmt.Fprintln(w, `<h3>Proof Checkpoint</h3>`)
	fmt.Fprintln(w, renderSmallList(nonEmptyStrings(
		"Current state: "+firstNonEmpty(packet.ProofState.CurrentState, "unknown"),
		packet.ProofState.ClosureCondition,
		"Artifacts: "+strings.Join(nonEmptyStrings(packet.ProofState.BaselineArtifact, packet.ProofState.AfterArtifact, packet.ProofState.CompareArtifact), " -> "),
	)))
	fmt.Fprintln(w, `<h3>Commands</h3>`)
	fmt.Fprintln(w, renderCommandList(assessOperatorPacketCommandStrings(packet.Commands)))
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(packet.DoneCriteria, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessOperatorWorkbenchDashboard(w io.Writer, r model.AssessReport) {
	workbench := r.OperatorWorkbench
	if !workbench.Available {
		return
	}
	closed := workbench.Mode == "closed_case"
	heading := "Operator Workbench"
	subtitle := "Current case, exact evidence, proof surface, rerun loop, and done criteria in one place."
	if closed {
		heading = "Closed Case Operator Workbench"
		subtitle = "Focused case evidence, observed controls, rerun loop, and closure criteria in one place."
	}

	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintf(w, `<div class="section-head"><div><h2>%s</h2><div class="subtle">%s</div></div></div>`, esc(heading), esc(subtitle))
	renderMetricRow(w, []kv{
		{"Case", firstNonEmpty(workbench.Case.ID, "not recorded")},
		{"Control", firstNonEmpty(workbench.Proof.Control, firstString(workbench.Proof.Controls), "not recorded")},
		{"Proof surface", firstNonEmpty(workbench.Proof.Surface, firstString(workbench.Proof.Surfaces), "not recorded")},
		{"Evidence refs", fmt.Sprintf("%d", len(dedupeEvidenceReferences(workbench.EvidenceToOpen)))},
		{"State", firstNonEmpty(workbench.Case.State, "open")},
	})
	renderAssessWorkbenchSignalChainDashboard(w, r.TargetPath, workbench.SignalChain)
	renderAssessWorkbenchProofStateDashboard(w, workbench.ProofState)
	renderAssessClosureLoopDashboard(w, r.TargetPath, workbench.ClosureLoop)
	renderAssessWorkbenchActionChecklistDashboard(w, r.TargetPath, workbench.Actions)
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>1. Current Case</h3>`)
	fmt.Fprintln(w, renderSmallList(nonEmptyStrings(
		workbench.Case.Title+" ("+workbench.Case.ID+")",
		"Severity: "+strings.ToUpper(firstNonEmpty(workbench.Case.Severity, "unknown")),
		"State: "+firstNonEmpty(workbench.Case.State, "open"),
		"Current step: "+firstNonEmpty(workbench.Case.CurrentStep, "not recorded"),
		workbench.Case.WhyFirst,
		workbench.Case.NextStep,
	)))
	fmt.Fprintln(w, `<h3>2. Evidence To Open</h3>`)
	renderAssessEvidenceReferenceTable(w, r.TargetPath, workbench.EvidenceToOpen, 10)
	fmt.Fprintln(w, `<h3>Graph Path</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(workbench.GraphPath, 8)))
	fmt.Fprintln(w, `</div>`)

	fmt.Fprintln(w, `<div>`)
	if closed {
		fmt.Fprintln(w, `<h3>3. Observed Proof</h3>`)
	} else {
		fmt.Fprintln(w, `<h3>3. Add Or Verify Proof</h3>`)
	}
	fmt.Fprintln(w, `<div class="subtle">Proof surfaces</div>`)
	fmt.Fprintln(w, renderDashboardPathList(r.TargetPath, limitStrings(workbench.Proof.Surfaces, 8)))
	fmt.Fprintln(w, `<div class="subtle">Proof patch</div>`)
	fmt.Fprintln(w, renderDashboardHTMLList(assessWorkbenchProofHTMLLines(r.TargetPath, workbench.Proof)))
	fmt.Fprintln(w, `<div class="subtle">Accepted evidence</div>`)
	fmt.Fprintln(w, renderDashboardHTMLList(assessWorkbenchEvidenceExampleHTMLLines(r.TargetPath, workbench.Proof)))
	if len(workbench.Proof.GeneratedProofPaths) > 0 || len(workbench.Proof.ApplyCommands) > 0 || workbench.Proof.GeneratedProofPath != "" || workbench.Proof.ApplyCommand != "" {
		fmt.Fprintln(w, `<h3>Generated Proof Files</h3>`)
		fmt.Fprintln(w, renderAssessProofBundleActionTable(
			r.TargetPath,
			firstNonEmptyStrings(workbench.Proof.GeneratedProofPaths, nonEmptyStrings(workbench.Proof.GeneratedProofPath)),
			firstNonEmptyStrings(workbench.Proof.DestinationPaths, firstNonEmptyStrings(workbench.Proof.SuggestedDestinations, nonEmptyStrings(workbench.Proof.DestinationPath, workbench.Proof.SuggestedDestination))),
			firstNonEmptyStrings(workbench.Proof.ApplyCommands, nonEmptyStrings(workbench.Proof.ApplyCommand)),
		))
	}
	fmt.Fprintln(w, `<h3>4. Verify The Change</h3>`)
	fmt.Fprintln(w, renderProofLoopCommandList(workbench.Verify.Commands))
	fmt.Fprintln(w, `<h3>5. Done Criteria</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(workbench.DoneCriteria, 5)))
	fmt.Fprintln(w, `<h3>Change Readout</h3>`)
	fmt.Fprintln(w, renderSmallList(workbench.ChangeReadout))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessWorkbenchSignalChainDashboard(w io.Writer, root string, items []model.AssessSignalNoiseItem) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintln(w, `<h3>Signal Chain</h3>`)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, `<thead><tr><th>Fact</th><th>Status</th><th>Readout</th><th>Evidence</th><th>Graph / controls</th></tr></thead><tbody>`)
	for _, item := range items {
		fmt.Fprintln(w, `<tr>`)
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div></td>`, esc(readableToken(firstNonEmpty(item.Category, item.ID))), esc(item.ID))
		fmt.Fprintf(w, `<td><div class="pill %s">%s</div></td>`, cssClass(item.Disposition), esc(readableToken(item.Disposition)))
		fmt.Fprintf(w, `<td>%s%s</td>`, esc(item.Summary), dashboardSignalRiskBoundaryHTML(item))
		fmt.Fprintf(w, `<td>%s%s</td>`,
			renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)),
			dashboardSignalSourcesHTML(root, item.Sources),
		)
		fmt.Fprintf(w, `<td>%s%s%s</td>`,
			dashboardSignalGraphHTML(item.GraphEdges),
			dashboardSignalControlsHTML(item.Controls),
			dashboardSignalLimitationsHTML(item.Limitations),
		)
		fmt.Fprintln(w, `</tr>`)
	}
	fmt.Fprintln(w, `</tbody></table></div>`)
}

func dashboardSignalRiskBoundaryHTML(item model.AssessSignalNoiseItem) string {
	if item.RiskBoundary == "" {
		return ""
	}
	return `<div class="subtle">Boundary</div>` + renderSmallList([]string{item.RiskBoundary})
}

func dashboardSignalSourcesHTML(root string, sources []string) string {
	if len(sources) == 0 {
		return ""
	}
	return `<div class="subtle">Sources</div>` + renderDashboardPathList(root, limitStrings(sources, 5))
}

func dashboardSignalGraphHTML(edges []string) string {
	if len(edges) == 0 {
		return ""
	}
	return `<div class="subtle">Graph</div>` + renderDashboardHTMLList(limitStrings(edges, 4))
}

func dashboardSignalControlsHTML(controls []string) string {
	if len(controls) == 0 {
		return ""
	}
	return `<div class="subtle">Controls</div>` + renderSmallList(limitStrings(controls, 5))
}

func dashboardSignalLimitationsHTML(limitations []string) string {
	if len(limitations) == 0 {
		return ""
	}
	return `<div class="subtle">Limitations</div>` + renderSmallList(limitStrings(limitations, 2))
}

func renderAssessWorkbenchProofStateDashboard(w io.Writer, state model.AssessWorkbenchProofState) {
	if state.CurrentState == "" && len(state.TargetControls) == 0 && state.ClosureCondition == "" {
		return
	}
	fmt.Fprintln(w, `<h3>Proof State</h3>`)
	renderMetricRow(w, []kv{
		{"Current state", readableToken(firstNonEmpty(state.CurrentState, "unknown"))},
		{"Current control", firstNonEmpty(state.CurrentControl, "not recorded")},
		{"Missing controls", fmt.Sprintf("%d", len(state.CurrentMissingControls))},
		{"Target controls", fmt.Sprintf("%d", len(state.TargetControls))},
	})
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<div class="subtle">Current proof facts</div>`)
	fmt.Fprintln(w, renderSmallList(nonEmptyStrings(
		"Missing: "+firstNonEmpty(strings.Join(limitStrings(state.CurrentMissingControls, 5), "; "), "none"),
		"Observed: "+firstNonEmpty(strings.Join(limitStrings(state.CurrentPresentControls, 5), "; "), "none"),
		"Target controls: "+firstNonEmpty(strings.Join(limitStrings(state.TargetControls, 5), "; "), "none"),
		state.ClosureCondition,
	)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<div class="subtle">Before / after artifacts</div>`)
	fmt.Fprintln(w, renderSmallList(nonEmptyStrings(
		"Baseline: "+state.BaselineArtifact,
		"After: "+state.AfterArtifact,
		"Compare: "+state.CompareArtifact,
	)))
	if state.CompareCommand != "" {
		fmt.Fprintln(w, renderCommandList([]string{state.CompareCommand}))
	}
	if len(state.SuccessCriteria) > 0 {
		fmt.Fprintln(w, `<div class="subtle">Done when</div>`)
		fmt.Fprintln(w, renderSmallList(limitStrings(state.SuccessCriteria, 3)))
	}
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
}

func renderAssessClosureLoopDashboard(w io.Writer, root string, steps []model.AssessClosureLoopStep) {
	if len(steps) == 0 {
		return
	}
	fmt.Fprintln(w, `<h3>Closure Loop</h3>`)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, `<thead><tr><th>Step</th><th>Status</th><th>Action</th><th>Files / Artifacts</th><th>Commands</th><th>Done When</th></tr></thead><tbody>`)
	for _, step := range steps {
		fmt.Fprintln(w, `<tr>`)
		fmt.Fprintf(w, `<td><strong>%d</strong><div class="mono">%s</div></td>`, step.Step, esc(step.ID))
		fmt.Fprintf(w, `<td><div class="pill %s">%s</div></td>`, cssClass(step.Status), esc(readableToken(step.Status)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div>%s</div>%s</td>`, esc(step.Title), esc(step.Summary), assessClosureLoopControlsHTML(step.Controls))
		fmt.Fprintf(w, `<td>%s</td>`, assessClosureLoopFilesArtifactsHTML(root, step))
		fmt.Fprintf(w, `<td>%s</td>`, renderCommandList(step.Commands))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(step.DoneCriteria, 4)), assessClosureLoopLimitationsHTML(step.Limitations))
		fmt.Fprintln(w, `</tr>`)
	}
	fmt.Fprintln(w, `</tbody></table></div>`)
}

func assessClosureLoopControlsHTML(controls []string) string {
	if len(controls) == 0 {
		return ""
	}
	return `<div class="subtle">Controls</div>` + renderSmallList(limitStrings(controls, 4))
}

func assessClosureLoopFilesArtifactsHTML(root string, step model.AssessClosureLoopStep) string {
	var parts []string
	if len(step.Files) > 0 {
		parts = append(parts, `<div class="subtle">Files</div>`+renderDashboardActionFileList(root, limitStrings(step.Files, 5)))
	}
	if len(step.Artifacts) > 0 {
		parts = append(parts, `<div class="subtle">Artifacts</div>`+renderDashboardArtifactList(limitStrings(step.Artifacts, 5)))
	}
	if len(parts) == 0 {
		return `<span class="subtle">none</span>`
	}
	return strings.Join(parts, "")
}

func assessClosureLoopLimitationsHTML(limitations []string) string {
	if len(limitations) == 0 {
		return ""
	}
	return `<div class="subtle">Limits</div>` + renderSmallList(limitStrings(limitations, 3))
}

func renderAssessWorkbenchActionChecklistDashboard(w io.Writer, root string, actions []model.AssessWorkbenchAction) {
	if len(actions) == 0 {
		return
	}
	fmt.Fprintln(w, `<h3>Action Checklist</h3>`)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, `<thead><tr><th>Step</th><th>Status</th><th>Action</th><th>Open / Evidence</th><th>Commands</th><th>Done When</th></tr></thead><tbody>`)
	for _, action := range actions {
		fmt.Fprintln(w, `<tr>`)
		fmt.Fprintf(w, `<td><strong>%d</strong><div class="mono">%s</div></td>`, action.Step, esc(action.ID))
		fmt.Fprintf(w, `<td><div class="pill %s">%s</div></td>`, cssClass(action.Status), esc(readableToken(action.Status)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div>%s</div>%s</td>`, esc(action.Title), esc(action.Instruction), assessWorkbenchActionControlsHTML(action))
		fmt.Fprintf(w, `<td>%s</td>`, assessWorkbenchActionEvidenceHTML(root, action))
		fmt.Fprintf(w, `<td>%s</td>`, renderCommandList(action.Commands))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(action.DoneCriteria, 4)), assessWorkbenchActionLimitationsHTML(action))
		fmt.Fprintln(w, `</tr>`)
	}
	fmt.Fprintln(w, `</tbody></table></div>`)
}

func assessWorkbenchActionControlsHTML(action model.AssessWorkbenchAction) string {
	if len(action.Controls) == 0 {
		return ""
	}
	return `<div class="subtle">Controls</div>` + renderSmallList(limitStrings(action.Controls, 4))
}

func assessWorkbenchActionEvidenceHTML(root string, action model.AssessWorkbenchAction) string {
	var parts []string
	if len(action.EvidenceReferences) > 0 {
		parts = append(parts, `<div class="subtle">Evidence refs</div>`+renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, action.EvidenceReferences, 4)))
	}
	if len(action.Files) > 0 {
		parts = append(parts, `<div class="subtle">Files</div>`+renderDashboardActionFileList(root, limitStrings(action.Files, 5)))
	}
	if len(parts) == 0 {
		return `<span class="subtle">none</span>`
	}
	return strings.Join(parts, "")
}

func renderDashboardActionFileList(root string, items []string) string {
	if len(items) == 0 {
		return `<span class="subtle">none</span>`
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if isGeneratedProofArtifactPath(item) {
			out = append(out, dashboardCopyablePathLineHTML("Generated file", item))
			continue
		}
		out = append(out, dashboardFileRefHTML(root, item))
	}
	return renderDashboardHTMLList(out)
}

func isGeneratedProofArtifactPath(value string) bool {
	value = filepath.ToSlash(strings.TrimSpace(value))
	return strings.HasPrefix(value, "proof-patches/")
}

func assessWorkbenchActionLimitationsHTML(action model.AssessWorkbenchAction) string {
	if len(action.Limitations) == 0 {
		return ""
	}
	return `<div class="subtle">Limits</div>` + renderSmallList(limitStrings(action.Limitations, 3))
}

func assessWorkbenchProofHTMLLines(root string, proof model.AssessWorkbenchProof) []string {
	if proof.ProofPatch != nil {
		lines := []string{"Proof patch: " + dashboardControlProofPatchHTML(root, *proof.ProofPatch)}
		lines = append(lines, proofPlanCurrentPatchHTMLLines(root, *proof.ProofPatch, true, proof.Mode == "observed")...)
		return lines
	}
	if proof.Mode == "observed" {
		return []string{"No proof patch is needed because Ariadne already observes the hard barrier for this case."}
	}
	return []string{"No parser-recognized proof patch was returned for this action."}
}

func assessWorkbenchEvidenceExampleHTMLLines(root string, proof model.AssessWorkbenchProof) []string {
	if proof.EvidenceExample != nil {
		return []string{"Accepted evidence: " + dashboardControlEvidenceExampleHTML(root, *proof.EvidenceExample)}
	}
	return []string{"No accepted evidence example was returned for this action."}
}

func renderAssessCaseLifecycleDashboard(w io.Writer, root string, lifecycle model.AssessCaseLifecycle) {
	if !lifecycle.Available && len(lifecycle.Steps) == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Case Lifecycle</h2><div class="subtle">Open case to proof, rerun, compare, and closure using deterministic artifacts.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Case", firstNonEmpty(lifecycle.CaseID, "not recorded")},
		{"State", statusLabel(firstNonEmpty(lifecycle.CaseState, "unknown"))},
		{"Current step", firstNonEmpty(lifecycle.CurrentStepID, "none")},
		{"Steps", fmt.Sprintf("%d", len(lifecycle.Steps))},
	})
	if lifecycle.Summary != "" {
		fmt.Fprintf(w, `<p><strong>Readout:</strong> %s</p>`, esc(lifecycle.Summary))
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, `<thead><tr><th>Step</th><th>Status</th><th>What Happens</th><th>Commands / Artifacts</th><th>Evidence / Closure</th></tr></thead><tbody>`)
	for idx, step := range lifecycle.Steps {
		fmt.Fprintln(w, `<tr>`)
		fmt.Fprintf(w, `<td><strong>%d. %s</strong><div class="mono">%s</div></td>`, idx+1, esc(step.Title), esc(step.ID))
		fmt.Fprintf(w, `<td><div class="pill %s">%s</div></td>`, cssClass(step.Status), esc(readableToken(step.Status)))
		fmt.Fprintf(w, `<td>%s</td>`, esc(step.Summary))
		fmt.Fprintf(w, `<td>%s</td>`, renderAssessLifecycleCommandArtifactHTML(root, step))
		fmt.Fprintf(w, `<td>%s</td>`, renderAssessLifecycleEvidenceClosureHTML(root, step))
		fmt.Fprintln(w, `</tr>`)
	}
	fmt.Fprintln(w, `</tbody></table></div>`)
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Lifecycle Readout</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(lifecycle.Readout, 5)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Limits</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(lifecycle.Limitations, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessLifecycleCommandArtifactHTML(root string, step model.AssessCaseLifecycleStep) string {
	var parts []string
	if len(step.Commands) > 0 {
		parts = append(parts, `<h3>Commands</h3>`+renderCommandList(limitStrings(step.Commands, 4)))
	}
	if len(step.Artifacts) > 0 {
		parts = append(parts, `<h3>Artifacts</h3>`+renderDashboardArtifactList(limitStrings(step.Artifacts, 5)))
	}
	if len(step.ProofSurfaces) > 0 {
		parts = append(parts, `<h3>Surfaces</h3>`+renderDashboardPathList(root, limitStrings(step.ProofSurfaces, 5)))
	}
	if len(parts) == 0 {
		return `<span class="subtle">none</span>`
	}
	return strings.Join(parts, "")
}

func renderDashboardArtifactList(items []string) string {
	if len(items) == 0 {
		return `<span class="subtle">none</span>`
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, dashboardCopyablePathLineHTML("Artifact", item))
	}
	return renderDashboardHTMLList(lines)
}

func renderAssessLifecycleEvidenceClosureHTML(root string, step model.AssessCaseLifecycleStep) string {
	var parts []string
	if len(step.EvidenceReferences) > 0 {
		parts = append(parts, `<h3>Evidence</h3>`+renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, step.EvidenceReferences, 4)))
	}
	if len(step.Controls) > 0 {
		parts = append(parts, `<h3>Controls</h3>`+renderSmallList(limitStrings(step.Controls, 5)))
	}
	if len(step.SuccessCriteria) > 0 {
		parts = append(parts, `<h3>Done when</h3>`+renderSmallList(limitStrings(step.SuccessCriteria, 4)))
	}
	if len(step.Limitations) > 0 {
		parts = append(parts, `<h3>Limits</h3>`+renderSmallList(limitStrings(step.Limitations, 3)))
	}
	if len(parts) == 0 {
		return `<span class="subtle">none</span>`
	}
	return strings.Join(parts, "")
}

func renderAssessDecisionDashboard(w io.Writer, root string, decision model.AssessDecision) {
	if decision.Status == "" && decision.Headline == "" {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Decision Packet</h2><div class="subtle">The compact operator answer derived from deterministic facts, graph paths, controls, and proof state.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Verdict", statusLabel(firstNonEmpty(decision.Status, "unknown"))},
		{"Start here", firstNonEmpty(decision.StartHere, "none")},
		{"Severity", strings.ToUpper(firstNonEmpty(decision.CaseSeverity, "none"))},
		{"State", statusLabel(firstNonEmpty(decision.CaseState, "unknown"))},
		{"Evidence files", fmt.Sprintf("%d", len(decision.EvidenceSources))},
		{"Missing barriers", fmt.Sprintf("%d", len(decision.MissingHardBarriers))},
		{"Done criteria", fmt.Sprintf("%d", len(decision.DoneCriteria))},
	})
	if decision.Headline != "" {
		fmt.Fprintf(w, `<p><strong>Readout:</strong> %s</p>`, esc(decision.Headline))
	}
	if decision.WhyPrioritized != "" {
		fmt.Fprintf(w, `<p><strong>Why First:</strong> %s</p>`, esc(decision.WhyPrioritized))
	}
	var activeCase []string
	if decision.TopCaseID != "" {
		activeCase = append(activeCase, "Case ID: "+decision.TopCaseID)
	}
	if decision.TopCaseTitle != "" {
		activeCase = append(activeCase, "Case title: "+decision.TopCaseTitle)
	}
	if decision.CurrentControl != "" {
		activeCase = append(activeCase, "Current control: "+decision.CurrentControl)
	}
	if decision.CurrentProofSurface != "" {
		activeCase = append(activeCase, "Current proof surface: "+decision.CurrentProofSurface)
	}
	if len(activeCase) > 0 {
		fmt.Fprintln(w, `<h3>Active Case</h3>`)
		fmt.Fprintln(w, renderSmallList(activeCase))
	}
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Inspection Summary</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.InspectionSummary))
	fmt.Fprintln(w, `<h3>Risk Basis</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.RiskReasons))
	fmt.Fprintln(w, `<h3>Normal Capability</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.NormalCapabilities))
	fmt.Fprintln(w, `<h3>Path</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.PathSummary))
	fmt.Fprintln(w, `<h3>Evidence Files</h3>`)
	fmt.Fprintln(w, renderDashboardPathList(root, decision.EvidenceSources))
	fmt.Fprintln(w, `<h3>Evidence Facts</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(decisionEvidenceReferenceHTMLLines(root, decision.EvidenceReferences, 5)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Action</h3>`)
	fmt.Fprintln(w, renderSmallList(nonEmptyStrings(decision.Instruction)))
	fmt.Fprintln(w, `<h3>Missing Hard Barriers</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.MissingHardBarriers))
	fmt.Fprintln(w, `<h3>Present Hard Barriers</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.PresentHardBarriers))
	fmt.Fprintln(w, `<h3>Partial Or Friction Controls</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.PartialOrFrictionControls))
	fmt.Fprintln(w, `<h3>Unknown Evidence</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.UnknownEvidence))
	fmt.Fprintln(w, `<h3>Evidence Gap Actions</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.EvidenceGapActions))
	fmt.Fprintln(w, `<h3>Proof Surface</h3>`)
	fmt.Fprintln(w, renderDashboardPathList(root, nonEmptyStrings(decision.ProofSurface)))
	if decision.GeneratedProofPath != "" || decision.DestinationPath != "" || decision.ApplyCommand != "" {
		fmt.Fprintln(w, `<h3>Review / Apply Generated Proof</h3>`)
		fmt.Fprintln(w, renderAssessProofBundleActionTable(
			root,
			nonEmptyStrings(decision.GeneratedProofPath),
			nonEmptyStrings(firstNonEmpty(decision.DestinationPath, decision.SuggestedDestination)),
			nonEmptyStrings(decision.ApplyCommand),
		))
	}
	if len(decision.GeneratedProofPaths) > 0 || len(decision.ApplyCommands) > 0 {
		fmt.Fprintln(w, `<h3>Review / Apply Full Proof Bundle</h3>`)
		renderAssessDecisionClosureBundleDashboard(w, decision)
		fmt.Fprintln(w, renderAssessProofBundleActionTable(
			root,
			decision.GeneratedProofPaths,
			firstNonEmptyStrings(decision.DestinationPaths, decision.SuggestedDestinations),
			decision.ApplyCommands,
		))
	}
	fmt.Fprintln(w, `<h3>Commands</h3>`)
	fmt.Fprintln(w, renderCommandList(nonEmptyStrings(decision.BeforeProofCommand, decision.ProofCommand, decision.RerunCommand, decision.AfterProofCommand, decision.CompareCommand)))
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.DoneCriteria))
	fmt.Fprintln(w, `<h3>Decision Limits</h3>`)
	fmt.Fprintln(w, renderSmallList(decision.Limitations))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessDecisionClosureBundleDashboard(w io.Writer, decision model.AssessDecision) {
	if len(decision.MissingHardBarriers) <= 1 && len(decision.GeneratedProofPaths) <= 1 {
		return
	}
	if len(decision.MissingHardBarriers) > 0 {
		fmt.Fprintln(w, `<div class="subtle">Closure bundle controls</div>`)
		fmt.Fprintln(w, renderSmallList(firstStrings(uniqueStrings(decision.MissingHardBarriers), 8)))
	}
	if len(decision.GeneratedProofPaths) > 0 {
		fmt.Fprintln(w, `<div class="subtle">Closure bundle files</div>`)
		fmt.Fprintln(w, renderSmallList(firstStrings(uniqueStrings(decision.GeneratedProofPaths), 6)))
	}
	fmt.Fprintln(w, `<div class="subtle">Closure rule</div>`)
	fmt.Fprintln(w, renderSmallList([]string{"Rerun must show every bundle control is no longer a missing hard barrier for this case."}))
}

func assessFocusSummary(r model.AssessReport) string {
	var parts []string
	if r.CaseFilter != "" {
		parts = append(parts, "case="+r.CaseFilter)
	}
	if r.ControlFilter != "" {
		parts = append(parts, "control="+r.ControlFilter)
	}
	return strings.Join(parts, "; ")
}

func renderAssessSignalQualityDashboard(w io.Writer, root string, quality model.AssessSignalQuality) {
	if quality.Status == "" && quality.Summary == "" {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Signal Quality</h2><div class="subtle">Why this is actionable signal instead of ordinary agent capability.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Status", statusLabel(firstNonEmpty(quality.Status, "unknown"))},
		{"Actionable facts", fmt.Sprintf("%d", len(quality.ActionableBecause))},
		{"Expected capabilities", fmt.Sprintf("%d", len(quality.ExpectedCapabilities))},
		{"Noise filters", fmt.Sprintf("%d", len(quality.NoiseFilters))},
		{"Close/downgrade paths", fmt.Sprintf("%d", len(quality.ControlBreakpoints))},
	})
	if quality.Summary != "" {
		fmt.Fprintf(w, `<p><strong>Readout:</strong> %s</p>`, esc(quality.Summary))
	}
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Actionable Because</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(quality.ActionableBecause, 5)))
	fmt.Fprintln(w, `<h3>Expected Capability</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(quality.ExpectedCapabilities, 4)))
	fmt.Fprintln(w, `<h3>Noise Filters</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(quality.NoiseFilters, 4)))
	fmt.Fprintln(w, `<h3>Decision Rules</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(quality.DecisionRules, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Close Or Downgrade By</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(quality.ControlBreakpoints, 5)))
	fmt.Fprintln(w, `<h3>Graph Edges</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(quality.GraphEdges, 5)))
	fmt.Fprintln(w, `<h3>Evidence</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, quality.EvidenceReferences, 5)))
	fmt.Fprintln(w, `<h3>Evidence Gaps</h3>`)
	fmt.Fprintln(w, renderEvidenceGapActionList(limitStrings(quality.EvidenceGaps, 5)))
	fmt.Fprintln(w, `<h3>Limits</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(quality.Limitations, 3)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessSignalNoiseDashboard(w io.Writer, root string, signal model.AssessSignalNoise) {
	totalItems := len(signal.ExpectedCapability) + len(signal.ExposureTransition) + len(signal.ControlEvidence) + len(signal.DowngradeEvidence) + len(signal.EvidenceGaps)
	if signal.Status == "" && signal.Summary == "" && totalItems == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Signal / Noise Evidence</h2><div class="subtle">Expected capability, exposure transitions, control evidence, downgrade evidence, and gaps as separate facts.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Status", statusLabel(firstNonEmpty(signal.Status, "unknown"))},
		{"Expected", fmt.Sprintf("%d", len(signal.ExpectedCapability))},
		{"Transitions", fmt.Sprintf("%d", len(signal.ExposureTransition))},
		{"Controls", fmt.Sprintf("%d", len(signal.ControlEvidence))},
		{"Downgrade", fmt.Sprintf("%d", len(signal.DowngradeEvidence))},
		{"Gaps", fmt.Sprintf("%d", len(signal.EvidenceGaps))},
	})
	if signal.Summary != "" {
		fmt.Fprintf(w, `<p><strong>Readout:</strong> %s</p>`, esc(signal.Summary))
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, `<thead><tr><th>Bucket</th><th>Disposition</th><th>Fact</th><th>Evidence / Sources</th><th>Graph / Controls</th></tr></thead><tbody>`)
	renderAssessSignalNoiseRows(w, root, "Expected Capability", signal.ExpectedCapability)
	renderAssessSignalNoiseRows(w, root, "Exposure Transition", signal.ExposureTransition)
	renderAssessSignalNoiseRows(w, root, "Control Evidence", signal.ControlEvidence)
	renderAssessSignalNoiseRows(w, root, "Downgrade Evidence", signal.DowngradeEvidence)
	renderAssessSignalNoiseRows(w, root, "Evidence Gaps", signal.EvidenceGaps)
	fmt.Fprintln(w, `</tbody></table></div>`)
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Decision Rules</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(signal.DecisionRules, 5)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Limits</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(signal.Limitations, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessSignalNoiseRows(w io.Writer, root string, bucket string, items []model.AssessSignalNoiseItem) {
	for _, item := range items {
		fmt.Fprintln(w, `<tr>`)
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(bucket), esc(item.ID), esc(item.Category))
		fmt.Fprintf(w, `<td><div class="pill %s">%s</div></td>`, cssClass(item.Disposition), esc(readableToken(item.Disposition)))
		fmt.Fprintf(w, `<td>%s%s</td>`, esc(item.Summary), assessSignalNoiseRiskBoundaryHTML(item.RiskBoundary))
		fmt.Fprintf(w, `<td>%s</td>`, renderAssessSignalNoiseEvidenceHTML(root, item))
		fmt.Fprintf(w, `<td>%s</td>`, renderAssessSignalNoiseGraphControlHTML(item))
		fmt.Fprintln(w, `</tr>`)
	}
}

func assessSignalNoiseRiskBoundaryHTML(value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf(`<div class="subtle">%s</div>`, esc(value))
}

func renderAssessSignalNoiseEvidenceHTML(root string, item model.AssessSignalNoiseItem) string {
	var parts []string
	if len(item.EvidenceReferences) > 0 {
		parts = append(parts, `<h3>Evidence</h3>`+renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
	}
	if len(item.Sources) > 0 {
		parts = append(parts, `<h3>Sources</h3>`+renderSmallList(limitStrings(item.Sources, 5)))
	}
	if len(parts) == 0 {
		return `<span class="subtle">none</span>`
	}
	return strings.Join(parts, "")
}

func renderAssessSignalNoiseGraphControlHTML(item model.AssessSignalNoiseItem) string {
	var parts []string
	if len(item.GraphEdges) > 0 {
		parts = append(parts, `<h3>Graph</h3>`+renderSmallList(limitStrings(item.GraphEdges, 5)))
	}
	if len(item.Controls) > 0 {
		parts = append(parts, `<h3>Controls</h3>`+renderSmallList(limitStrings(item.Controls, 5)))
	}
	if len(item.Limitations) > 0 {
		parts = append(parts, `<h3>Limits</h3>`+renderSmallList(limitStrings(item.Limitations, 3)))
	}
	if len(parts) == 0 {
		return `<span class="subtle">none</span>`
	}
	return strings.Join(parts, "")
}

func renderAssessLethalTrifectaDashboard(w io.Writer, root string, trifecta model.AssessLethalTrifecta) {
	if trifecta.Summary == "" {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Lethal Trifecta</h2><div class="subtle">Private data, untrusted content, and external communication in one supported agent graph.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Status", statusLabel(string(trifecta.Status))},
		{"Present", fmt.Sprintf("%t", trifecta.Present)},
		{"Complete", fmt.Sprintf("%t", trifecta.Complete)},
		{"Protected", fmt.Sprintf("%t", trifecta.Protected)},
		{"Break controls", fmt.Sprintf("%d", len(trifecta.ControlsBreakPath))},
	})
	fmt.Fprintf(w, `<p><strong>Readout:</strong> %s</p>`, esc(trifecta.Summary))
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, `<thead><tr><th>Ingredient</th><th>Status</th><th>Graph</th><th>Evidence</th></tr></thead><tbody>`)
	for _, ingredient := range trifecta.Ingredients {
		state := "missing"
		if ingredient.Present {
			state = "present"
		}
		fmt.Fprintln(w, `<tr>`)
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(ingredient.Label), esc(ingredient.ID), esc(ingredient.Summary))
		fmt.Fprintf(w, `<td><div class="pill %s">%s</div></td>`, cssClass(state), esc(readableToken(state)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(ingredient.GraphEdges, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, ingredient.EvidenceReferences, 4)))
		fmt.Fprintln(w, `</tr>`)
	}
	fmt.Fprintln(w, `</tbody></table></div>`)
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Break Path</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(trifecta.ControlsBreakPath, 6)))
	fmt.Fprintln(w, `<h3>Decision Rules</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(trifecta.DecisionRules, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Graph Edges</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(trifecta.GraphEdges, 8)))
	fmt.Fprintln(w, `<h3>Limits</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(trifecta.Limitations, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessTriageDashboard(w io.Writer, root string, triage model.AssessTriage) {
	if triage.Status == "" && triage.Headline == "" {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Signal Triage</h2><div class="subtle">Fact-first separation of real risk, expected agent capability, missing controls, partial controls, and evidence gaps.</div></div></div>`)
	startLabel := "Start here"
	if triage.Status == "controlled" && triage.StartHere != "" && len(triage.MissingHardBarriers) == 0 {
		startLabel = "Focused case"
	}
	renderMetricRow(w, []kv{
		{"Status", statusLabel(firstNonEmpty(triage.Status, "unknown"))},
		{startLabel, firstNonEmpty(triage.StartHere, "none")},
		{"Hard signals", fmt.Sprintf("%d", len(triage.HardRiskSignals))},
		{"Signal details", fmt.Sprintf("%d", len(triage.SignalDetails))},
		{"Missing barriers", fmt.Sprintf("%d", len(triage.MissingHardBarriers))},
		{"Evidence refs", fmt.Sprintf("%d", len(dedupeEvidenceReferences(triage.EvidenceReferences)))},
	})
	if triage.Headline != "" {
		fmt.Fprintf(w, `<p><strong>Readout:</strong> %s</p>`, esc(triage.Headline))
	}
	if triage.NextAction != "" {
		fmt.Fprintf(w, `<p><strong>Next action:</strong> %s</p>`, esc(triage.NextAction))
	}
	renderAssessSignalDetailsDashboard(w, root, triage.SignalDetails)
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Hard Signal</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(triage.HardRiskSignals, 5)))
	fmt.Fprintln(w, `<h3>Normal Capability</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(triage.NormalCapabilities, 5)))
	fmt.Fprintln(w, `<h3>Evidence To Inspect</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, triage.EvidenceReferences, 5)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Missing Hard Barriers</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(triage.MissingHardBarriers, 8)))
	fmt.Fprintln(w, `<h3>Partial Or Friction Controls</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(triage.PartialOrFrictionControls, 6)))
	fmt.Fprintln(w, `<h3>Present Hard Barriers</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(triage.PresentHardBarriers, 6)))
	fmt.Fprintln(w, `<h3>Unknown Evidence</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(triage.UnknownEvidence, 5)))
	fmt.Fprintln(w, `<h3>Evidence Gap Actions</h3>`)
	fmt.Fprintln(w, renderEvidenceGapActionList(limitStrings(triage.EvidenceGapActions, 5)))
	fmt.Fprintln(w, `<h3>Proof Loop</h3>`)
	fmt.Fprintln(w, renderProofLoopCommandList(triage.ProofLoop))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessSignalDetailsDashboard(w io.Writer, root string, signals []model.AssessSignal) {
	if len(signals) == 0 {
		return
	}
	fmt.Fprintln(w, `<h3>Signal Details</h3>`)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, `<thead><tr><th>Signal</th><th>Disposition</th><th>Why it matters</th><th>Risk boundary</th><th>Graph / evidence / controls</th></tr></thead><tbody>`)
	limit := len(signals)
	if limit > 6 {
		limit = 6
	}
	for _, signal := range signals[:limit] {
		fmt.Fprintln(w, `<tr>`)
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(signal.Summary), esc(signal.ID), esc(readableToken(signal.Category)))
		fmt.Fprintf(w, `<td><div class="pill %s">%s</div></td>`, cssClass(signal.Disposition), esc(readableToken(signal.Disposition)))
		fmt.Fprintf(w, `<td>%s</td>`, esc(signal.WhyItMatters))
		fmt.Fprintf(w, `<td>%s</td>`, esc(signal.RiskBoundary))
		fmt.Fprintf(w, `<td><h3>Graph edges</h3>%s<h3>Evidence</h3>%s<h3>Controls</h3>%s<h3>Limitations</h3>%s</td>`,
			renderSmallList(limitStrings(signal.GraphEdges, 5)),
			renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, signal.EvidenceReferences, 4)),
			renderSmallList(limitStrings(signal.RelatedControls, 5)),
			renderSmallList(limitStrings(signal.Limitations, 3)))
		fmt.Fprintln(w, `</tr>`)
	}
	if len(signals) > limit {
		fmt.Fprintf(w, `<tr><td colspan="5"><span class="subtle">%d more signal detail(s) in JSON output.</span></td></tr>`, len(signals)-limit)
	}
	fmt.Fprintln(w, `</tbody></table></div>`)
}

func renderAssessClosurePlanDashboard(w io.Writer, root string, plan []model.AssessClosurePlanItem) {
	if len(plan) == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head"><div><h2>Ranked Closure Plan</h2><div class="subtle">A small proof queue distilled from the deterministic case board, so operators do not have to start from every missing control.</div></div></div>`)
	renderMetricRow(w, []kv{
		{"Plan items", fmt.Sprintf("%d", len(plan))},
		{"First control", plan[0].Control},
		{"First case", plan[0].CaseID},
		{"First severity", strings.ToUpper(plan[0].Severity)},
	})
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, `<thead><tr><th>Rank / control</th><th>Case / impact</th><th>Evidence</th><th>Proof</th><th>Rerun / done</th></tr></thead><tbody>`)
	limit := len(plan)
	if limit > 5 {
		limit = 5
	}
	for _, item := range plan[:limit] {
		fmt.Fprintln(w, `<tr>`)
		fmt.Fprintf(w, `<td><strong>#%d %s</strong><div class="pill %s">%s</div></td>`, item.Rank, esc(item.Control), cssClass(item.Severity), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div><div class="subtle">%d flaw(s), %d target(s)</div><h3>Why</h3><div>%s</div><h3>What it closes</h3><div>%s</div></td>`, esc(firstNonEmpty(item.CaseTitle, item.CaseID)), esc(item.CaseID), item.AffectedFlaws, item.AffectedTargets, esc(item.WhyThisControl), esc(item.WhatItCloses))
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td><h3>Surface</h3>%s<h3>Patch</h3>%s</td>`, renderDashboardPathList(root, nonEmptyStrings(item.ProofSurface)), renderAssessClosurePlanPatchHTML(root, item.ProofPatch))
		fmt.Fprintf(w, `<td><h3>Rerun</h3>%s<h3>Compare</h3>%s<h3>Done when</h3>%s</td>`, renderCommandList(nonEmptyStrings(item.RerunCommand)), renderCommandList(nonEmptyStrings(item.CompareCommand)), renderSmallList(limitStrings(item.DoneCriteria, 3)))
		fmt.Fprintln(w, `</tr>`)
	}
	if len(plan) > limit {
		fmt.Fprintf(w, `<tr><td colspan="5"><span class="subtle">%d more closure plan item(s) in JSON output.</span></td></tr>`, len(plan)-limit)
	}
	fmt.Fprintln(w, `</tbody></table></div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessClosurePlanPatchHTML(root string, patch *model.ControlProofPatch) string {
	if patch == nil {
		return `<span class="subtle">none</span>`
	}
	return renderDashboardHTMLList(controlProofPatchHTMLLines(root, []model.ControlProofPatch{*patch}, 1))
}

func renderAssessFirstActionDashboard(w io.Writer, root string, action model.AssessFirstAction, state model.AssessControlState) {
	if !action.Available {
		return
	}
	closed := assessFirstActionClosed(action)
	heading := "First Action"
	subtitle := "The highest-ranked operator action from deterministic case-board evidence."
	if closed {
		heading = "Closed Case Evidence"
		subtitle = "Deterministic evidence that the focused case is already controlled."
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintf(w, `<div class="section-head"><div><h2>%s</h2><div class="subtle">%s</div></div></div>`, esc(heading), esc(subtitle))
	renderMetricRow(w, []kv{
		{"Case", action.CaseID},
		{"Severity", strings.ToUpper(action.Severity)},
		{"State", firstNonEmpty(action.State, "open")},
		{"Evidence refs", fmt.Sprintf("%d", len(action.EvidenceReferences))},
		{assessActionSurfaceMetricLabel(action), fmt.Sprintf("%d", len(assessActionDashboardSurfaces(action)))},
	})
	fmt.Fprintf(w, `<h3>%s</h3>`, esc(action.Title))
	if action.WhyFirst != "" {
		fmt.Fprintf(w, `<p>%s</p>`, esc(action.WhyFirst))
	}
	if action.NextStep != "" {
		fmt.Fprintf(w, `<p><strong>Next step:</strong> %s</p>`, esc(action.NextStep))
	}
	renderAssessControlStateDashboard(w, root, state)
	renderAssessCurrentActionPacketDashboard(w, root, action)
	renderAssessWorkflowDashboard(w, root, action.Workflow)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessControlStateDashboard(w io.Writer, root string, state model.AssessControlState) {
	if !state.Available {
		return
	}
	fmt.Fprintln(w, `<h3>Control State</h3>`)
	renderMetricRow(w, []kv{
		{"Missing hard barriers", fmt.Sprintf("%d", len(state.MissingHardBarriers))},
		{"Present hard barriers", fmt.Sprintf("%d", len(state.PresentHardBarriers))},
		{"Partial controls", fmt.Sprintf("%d", len(state.PartialOrFrictionControls))},
		{"Unknown evidence", fmt.Sprintf("%d", len(state.UnknownEvidence))},
	})
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>State Summary</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(state.Summary, 4)))
	fmt.Fprintln(w, `<h3>Path To Fix</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(state.PathSummary, 7)))
	fmt.Fprintln(w, `<h3>Missing Hard Barriers</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(state.MissingHardBarriers, 6)))
	fmt.Fprintln(w, `<h3>Present Hard Barriers</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(state.PresentHardBarriers, 6)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Partial Or Friction Controls</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(state.PartialOrFrictionControls, 6)))
	fmt.Fprintln(w, `<h3>Unknown Evidence</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(state.UnknownEvidence, 4)))
	fmt.Fprintln(w, `<h3>Evidence Sources</h3>`)
	fmt.Fprintln(w, renderDashboardPathList(root, limitStrings(state.EvidenceSources, 8)))
	fmt.Fprintln(w, `<h3>Graph Edges</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(state.GraphEdges, 6)))
	fmt.Fprintln(w, `<h3>Proof Surfaces</h3>`)
	fmt.Fprintln(w, renderDashboardPathList(root, limitStrings(state.ProofSurfaces, 8)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
}

func renderAssessCurrentActionPacketDashboard(w io.Writer, root string, action model.AssessFirstAction) {
	current := action.CurrentAction
	if !current.Available {
		return
	}
	closed := assessFirstActionClosed(action)
	evidenceRefs := current.EvidenceReferences
	if len(evidenceRefs) == 0 {
		evidenceRefs = action.EvidenceReferences
	}
	proofSurfaces := assessActionDashboardSurfaces(action)
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

	if closed {
		fmt.Fprintln(w, `<h3>Evidence Packet</h3>`)
	} else {
		fmt.Fprintln(w, `<h3>Current Action Packet</h3>`)
	}
	renderMetricRow(w, []kv{
		{"Step", firstNonEmpty(current.WorkflowStepTitle, "not recorded")},
		{"Control", firstNonEmpty(current.Control, "not recorded")},
		{assessActionSurfaceSingularLabel(action), firstNonEmpty(current.Surface, "not recorded")},
		{"Proof patch", assessProofPatchMetric(current)},
		{"Evidence refs", fmt.Sprintf("%d", len(dedupeEvidenceReferences(evidenceRefs)))},
	})
	fmt.Fprintln(w, `<div class="two-col">`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Current Action</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(assessCurrentActionHTMLLines(root, current)))
	fmt.Fprintln(w, `<h3>Evidence To Inspect</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, evidenceRefs, 6)))
	fmt.Fprintf(w, `<h3>%s</h3>`, esc(assessActionControlsHeading(action)))
	fmt.Fprintln(w, renderSmallList(limitStrings(action.StartingControls, 6)))
	fmt.Fprintf(w, `<h3>%s</h3>`, esc(assessActionSurfacesHeading(action)))
	fmt.Fprintln(w, renderDashboardPathList(root, limitStrings(proofSurfaces, 6)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintf(w, `<h3>%s</h3>`, esc(assessActionProofHeading(action)))
	fmt.Fprintln(w, `<div class="subtle">Proof Patch</div>`)
	fmt.Fprintln(w, renderDashboardHTMLList(assessCurrentProofHTMLLines(root, current)))
	fmt.Fprintln(w, `<h3>Accepted Evidence</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(assessCurrentEvidenceExampleHTMLLines(root, current, action.EvidenceExamples)))
	if current.PatchExportCommand != "" {
		fmt.Fprintln(w, `<h3>Export Suggested Files</h3>`)
		fmt.Fprintln(w, `<div class="subtle">Export suggested files:</div>`)
		fmt.Fprintln(w, renderCommandList([]string{current.PatchExportCommand}))
	}
	if current.GeneratedProofPath != "" || current.DestinationPath != "" || current.ApplyCommand != "" {
		fmt.Fprintln(w, `<h3>Review / Apply Generated Proof</h3>`)
		fmt.Fprintln(w, renderAssessProofBundleActionTable(
			root,
			nonEmptyStrings(current.GeneratedProofPath),
			nonEmptyStrings(firstNonEmpty(current.DestinationPath, current.SuggestedDestination)),
			nonEmptyStrings(current.ApplyCommand),
		))
	}
	if len(action.GeneratedProofPaths) > 0 || len(action.ApplyCommands) > 0 {
		fmt.Fprintln(w, `<h3>Review / Apply Full Proof Bundle</h3>`)
		renderAssessClosureBundleDashboard(w, root, action)
		fmt.Fprintln(w, renderAssessProofBundleActionTable(
			root,
			action.GeneratedProofPaths,
			firstNonEmptyStrings(action.DestinationPaths, action.SuggestedDestinations),
			action.ApplyCommands,
		))
	}
	fmt.Fprintln(w, `<h3>Rerun</h3>`)
	fmt.Fprintln(w, renderCommandList(limitStrings(rerunCommands, 3)))
	fmt.Fprintln(w, `<h3>Compare Loop</h3>`)
	fmt.Fprintln(w, renderCommandList(limitStrings(compareCommands, 3)))
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(successCriteria, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
}

func renderAssessClosureBundleDashboard(w io.Writer, root string, action model.AssessFirstAction) {
	if len(action.ProofPatches) <= 1 {
		return
	}
	controls := proofPatchControls(action.ProofPatches)
	files := action.GeneratedProofPaths
	if len(files) == 0 {
		files = proofPatchBundleSurfaces(action.ProofPatches)
	}
	if len(controls) > 0 {
		fmt.Fprintln(w, `<div class="subtle">Closure bundle controls</div>`)
		fmt.Fprintln(w, renderSmallList(firstStrings(controls, 8)))
	}
	if len(files) > 0 {
		fmt.Fprintln(w, `<div class="subtle">Closure bundle files</div>`)
		fmt.Fprintln(w, renderSmallList(firstStrings(files, 6)))
	}
	fmt.Fprintln(w, `<div class="subtle">Closure rule</div>`)
	fmt.Fprintln(w, renderSmallList([]string{"Rerun must show every bundle control is no longer a missing hard barrier for this case."}))
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

func assessActionSurfaceMetricLabel(action model.AssessFirstAction) string {
	if assessFirstActionClosed(action) {
		return "Evidence surfaces"
	}
	return "Proof surfaces"
}

func assessActionSurfaceSingularLabel(action model.AssessFirstAction) string {
	if assessFirstActionClosed(action) {
		return "Evidence surface"
	}
	return "Proof surface"
}

func assessActionControlsHeading(action model.AssessFirstAction) string {
	if assessFirstActionClosed(action) {
		return "Observed Hard Barriers"
	}
	return "Controls To Start With"
}

func assessActionSurfacesHeading(action model.AssessFirstAction) string {
	if assessFirstActionClosed(action) {
		return "Evidence Surfaces"
	}
	return "Proof Surfaces"
}

func assessActionProofHeading(action model.AssessFirstAction) string {
	if assessFirstActionClosed(action) {
		return "Proof State"
	}
	return "Proof To Add Or Verify"
}

func assessActionDashboardSurfaces(action model.AssessFirstAction) []string {
	if assessFirstActionClosed(action) {
		return assessActionEvidenceSurfaces(action)
	}
	return append([]string{}, action.ProofSurfaces...)
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
		fmt.Fprintf(w, `<td>%s</td>`, renderCommandList(assessWorkflowProofCommandLines(step)))
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

func renderAssessClosureEvidenceDashboard(w io.Writer, root string, closure model.AssessClosureEvidence) {
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
	renderAssessClosurePathTable(w, root, closure.ControlledPaths, true)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Partial Evidence</h3>`)
	renderAssessClosurePathTable(w, root, closure.PartialPaths, false)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessClosurePathTable(w io.Writer, root string, items []model.AssessClosurePath, controlled bool) {
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
			fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
		} else {
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.PartialOrFrictionControls, 5)))
			fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.RemainingMissingHardBarriers, 5)))
			fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
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
	closed := controlOperatorCaseIsClosed(item)
	heading := "Active Case Workbench"
	subtitle := "Start with the highest-priority break path, then prove the hard barrier that closes it."
	if closed {
		heading = "Closed Case Workbench"
		subtitle = "Inspect the deterministic evidence that keeps this focused case closed."
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintf(w, `<div class="section-head"><div><h2>%s</h2><div class="subtle">%s</div></div></div>`, esc(heading), esc(subtitle))
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
	renderAssessEvidenceReferenceTable(w, r.TargetPath, item.EvidenceReferences, 6)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	if closed {
		fmt.Fprintln(w, `<h3>Observed Hard Barriers</h3>`)
	} else {
		fmt.Fprintln(w, `<h3>Controls To Start With</h3>`)
	}
	fmt.Fprintln(w, renderSmallList(limitStrings(item.StartingControls, 6)))
	if closed {
		fmt.Fprintln(w, `<h3>Control Evidence</h3>`)
	} else {
		fmt.Fprintln(w, `<h3>Control Proof Recipe</h3>`)
	}
	renderAssessControlProofRecipeTable(w, r.TargetPath, item)
	if closed {
		fmt.Fprintln(w, `<h3>Evidence Surfaces</h3>`)
	} else {
		fmt.Fprintln(w, `<h3>Proof Surfaces</h3>`)
	}
	fmt.Fprintln(w, renderDashboardPathList(r.TargetPath, limitStrings(assessOperatorCaseDashboardSurfaces(item), 8)))
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
	fmt.Fprintln(w, renderCommandList(limitStrings(assessCaseCommands(r.NextCommands, item), 4)))
	if proofPlan != nil && len(proofPlan.CompareCommands) > 0 {
		fmt.Fprintln(w, `<h3>Compare Loop</h3>`)
		fmt.Fprintln(w, renderCommandList(limitStrings(proofPlan.CompareCommands, 3)))
	}
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(item.SuccessCriteria, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</section>`)
}

func renderAssessEvidenceReferenceTable(w io.Writer, root string, refs []model.EvidenceReference, limit int) {
	rows := buildAssessSourceReferenceRows(root, refs)
	if len(rows) == 0 {
		fmt.Fprintln(w, `<div class="empty">No evidence references were returned for this case.</div>`)
		return
	}
	renderAssessSourceReferenceRowTable(w, rows, limit)
}

func renderAssessSourceReferenceRowTable(w io.Writer, rows []model.AssessSourceRefRow, limit int) {
	if len(rows) == 0 {
		fmt.Fprintln(w, `<div class="empty">No evidence references were returned for this case.</div>`)
		return
	}
	if limit <= 0 || limit > len(rows) {
		limit = len(rows)
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table class="compact-table">`)
	fmt.Fprintln(w, "<thead><tr><th>Source</th><th>Line</th><th>Kind</th><th>Fact</th><th>Inspect command</th></tr></thead><tbody>")
	for i, row := range rows[:limit] {
		fmt.Fprintf(w, `<tr id="%s">`, esc(dashboardAnchorID("evidence", fmt.Sprintf("%d-%s-%s", i+1, row.Kind, row.Source))))
		fmt.Fprintf(w, `<td>%s</td>`, dashboardSourceReferenceRowSourceHTML(row))
		fmt.Fprintf(w, `<td><span class="mono">%s</span></td>`, esc(row.Line))
		fmt.Fprintf(w, `<td>%s</td>`, esc(row.Kind))
		fmt.Fprintf(w, `<td>%s%s</td>`, esc(row.Fact), dashboardSourceReferenceMetadataBadge(row))
		fmt.Fprintf(w, `<td>%s</td>`, dashboardSourceReferenceInspectCommandHTML(row))
		fmt.Fprintln(w, "</tr>")
	}
	if len(rows) > limit {
		fmt.Fprintf(w, `<tr><td colspan="5"><span class="subtle">%d more evidence reference(s) in JSON output.</span></td></tr>`, len(rows)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func dashboardSourceReferenceRowSourceHTML(row model.AssessSourceRefRow) string {
	if row.LocalPath != "" {
		return dashboardFileRefWithLabelHTML("", row.LocalPath, firstNonEmpty(row.DisplaySource, row.Source))
	}
	return fmt.Sprintf(`<span class="mono">%s</span>`, esc(firstNonEmpty(row.DisplaySource, row.Source)))
}

func dashboardSourceReferenceMetadataBadge(row model.AssessSourceRefRow) string {
	if !row.MetadataOnly {
		return ""
	}
	return `<div class="subtle">metadata-only inspect command</div>`
}

func dashboardSourceReferenceInspectCommandHTML(row model.AssessSourceRefRow) string {
	if row.InspectCommand == "" {
		return `<span class="subtle">source is not a local file</span>`
	}
	return renderCommandList([]string{row.InspectCommand})
}

func renderAssessControlProofRecipeTable(w io.Writer, root string, item model.ControlOperatorCase) {
	if len(item.StartingControls) == 0 {
		fmt.Fprintln(w, `<div class="empty">No starting controls were returned for this case.</div>`)
		return
	}
	closed := controlOperatorCaseIsClosed(item)
	fmt.Fprintln(w, `<div class="table-wrap"><table class="compact-table">`)
	if closed {
		fmt.Fprintln(w, "<thead><tr><th>Control</th><th>Observed at</th><th>Evidence</th><th>Proof patch</th></tr></thead><tbody>")
	} else {
		fmt.Fprintln(w, "<thead><tr><th>Control</th><th>Add or verify at</th><th>Accepted evidence</th><th>Proof patch</th></tr></thead><tbody>")
	}
	for _, control := range limitStrings(item.StartingControls, 6) {
		examples := controlExamplesForControl(item.EvidenceExamples, control)
		patches := controlPatchesForControl(item.ProofPatches, control)
		surfaces := proofSurfacesForControl(item.ProofSurfaces, examples)
		refs := evidenceReferencesForControl(item.EvidenceReferences, control)
		if closed {
			surfaces = evidenceReferenceSourcesForControl(item.EvidenceReferences, control)
			if len(surfaces) == 0 {
				surfaces = assessOperatorCaseDashboardSurfaces(item)
			}
		}
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="mono">%s</span></td>`, esc(control))
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardPathList(root, limitStrings(surfaces, 4)))
		if closed {
			fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, refs, 2)))
			fmt.Fprintf(w, `<td><span class="subtle">none</span></td>`)
		} else {
			fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(controlEvidenceExampleHTMLLines(root, examples, 2)))
			fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(controlProofPatchHTMLLines(root, patches, 2)))
		}
		fmt.Fprintln(w, "</tr>")
	}
	if len(item.StartingControls) > 6 {
		fmt.Fprintf(w, `<tr><td colspan="4"><span class="subtle">%d more starting control(s) in JSON output.</span></td></tr>`, len(item.StartingControls)-6)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func assessOperatorCaseDashboardSurfaces(item model.ControlOperatorCase) []string {
	if controlOperatorCaseIsClosed(item) {
		surfaces := evidenceReferenceSources(item.EvidenceReferences, true)
		if len(surfaces) > 0 {
			return surfaces
		}
	}
	return append([]string{}, item.ProofSurfaces...)
}

func evidenceReferencesForControl(refs []model.EvidenceReference, control string) []model.EvidenceReference {
	control = strings.TrimSpace(control)
	var out []model.EvidenceReference
	for _, ref := range refs {
		if control == "" {
			continue
		}
		if ref.ID == control || strings.Contains(ref.ID, control) || strings.Contains(ref.Summary, strings.TrimPrefix(control, "control:")) {
			out = append(out, ref)
		}
	}
	return dedupeEvidenceReferences(out)
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
	if len(inventory.FactHighlights) > 0 {
		fmt.Fprintln(w, `<h3>Fact Highlights</h3>`)
		renderAssessFactHighlightTable(w, inventory.TargetPath, inventory.FactHighlights)
	}
	if len(inventory.SurfaceMap) > 0 {
		fmt.Fprintln(w, `<h3>Runtime Surface Map</h3>`)
		renderAssessSurfaceMapTable(w, inventory.SurfaceMap)
	}
	fmt.Fprintln(w, `</section>`)
}

func renderAssessFactHighlightTable(w io.Writer, root string, items []model.AssessFact) {
	if len(items) == 0 {
		fmt.Fprintln(w, `<div class="empty">No fact highlights were retained for this assessment.</div>`)
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table class="compact-table">`)
	fmt.Fprintln(w, "<thead><tr><th>Fact</th><th>Source</th><th>Evidence</th><th>Summary</th></tr></thead><tbody>")
	for _, item := range limitAssessFacts(items, 8) {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div></td>`, esc(firstNonEmpty(item.Type, "fact")), esc(firstNonEmpty(item.Runtime, item.Scope, "unknown")))
		fmt.Fprintf(w, `<td>%s</td>`, dashboardFactHighlightSourceHTML(root, item))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(nonEmptyStrings(item.EvidenceGrade, item.Redaction)))
		fmt.Fprintf(w, `<td>%s</td>`, esc(item.Summary))
		fmt.Fprintln(w, "</tr>")
	}
	if len(items) > 8 {
		fmt.Fprintf(w, `<tr><td colspan="4" class="subtle">%d additional fact highlight(s) in JSON output</td></tr>`, len(items)-8)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func dashboardFactHighlightSourceHTML(root string, item model.AssessFact) string {
	source := strings.TrimSpace(item.Source)
	if item.Target != "" {
		if source == "" {
			return fmt.Sprintf(`<span class="mono">%s</span>`, esc(item.Target))
		}
		return fmt.Sprintf(`<span class="mono">%s:%s</span>`, esc(item.Target), esc(source))
	}
	if source == "" {
		return `<span class="subtle">not recorded</span>`
	}
	return dashboardFileRefHTML(root, source)
}

func limitAssessFacts(items []model.AssessFact, limit int) []model.AssessFact {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.AssessFact{}, items[:limit]...)
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
		renderArchitectureFlawTable(w, r.TargetPath, r.Architecture.Flaws)
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
			fmt.Fprintf(w, `<td>%s</td>`, renderDashboardPathList(r.TargetPath, limitStrings(group.EvidenceSources, 6)))
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
	fmt.Fprintln(w, renderCommandList(commands))
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

func renderZeroTrustDashboard(w io.Writer, root string, z model.ZeroTrust) {
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
	renderZeroTrustBoundaryCoverageDashboard(w, root, buildArchitectureBoundaryCoverage([]architectureCoverageInput{{
		TargetID:  "target",
		ZeroTrust: z,
	}}), 8)
	renderArchitectureFlawsDashboard(w, root, z)
	fmt.Fprintln(w, `<h3>Boundary Checks</h3>`)
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Boundary</th><th>Finding</th><th>Evidence</th><th>Graph / Control</th><th>Next action</th></tr></thead><tbody>")
	for _, check := range z.Checks {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(check.Status)), esc(statusLabel(string(check.Status))))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(check.Boundary), esc(check.Principle), esc(check.ID), esc(check.Tier))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%s</div></td>`, esc(check.Finding), esc(check.DesignTest))
		fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustEvidence(root, check.Evidence))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(check.GraphEdges, 4)), renderControlLine(check.Controls))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(check.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	renderZeroTrustMaturity(w, root, z.Maturity)
	renderZeroTrustCoverage(w, z.Coverage)
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureFlawsDashboard(w io.Writer, root string, z model.ZeroTrust) {
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
		fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustEvidence(root, flaw.Evidence))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(flaw.GraphEdges, 4)), renderControlLine(flaw.Controls))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(flaw.ControlEvidenceNeeded, 6)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Next action</h3>%s</td>`, renderDashboardPathList(root, limitStrings(flaw.EvidenceSurfaces, 4)), renderSmallList(limitStrings(flaw.Actions, 3)))
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

func renderArchitectureFrameworkCoverageDashboard(w io.Writer, root string, items []model.ArchitectureFrameworkArea) {
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
		fmt.Fprintf(w, `<td>%s%s</td>`, renderDashboardPathList(root, limitStrings(item.EvidenceSources, 6)), renderControlLine(limitStrings(item.Controls, 5)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Flaws, 5)))
		fmt.Fprintf(w, `<td><h3>Control evidence needed</h3>%s<h3>Missing evidence</h3>%s<h3>Next collectors</h3>%s</td>`, renderSmallList(limitStrings(item.ControlEvidenceNeeded, 6)), renderSmallList(limitStrings(item.MissingEvidence, 5)), renderSmallList(limitStrings(item.NextCollectors, 3)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.Limitations, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureFlawTableDashboard(w io.Writer, root string, flaws []model.ZeroTrustArchitecture) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Architecture Failure Map</h2><div class="subtle">Each row states the boundary break, the evidence anchor, and the hard barrier needed to close it.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(flaws) == 0 {
		fmt.Fprintln(w, `<div class="empty">No architecture flaws matched this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	renderArchitectureFlawTable(w, root, flaws)
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureClosurePlanDashboard(w io.Writer, root string, items []model.ArchitectureClosure) {
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
		fmt.Fprintf(w, `<td><h3>Anchors</h3>%s<h3>References</h3>%s</td>`, renderDashboardPathList(root, limitStrings(item.EvidenceSources, 6)), renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Actions</h3>%s</td>`, renderDashboardPathList(root, limitStrings(item.EvidenceSurfaces, 5)), renderSmallList(limitStrings(item.Actions, 3)))
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
		fmt.Fprintf(w, `<td><h3>%s</h3>%s<h3>%s</h3>%s<h3>New Control IDs</h3>%s<h3>Removed Control IDs</h3>%s</td>`,
			esc(caseCompareControlsLabel("before", item.BeforeState)),
			renderSmallList(item.BeforeControls),
			esc(caseCompareControlsLabel("after", item.AfterState)),
			renderSmallList(item.AfterControls),
			renderSmallList(item.AddedControls),
			renderSmallList(item.RemovedControls),
		)
		fmt.Fprintf(w, `<td><h3>Proof patches</h3><div>%d -> %d</div><h3>Evidence refs</h3><div>%d -> %d</div><h3>After evidence</h3>%s<h3>Added evidence</h3>%s<h3>Removed evidence</h3>%s</td>`,
			item.BeforeProofPatches,
			item.AfterProofPatches,
			item.BeforeEvidenceRefs,
			item.AfterEvidenceRefs,
			renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines("", item.AfterEvidence, 3)),
			renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines("", item.AddedEvidence, 3)),
			renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines("", item.RemovedEvidence, 3)),
		)
		fmt.Fprintf(w, `<td>%s<h3>After rerun</h3>%s<h3>After compare loop</h3>%s</td>`,
			esc(firstNonEmpty(item.AfterNextStep, "none")),
			renderCommandList(limitStrings(item.AfterRerunCommands, 2)),
			renderCommandList(limitStrings(item.AfterCompareCommands, 3)),
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
		proofBundle := proofPlanClosureBundleHTML(item.ProofPatches, r.PatchExportCommand)
		fmt.Fprintf(w, `<tr id="%s">`, esc(dashboardAnchorID("workbench", item.ID)))
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span><h3>%s</h3><div class="mono">%s</div><div class="subtle">%s</div><h3>Next step</h3><div>%s</div></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)), esc(item.Title), esc(item.ID), esc(item.StateReason), esc(item.NextStep))
		fmt.Fprintf(w, `<td><h3>Evidence references</h3>%s<h3>Proof surfaces</h3>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(r.TargetPath, item.EvidenceReferences, 5)), renderDashboardPathList(r.TargetPath, limitStrings(item.ProofSurfaces, 6)))
		fmt.Fprintf(w, `<td><h3>%s</h3>%s%s<h3>Evidence payload</h3>%s</td>`, esc(controlLabel), renderSmallList(limitStrings(item.StartingControls, 5)), proofBundle, renderProofPatchPayloads(item.ProofPatches, 3))
		fmt.Fprintf(w, `<td><h3>Rerun</h3>%s<h3>Done when</h3>%s<h3>Limits</h3>%s</td>`, renderCommandList(limitStrings(item.RerunCommands, 3)), renderSmallList(limitStrings(item.SuccessCriteria, 4)), renderSmallList(limitStrings(item.Limitations, 2)))
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
	renderProofPlanClosureBundleDashboard(w, r.ProofPatches, r.PatchExportCommand)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div>`)
	fmt.Fprintln(w, `<h3>Proof To Add Or Verify</h3>`)
	fmt.Fprintln(w, renderDashboardHTMLList(proofPlanCurrentPatchHTMLLines(r.TargetPath, patch, hasPatch, hasCase && controlOperatorCaseIsClosed(item))))
	if r.PatchExportCommand != "" {
		fmt.Fprintln(w, `<h3>Export Suggested Files</h3>`)
		fmt.Fprintln(w, renderCommandList([]string{r.PatchExportCommand}))
	}
	fmt.Fprintln(w, `<h3>Rerun</h3>`)
	fmt.Fprintln(w, renderCommandList(limitStrings(rerunCommands, 3)))
	fmt.Fprintln(w, `<h3>Compare Loop</h3>`)
	fmt.Fprintln(w, renderCommandList(limitStrings(r.CompareCommands, 3)))
	fmt.Fprintln(w, `<h3>Done When</h3>`)
	fmt.Fprintln(w, renderSmallList(limitStrings(successCriteria, 4)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, "</section>")
}

func renderProofPlanClosureBundleDashboard(w io.Writer, patches []model.ControlProofPatch, patchExportCommand string) {
	if block := proofPlanClosureBundleHTML(patches, patchExportCommand); block != "" {
		fmt.Fprintln(w, block)
	}
}

func proofPlanClosureBundleHTML(patches []model.ControlProofPatch, patchExportCommand string) string {
	return closureBundleHTML("Closure bundle files", proofPatchControls(patches), proofPlanClosureBundleFiles(patches, patchExportCommand))
}

func controlOperatorCaseClosureBundleHTML(item model.ControlOperatorCase) string {
	return closureBundleHTML("Closure bundle surfaces", proofPatchControls(item.ProofPatches), proofPatchBundleSurfaces(item.ProofPatches))
}

func closureBundleHTML(fileLabel string, controls []string, files []string) string {
	controls = uniqueStrings(controls)
	files = uniqueStrings(files)
	if len(controls) <= 1 && len(files) <= 1 {
		return ""
	}
	var b strings.Builder
	if len(controls) > 0 {
		b.WriteString(`<h3>Closure Bundle Controls</h3>`)
		b.WriteString(renderSmallList(firstStrings(controls, 8)))
	}
	if len(files) > 0 {
		b.WriteString(`<h3>`)
		b.WriteString(esc(fileLabel))
		b.WriteString(`</h3>`)
		b.WriteString(renderSmallList(firstStrings(files, 6)))
	}
	b.WriteString(`<h3>Closure Rule</h3>`)
	b.WriteString(renderSmallList([]string{"Rerun must show every bundle control is no longer a missing hard barrier for this case."}))
	return b.String()
}

func proofPlanClosureBundleFiles(patches []model.ControlProofPatch, patchExportCommand string) []string {
	surfaces := proofPatchBundleSurfaces(patches)
	exportDir := proofPatchExportDirFromCommand(patchExportCommand)
	if exportDir == "" {
		return surfaces
	}
	var out []string
	for _, surface := range surfaces {
		out = append(out, filepath.Clean(filepath.Join(exportDir, proofPatchExportSurfaceRelPath(surface))))
	}
	return uniqueStrings(out)
}

func renderProofPlanWorkflowDashboard(w io.Writer, r model.ProofPlanReport) {
	if len(r.Workflow) == 0 {
		return
	}
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Proof Workflow</h2><div class="subtle">Run the loop in this order: baseline, evidence, rerun, compare, done criteria.</div></div>`)
	fmt.Fprintln(w, "</div>")
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Step</th><th>What it does</th><th>Commands</th><th>Evidence / surfaces</th><th>Done when</th></tr></thead><tbody>")
	for i, step := range r.Workflow {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><strong>%d. %s</strong><div class="mono">%s</div></td>`, i+1, esc(firstNonEmpty(step.Title, step.ID)), esc(step.ID))
		fmt.Fprintf(w, `<td>%s%s</td>`, esc(step.Summary), renderWorkflowLimitations(step.Limitations))
		fmt.Fprintf(w, `<td>%s</td>`, renderCommandList(limitStrings(step.Commands, 4)))
		fmt.Fprintf(w, `<td><h3>Evidence</h3>%s<h3>Surfaces</h3>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(r.TargetPath, step.EvidenceReferences, 4)), renderDashboardPathList(r.TargetPath, limitStrings(step.ProofSurfaces, 5)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(step.SuccessCriteria, 4)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderWorkflowLimitations(limitations []string) string {
	if len(limitations) == 0 {
		return ""
	}
	return `<h3>Limit</h3>` + renderSmallList(limitStrings(limitations, 2))
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

func decisionEvidenceReferenceHTMLLines(root string, refs []model.EvidenceReference, limit int) []string {
	refs = rankEvidenceReferencesForOperator(refs)
	if len(refs) == 0 {
		return []string{}
	}
	total := len(refs)
	if limit > 0 && len(refs) > limit {
		refs = refs[:limit]
	}
	out := make([]string, 0, len(refs)+1)
	for _, ref := range refs {
		out = append(out, dashboardEvidenceReferenceHTML(root, ref))
	}
	if limit > 0 && total > limit {
		out = append(out, fmt.Sprintf("%d additional evidence reference(s) in JSON", total-limit))
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
		fmt.Fprintf(w, `<td><h3>Rerun</h3>%s<h3>Done when</h3>%s<h3>Limit</h3>%s</td>`, renderCommandList(limitStrings(patch.RerunCommands, 2)), renderSmallList(limitStrings(patch.SuccessCriteria, 3)), renderSmallList(limitStrings(patch.Limitations, 1)))
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
	fmt.Fprintln(w, renderCommandList(limitStrings(r.RerunCommands, 6)))
	fmt.Fprintln(w, `</div>`)
	fmt.Fprintln(w, `<div><h3>Export Suggested Files</h3>`)
	fmt.Fprintln(w, renderCommandList(nonEmptyStrings(r.PatchExportCommand)))
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
	fmt.Fprintln(w, renderCommandList(limitStrings(r.CompareCommands, 6)))
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

func renderControlOperatorCasesDashboard(w io.Writer, root string, cases []model.ControlOperatorCase) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Operator Cases</h2><div class="subtle">A smaller action layer that connects architecture breakage, evidence references, evidence or proof surfaces, proof patches, rerun criteria, and compare-loop commands.</div></div>`)
	fmt.Fprintln(w, "</div>")
	if len(cases) == 0 {
		fmt.Fprintln(w, `<div class="empty">No operator cases were returned for this status filter.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Severity</th><th>Case</th><th>State / next step</th><th>Why it exists</th><th>Evidence references</th><th>Start with</th><th>Evidence / proof</th><th>Export / rerun / done when</th></tr></thead><tbody>")
	limit := len(cases)
	if limit > 10 {
		limit = 10
	}
	for _, item := range cases[:limit] {
		surfaceHeading := "Proof surfaces"
		exampleHeading := "Evidence examples"
		surfaces := item.ProofSurfaces
		if controlOperatorCaseIsClosed(item) {
			surfaceHeading = "Evidence surfaces"
			exampleHeading = "Observed evidence"
			surfaces = assessOperatorCaseDashboardSurfaces(item)
		}
		fmt.Fprintf(w, `<tr id="%s">`, esc(dashboardAnchorID("case", item.ID)))
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(item.Severity), esc(strings.ToUpper(item.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="mono">%s</div><div class="subtle">%d control(s), %d flaw(s), %d target(s)</div></td>`, esc(controlOperatorCaseDisplayTitle(item)), esc(item.ID), item.ControlCount, item.FlawCount, item.TargetCount)
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><h3>Priority</h3><div>%s</div><h3>Next step</h3><div>%s</div></td>`, esc(firstNonEmpty(item.State, "open")), esc(item.StateReason), esc(item.PriorityReason), esc(item.NextStep))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%s</div></td>`, esc(item.Question), esc(item.Finding))
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderOperatorCaseStartCell(item))
		fmt.Fprintf(w, `<td><h3>%s</h3>%s%s<h3>Proof patches</h3>%s<h3>%s</h3>%s</td>`, esc(surfaceHeading), renderDashboardPathList(root, limitStrings(surfaces, 6)), controlOperatorCaseClosureBundleHTML(item), renderDashboardHTMLList(controlProofPatchHTMLLines(root, item.ProofPatches, 2)), esc(exampleHeading), renderDashboardHTMLList(controlEvidenceExampleHTMLLines(root, item.EvidenceExamples, 2)))
		fmt.Fprintf(w, `<td>%s<h3>Rerun</h3>%s<h3>Compare loop</h3>%s<h3>Done when</h3>%s</td>`, renderOperatorCaseExportCommandBlock(item), renderCommandList(limitStrings(item.RerunCommands, 2)), renderCommandList(limitStrings(item.CompareCommands, 3)), renderSmallList(limitStrings(item.SuccessCriteria, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(cases) > limit {
		fmt.Fprintf(w, `<tr><td colspan="8"><span class="subtle">%d more operator cases in JSON output.</span></td></tr>`, len(cases)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderOperatorCaseExportCommandBlock(item model.ControlOperatorCase) string {
	if item.PatchExportCommand == "" {
		return ""
	}
	return `<h3>Export proof files</h3>` + renderCommandList([]string{item.PatchExportCommand})
}

func renderOperatorCaseStartCell(item model.ControlOperatorCase) string {
	out := renderSmallList(limitStrings(item.StartingControls, 5))
	taskIDs := strings.Join(limitStrings(item.StartingTaskIDs, 5), ", ")
	if taskIDs != "" {
		out += fmt.Sprintf(`<div class="mono">%s</div>`, esc(taskIDs))
	}
	return out
}

func renderControlBreakPathWorkstreamsDashboard(w io.Writer, root string, workstreams []model.ControlBreakPathWorkstream) {
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
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardPathList(root, limitStrings(item.ProofSurfaces, 6)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(item.SuccessCriteria, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(workstreams) > limit {
		fmt.Fprintf(w, `<tr><td colspan="7"><span class="subtle">%d more workstreams in JSON output.</span></td></tr>`, len(workstreams)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderControlVerificationTasksDashboard(w io.Writer, root string, tasks []model.ControlVerificationTask) {
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
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, task.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardPathList(root, limitStrings(task.ProofSurfaces, 6)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(task.RecognizedIndicators, 8)))
		fmt.Fprintf(w, `<td><h3>Patch</h3>%s<h3>Examples</h3>%s</td>`, renderDashboardHTMLList(controlProofPatchHTMLLines(root, task.ProofPatches, 2)), renderDashboardHTMLList(controlEvidenceExampleHTMLLines(root, task.EvidenceExamples, 2)))
		fmt.Fprintf(w, `<td><h3>Rerun</h3>%s<h3>Done when</h3>%s</td>`, renderCommandList(limitStrings(task.RerunCommands, 2)), renderSmallList(limitStrings(task.SuccessCriteria, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	if len(tasks) > limit {
		fmt.Fprintf(w, `<tr><td colspan="8"><span class="subtle">%d more verification tasks in JSON output.</span></td></tr>`, len(tasks)-limit)
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderControlCatalogFamiliesDashboard(w io.Writer, root string, items []model.ArchitectureClosureFamily) {
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
		fmt.Fprintf(w, `<td><h3>Proof surfaces</h3>%s<h3>Evidence anchors</h3>%s<h3>Evidence references</h3>%s</td>`, renderDashboardPathList(root, limitStrings(item.EvidenceSurfaces, 6)), renderDashboardPathList(root, limitStrings(item.EvidenceSources, 6)), renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderControlCatalogControlsDashboard(w io.Writer, root string, items []model.ArchitectureClosure, proofSpecs []model.ControlProofSpec) {
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
		fmt.Fprintf(w, `<td><h3>Anchors</h3>%s<h3>References</h3>%s</td>`, renderDashboardPathList(root, limitStrings(item.EvidenceSources, 6)), renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardPathList(root, limitStrings(item.EvidenceSurfaces, 6)))
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

func renderArchitectureClosureFamiliesDashboard(w io.Writer, root string, items []model.ArchitectureClosureFamily) {
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
		fmt.Fprintf(w, `<td><h3>Anchors</h3>%s<h3>References</h3>%s</td>`, renderDashboardPathList(root, limitStrings(item.EvidenceSources, 6)), renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, item.EvidenceReferences, 4)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Actions</h3>%s</td>`, renderDashboardPathList(root, limitStrings(item.EvidenceSurfaces, 5)), renderSmallList(limitStrings(item.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	fmt.Fprintln(w, "</section>")
}

func renderArchitectureFlawTable(w io.Writer, root string, flaws []model.ZeroTrustArchitecture) {
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Architecture flaw</th><th>Control test</th><th>Evidence anchors</th><th>Graph / observed controls</th><th>Breaks when</th><th>Evidence surfaces / next action</th></tr></thead><tbody>")
	for _, flaw := range flaws {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span><div class="pill %s">%s</div></td>`, cssClass(string(flaw.Status)), esc(statusLabel(string(flaw.Status))), cssClass(flaw.Severity), esc(strings.ToUpper(flaw.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div><div class="subtle">%s</div><div class="subtle">%s</div></td>`, esc(flaw.Title), esc(flaw.Principle), esc(flaw.ID), esc(strings.Join(flaw.Boundaries, ", ")), esc(flaw.Finding))
		fmt.Fprintf(w, `<td>%s</td>`, renderArchitectureControlTest(flaw.ControlTest))
		fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustEvidence(root, flaw.Evidence))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(flaw.GraphEdges, 4)), renderControlLine(flaw.Controls))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(flaw.ControlEvidenceNeeded, 6)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Next action</h3>%s</td>`, renderDashboardPathList(root, limitStrings(flaw.EvidenceSurfaces, 5)), renderSmallList(limitStrings(flaw.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
}

func renderZeroTrustBoundaryCoverageDashboard(w io.Writer, root string, boundaries []model.ArchitectureBoundary, limit int) {
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
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardPathList(root, limitStrings(boundary.EvidenceSources, 5)))
		fmt.Fprintf(w, `<td><h3>Missing evidence</h3>%s<h3>Next collectors</h3>%s</td>`, renderSmallList(limitStrings(boundary.MissingEvidence, 5)), renderSmallList(limitStrings(boundary.NextCollectors, 3)))
		fmt.Fprintf(w, `<td><h3>Controls observed</h3>%s<h3>Evidence needed</h3>%s</td>`, renderSmallList(limitStrings(boundary.Controls, 5)), renderSmallList(limitStrings(boundary.ControlEvidenceNeeded, 6)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	if len(boundaries) > limit {
		fmt.Fprintf(w, `<div class="subtle">%d boundary coverage rows omitted from this HTML view. JSON output contains the full set.</div>`, len(boundaries)-limit)
	}
}

func renderZeroTrustMaturity(w io.Writer, root string, maturity model.ZeroTrustMaturity) {
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
		fmt.Fprintf(w, `<td>%s%s</td>`, renderZeroTrustEvidence(root, req.Evidence), renderControlLine(req.Controls))
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
	renderZeroTrustBoundaryCoverageDashboard(w, "", buildArchitectureBoundaryCoverage(coverageInputs), 10)
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

func renderArchitectureFlawGroupsDashboard(w io.Writer, root string, groups []model.ArchitectureFlawGroup) {
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
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardPathList(root, limitStrings(group.EvidenceSources, 6)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(group.ControlEvidenceNeeded, 6)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Actions</h3>%s</td>`, renderDashboardPathList(root, limitStrings(group.EvidenceSurfaces, 5)), renderSmallList(limitStrings(group.Actions, 3)))
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

func renderZeroTrustEvidence(root string, evidence []model.ZeroTrustEvidence) string {
	if len(evidence) == 0 {
		return `<span class="subtle">No direct evidence mapped.</span>`
	}
	var b strings.Builder
	b.WriteString(`<ul class="list">`)
	for _, item := range limitEvidence(evidence, 5) {
		b.WriteString("<li>")
		if item.Source != "" {
			label := evidenceReferenceSourceLabel(item.Source, model.EvidenceReference{
				Source:    item.Source,
				LineStart: item.LineStart,
				LineEnd:   item.LineEnd,
			})
			b.WriteString(dashboardFileRefWithLabelHTML(root, item.Source, label))
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

func renderExposureSection(w io.Writer, root string, exposures []model.ExposureResult) {
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
		fmt.Fprintf(w, `<td>%s</td>`, renderDashboardHTMLList(proofPlanEvidenceReferenceHTMLLines(root, exposure.EvidenceReferences, 4)))
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

func renderCommandList(commands []string) string {
	commands = nonEmptyStrings(commands...)
	if len(commands) == 0 {
		return `<span class="subtle">none</span>`
	}
	var b strings.Builder
	b.WriteString(`<div class="command-list">`)
	for _, command := range commands {
		if isLimitSummary(command) {
			fmt.Fprintf(&b, `<div class="subtle">%s</div>`, esc(command))
			continue
		}
		b.WriteString(`<div class="command-row">`)
		fmt.Fprintf(&b, `<code class="mono">%s</code>`, esc(command))
		fmt.Fprintf(&b, `<button type="button" class="copy-command" data-copy-command data-command="%s">Copy</button>`, esc(command))
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func renderAssessProofBundleActionTable(root string, generated []string, destinations []string, commands []string) string {
	generated = nonEmptyStrings(generated...)
	destinations = nonEmptyStrings(destinations...)
	commands = nonEmptyStrings(commands...)
	rows := maxDashboardRowCount(len(generated), len(destinations), len(commands))
	if rows == 0 {
		return `<span class="subtle">none</span>`
	}
	var b strings.Builder
	b.WriteString(`<div class="subtle">Proof Bundle Actions</div>`)
	b.WriteString(`<div class="table-wrap"><table class="compact-table">`)
	b.WriteString(`<thead><tr><th>Generated Artifact</th><th>Suggested Destination</th><th>Apply Command</th></tr></thead><tbody>`)
	for idx := 0; idx < rows; idx++ {
		b.WriteString(`<tr>`)
		fmt.Fprintf(&b, `<td>%s</td>`, dashboardGeneratedArtifactHTML(generated, idx))
		fmt.Fprintf(&b, `<td>%s</td>`, dashboardSuggestedDestinationHTML(root, destinations, idx))
		fmt.Fprintf(&b, `<td>%s</td>`, renderCommandList(stringAt(commands, idx)))
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

func dashboardGeneratedArtifactHTML(values []string, idx int) string {
	value := firstStringAt(values, idx)
	if value == "" {
		return `<span class="subtle">none</span>`
	}
	return dashboardCopyablePathLineHTML("Generated file", value)
}

func dashboardSuggestedDestinationHTML(root string, values []string, idx int) string {
	value := firstStringAt(values, idx)
	if value == "" {
		return `<span class="subtle">none</span>`
	}
	ref := dashboardFileRefWithLabelHTML(root, value, dashboardRelativePathLabel(root, value))
	if ref == "" {
		return dashboardCopyablePathLineHTML("Suggested destination", value)
	}
	return "Suggested destination: " + ref
}

func dashboardCopyablePathLineHTML(label string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return `<span class="subtle">none</span>`
	}
	line := strings.TrimSpace(label + ": " + value)
	return fmt.Sprintf(
		`<span class="file-ref"><span class="mono">%s</span><button type="button" class="copy-inline" data-copy-value="%s">Copy path</button></span>`,
		esc(line),
		esc(value),
	)
}

func maxDashboardRowCount(values ...int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func firstStringAt(values []string, idx int) string {
	if idx < 0 || idx >= len(values) {
		return ""
	}
	return values[idx]
}

func stringAt(values []string, idx int) []string {
	value := firstStringAt(values, idx)
	if value == "" {
		return []string{}
	}
	return []string{value}
}

func renderProofLoopCommandList(values []string) string {
	values = nonEmptyStrings(values...)
	if len(values) == 0 {
		return `<span class="subtle">none</span>`
	}
	var b strings.Builder
	b.WriteString(`<div class="command-list">`)
	for _, value := range values {
		label, command, ok := proofLoopCommandParts(value)
		if !ok {
			fmt.Fprintf(&b, `<div class="subtle">%s</div>`, esc(value))
			continue
		}
		b.WriteString(`<div class="command-row">`)
		b.WriteString(`<div>`)
		if label != "" {
			fmt.Fprintf(&b, `<div class="subtle">%s</div>`, esc(label))
		}
		fmt.Fprintf(&b, `<code class="mono">%s</code>`, esc(command))
		b.WriteString(`</div>`)
		fmt.Fprintf(&b, `<button type="button" class="copy-command" data-copy-command data-command="%s">Copy</button>`, esc(command))
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func proofLoopCommandParts(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	idx := strings.Index(value, ": ")
	if idx < 0 {
		return "", "", false
	}
	label := strings.TrimSpace(value[:idx])
	command := strings.TrimSpace(value[idx+2:])
	if command == "" {
		return "", "", false
	}
	return label, command, true
}

func renderEvidenceGapActionList(actions []string) string {
	actions = nonEmptyStrings(actions...)
	if len(actions) == 0 {
		return `<span class="subtle">none</span>`
	}
	var b strings.Builder
	b.WriteString(`<ul class="list">`)
	for _, action := range actions {
		label, command := splitEvidenceGapActionCommand(action)
		b.WriteString("<li>")
		if command == "" {
			b.WriteString(esc(label))
		} else {
			fmt.Fprintf(&b, `<div>%s</div>`, esc(label))
			b.WriteString(renderCommandList([]string{command}))
		}
		b.WriteString("</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func splitEvidenceGapActionCommand(action string) (string, string) {
	action = strings.TrimSpace(action)
	marker := ": " + ariadneCommand() + " "
	idx := strings.Index(action, marker)
	if idx < 0 {
		return action, ""
	}
	return strings.TrimSpace(action[:idx]), strings.TrimSpace(action[idx+2:])
}

func isLimitSummary(value string) bool {
	return strings.HasSuffix(strings.TrimSpace(value), " additional items in JSON")
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
	values = rankEvidenceReferencesForOperator(values)
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
	label := evidenceReferenceSourceLabel(source, value)
	prefix := dashboardFileRefWithLabelHTML(root, source, label)
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

func controlEvidenceExampleHTMLLines(root string, examples []model.ControlEvidenceExample, limit int) []string {
	if limit <= 0 || limit > len(examples) {
		limit = len(examples)
	}
	out := make([]string, 0, limit+1)
	for _, example := range examples[:limit] {
		out = append(out, dashboardControlEvidenceExampleHTML(root, example))
	}
	if len(examples) > limit {
		out = append(out, esc(fmt.Sprintf("%d additional example(s) in JSON output", len(examples)-limit)))
	}
	if out == nil {
		return []string{}
	}
	return out
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

func controlProofPatchHTMLLines(root string, patches []model.ControlProofPatch, limit int) []string {
	if limit <= 0 || limit > len(patches) {
		limit = len(patches)
	}
	out := make([]string, 0, limit+1)
	for _, patch := range patches[:limit] {
		out = append(out, dashboardControlProofPatchHTML(root, patch))
	}
	if len(patches) > limit {
		out = append(out, esc(fmt.Sprintf("%d additional proof patch(es) in JSON output", len(patches)-limit)))
	}
	if out == nil {
		return []string{}
	}
	return out
}

func dashboardFileRefHTML(root, value string) string {
	return dashboardFileRefWithLabelHTML(root, value, value)
}

func dashboardFileRefWithLabelHTML(root, value, label string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	path := dashboardFilePath(root, value)
	if path == "" {
		if dashboardLooksLikeLocalPath(value) {
			return fmt.Sprintf(
				`<span class="file-ref"><span class="mono">%s</span><button type="button" class="copy-inline" data-copy-value="%s">Copy path</button></span>`,
				esc(firstNonEmpty(label, value)),
				esc(value),
			)
		}
		return fmt.Sprintf(`<span class="mono">%s</span>`, esc(firstNonEmpty(label, value)))
	}
	href := (&url.URL{Scheme: "file", Path: path}).String()
	return fmt.Sprintf(
		`<span class="file-ref"><a class="file-link mono" href="%s">%s</a><button type="button" class="copy-inline" data-copy-value="%s">Copy path</button></span>`,
		esc(href),
		esc(firstNonEmpty(label, value)),
		esc(path),
	)
}

func dashboardFileHref(root, value string) string {
	path := dashboardFilePath(root, value)
	if path == "" {
		return ""
	}
	return (&url.URL{Scheme: "file", Path: path}).String()
}

func dashboardFilePath(root, value string) string {
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
	return path
}

func dashboardRelativePathLabel(root, value string) string {
	value = strings.TrimSpace(value)
	path := dashboardFilePath(root, value)
	if path == "" || !filepath.IsAbs(path) {
		return value
	}
	root = strings.TrimSpace(root)
	if root == "" {
		return value
	}
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return value
	}
	return rel
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
