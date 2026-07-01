package report

import (
	"fmt"
	"html"
	"io"
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
	fmt.Fprintln(w, "<thead><tr><th>Status</th><th>Architecture flaw</th><th>Why it matters</th><th>Evidence</th><th>Graph / Observed control</th><th>Breaks when</th><th>Evidence surfaces / Next action</th></tr></thead><tbody>")
	for _, flaw := range z.ArchitectureFlaws {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span><div class="pill %s">%s</div></td>`, cssClass(string(flaw.Status)), esc(statusLabel(string(flaw.Status))), cssClass(flaw.Severity), esc(strings.ToUpper(flaw.Severity)))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div><div class="subtle">%s</div></td>`, esc(flaw.Title), esc(flaw.Principle), esc(flaw.ID), esc(strings.Join(flaw.Boundaries, ", ")))
		fmt.Fprintf(w, `<td>%s<div class="subtle">%s</div></td>`, esc(flaw.Finding), esc(flaw.WhyItMatters))
		fmt.Fprintf(w, `<td>%s</td>`, renderZeroTrustEvidence(flaw.Evidence))
		fmt.Fprintf(w, `<td>%s%s</td>`, renderSmallList(limitStrings(flaw.GraphEdges, 4)), renderControlLine(flaw.Controls))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(limitStrings(flaw.ControlEvidenceNeeded, 6)))
		fmt.Fprintf(w, `<td><h3>Evidence surfaces</h3>%s<h3>Next action</h3>%s</td>`, renderSmallList(limitStrings(flaw.EvidenceSurfaces, 4)), renderSmallList(limitStrings(flaw.Actions, 3)))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
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
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Target</th><th>Zero Trust readout</th></tr></thead><tbody>")
	for _, row := range byTarget {
		fmt.Fprintf(w, "<tr><td><strong>%s</strong></td><td>%s</td></tr>\n", esc(row.Key), esc(row.Value))
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
