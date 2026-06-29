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
	renderIssueDashboard(w, r.Interpretation)
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
	renderIssueDashboard(w, r.Interpretation)
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
	fmt.Fprintln(w, `<div class="subtle">Deterministic facts, graph-backed exposure paths, and priority interpretation.</div>`)
	fmt.Fprintln(w, "</div>")
	for _, field := range fields {
		fmt.Fprintln(w, `<div class="metric">`)
		fmt.Fprintf(w, `<div class="label">%s</div>`, esc(field.Key))
		fmt.Fprintf(w, `<div class="value">%s</div>`, esc(field.Value))
		fmt.Fprintln(w, "</div>")
	}
	fmt.Fprintln(w, "</section>")
}

func renderIssueDashboard(w io.Writer, interpretation model.Interpretation) {
	fmt.Fprintln(w, `<section class="panel">`)
	fmt.Fprintln(w, `<div class="section-head">`)
	fmt.Fprintln(w, `<div><h2>Issue Dashboard</h2><div class="subtle">Prioritized only after deterministic facts connect into graph paths.</div></div>`)
	fmt.Fprintf(w, `<div class="subtle">Mode: %s</div>`, esc(firstNonEmpty(interpretation.Mode, "not evaluated")))
	fmt.Fprintln(w, "</div>")
	renderIssueMetrics(w, interpretation.Summary)
	if len(interpretation.Issues) == 0 {
		fmt.Fprintln(w, `<div class="empty">No prioritized issues were returned for this run.</div>`)
		fmt.Fprintln(w, "</section>")
		return
	}
	fmt.Fprintln(w, `<div class="table-wrap"><table>`)
	fmt.Fprintln(w, "<thead><tr><th>Priority</th><th>Severity</th><th>Issue</th><th>Status</th><th>Evidence</th><th>Action</th></tr></thead><tbody>")
	for _, issue := range interpretation.Issues {
		fmt.Fprintln(w, "<tr>")
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(issue.Priority)), esc(strings.ToUpper(string(issue.Priority))))
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span></td>`, cssClass(string(issue.Severity)), esc(strings.ToUpper(string(issue.Severity))))
		fmt.Fprintf(w, `<td><strong>%s</strong><div class="subtle">%s</div><div class="mono">%s</div></td>`, esc(issue.Title), esc(issue.Rationale), esc(issue.ID))
		fmt.Fprintf(w, `<td><span class="pill %s">%s</span><div class="subtle">%s</div></td>`, cssClass(string(issue.ExposureStatus)), esc(strings.ToUpper(string(issue.ExposureStatus))), esc(string(issue.Disposition)))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(issue.Signals))
		fmt.Fprintf(w, `<td>%s</td>`, renderSmallList(issue.Actions))
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody></table></div>")
	renderInterpretationLimitations(w, interpretation)
	fmt.Fprintln(w, "</section>")
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
