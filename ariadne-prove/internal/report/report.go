package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

func Render(w io.Writer, r model.Report, format string) error {
	switch strings.ToLower(format) {
	case "", "table":
		return renderTable(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "dot", "graphviz":
		return renderGraphDOT(w, graphTitle(r.RunKind, r.Story.ID), r.Graph)
	case "mermaid":
		return renderGraphMermaid(w, graphTitle(r.RunKind, r.Story.ID), r.Graph)
	case "html", "dashboard":
		return renderReportDashboard(w, r)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

func RenderInventory(w io.Writer, r model.InventoryReport, format string) error {
	switch strings.ToLower(format) {
	case "", "table":
		return renderInventoryTable(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "dot", "graphviz":
		return renderGraphDOT(w, "Ariadne inventory graph", r.Graph)
	case "mermaid":
		return renderGraphMermaid(w, "Ariadne inventory graph", r.Graph)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

func RenderScan(w io.Writer, r model.ScanReport, format string) error {
	switch strings.ToLower(format) {
	case "", "table":
		return renderScanTable(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "dot", "graphviz":
		return renderScanDOT(w, r)
	case "mermaid":
		return renderScanMermaid(w, r)
	case "html", "dashboard":
		return renderScanDashboard(w, r)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

func renderGraphDOT(w io.Writer, title string, g model.Graph) error {
	fmt.Fprintln(w, "digraph ariadne_graph {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintf(w, "  labelloc=\"t\";\n")
	fmt.Fprintf(w, "  label=%s;\n", dotQuote(title))
	renderGraphDOTBody(w, g, "")
	fmt.Fprintln(w, "}")
	return nil
}

func renderScanDOT(w io.Writer, r model.ScanReport) error {
	fmt.Fprintln(w, "digraph ariadne_scan {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintf(w, "  labelloc=\"t\";\n")
	fmt.Fprintf(w, "  label=%s;\n", dotQuote("Ariadne scan graph"))
	for i, target := range r.Targets {
		if target.Error != "" {
			continue
		}
		prefix := fmt.Sprintf("target%d_", i)
		fmt.Fprintf(w, "  subgraph cluster_%d {\n", i)
		fmt.Fprintf(w, "    label=%s;\n", dotQuote("target: "+target.Target.ID))
		renderGraphDOTBody(w, target.Report.Graph, prefix)
		fmt.Fprintln(w, "  }")
	}
	fmt.Fprintln(w, "}")
	return nil
}

func renderGraphDOTBody(w io.Writer, g model.Graph, prefix string) {
	for _, node := range g.Nodes {
		fmt.Fprintf(w, "    %s [label=%s, shape=%s];\n", dotQuote(prefix+node.ID), dotQuote(nodeLabel(node)), dotShape(node.Type))
	}
	for _, edge := range g.Edges {
		fmt.Fprintf(w, "    %s -> %s [label=%s];\n", dotQuote(prefix+edge.From), dotQuote(prefix+edge.To), dotQuote(edge.Type))
	}
}

func renderGraphMermaid(w io.Writer, title string, g model.Graph) error {
	fmt.Fprintln(w, "---")
	fmt.Fprintf(w, "title: %s\n", mermaidText(title))
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w, "flowchart LR")
	renderGraphMermaidBody(w, g, "")
	return nil
}

func renderScanMermaid(w io.Writer, r model.ScanReport) error {
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w, "title: Ariadne scan graph")
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w, "flowchart LR")
	for i, target := range r.Targets {
		if target.Error != "" {
			continue
		}
		prefix := fmt.Sprintf("target%d_", i)
		fmt.Fprintf(w, "  subgraph cluster_%d[\"%s\"]\n", i, mermaidText("target: "+target.Target.ID))
		renderGraphMermaidBody(w, target.Report.Graph, prefix)
		fmt.Fprintln(w, "  end")
	}
	return nil
}

func renderGraphMermaidBody(w io.Writer, g model.Graph, prefix string) {
	ids := make(map[string]string, len(g.Nodes))
	for i, node := range g.Nodes {
		id := fmt.Sprintf("%sn%d", prefix, i)
		ids[node.ID] = id
		fmt.Fprintf(w, "    %s[\"%s\"]\n", id, mermaidText(nodeLabel(node)))
	}
	for _, edge := range g.Edges {
		from, fromOK := ids[edge.From]
		to, toOK := ids[edge.To]
		if !fromOK || !toOK {
			continue
		}
		fmt.Fprintf(w, "    %s -->|\"%s\"| %s\n", from, mermaidText(edge.Type), to)
	}
}

func graphTitle(runKind, storyID string) string {
	if storyID != "" && storyID != "real-path" {
		return "Ariadne story graph: " + storyID
	}
	if runKind != "" {
		return "Ariadne " + runKind + " graph"
	}
	return "Ariadne graph"
}

func nodeLabel(node model.Node) string {
	parts := []string{node.Type + ": " + node.Label}
	if node.Runtime != "" && node.Runtime != node.Label {
		parts = append(parts, "runtime: "+node.Runtime)
	}
	if node.Source != "" {
		parts = append(parts, "source: "+node.Source)
	}
	return strings.Join(parts, "\n")
}

func dotShape(nodeType string) string {
	switch nodeType {
	case "runtime":
		return "box"
	case "authority":
		return "hexagon"
	case "boundary":
		return "octagon"
	case "control":
		return "diamond"
	case "trust_input":
		return "note"
	default:
		return "ellipse"
	}
}

func dotQuote(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + replacer.Replace(value) + `"`
}

func mermaidText(value string) string {
	replacer := strings.NewReplacer(
		`"`, "#quot;",
		"[", "(",
		"]", ")",
		"|", "/",
		"\n", "<br/>",
	)
	return replacer.Replace(value)
}

func renderScanTable(w io.Writer, r model.ScanReport) error {
	fmt.Fprintf(w, "Ariadne Scan\n\n")
	fmt.Fprintf(w, "Mode: %s\n", r.Mode)
	fmt.Fprintf(w, "Agent: %s\n", r.Agent)
	fmt.Fprintf(w, "Targets: %d completed, %d errors\n", r.Summary.Completed, r.Summary.Errors)
	fmt.Fprintf(w, "Exposure paths: %d exposed, %d protected, %d inconclusive\n\n", r.Summary.Exposed, r.Summary.Protected, r.Summary.Inconclusive)
	renderIssueSummary(w, r.Interpretation)
	for _, target := range r.Targets {
		fmt.Fprintf(w, "Target: %s (%s)\n", target.Target.ID, target.Target.Path)
		if target.Error != "" {
			fmt.Fprintf(w, "  Error: %s\n\n", target.Error)
			continue
		}
		if len(target.Report.Exposures) == 0 {
			fmt.Fprintf(w, "  - no exposure paths returned\n\n")
			continue
		}
		for _, exposure := range target.Report.Exposures {
			fmt.Fprintf(w, "  - %s: %s (%s)\n", exposure.ID, strings.ToUpper(string(exposure.Status)), exposure.ProofMode)
		}
		fmt.Fprintln(w)
	}
	if len(r.Limitations) > 0 {
		fmt.Fprintf(w, "Limitations:\n")
		for _, limitation := range r.Limitations {
			fmt.Fprintf(w, "  - %s\n", limitation)
		}
	}
	return nil
}

func renderInventoryTable(w io.Writer, r model.InventoryReport) error {
	fmt.Fprintf(w, "Ariadne Inventory\n\n")
	fmt.Fprintf(w, "Target: %s\n", r.TargetPath)
	fmt.Fprintf(w, "Mode: %s\n", r.Mode)
	fmt.Fprintf(w, "Agent: %s\n\n", r.Agent)
	fmt.Fprintf(w, "AI surfaces discovered:\n")
	if len(r.Collection.Surfaces) == 0 {
		fmt.Fprintf(w, "  - none discovered for supported surface families\n")
	} else {
		for _, surface := range r.Collection.Surfaces {
			fmt.Fprintf(w, "  - %s [%s/%s/%s] %s\n", surface.Source, surface.Runtime, surface.Category, surface.HandlingMode, surface.Summary)
		}
	}
	fmt.Fprintf(w, "\nFacts collected:\n")
	if len(r.Collection.Facts) == 0 {
		fmt.Fprintf(w, "  - no deterministic facts collected\n")
	} else {
		for _, fact := range r.Collection.Facts {
			fmt.Fprintf(w, "  - %s: %s Source: %s Evidence: %s Redaction: %s\n", fact.Type, fact.Summary, empty(fact.Source, "not recorded"), fact.EvidenceGrade, fact.Redaction)
		}
	}
	fmt.Fprintf(w, "\nModeled graph:\n")
	fmt.Fprintf(w, "  Nodes: %d\n", len(r.Graph.Nodes))
	fmt.Fprintf(w, "  Edges: %d\n", len(r.Graph.Edges))
	if len(r.Collection.Warnings) > 0 {
		fmt.Fprintf(w, "\nWarnings:\n")
		for _, warning := range r.Collection.Warnings {
			fmt.Fprintf(w, "  - %s\n", warning)
		}
	}
	if len(r.Limitations) > 0 {
		fmt.Fprintf(w, "\nLimitations:\n")
		for _, limitation := range r.Limitations {
			fmt.Fprintf(w, "  - %s\n", limitation)
		}
	}
	return nil
}

func renderTable(w io.Writer, r model.Report) error {
	if r.RunKind == "path" {
		fmt.Fprintf(w, "Ariadne Prove\n\n")
		fmt.Fprintf(w, "Target: %s\n", r.TargetPath)
		fmt.Fprintf(w, "Mode: %s\n", r.Story.Mode)
		fmt.Fprintf(w, "Agent: %s\n\n", r.Story.Runtime)
	} else {
		match := "PASS"
		if !r.Matched {
			match = "FAIL"
		}
		fmt.Fprintf(w, "Ariadne Story Lab\n\n")
		fmt.Fprintf(w, "Story: %s\n", r.Story.ID)
		fmt.Fprintf(w, "Persona: %s\n", r.Story.Persona)
		fmt.Fprintf(w, "Question: %s\n", r.Story.UserQuestion)
		fmt.Fprintf(w, "Oracle: %s\n\n", match)
	}
	exposures := r.Exposures
	if len(exposures) == 0 {
		exposures = []model.ExposureResult{r.Exposure}
	}
	renderIssueSummary(w, r.Interpretation)
	renderZeroTrustTable(w, r.ZeroTrust)
	for i, exposure := range exposures {
		if len(exposures) > 1 {
			fmt.Fprintf(w, "Exposure Path %d: %s\n", i+1, exposure.Title)
		}
		fmt.Fprintf(w, "What was tested:\n  %s\n\n", exposure.WhatWasTested)
		fmt.Fprintf(w, "Facts:\n")
		renderFacts(w, r, exposure)
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Graph path:\n")
		if len(exposure.PathEdges) == 0 {
			fmt.Fprintf(w, "  - no complete supported path established\n")
		}
		for _, edge := range exposure.PathEdges {
			fmt.Fprintf(w, "  - %s\n", edge)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Classification:\n")
		fmt.Fprintf(w, "  Status: %s\n", strings.ToUpper(string(exposure.Status)))
		fmt.Fprintf(w, "  Proof mode: %s\n", exposure.ProofMode)
		fmt.Fprintf(w, "  Observation: %s - %s\n\n", exposure.Observation.Status, exposure.Observation.Summary)
		fmt.Fprintf(w, "Why it matters:\n  %s\n\n", exposure.WhyItMatters)
		if len(exposure.ControlsBreakPath) > 0 {
			fmt.Fprintf(w, "Controls that break the path:\n")
			for _, control := range exposure.ControlsBreakPath {
				fmt.Fprintf(w, "  - %s\n", control)
			}
			fmt.Fprintln(w)
		}
		if i < len(exposures)-1 {
			fmt.Fprintln(w)
		}
	}
	if len(r.Mismatches) > 0 {
		fmt.Fprintf(w, "\nMismatches:\n")
		for _, mismatch := range r.Mismatches {
			fmt.Fprintf(w, "  - %s\n", mismatch)
		}
	}
	return nil
}

func renderZeroTrustTable(w io.Writer, z model.ZeroTrust) {
	if z.FrameworkVersion == "" {
		return
	}
	fmt.Fprintf(w, "Zero Trust architecture:\n")
	fmt.Fprintf(w, "  Checks: %d total, %d breaking, %d controlled, %d unknown, %d not observed\n",
		z.Summary.Total,
		z.Summary.Breaking,
		z.Summary.Controlled,
		z.Summary.Unknown,
		z.Summary.NotObserved,
	)
	if len(z.ArchitectureFlaws) > 0 {
		fmt.Fprintf(w, "  Architecture flaws: %d total, %d breaking, %d controlled, %d unknown, %d not observed\n",
			z.ArchitectureSummary.Total,
			z.ArchitectureSummary.Breaking,
			z.ArchitectureSummary.Controlled,
			z.ArchitectureSummary.Unknown,
			z.ArchitectureSummary.NotObserved,
		)
		rendered := 0
		for _, flaw := range z.ArchitectureFlaws {
			if flaw.Status == model.ZeroTrustNotObserved {
				continue
			}
			if rendered >= 8 {
				fmt.Fprintf(w, "    - %d more architecture flaw categories in JSON or dashboard output\n", countObservedArchitectureFlaws(z.ArchitectureFlaws)-rendered)
				break
			}
			rendered++
			fmt.Fprintf(w, "    - %s %s: %s\n", statusLabel(string(flaw.Status)), flaw.Title, flaw.Finding)
			if len(flaw.Evidence) > 0 {
				fmt.Fprintf(w, "      Evidence: %s\n", zeroTrustEvidenceLine(flaw.Evidence, 3))
			}
			if len(flaw.Controls) > 0 {
				fmt.Fprintf(w, "      Controls: %s\n", strings.Join(flaw.Controls, "; "))
			}
			if len(flaw.Actions) > 0 {
				fmt.Fprintf(w, "      Next: %s\n", flaw.Actions[0])
			}
		}
		if rendered == 0 {
			fmt.Fprintf(w, "    - no observed architecture flaw categories returned\n")
		}
	}
	if z.Maturity.TargetTier != "" {
		fmt.Fprintf(w, "  Foundation maturity evidence: %d/%d requirements evidenced, %d gaps (%d breaking, %d unknown, %d not observed), %d hard barriers, %d friction-only controls\n",
			z.Maturity.Summary.Met,
			z.Maturity.Summary.Total,
			z.Maturity.Summary.Gaps,
			z.Maturity.Summary.Breaking,
			z.Maturity.Summary.Unknown,
			z.Maturity.Summary.NotObserved,
			z.Maturity.Summary.HardBarriers,
			z.Maturity.Summary.FrictionOnly,
		)
		limit := len(z.Maturity.Requirements)
		if limit > 5 {
			limit = 5
		}
		for _, req := range z.Maturity.Requirements[:limit] {
			fmt.Fprintf(w, "    - %s %s: %s\n", statusLabel(string(req.Status)), req.Capability, req.Finding)
			if len(req.MissingEvidence) > 0 {
				fmt.Fprintf(w, "      Missing: %s\n", strings.Join(req.MissingEvidence, "; "))
			}
		}
		if len(z.Maturity.Requirements) > limit {
			fmt.Fprintf(w, "    - %d more Foundation requirements in JSON or dashboard output\n", len(z.Maturity.Requirements)-limit)
		}
	}
	for _, check := range z.Checks {
		fmt.Fprintf(w, "  - %s %s / %s: %s\n", statusLabel(string(check.Status)), check.Principle, check.Boundary, check.Finding)
		if len(check.Evidence) > 0 {
			fmt.Fprintf(w, "    Evidence: %s\n", zeroTrustEvidenceLine(check.Evidence, 3))
		}
		if len(check.Controls) > 0 {
			fmt.Fprintf(w, "    Controls: %s\n", strings.Join(check.Controls, "; "))
		}
		if len(check.Actions) > 0 {
			fmt.Fprintf(w, "    Next: %s\n", check.Actions[0])
		}
	}
	if len(z.Coverage.GapDetails) > 0 {
		fmt.Fprintf(w, "  Evidence coverage: %d known, %d gaps (%d unknown, %d not observed)\n",
			z.Coverage.Known,
			z.Coverage.Gaps,
			z.Coverage.Unknown,
			z.Coverage.NotObserved,
		)
		limit := len(z.Coverage.GapDetails)
		if limit > 4 {
			limit = 4
		}
		for _, gap := range z.Coverage.GapDetails[:limit] {
			fmt.Fprintf(w, "    - %s: missing %s. Next collector: %s\n",
				gap.Boundary,
				strings.Join(gap.MissingEvidence, "; "),
				gap.NextCollector,
			)
		}
		if len(z.Coverage.GapDetails) > limit {
			fmt.Fprintf(w, "    - %d more coverage gaps in JSON or dashboard output\n", len(z.Coverage.GapDetails)-limit)
		}
	}
	fmt.Fprintln(w)
}

func countObservedArchitectureFlaws(flaws []model.ZeroTrustArchitecture) int {
	count := 0
	for _, flaw := range flaws {
		if flaw.Status != model.ZeroTrustNotObserved {
			count++
		}
	}
	return count
}

func zeroTrustEvidenceLine(evidence []model.ZeroTrustEvidence, limit int) string {
	var parts []string
	seen := map[string]bool{}
	for _, item := range evidence {
		source := item.Source
		if source == "" {
			source = item.ID
		}
		if source == "" {
			source = item.Kind
		}
		if source == "" || seen[source] {
			continue
		}
		if len(parts) >= limit {
			parts = append(parts, fmt.Sprintf("%d more", len(evidence)-len(parts)))
			break
		}
		seen[source] = true
		parts = append(parts, source)
	}
	return strings.Join(parts, "; ")
}

func statusLabel(value string) string {
	return strings.ToUpper(strings.ReplaceAll(value, "_", " "))
}

func renderIssueSummary(w io.Writer, interpretation model.Interpretation) {
	if interpretation.Mode == "" {
		return
	}
	fmt.Fprintf(w, "%s:\n", interpretationLabel(interpretation))
	fmt.Fprintf(w, "  Issues: %d total, %d critical, %d high, %d medium, %d low, %d info\n",
		interpretation.Summary.Total,
		interpretation.Summary.Critical,
		interpretation.Summary.High,
		interpretation.Summary.Medium,
		interpretation.Summary.Low,
		interpretation.Summary.Info,
	)
	if interpretation.ReviewSource != "" || interpretation.RequestDigest != "" {
		fmt.Fprintf(w, "  Review: %s", empty(interpretation.ReviewSource, "not recorded"))
		if interpretation.RequestDigest != "" {
			digest := interpretation.RequestDigest
			if len(digest) > 12 {
				digest = digest[:12]
			}
			fmt.Fprintf(w, " Request: %s", digest)
		}
		fmt.Fprintln(w)
	}
	if len(interpretation.Issues) == 0 {
		fmt.Fprintf(w, "  - no prioritized issues returned\n\n")
		return
	}
	limit := len(interpretation.Issues)
	if limit > 8 {
		limit = 8
	}
	for _, issue := range interpretation.Issues[:limit] {
		target := ""
		if issue.AffectedTarget != "" {
			target = " Target: " + issue.AffectedTarget
		}
		fmt.Fprintf(w, "  - %s/%s %s [%s]%s\n", strings.ToUpper(string(issue.Priority)), strings.ToUpper(string(issue.Severity)), issue.Title, issue.Disposition, target)
	}
	if len(interpretation.Issues) > limit {
		fmt.Fprintf(w, "  - %d more issues in JSON or dashboard output\n", len(interpretation.Issues)-limit)
	}
	fmt.Fprintln(w)
}

func interpretationLabel(interpretation model.Interpretation) string {
	switch interpretation.Mode {
	case "llm_review":
		return "LLM priority review"
	case "deterministic":
		return "Deterministic priority"
	default:
		return "Priority interpretation"
	}
}

func renderFacts(w io.Writer, r model.Report, exposure model.ExposureResult) {
	facts := factsForExposure(r, exposure)
	if len(facts) == 0 {
		fmt.Fprintf(w, "  - no supporting facts collected for this supported exposure family\n")
		return
	}
	for _, fact := range facts {
		fmt.Fprintf(w, "  - %s\n", fact)
	}
}

func factsForExposure(r model.Report, exposure model.ExposureResult) []string {
	nodeIDs := map[string]bool{}
	for _, edge := range exposure.PathEdges {
		parts := strings.Split(edge, "|")
		if len(parts) == 3 {
			nodeIDs[parts[0]] = true
			nodeIDs[parts[2]] = true
		}
	}
	if len(exposure.PathEdges) == 0 {
		for _, node := range r.Graph.Nodes {
			if node.Type == "trust_input" || node.Type == "boundary" || node.Type == "config" {
				nodeIDs[node.ID] = true
			}
		}
	}
	nodeByID := map[string]model.Node{}
	for _, node := range r.Graph.Nodes {
		nodeByID[node.ID] = node
	}
	evidenceByID := map[string]model.Evidence{}
	for _, evidence := range r.Evidence {
		evidenceByID[evidence.ID] = evidence
	}
	var facts []string
	for id := range nodeIDs {
		if node, ok := nodeByID[id]; ok {
			facts = append(facts, factForNode(node))
		}
	}
	for _, edge := range r.Graph.Edges {
		for _, pathEdge := range exposure.PathEdges {
			if edge.Key() == pathEdge && edge.EvidenceID != "" {
				if evidence, ok := evidenceByID[edge.EvidenceID]; ok {
					facts = append(facts, "Evidence: "+evidence.Summary+" Source: "+empty(evidence.Source, "not recorded"))
				}
			}
		}
	}
	facts = uniqueStrings(facts)
	sort.Strings(facts)
	return facts
}

func factForNode(node model.Node) string {
	source := ""
	if node.Source != "" {
		source = " Source: " + node.Source
	}
	switch node.Type {
	case "runtime":
		return "Runtime observed: " + node.Label + source
	case "config":
		return "Config observed: " + node.Label + source
	case "trust_input":
		return "Trust input observed: " + node.Label + source
	case "tool":
		return "Tool observed: " + node.Label + source
	case "authority":
		return "Authority modeled: " + node.Label
	case "boundary":
		return "Boundary modeled: " + node.Label + source
	case "control":
		return "Control observed: " + node.Label + source
	default:
		return "Graph node observed: " + node.Type + " " + node.Label + source
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func empty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
