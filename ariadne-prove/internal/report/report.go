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

func RenderArchitecture(w io.Writer, r model.Report, format string, statusFilter string) error {
	architecture, err := BuildArchitectureReport(r, statusFilter)
	if err != nil {
		return err
	}
	switch strings.ToLower(format) {
	case "", "table":
		return renderArchitectureTable(w, architecture)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(architecture)
	case "html", "dashboard":
		return renderArchitectureDashboard(w, architecture)
	default:
		return fmt.Errorf("unknown architecture format: %s", format)
	}
}

func RenderArchitectureScan(w io.Writer, r model.ScanReport, format string, statusFilter string) error {
	architecture, err := BuildArchitectureScanReport(r, statusFilter)
	if err != nil {
		return err
	}
	switch strings.ToLower(format) {
	case "", "table":
		return renderArchitectureScanTable(w, architecture)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(architecture)
	case "html", "dashboard":
		return renderArchitectureScanDashboard(w, architecture)
	default:
		return fmt.Errorf("unknown architecture format: %s", format)
	}
}

func BuildArchitectureReport(r model.Report, statusFilter string) (model.ArchitectureReport, error) {
	filter := strings.ToLower(strings.TrimSpace(statusFilter))
	if filter == "" {
		filter = "breaking"
	}
	if !validArchitectureStatusFilter(filter) {
		return model.ArchitectureReport{}, fmt.Errorf("unknown architecture status filter: %s", statusFilter)
	}
	flaws := make([]model.ZeroTrustArchitecture, 0, len(r.ZeroTrust.ArchitectureFlaws))
	for _, flaw := range r.ZeroTrust.ArchitectureFlaws {
		if architectureStatusAllowed(flaw.Status, filter) {
			flaws = append(flaws, flaw)
		}
	}
	if flaws == nil {
		flaws = []model.ZeroTrustArchitecture{}
	}
	return model.ArchitectureReport{
		SchemaVersion:    model.SchemaVersion,
		RunID:            r.RunID,
		GeneratedAt:      r.GeneratedAt,
		TargetPath:       r.TargetPath,
		Mode:             r.Story.Mode,
		Agent:            r.Story.Runtime,
		FrameworkVersion: r.ZeroTrust.FrameworkVersion,
		StatusFilter:     filter,
		Summary:          summarizeArchitectureFlaws(flaws),
		OverallSummary:   r.ZeroTrust.ArchitectureSummary,
		EvidenceCoverage: r.ZeroTrust.Coverage,
		Maturity:         r.ZeroTrust.Maturity,
		BoundaryCoverage: buildArchitectureBoundaryCoverage([]architectureCoverageInput{{
			TargetID:  "target",
			ZeroTrust: r.ZeroTrust,
		}}),
		Flaws:       flaws,
		Redaction:   r.Redaction,
		Limitations: append([]string{}, r.Limitations...),
	}, nil
}

func BuildArchitectureScanReport(r model.ScanReport, statusFilter string) (model.ArchitectureScanReport, error) {
	filter := strings.ToLower(strings.TrimSpace(statusFilter))
	if filter == "" {
		filter = "breaking"
	}
	if !validArchitectureStatusFilter(filter) {
		return model.ArchitectureScanReport{}, fmt.Errorf("unknown architecture status filter: %s", statusFilter)
	}
	out := model.ArchitectureScanReport{
		SchemaVersion: model.SchemaVersion,
		RunID:         r.RunID,
		GeneratedAt:   r.GeneratedAt,
		RunKind:       "architecture_scan",
		Mode:          r.Mode,
		Agent:         r.Agent,
		StatusFilter:  filter,
		Redaction:     r.Redaction,
		Limitations:   append([]string{}, r.Limitations...),
	}
	out.Summary.Targets = r.Summary.Targets
	groups := map[string]*model.ArchitectureFlawGroup{}
	var coverageInputs []architectureCoverageInput
	for _, target := range r.Targets {
		targetReport := model.ArchitectureTargetReport{Target: target.Target}
		if target.Error != "" {
			targetReport.Error = target.Error
			out.Summary.Errors++
			out.Targets = append(out.Targets, targetReport)
			continue
		}
		out.Summary.Completed++
		coverageInputs = append(coverageInputs, architectureCoverageInput{
			TargetID:  target.Target.ID,
			ZeroTrust: target.Report.ZeroTrust,
		})
		for _, flaw := range target.Report.ZeroTrust.ArchitectureFlaws {
			if !architectureStatusAllowed(flaw.Status, filter) {
				continue
			}
			targetReport.Flaws = append(targetReport.Flaws, flaw)
			incrementZeroTrustSummary(&targetReport.Summary, flaw.Status)
			incrementArchitectureScanSummary(&out.Summary, flaw.Status)
			group := groups[flaw.ID]
			if group == nil {
				group = &model.ArchitectureFlawGroup{
					ID:                    flaw.ID,
					Title:                 flaw.Title,
					Severity:              flaw.Severity,
					Principle:             flaw.Principle,
					Tier:                  flaw.Tier,
					ControlTestResults:    map[string]int{},
					ControlEvidenceNeeded: append([]string{}, flaw.ControlEvidenceNeeded...),
					EvidenceSurfaces:      append([]string{}, flaw.EvidenceSurfaces...),
					Actions:               append([]string{}, flaw.Actions...),
				}
				groups[flaw.ID] = group
			}
			incrementZeroTrustSummary(&group.StatusCounts, flaw.Status)
			if flaw.ControlTest.Result != "" {
				if group.ControlTestResults == nil {
					group.ControlTestResults = map[string]int{}
				}
				group.ControlTestResults[flaw.ControlTest.Result]++
			}
			group.Targets = append(group.Targets, target.Target.ID)
			group.EvidenceSources = append(group.EvidenceSources, zeroTrustEvidenceSources(flaw.Evidence)...)
		}
		targetReport.Summary.Total = len(targetReport.Flaws)
		if targetReport.Flaws == nil {
			targetReport.Flaws = []model.ZeroTrustArchitecture{}
		}
		out.Targets = append(out.Targets, targetReport)
	}
	out.Summary.DistinctFlaws = len(groups)
	for _, group := range groups {
		group.Targets = uniqueSortedStrings(group.Targets)
		group.TargetCount = len(group.Targets)
		group.ControlEvidenceNeeded = uniqueSortedStrings(group.ControlEvidenceNeeded)
		group.EvidenceSurfaces = uniqueSortedStrings(group.EvidenceSurfaces)
		group.EvidenceSources = uniqueSortedStrings(group.EvidenceSources)
		group.Actions = uniqueSortedStrings(group.Actions)
		out.Groups = append(out.Groups, *group)
	}
	sort.Slice(out.Groups, func(i, j int) bool {
		if out.Groups[i].Severity == out.Groups[j].Severity {
			return out.Groups[i].Title < out.Groups[j].Title
		}
		return severityRank(out.Groups[i].Severity) > severityRank(out.Groups[j].Severity)
	})
	out.BoundaryCoverage = buildArchitectureBoundaryCoverage(coverageInputs)
	if out.Groups == nil {
		out.Groups = []model.ArchitectureFlawGroup{}
	}
	if out.BoundaryCoverage == nil {
		out.BoundaryCoverage = []model.ArchitectureBoundary{}
	}
	if out.Targets == nil {
		out.Targets = []model.ArchitectureTargetReport{}
	}
	return out, nil
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
			if len(flaw.ControlEvidenceNeeded) > 0 {
				fmt.Fprintf(w, "      Breaks when: %s\n", strings.Join(limitStrings(flaw.ControlEvidenceNeeded, 5), "; "))
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

func renderArchitectureTable(w io.Writer, r model.ArchitectureReport) error {
	fmt.Fprintf(w, "Ariadne Zero Trust architecture:\n")
	if r.TargetPath != "" {
		fmt.Fprintf(w, "  Target: %s\n", r.TargetPath)
	}
	fmt.Fprintf(w, "  Mode: %s  Agent: %s  Filter: %s\n", empty(r.Mode, "unknown"), empty(r.Agent, "unknown"), r.StatusFilter)
	fmt.Fprintf(w, "  Matching flaws: %d total, %d breaking, %d controlled, %d unknown, %d not observed\n",
		r.Summary.Total,
		r.Summary.Breaking,
		r.Summary.Controlled,
		r.Summary.Unknown,
		r.Summary.NotObserved,
	)
	fmt.Fprintf(w, "  Overall flaws: %d total, %d breaking, %d controlled, %d unknown, %d not observed\n",
		r.OverallSummary.Total,
		r.OverallSummary.Breaking,
		r.OverallSummary.Controlled,
		r.OverallSummary.Unknown,
		r.OverallSummary.NotObserved,
	)
	renderArchitectureBoundarySummary(w, r.BoundaryCoverage, r.EvidenceCoverage)
	if len(r.Flaws) == 0 {
		fmt.Fprintf(w, "  - no architecture flaws matched status filter %q\n\n", r.StatusFilter)
		return nil
	}
	for _, flaw := range r.Flaws {
		fmt.Fprintf(w, "  - %s %s %s: %s\n", statusLabel(string(flaw.Status)), strings.ToUpper(flaw.Severity), flaw.Title, flaw.Finding)
		if len(flaw.Evidence) > 0 {
			fmt.Fprintf(w, "    Evidence: %s\n", zeroTrustEvidenceLine(flaw.Evidence, 4))
		}
		if len(flaw.GraphEdges) > 0 {
			fmt.Fprintf(w, "    Graph: %s\n", strings.Join(limitStrings(flaw.GraphEdges, 4), "; "))
		}
		if flaw.ControlTest.Result != "" {
			fmt.Fprintf(w, "    Control test: %s - %s\n", readableToken(flaw.ControlTest.Result), flaw.ControlTest.Summary)
			if len(flaw.ControlTest.MissingHardBarriers) > 0 {
				fmt.Fprintf(w, "      Missing hard barriers: %s\n", strings.Join(limitStrings(flaw.ControlTest.MissingHardBarriers, 6), "; "))
			}
			if len(flaw.ControlTest.PartialOrFrictionControls) > 0 {
				fmt.Fprintf(w, "      Partial/friction controls: %s\n", strings.Join(limitStrings(flaw.ControlTest.PartialOrFrictionControls, 6), "; "))
			}
			if len(flaw.ControlTest.HardBarriersObserved) > 0 {
				fmt.Fprintf(w, "      Hard barriers observed: %s\n", strings.Join(limitStrings(flaw.ControlTest.HardBarriersObserved, 6), "; "))
			}
		}
		if len(flaw.Controls) > 0 {
			fmt.Fprintf(w, "    Controls: %s\n", strings.Join(flaw.Controls, "; "))
		}
		if len(flaw.ControlEvidenceNeeded) > 0 {
			fmt.Fprintf(w, "    Breaks when: %s\n", strings.Join(limitStrings(flaw.ControlEvidenceNeeded, 6), "; "))
		}
		if len(flaw.EvidenceSurfaces) > 0 {
			fmt.Fprintf(w, "    Evidence surfaces: %s\n", strings.Join(limitStrings(flaw.EvidenceSurfaces, 5), "; "))
		}
		if flaw.WhyItMatters != "" {
			fmt.Fprintf(w, "    Why: %s\n", flaw.WhyItMatters)
		}
		if len(flaw.Actions) > 0 {
			fmt.Fprintf(w, "    Next: %s\n", strings.Join(limitStrings(flaw.Actions, 3), "; "))
		}
		if len(flaw.Limitations) > 0 {
			fmt.Fprintf(w, "    Limits: %s\n", strings.Join(limitStrings(flaw.Limitations, 2), "; "))
		}
	}
	fmt.Fprintln(w)
	return nil
}

func renderArchitectureScanTable(w io.Writer, r model.ArchitectureScanReport) error {
	fmt.Fprintf(w, "Ariadne Zero Trust architecture fleet:\n")
	fmt.Fprintf(w, "  Mode: %s  Agent: %s  Filter: %s\n", empty(r.Mode, "unknown"), empty(r.Agent, "unknown"), r.StatusFilter)
	fmt.Fprintf(w, "  Targets: %d total, %d completed, %d errors\n", r.Summary.Targets, r.Summary.Completed, r.Summary.Errors)
	fmt.Fprintf(w, "  Matching flaws: %d total across targets, %d distinct, %d breaking, %d controlled, %d unknown, %d not observed\n",
		r.Summary.MatchingFlaws,
		r.Summary.DistinctFlaws,
		r.Summary.Breaking,
		r.Summary.Controlled,
		r.Summary.Unknown,
		r.Summary.NotObserved,
	)
	renderArchitectureBoundaryCoverage(w, r.BoundaryCoverage, 8)
	if len(r.Groups) == 0 {
		fmt.Fprintf(w, "  - no architecture flaws matched status filter %q\n\n", r.StatusFilter)
		return nil
	}
	fmt.Fprintf(w, "  Flaws by target coverage:\n")
	for _, group := range r.Groups {
		fmt.Fprintf(w, "    - %s %s: %d target(s); %d breaking, %d controlled, %d unknown, %d not observed\n",
			strings.ToUpper(group.Severity),
			group.Title,
			group.TargetCount,
			group.StatusCounts.Breaking,
			group.StatusCounts.Controlled,
			group.StatusCounts.Unknown,
			group.StatusCounts.NotObserved,
		)
		fmt.Fprintf(w, "      Targets: %s\n", strings.Join(limitStrings(group.Targets, 6), "; "))
		if len(group.EvidenceSources) > 0 {
			fmt.Fprintf(w, "      Evidence: %s\n", strings.Join(limitStrings(group.EvidenceSources, 5), "; "))
		}
		if len(group.ControlTestResults) > 0 {
			fmt.Fprintf(w, "      Control test: %s\n", architectureControlTestResultsLine(group.ControlTestResults))
		}
		if len(group.ControlEvidenceNeeded) > 0 {
			fmt.Fprintf(w, "      Breaks when: %s\n", strings.Join(limitStrings(group.ControlEvidenceNeeded, 6), "; "))
		}
		if len(group.EvidenceSurfaces) > 0 {
			fmt.Fprintf(w, "      Evidence surfaces: %s\n", strings.Join(limitStrings(group.EvidenceSurfaces, 5), "; "))
		}
	}
	fmt.Fprintf(w, "  Targets:\n")
	for _, target := range r.Targets {
		if target.Error != "" {
			fmt.Fprintf(w, "    - %s: error: %s\n", target.Target.ID, target.Error)
			continue
		}
		fmt.Fprintf(w, "    - %s: %d matching flaws (%d breaking, %d controlled, %d unknown, %d not observed)\n",
			target.Target.ID,
			target.Summary.Total,
			target.Summary.Breaking,
			target.Summary.Controlled,
			target.Summary.Unknown,
			target.Summary.NotObserved,
		)
	}
	fmt.Fprintln(w)
	return nil
}

func renderArchitectureBoundarySummary(w io.Writer, boundaries []model.ArchitectureBoundary, coverage model.ZeroTrustCoverage) {
	if len(boundaries) == 0 {
		return
	}
	var summary model.ZeroTrustSummary
	for _, boundary := range boundaries {
		summary.Total += boundary.StatusCounts.Total
		summary.Breaking += boundary.StatusCounts.Breaking
		summary.Controlled += boundary.StatusCounts.Controlled
		summary.Unknown += boundary.StatusCounts.Unknown
		summary.NotObserved += boundary.StatusCounts.NotObserved
	}
	fmt.Fprintf(w, "  Boundary checks: %d total, %d breaking, %d controlled, %d unknown, %d not observed; evidence gaps: %d\n",
		summary.Total,
		summary.Breaking,
		summary.Controlled,
		summary.Unknown,
		summary.NotObserved,
		coverage.Gaps,
	)
}

func renderArchitectureBoundaryCoverage(w io.Writer, boundaries []model.ArchitectureBoundary, limit int) {
	if len(boundaries) == 0 {
		return
	}
	fmt.Fprintf(w, "  Boundary coverage:\n")
	if limit <= 0 || limit > len(boundaries) {
		limit = len(boundaries)
	}
	for _, boundary := range boundaries[:limit] {
		fmt.Fprintf(w, "    - %s: %d target-check(s); %d breaking, %d controlled, %d unknown, %d not observed\n",
			boundary.Boundary,
			boundary.StatusCounts.Total,
			boundary.StatusCounts.Breaking,
			boundary.StatusCounts.Controlled,
			boundary.StatusCounts.Unknown,
			boundary.StatusCounts.NotObserved,
		)
		if targets := architectureBoundaryTargetsLine(boundary); targets != "" {
			fmt.Fprintf(w, "      Targets: %s\n", targets)
		}
		if len(boundary.EvidenceSources) > 0 {
			fmt.Fprintf(w, "      Evidence: %s\n", strings.Join(limitStrings(boundary.EvidenceSources, 5), "; "))
		}
		if len(boundary.ControlEvidenceNeeded) > 0 {
			fmt.Fprintf(w, "      Control evidence needed: %s\n", strings.Join(limitStrings(boundary.ControlEvidenceNeeded, 5), "; "))
		}
		if len(boundary.MissingEvidence) > 0 {
			fmt.Fprintf(w, "      Missing evidence: %s\n", strings.Join(limitStrings(boundary.MissingEvidence, 5), "; "))
		}
		if len(boundary.NextCollectors) > 0 {
			fmt.Fprintf(w, "      Next collectors: %s\n", strings.Join(limitStrings(boundary.NextCollectors, 3), "; "))
		}
	}
	if len(boundaries) > limit {
		fmt.Fprintf(w, "    - %d more boundary coverage rows in JSON output\n", len(boundaries)-limit)
	}
}

func summarizeArchitectureFlaws(flaws []model.ZeroTrustArchitecture) model.ZeroTrustSummary {
	var summary model.ZeroTrustSummary
	summary.Total = len(flaws)
	for _, flaw := range flaws {
		switch flaw.Status {
		case model.ZeroTrustBreaking:
			summary.Breaking++
		case model.ZeroTrustControlled:
			summary.Controlled++
		case model.ZeroTrustUnknown:
			summary.Unknown++
		default:
			summary.NotObserved++
		}
	}
	return summary
}

func incrementZeroTrustSummary(summary *model.ZeroTrustSummary, status model.ZeroTrustStatus) {
	summary.Total++
	switch status {
	case model.ZeroTrustBreaking:
		summary.Breaking++
	case model.ZeroTrustControlled:
		summary.Controlled++
	case model.ZeroTrustUnknown:
		summary.Unknown++
	default:
		summary.NotObserved++
	}
}

func incrementArchitectureScanSummary(summary *model.ArchitectureScanSummary, status model.ZeroTrustStatus) {
	summary.MatchingFlaws++
	switch status {
	case model.ZeroTrustBreaking:
		summary.Breaking++
	case model.ZeroTrustControlled:
		summary.Controlled++
	case model.ZeroTrustUnknown:
		summary.Unknown++
	default:
		summary.NotObserved++
	}
}

type architectureCoverageInput struct {
	TargetID  string
	ZeroTrust model.ZeroTrust
}

func buildArchitectureBoundaryCoverage(inputs []architectureCoverageInput) []model.ArchitectureBoundary {
	byCheckID := map[string]*model.ArchitectureBoundary{}
	for _, input := range inputs {
		targetID := input.TargetID
		if targetID == "" {
			targetID = "target"
		}
		controlEvidenceByCheck, evidenceSurfacesByCheck := architectureContractsByCheck(input.ZeroTrust.ArchitectureFlaws)
		gapsByCheck := architectureGapsByCheck(input.ZeroTrust.Coverage.GapDetails)
		for _, check := range input.ZeroTrust.Checks {
			boundary := byCheckID[check.ID]
			if boundary == nil {
				boundary = &model.ArchitectureBoundary{
					CheckID:    check.ID,
					Boundary:   check.Boundary,
					Principle:  check.Principle,
					Tier:       check.Tier,
					DesignTest: check.DesignTest,
				}
				byCheckID[check.ID] = boundary
			}
			incrementZeroTrustSummary(&boundary.StatusCounts, check.Status)
			appendArchitectureBoundaryTarget(boundary, check.Status, targetID)
			boundary.EvidenceSources = append(boundary.EvidenceSources, zeroTrustEvidenceSources(check.Evidence)...)
			boundary.Controls = append(boundary.Controls, check.Controls...)
			boundary.ControlEvidenceNeeded = append(boundary.ControlEvidenceNeeded, controlEvidenceByCheck[check.ID]...)
			boundary.EvidenceSurfaces = append(boundary.EvidenceSurfaces, evidenceSurfacesByCheck[check.ID]...)
			boundary.Actions = append(boundary.Actions, check.Actions...)
			boundary.Limitations = append(boundary.Limitations, check.Limitations...)
			for _, gap := range gapsByCheck[check.ID] {
				boundary.MissingEvidence = append(boundary.MissingEvidence, gap.MissingEvidence...)
				if gap.NextCollector != "" {
					boundary.NextCollectors = append(boundary.NextCollectors, gap.NextCollector)
				}
			}
		}
	}
	out := make([]model.ArchitectureBoundary, 0, len(byCheckID))
	for _, boundary := range byCheckID {
		boundary.BreakingTargets = uniqueSortedStrings(boundary.BreakingTargets)
		boundary.ControlledTargets = uniqueSortedStrings(boundary.ControlledTargets)
		boundary.UnknownTargets = uniqueSortedStrings(boundary.UnknownTargets)
		boundary.NotObservedTargets = uniqueSortedStrings(boundary.NotObservedTargets)
		boundary.TargetCount = len(boundary.BreakingTargets) + len(boundary.ControlledTargets) + len(boundary.UnknownTargets) + len(boundary.NotObservedTargets)
		boundary.EvidenceSources = uniqueSortedStrings(boundary.EvidenceSources)
		boundary.Controls = uniqueSortedStrings(boundary.Controls)
		boundary.ControlEvidenceNeeded = uniqueSortedStrings(boundary.ControlEvidenceNeeded)
		boundary.EvidenceSurfaces = uniqueSortedStrings(boundary.EvidenceSurfaces)
		boundary.MissingEvidence = uniqueSortedStrings(boundary.MissingEvidence)
		boundary.NextCollectors = uniqueSortedStrings(boundary.NextCollectors)
		boundary.Actions = uniqueSortedStrings(boundary.Actions)
		boundary.Limitations = uniqueSortedStrings(boundary.Limitations)
		out = append(out, *boundary)
	}
	sort.Slice(out, func(i, j int) bool {
		left := architectureBoundaryRank(out[i])
		right := architectureBoundaryRank(out[j])
		if left == right {
			return out[i].Boundary < out[j].Boundary
		}
		return left > right
	})
	if out == nil {
		return []model.ArchitectureBoundary{}
	}
	return out
}

func architectureContractsByCheck(flaws []model.ZeroTrustArchitecture) (map[string][]string, map[string][]string) {
	controlEvidenceByCheck := map[string][]string{}
	evidenceSurfacesByCheck := map[string][]string{}
	for _, flaw := range flaws {
		for _, checkID := range flaw.CheckIDs {
			controlEvidenceByCheck[checkID] = append(controlEvidenceByCheck[checkID], flaw.ControlEvidenceNeeded...)
			evidenceSurfacesByCheck[checkID] = append(evidenceSurfacesByCheck[checkID], flaw.EvidenceSurfaces...)
		}
	}
	return controlEvidenceByCheck, evidenceSurfacesByCheck
}

func architectureGapsByCheck(gaps []model.ZeroTrustGap) map[string][]model.ZeroTrustGap {
	out := map[string][]model.ZeroTrustGap{}
	for _, gap := range gaps {
		out[gap.CheckID] = append(out[gap.CheckID], gap)
	}
	return out
}

func appendArchitectureBoundaryTarget(boundary *model.ArchitectureBoundary, status model.ZeroTrustStatus, targetID string) {
	switch status {
	case model.ZeroTrustBreaking:
		boundary.BreakingTargets = append(boundary.BreakingTargets, targetID)
	case model.ZeroTrustControlled:
		boundary.ControlledTargets = append(boundary.ControlledTargets, targetID)
	case model.ZeroTrustUnknown:
		boundary.UnknownTargets = append(boundary.UnknownTargets, targetID)
	default:
		boundary.NotObservedTargets = append(boundary.NotObservedTargets, targetID)
	}
}

func architectureBoundaryRank(boundary model.ArchitectureBoundary) int {
	return boundary.StatusCounts.Breaking*1000 + boundary.StatusCounts.Unknown*100 + boundary.StatusCounts.NotObserved*10 + boundary.StatusCounts.Controlled
}

func architectureBoundaryTargetsLine(boundary model.ArchitectureBoundary) string {
	var parts []string
	if len(boundary.BreakingTargets) > 0 {
		parts = append(parts, "breaking "+strings.Join(limitStrings(boundary.BreakingTargets, 4), ", "))
	}
	if len(boundary.UnknownTargets) > 0 {
		parts = append(parts, "unknown "+strings.Join(limitStrings(boundary.UnknownTargets, 4), ", "))
	}
	if len(boundary.NotObservedTargets) > 0 {
		parts = append(parts, "not observed "+strings.Join(limitStrings(boundary.NotObservedTargets, 4), ", "))
	}
	if len(boundary.ControlledTargets) > 0 {
		parts = append(parts, "controlled "+strings.Join(limitStrings(boundary.ControlledTargets, 4), ", "))
	}
	return strings.Join(parts, "; ")
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	if out == nil {
		return []string{}
	}
	return out
}

func zeroTrustEvidenceSources(evidence []model.ZeroTrustEvidence) []string {
	var out []string
	for _, item := range evidence {
		source := item.Source
		if source == "" {
			source = item.ID
		}
		if source == "" {
			source = item.Kind
		}
		if source != "" && source != "evidence:omitted" {
			out = append(out, source)
		}
	}
	return out
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func validArchitectureStatusFilter(filter string) bool {
	switch filter {
	case "all", "breaking", "controlled", "unknown", "not_observed", "observed":
		return true
	default:
		return false
	}
}

func architectureStatusAllowed(status model.ZeroTrustStatus, filter string) bool {
	switch filter {
	case "all":
		return true
	case "observed":
		return status != model.ZeroTrustNotObserved
	default:
		return string(status) == filter
	}
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

func readableToken(value string) string {
	if value == "" {
		return ""
	}
	return strings.ReplaceAll(value, "_", " ")
}

func architectureControlTestResultsLine(results map[string]int) string {
	if len(results) == 0 {
		return ""
	}
	keys := make([]string, 0, len(results))
	for key := range results {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", readableToken(key), results[key]))
	}
	return strings.Join(parts, "; ")
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
