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

func RenderControls(w io.Writer, r model.Report, format string, statusFilter string) error {
	architecture, err := BuildArchitectureReport(r, statusFilter)
	if err != nil {
		return err
	}
	catalog := BuildControlCatalogReport(architecture)
	return renderControlCatalog(w, catalog, format)
}

func RenderControlsScan(w io.Writer, r model.ScanReport, format string, statusFilter string) error {
	architecture, err := BuildArchitectureScanReport(r, statusFilter)
	if err != nil {
		return err
	}
	catalog := BuildControlCatalogScanReport(architecture)
	return renderControlCatalog(w, catalog, format)
}

func BuildControlCatalogReport(r model.ArchitectureReport) model.ControlCatalogReport {
	proofSpecs := buildControlProofSpecs(r.ClosurePlan)
	verificationTasks := buildControlVerificationTasks(r.ClosurePlan, proofSpecs, controlVerificationCommandContext{RunKind: "control_catalog", Path: r.TargetPath, Mode: r.Mode, Agent: r.Agent, StatusFilter: r.StatusFilter})
	workstreams := buildControlBreakPathWorkstreams(r.ClosureFamilies, verificationTasks)
	catalog := model.ControlCatalogReport{
		SchemaVersion:     model.SchemaVersion,
		RunID:             r.RunID,
		GeneratedAt:       r.GeneratedAt,
		RunKind:           "control_catalog",
		TargetPath:        r.TargetPath,
		Mode:              r.Mode,
		Agent:             r.Agent,
		StatusFilter:      r.StatusFilter,
		Summary:           summarizeControlCatalog(r.ClosurePlan),
		Controls:          append([]model.ArchitectureClosure{}, r.ClosurePlan...),
		Families:          append([]model.ArchitectureClosureFamily{}, r.ClosureFamilies...),
		OperatorCases:     buildControlOperatorCases(workstreams, verificationTasks),
		Workstreams:       workstreams,
		ProofSpecs:        proofSpecs,
		VerificationTasks: verificationTasks,
		Redaction:         r.Redaction,
		Limitations:       append([]string{}, r.Limitations...),
	}
	if catalog.Controls == nil {
		catalog.Controls = []model.ArchitectureClosure{}
	}
	if catalog.Families == nil {
		catalog.Families = []model.ArchitectureClosureFamily{}
	}
	if catalog.OperatorCases == nil {
		catalog.OperatorCases = []model.ControlOperatorCase{}
	}
	if catalog.Workstreams == nil {
		catalog.Workstreams = []model.ControlBreakPathWorkstream{}
	}
	if catalog.ProofSpecs == nil {
		catalog.ProofSpecs = []model.ControlProofSpec{}
	}
	if catalog.VerificationTasks == nil {
		catalog.VerificationTasks = []model.ControlVerificationTask{}
	}
	return catalog
}

func BuildControlCatalogScanReport(r model.ArchitectureScanReport) model.ControlCatalogReport {
	proofSpecs := buildControlProofSpecs(r.ClosurePlan)
	verificationTasks := buildControlVerificationTasks(r.ClosurePlan, proofSpecs, controlVerificationCommandContext{RunKind: "control_catalog_scan", Mode: r.Mode, Agent: r.Agent, StatusFilter: r.StatusFilter})
	workstreams := buildControlBreakPathWorkstreams(r.ClosureFamilies, verificationTasks)
	catalog := model.ControlCatalogReport{
		SchemaVersion:     model.SchemaVersion,
		RunID:             r.RunID,
		GeneratedAt:       r.GeneratedAt,
		RunKind:           "control_catalog_scan",
		Mode:              r.Mode,
		Agent:             r.Agent,
		StatusFilter:      r.StatusFilter,
		Summary:           summarizeControlCatalog(r.ClosurePlan),
		Controls:          append([]model.ArchitectureClosure{}, r.ClosurePlan...),
		Families:          append([]model.ArchitectureClosureFamily{}, r.ClosureFamilies...),
		OperatorCases:     buildControlOperatorCases(workstreams, verificationTasks),
		Workstreams:       workstreams,
		ProofSpecs:        proofSpecs,
		VerificationTasks: verificationTasks,
		Redaction:         r.Redaction,
		Limitations:       append([]string{}, r.Limitations...),
	}
	if catalog.Controls == nil {
		catalog.Controls = []model.ArchitectureClosure{}
	}
	if catalog.Families == nil {
		catalog.Families = []model.ArchitectureClosureFamily{}
	}
	if catalog.OperatorCases == nil {
		catalog.OperatorCases = []model.ControlOperatorCase{}
	}
	if catalog.Workstreams == nil {
		catalog.Workstreams = []model.ControlBreakPathWorkstream{}
	}
	if catalog.ProofSpecs == nil {
		catalog.ProofSpecs = []model.ControlProofSpec{}
	}
	if catalog.VerificationTasks == nil {
		catalog.VerificationTasks = []model.ControlVerificationTask{}
	}
	return catalog
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
	closurePlan := buildArchitectureClosurePlan([]architectureClosureInput{{TargetID: "target", Flaws: flaws}})
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
		EvidencePlan: buildArchitectureEvidencePlan([]architectureCoverageInput{{
			TargetID:  "target",
			ZeroTrust: r.ZeroTrust,
		}}),
		FrameworkCoverage: buildArchitectureFrameworkCoverage([]architectureCoverageInput{{
			TargetID:  "target",
			ZeroTrust: r.ZeroTrust,
		}}),
		Maturity: r.ZeroTrust.Maturity,
		BoundaryCoverage: buildArchitectureBoundaryCoverage([]architectureCoverageInput{{
			TargetID:  "target",
			ZeroTrust: r.ZeroTrust,
		}}),
		Flaws:           flaws,
		ClosurePlan:     closurePlan,
		ClosureFamilies: buildArchitectureClosureFamilies(closurePlan),
		Redaction:       r.Redaction,
		Limitations:     append([]string{}, r.Limitations...),
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
	var closureInputs []architectureClosureInput
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
		closureInputs = append(closureInputs, architectureClosureInput{
			TargetID: target.Target.ID,
			Flaws:    targetReport.Flaws,
		})
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
	out.EvidencePlan = buildArchitectureEvidencePlan(coverageInputs)
	out.FrameworkCoverage = buildArchitectureFrameworkCoverage(coverageInputs)
	out.BoundaryCoverage = buildArchitectureBoundaryCoverage(coverageInputs)
	out.ClosurePlan = buildArchitectureClosurePlan(closureInputs)
	out.ClosureFamilies = buildArchitectureClosureFamilies(out.ClosurePlan)
	if out.Groups == nil {
		out.Groups = []model.ArchitectureFlawGroup{}
	}
	if out.BoundaryCoverage == nil {
		out.BoundaryCoverage = []model.ArchitectureBoundary{}
	}
	if out.EvidencePlan == nil {
		out.EvidencePlan = []model.ArchitectureEvidencePlan{}
	}
	if out.FrameworkCoverage == nil {
		out.FrameworkCoverage = []model.ArchitectureFrameworkArea{}
	}
	if out.ClosurePlan == nil {
		out.ClosurePlan = []model.ArchitectureClosure{}
	}
	if out.ClosureFamilies == nil {
		out.ClosureFamilies = []model.ArchitectureClosureFamily{}
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
	renderArchitectureFrameworkCoverage(w, r.FrameworkCoverage, 8)
	renderArchitectureEvidencePlan(w, r.EvidencePlan, 6)
	renderArchitectureClosureFamilies(w, r.ClosureFamilies, 8)
	renderArchitectureClosurePlan(w, r.ClosurePlan, 8)
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
	renderArchitectureFrameworkCoverage(w, r.FrameworkCoverage, 10)
	renderArchitectureEvidencePlan(w, r.EvidencePlan, 8)
	renderArchitectureClosureFamilies(w, r.ClosureFamilies, 10)
	renderArchitectureClosurePlan(w, r.ClosurePlan, 10)
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

func renderControlCatalog(w io.Writer, r model.ControlCatalogReport, format string) error {
	switch strings.ToLower(format) {
	case "", "table":
		return renderControlCatalogTable(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "html", "dashboard":
		return renderControlCatalogDashboard(w, r)
	default:
		return fmt.Errorf("unknown controls format: %s", format)
	}
}

func renderControlCatalogTable(w io.Writer, r model.ControlCatalogReport) error {
	fmt.Fprintf(w, "Ariadne control evidence catalog:\n")
	if r.TargetPath != "" {
		fmt.Fprintf(w, "  Target: %s\n", r.TargetPath)
	}
	fmt.Fprintf(w, "  Run: %s  Mode: %s  Agent: %s  Filter: %s\n", empty(r.RunKind, "control_catalog"), empty(r.Mode, "unknown"), empty(r.Agent, "unknown"), r.StatusFilter)
	fmt.Fprintf(w, "  Missing hard barriers: %d controls; %d critical, %d high, %d medium, %d low; %d target(s); %d flaw(s)\n",
		r.Summary.Controls,
		r.Summary.Critical,
		r.Summary.High,
		r.Summary.Medium,
		r.Summary.Low,
		r.Summary.Targets,
		r.Summary.Flaws,
	)
	if len(r.Families) > 0 {
		fmt.Fprintf(w, "  Control families:\n")
		limit := len(r.Families)
		if limit > 8 {
			limit = 8
		}
		for _, family := range r.Families[:limit] {
			fmt.Fprintf(w, "    - %s %s: %d control(s), %d flaw(s), %d target(s)\n",
				strings.ToUpper(family.Severity),
				family.Title,
				family.ControlCount,
				family.FlawCount,
				family.TargetCount,
			)
			if len(family.Controls) > 0 {
				fmt.Fprintf(w, "      Controls: %s\n", strings.Join(limitStrings(family.Controls, 6), "; "))
			}
			if len(family.EvidenceSurfaces) > 0 {
				fmt.Fprintf(w, "      Where to prove this: %s\n", strings.Join(limitStrings(family.EvidenceSurfaces, 5), "; "))
			}
		}
		if len(r.Families) > limit {
			fmt.Fprintf(w, "    - %d more control families in JSON output\n", len(r.Families)-limit)
		}
	}
	if len(r.Controls) == 0 {
		fmt.Fprintf(w, "  - no missing hard-barrier controls matched status filter %q\n\n", r.StatusFilter)
		return nil
	}
	renderControlOperatorCases(w, r.OperatorCases, 6)
	renderControlBreakPathWorkstreams(w, r.Workstreams, 8)
	renderControlVerificationTasks(w, r.VerificationTasks, 8)
	fmt.Fprintf(w, "  Controls:\n")
	limit := len(r.Controls)
	if limit > 12 {
		limit = 12
	}
	proofByControl := controlProofSpecsByControl(r.ProofSpecs)
	for _, item := range r.Controls[:limit] {
		fmt.Fprintf(w, "    - %s %s: %d flaw(s), %d target(s)\n",
			strings.ToUpper(item.Severity),
			item.Control,
			item.FlawCount,
			item.TargetCount,
		)
		if len(item.Flaws) > 0 {
			fmt.Fprintf(w, "      Closes flaws: %s\n", strings.Join(limitStrings(item.Flaws, 4), "; "))
		}
		if len(item.Targets) > 0 {
			fmt.Fprintf(w, "      Targets: %s\n", strings.Join(limitStrings(item.Targets, 6), "; "))
		}
		if len(item.EvidenceSources) > 0 {
			fmt.Fprintf(w, "      Evidence anchors: %s\n", strings.Join(limitStrings(item.EvidenceSources, 5), "; "))
		}
		if len(item.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "      Evidence references: %s\n", strings.Join(evidenceReferenceLines(item.EvidenceReferences, 3), "; "))
		}
		if len(item.EvidenceSurfaces) > 0 {
			fmt.Fprintf(w, "      Where to prove this: %s\n", strings.Join(limitStrings(item.EvidenceSurfaces, 5), "; "))
		}
		if proof := proofByControl[item.Control]; len(proof.RecognizedIndicators) > 0 {
			fmt.Fprintf(w, "      Recognized indicators: %s\n", strings.Join(limitStrings(proof.RecognizedIndicators, 6), "; "))
		}
		if len(item.Actions) > 0 {
			fmt.Fprintf(w, "      What would prove it: %s\n", strings.Join(limitStrings(item.Actions, 3), "; "))
		}
	}
	if len(r.Controls) > limit {
		fmt.Fprintf(w, "    - %d more controls in JSON output\n", len(r.Controls)-limit)
	}
	fmt.Fprintln(w)
	return nil
}

func controlProofSpecsByControl(items []model.ControlProofSpec) map[string]model.ControlProofSpec {
	out := map[string]model.ControlProofSpec{}
	for _, item := range items {
		if item.Control != "" {
			out[item.Control] = item
		}
	}
	return out
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

func renderArchitectureFrameworkCoverage(w io.Writer, items []model.ArchitectureFrameworkArea, limit int) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "  Framework coverage:\n")
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	for _, item := range items[:limit] {
		fmt.Fprintf(w, "    - %s: %d target(s); %d breaking, %d controlled, %d unknown, %d not observed\n",
			item.Area,
			item.TargetCount,
			item.StatusCounts.Breaking,
			item.StatusCounts.Controlled,
			item.StatusCounts.Unknown,
			item.StatusCounts.NotObserved,
		)
		if item.Source != "" {
			fmt.Fprintf(w, "      Source: %s\n", item.Source)
		}
		if len(item.CheckIDs) > 0 {
			fmt.Fprintf(w, "      Checks: %s\n", strings.Join(limitStrings(item.CheckIDs, 6), "; "))
		}
		if len(item.Flaws) > 0 {
			fmt.Fprintf(w, "      Flaws: %s\n", strings.Join(limitStrings(item.Flaws, 4), "; "))
		}
		if len(item.EvidenceSources) > 0 {
			fmt.Fprintf(w, "      Evidence: %s\n", strings.Join(limitStrings(item.EvidenceSources, 5), "; "))
		}
		if len(item.ControlEvidenceNeeded) > 0 {
			fmt.Fprintf(w, "      Control evidence needed: %s\n", strings.Join(limitStrings(item.ControlEvidenceNeeded, 5), "; "))
		}
		if len(item.MissingEvidence) > 0 {
			fmt.Fprintf(w, "      Missing evidence: %s\n", strings.Join(limitStrings(item.MissingEvidence, 4), "; "))
		}
		if len(item.NextCollectors) > 0 {
			fmt.Fprintf(w, "      Next collectors: %s\n", strings.Join(limitStrings(item.NextCollectors, 2), "; "))
		}
	}
	if len(items) > limit {
		fmt.Fprintf(w, "    - %d more framework coverage rows in JSON output\n", len(items)-limit)
	}
}

func renderArchitectureClosurePlan(w io.Writer, items []model.ArchitectureClosure, limit int) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "  Closure plan:\n")
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	for _, item := range items[:limit] {
		fmt.Fprintf(w, "    - %s %s: %d flaw(s), %d target(s)\n",
			strings.ToUpper(item.Severity),
			item.Control,
			item.FlawCount,
			item.TargetCount,
		)
		if len(item.Flaws) > 0 {
			fmt.Fprintf(w, "      Flaws: %s\n", strings.Join(limitStrings(item.Flaws, 4), "; "))
		}
		if len(item.Targets) > 0 {
			fmt.Fprintf(w, "      Targets: %s\n", strings.Join(limitStrings(item.Targets, 5), "; "))
		}
		if len(item.EvidenceSources) > 0 {
			fmt.Fprintf(w, "      Evidence: %s\n", strings.Join(limitStrings(item.EvidenceSources, 5), "; "))
		}
		if len(item.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "      Evidence references: %s\n", strings.Join(evidenceReferenceLines(item.EvidenceReferences, 3), "; "))
		}
		if len(item.EvidenceSurfaces) > 0 {
			fmt.Fprintf(w, "      Evidence surfaces: %s\n", strings.Join(limitStrings(item.EvidenceSurfaces, 5), "; "))
		}
		if len(item.Actions) > 0 {
			fmt.Fprintf(w, "      Actions: %s\n", strings.Join(limitStrings(item.Actions, 3), "; "))
		}
	}
	if len(items) > limit {
		fmt.Fprintf(w, "    - %d more closure items in JSON output\n", len(items)-limit)
	}
}

func renderArchitectureEvidencePlan(w io.Writer, items []model.ArchitectureEvidencePlan, limit int) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "  Evidence plan:\n")
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	for _, item := range items[:limit] {
		fmt.Fprintf(w, "    - %s: %d gap(s), %d target(s)\n", item.NextCollector, item.GapCount, item.TargetCount)
		if len(item.Boundaries) > 0 {
			fmt.Fprintf(w, "      Boundaries: %s\n", strings.Join(limitStrings(item.Boundaries, 4), "; "))
		}
		if len(item.Targets) > 0 {
			fmt.Fprintf(w, "      Targets: %s\n", strings.Join(limitStrings(item.Targets, 5), "; "))
		}
		if len(item.MissingEvidence) > 0 {
			fmt.Fprintf(w, "      Missing evidence: %s\n", strings.Join(limitStrings(item.MissingEvidence, 5), "; "))
		}
	}
	if len(items) > limit {
		fmt.Fprintf(w, "    - %d more evidence-plan rows in JSON output\n", len(items)-limit)
	}
}

func renderArchitectureClosureFamilies(w io.Writer, items []model.ArchitectureClosureFamily, limit int) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "  Closure families:\n")
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	for _, item := range items[:limit] {
		fmt.Fprintf(w, "    - %s %s: %d control(s), %d flaw(s), %d target(s)\n",
			strings.ToUpper(item.Severity),
			item.Title,
			item.ControlCount,
			item.FlawCount,
			item.TargetCount,
		)
		if len(item.Controls) > 0 {
			fmt.Fprintf(w, "      Controls: %s\n", strings.Join(limitStrings(item.Controls, 6), "; "))
		}
		if len(item.Flaws) > 0 {
			fmt.Fprintf(w, "      Flaws: %s\n", strings.Join(limitStrings(item.Flaws, 4), "; "))
		}
		if len(item.Targets) > 0 {
			fmt.Fprintf(w, "      Targets: %s\n", strings.Join(limitStrings(item.Targets, 5), "; "))
		}
		if len(item.EvidenceSources) > 0 {
			fmt.Fprintf(w, "      Evidence: %s\n", strings.Join(limitStrings(item.EvidenceSources, 5), "; "))
		}
		if len(item.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "      Evidence references: %s\n", strings.Join(evidenceReferenceLines(item.EvidenceReferences, 3), "; "))
		}
		if len(item.Actions) > 0 {
			fmt.Fprintf(w, "      Actions: %s\n", strings.Join(limitStrings(item.Actions, 3), "; "))
		}
	}
	if len(items) > limit {
		fmt.Fprintf(w, "    - %d more closure families in JSON output\n", len(items)-limit)
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

func summarizeControlCatalog(items []model.ArchitectureClosure) model.ControlCatalogSummary {
	var summary model.ControlCatalogSummary
	targets := map[string]bool{}
	flaws := map[string]bool{}
	for _, item := range items {
		summary.Controls++
		switch strings.ToLower(item.Severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
		for _, target := range item.Targets {
			if target != "" {
				targets[target] = true
			}
		}
		for _, flaw := range item.Flaws {
			if flaw != "" {
				flaws[flaw] = true
			}
		}
	}
	summary.Targets = len(targets)
	summary.Flaws = len(flaws)
	return summary
}

func renderControlOperatorCases(w io.Writer, cases []model.ControlOperatorCase, limit int) {
	if len(cases) == 0 {
		return
	}
	fmt.Fprintf(w, "  Operator cases:\n")
	if limit <= 0 || limit > len(cases) {
		limit = len(cases)
	}
	for _, item := range cases[:limit] {
		fmt.Fprintf(w, "    - %s %s (%s): %d control(s), %d flaw(s), %d target(s)\n",
			strings.ToUpper(item.Severity),
			item.Title,
			item.ID,
			item.ControlCount,
			item.FlawCount,
			item.TargetCount,
		)
		if item.Question != "" {
			fmt.Fprintf(w, "      Question: %s\n", item.Question)
		}
		if item.Finding != "" {
			fmt.Fprintf(w, "      Why this case exists: %s\n", item.Finding)
		}
		if len(item.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "      Evidence references: %s\n", strings.Join(evidenceReferenceLines(item.EvidenceReferences, 2), "; "))
		}
		if len(item.StartingControls) > 0 {
			fmt.Fprintf(w, "      Start with: %s\n", strings.Join(limitStrings(item.StartingControls, 4), "; "))
		}
		if len(item.ProofSurfaces) > 0 {
			fmt.Fprintf(w, "      Prove at: %s\n", strings.Join(limitStrings(item.ProofSurfaces, 4), "; "))
		}
		if len(item.EvidenceExamples) > 0 {
			fmt.Fprintf(w, "      Evidence examples: %s\n", strings.Join(controlEvidenceExampleLines(item.EvidenceExamples, 2), "; "))
		}
		if len(item.RerunCommands) > 0 {
			fmt.Fprintf(w, "      Rerun: %s\n", strings.Join(limitStrings(item.RerunCommands, 2), "; "))
		}
		if len(item.SuccessCriteria) > 0 {
			fmt.Fprintf(w, "      Done when: %s\n", strings.Join(limitStrings(item.SuccessCriteria, 2), "; "))
		}
	}
	if len(cases) > limit {
		fmt.Fprintf(w, "    - %d more operator cases in JSON output\n", len(cases)-limit)
	}
}

func buildControlOperatorCases(workstreams []model.ControlBreakPathWorkstream, tasks []model.ControlVerificationTask) []model.ControlOperatorCase {
	taskByControl := map[string]model.ControlVerificationTask{}
	for _, task := range tasks {
		if task.Control != "" {
			taskByControl[task.Control] = task
		}
	}
	var out []model.ControlOperatorCase
	for _, workstream := range workstreams {
		selectedTasks := controlOperatorCaseStartingTasks(workstream, taskByControl)
		caseItem := model.ControlOperatorCase{
			ID:                 "case:" + workstream.ID,
			Title:              workstream.Title,
			Severity:           workstream.Severity,
			Question:           controlOperatorCaseQuestion(workstream),
			Finding:            workstream.Rationale,
			TargetCount:        workstream.TargetCount,
			FlawCount:          workstream.FlawCount,
			ControlCount:       workstream.ControlCount,
			Targets:            append([]string{}, workstream.Targets...),
			Flaws:              append([]string{}, workstream.Flaws...),
			EvidenceReferences: append([]model.EvidenceReference{}, workstream.EvidenceReferences...),
			StartingControls:   controlOperatorCaseStartingControls(selectedTasks),
			StartingTaskIDs:    controlOperatorCaseStartingTaskIDs(selectedTasks),
			ProofSurfaces:      append([]string{}, workstream.ProofSurfaces...),
			RerunCommands:      controlOperatorCaseRerunCommands(selectedTasks),
			SuccessCriteria:    append([]string{}, workstream.SuccessCriteria...),
			Limitations:        append([]string{}, workstream.Limitations...),
		}
		var examples []model.ControlEvidenceExample
		var limitations []string
		for _, task := range selectedTasks {
			examples = append(examples, task.EvidenceExamples...)
			limitations = append(limitations, task.Limitations...)
		}
		caseItem.EvidenceExamples = dedupeControlEvidenceExamples(examples)
		caseItem.Limitations = uniqueSortedStrings(append(caseItem.Limitations, limitations...))
		if len(caseItem.Limitations) == 0 {
			caseItem.Limitations = []string{"Operator cases are deterministic proof guides; they do not prove live enforcement unless Ariadne observes runtime enforcement evidence or the missing hard barriers disappear."}
		}
		out = append(out, caseItem)
	}
	if out == nil {
		return []model.ControlOperatorCase{}
	}
	return out
}

func controlOperatorCaseQuestion(workstream model.ControlBreakPathWorkstream) string {
	if workstream.Title == "" {
		return "What evidence proves this architecture break path is closed?"
	}
	return fmt.Sprintf("What evidence proves the %s break path is closed?", workstream.Title)
}

func controlOperatorCaseStartingTasks(workstream model.ControlBreakPathWorkstream, taskByControl map[string]model.ControlVerificationTask) []model.ControlVerificationTask {
	orderedControls := append([]string{}, workstream.Controls...)
	if len(orderedControls) == 0 {
		orderedControls = append([]string{}, workstream.StartingControls...)
	}
	var selected []model.ControlVerificationTask
	for _, requireControlPrefix := range []bool{true, false} {
		for _, control := range orderedControls {
			if requireControlPrefix && !strings.HasPrefix(control, "control:") {
				continue
			}
			if !requireControlPrefix && strings.HasPrefix(control, "control:") {
				continue
			}
			task, ok := taskByControl[control]
			if !ok || hasControlVerificationTask(selected, task.ID) {
				continue
			}
			selected = append(selected, task)
			if len(selected) >= 5 {
				return selected
			}
		}
		if len(selected) > 0 {
			return selected
		}
	}
	return selected
}

func hasControlVerificationTask(tasks []model.ControlVerificationTask, id string) bool {
	for _, task := range tasks {
		if task.ID == id {
			return true
		}
	}
	return false
}

func controlOperatorCaseStartingControls(tasks []model.ControlVerificationTask) []string {
	var out []string
	for _, task := range tasks {
		out = append(out, task.Control)
	}
	return out
}

func controlOperatorCaseStartingTaskIDs(tasks []model.ControlVerificationTask) []string {
	var out []string
	for _, task := range tasks {
		out = append(out, task.ID)
	}
	return out
}

func controlOperatorCaseRerunCommands(tasks []model.ControlVerificationTask) []string {
	var out []string
	for _, task := range tasks {
		out = append(out, task.RerunCommands...)
		if len(out) >= 2 {
			break
		}
	}
	return uniqueStrings(firstStrings(out, 2))
}

func dedupeControlEvidenceExamples(items []model.ControlEvidenceExample) []model.ControlEvidenceExample {
	seen := map[string]bool{}
	var out []model.ControlEvidenceExample
	for _, item := range items {
		key := item.Surface + "\x00" + item.Summary + "\x00" + item.Example
		if key == "\x00\x00" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	if out == nil {
		return []model.ControlEvidenceExample{}
	}
	return out
}

func renderControlBreakPathWorkstreams(w io.Writer, workstreams []model.ControlBreakPathWorkstream, limit int) {
	if len(workstreams) == 0 {
		return
	}
	fmt.Fprintf(w, "  Break-path workstreams:\n")
	if limit <= 0 || limit > len(workstreams) {
		limit = len(workstreams)
	}
	for _, item := range workstreams[:limit] {
		fmt.Fprintf(w, "    - %s %s: %d control(s), %d flaw(s), %d target(s)\n",
			strings.ToUpper(item.Severity),
			item.Title,
			item.ControlCount,
			item.FlawCount,
			item.TargetCount,
		)
		if len(item.StartingControls) > 0 {
			fmt.Fprintf(w, "      Starting controls: %s\n", strings.Join(limitStrings(item.StartingControls, 5), "; "))
		}
		if len(item.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "      Evidence references: %s\n", strings.Join(evidenceReferenceLines(item.EvidenceReferences, 2), "; "))
		}
		if len(item.ProofSurfaces) > 0 {
			fmt.Fprintf(w, "      Where to prove this: %s\n", strings.Join(limitStrings(item.ProofSurfaces, 5), "; "))
		}
		if len(item.SuccessCriteria) > 0 {
			fmt.Fprintf(w, "      Done when: %s\n", strings.Join(limitStrings(item.SuccessCriteria, 2), "; "))
		}
	}
	if len(workstreams) > limit {
		fmt.Fprintf(w, "    - %d more workstreams in JSON output\n", len(workstreams)-limit)
	}
}

func buildControlBreakPathWorkstreams(families []model.ArchitectureClosureFamily, tasks []model.ControlVerificationTask) []model.ControlBreakPathWorkstream {
	taskByControl := map[string]model.ControlVerificationTask{}
	for _, task := range tasks {
		if task.Control != "" {
			taskByControl[task.Control] = task
		}
	}
	var out []model.ControlBreakPathWorkstream
	for _, family := range families {
		var startingTaskIDs []string
		var startingControls []string
		var evidenceRefs []model.EvidenceReference
		var proofSurfaces []string
		var limitations []string
		for _, control := range family.Controls {
			task, ok := taskByControl[control]
			if !ok {
				continue
			}
			if len(startingTaskIDs) < 5 {
				startingTaskIDs = append(startingTaskIDs, task.ID)
				startingControls = append(startingControls, task.Control)
			}
			evidenceRefs = append(evidenceRefs, task.EvidenceReferences...)
			proofSurfaces = append(proofSurfaces, task.ProofSurfaces...)
			limitations = append(limitations, task.Limitations...)
		}
		workstream := model.ControlBreakPathWorkstream{
			ID:                 family.ID,
			Title:              family.Title,
			Severity:           family.Severity,
			ControlCount:       family.ControlCount,
			FlawCount:          family.FlawCount,
			TargetCount:        family.TargetCount,
			Controls:           append([]string{}, family.Controls...),
			Flaws:              append([]string{}, family.Flaws...),
			Targets:            append([]string{}, family.Targets...),
			EvidenceReferences: dedupeEvidenceReferences(evidenceRefs),
			ProofSurfaces:      uniqueSortedStrings(proofSurfaces),
			StartingTaskIDs:    startingTaskIDs,
			StartingControls:   startingControls,
			Rationale:          controlWorkstreamRationale(family),
			SuccessCriteria:    controlWorkstreamSuccessCriteria(family),
			Limitations:        uniqueSortedStrings(limitations),
		}
		if len(workstream.Limitations) == 0 {
			workstream.Limitations = []string{"This workstream groups deterministic proof tasks. It does not prove runtime enforcement until Ariadne observes enforcement evidence or the missing hard barriers disappear from the architecture output."}
		}
		out = append(out, workstream)
	}
	if out == nil {
		return []model.ControlBreakPathWorkstream{}
	}
	return out
}

func controlWorkstreamRationale(family model.ArchitectureClosureFamily) string {
	if len(family.Flaws) == 0 {
		return "This capability family contains missing hard barriers from the architecture closure plan."
	}
	return fmt.Sprintf("Addresses %d architecture flaw(s) across %d target(s): %s", family.FlawCount, family.TargetCount, strings.Join(limitStrings(family.Flaws, 3), "; "))
}

func controlWorkstreamSuccessCriteria(family model.ArchitectureClosureFamily) []string {
	return []string{
		fmt.Sprintf("%s no longer appears in the control catalog workstreams for the selected status filter.", family.Title),
		"Relevant controls are no longer returned as missing hard barriers in the controls output.",
		"Associated architecture flaws are controlled, not observed, or no longer list the workstream controls in missing_hard_barriers.",
	}
}

func renderControlVerificationTasks(w io.Writer, tasks []model.ControlVerificationTask, limit int) {
	if len(tasks) == 0 {
		return
	}
	fmt.Fprintf(w, "  Verification tasks:\n")
	if limit <= 0 || limit > len(tasks) {
		limit = len(tasks)
	}
	for _, task := range tasks[:limit] {
		fmt.Fprintf(w, "    - %s %s\n", strings.ToUpper(task.Severity), task.Control)
		if task.Why != "" {
			fmt.Fprintf(w, "      Why: %s\n", task.Why)
		}
		if len(task.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "      Evidence references: %s\n", strings.Join(evidenceReferenceLines(task.EvidenceReferences, 2), "; "))
		}
		if len(task.ProofSurfaces) > 0 {
			fmt.Fprintf(w, "      Add or verify at: %s\n", strings.Join(limitStrings(task.ProofSurfaces, 4), "; "))
		}
		if len(task.RecognizedIndicators) > 0 {
			fmt.Fprintf(w, "      Accepted indicators: %s\n", strings.Join(limitStrings(task.RecognizedIndicators, 5), "; "))
		}
		if len(task.EvidenceExamples) > 0 {
			fmt.Fprintf(w, "      Evidence examples: %s\n", strings.Join(controlEvidenceExampleLines(task.EvidenceExamples, 2), "; "))
		}
		if len(task.RerunCommands) > 0 {
			fmt.Fprintf(w, "      Rerun: %s\n", strings.Join(limitStrings(task.RerunCommands, 2), "; "))
		}
		if len(task.SuccessCriteria) > 0 {
			fmt.Fprintf(w, "      Done when: %s\n", strings.Join(limitStrings(task.SuccessCriteria, 2), "; "))
		}
	}
	if len(tasks) > limit {
		fmt.Fprintf(w, "    - %d more verification tasks in JSON output\n", len(tasks)-limit)
	}
}

type controlVerificationCommandContext struct {
	RunKind      string
	Path         string
	Mode         string
	Agent        string
	StatusFilter string
}

func buildControlVerificationTasks(items []model.ArchitectureClosure, proofSpecs []model.ControlProofSpec, ctx controlVerificationCommandContext) []model.ControlVerificationTask {
	proofByControl := controlProofSpecsByControl(proofSpecs)
	var out []model.ControlVerificationTask
	for _, item := range items {
		if item.Control == "" {
			continue
		}
		proof := proofByControl[item.Control]
		proofSurfaces := proof.ProofSurfaces
		if len(proofSurfaces) == 0 {
			proofSurfaces = item.EvidenceSurfaces
		}
		limitations := append([]string{}, proof.Limitations...)
		if len(limitations) == 0 {
			limitations = []string{"This task verifies deterministic evidence Ariadne can parse; it does not prove live runtime enforcement unless runtime enforcement evidence is observed."}
		}
		task := model.ControlVerificationTask{
			ID:                   controlVerificationTaskID(item.Control),
			Control:              item.Control,
			Severity:             item.Severity,
			Targets:              append([]string{}, item.Targets...),
			Question:             fmt.Sprintf("Can Ariadne observe %s evidence that breaks this missing hard-barrier path?", item.Control),
			Why:                  controlVerificationWhy(item),
			EvidenceReferences:   dedupeEvidenceReferences(item.EvidenceReferences),
			ProofSurfaces:        uniqueSortedStrings(proofSurfaces),
			RecognizedIndicators: append([]string{}, proof.RecognizedIndicators...),
			EvidenceExamples:     controlEvidenceExamples(item.Control, proofSurfaces, proof.RecognizedIndicators),
			Actions:              append([]string{}, item.Actions...),
			RerunCommands:        controlVerificationCommands(ctx),
			SuccessCriteria:      controlVerificationSuccessCriteria(item.Control),
			Limitations:          limitations,
		}
		out = append(out, task)
	}
	if out == nil {
		return []model.ControlVerificationTask{}
	}
	return out
}

func controlVerificationTaskID(control string) string {
	var b strings.Builder
	b.WriteString("verify:")
	for _, r := range strings.ToLower(control) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		if b.Len() > len("verify:") && b.String()[b.Len()-1] != '-' {
			b.WriteRune('-')
		}
	}
	id := strings.TrimRight(b.String(), "-")
	if id == "verify:" {
		return "verify:control"
	}
	return id
}

func controlVerificationWhy(item model.ArchitectureClosure) string {
	if len(item.Flaws) == 0 {
		return "This missing hard barrier is part of the architecture closure plan."
	}
	return "Closes: " + strings.Join(limitStrings(item.Flaws, 4), "; ")
}

func controlVerificationCommands(ctx controlVerificationCommandContext) []string {
	mode := ctx.Mode
	if mode == "" {
		mode = "repo"
	}
	agent := ctx.Agent
	if agent == "" {
		agent = "all"
	}
	status := ctx.StatusFilter
	if status == "" {
		status = "breaking"
	}
	if ctx.RunKind == "control_catalog_scan" {
		return []string{
			fmt.Sprintf("ariadne controls --targets <targets-file> --mode %s --agent %s --status %s", shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(status)),
			fmt.Sprintf("ariadne architecture --targets <targets-file> --mode %s --agent %s --status all", shellQuoteCommandArg(mode), shellQuoteCommandArg(agent)),
		}
	}
	path := ctx.Path
	if path == "" {
		path = "<target-path>"
	}
	return []string{
		fmt.Sprintf("ariadne controls --path %s --mode %s --agent %s --status %s", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(status)),
		fmt.Sprintf("ariadne architecture --path %s --mode %s --agent %s --status all", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent)),
	}
}

func controlVerificationSuccessCriteria(control string) []string {
	return []string{
		fmt.Sprintf("%s is no longer returned in the controls output as a missing hard barrier.", control),
		fmt.Sprintf("Associated architecture flaws no longer list %s in control_test.missing_hard_barriers.", control),
		"If the task is still present, evidence_refs should point to the remaining source or architecture gap.",
	}
}

func controlEvidenceExamples(control string, proofSurfaces []string, indicators []string) []model.ControlEvidenceExample {
	surface := preferredControlEvidenceExampleSurface(control, proofSurfaces)
	if surface == "" {
		surface = "supported control evidence surface"
	}
	fields := firstStrings(controlEvidenceExampleIndicators(control, indicators), 2)
	return []model.ControlEvidenceExample{
		{
			Surface: surface,
			Summary: fmt.Sprintf("Declare %s evidence for %s using parser-recognized indicators.", strings.Join(fields, " and "), control),
			Example: controlEvidenceExampleBody(surface, fields),
			Limitations: []string{
				"Example evidence shows the declared proof shape only; live enforcement still requires observed runtime enforcement evidence when applicable.",
			},
		},
	}
}

func preferredControlEvidenceExampleSurface(control string, proofSurfaces []string) string {
	for _, preferred := range preferredControlEvidenceSurfaceOrder(control) {
		for _, surface := range proofSurfaces {
			if surface == preferred {
				return surface
			}
		}
	}
	for _, surface := range proofSurfaces {
		if strings.HasPrefix(surface, ".ariadne/") {
			return surface
		}
	}
	for _, surface := range proofSurfaces {
		if strings.HasPrefix(surface, ".claude/") || strings.HasPrefix(surface, ".codex/") {
			return surface
		}
	}
	if len(proofSurfaces) > 0 {
		return proofSurfaces[0]
	}
	return ""
}

func preferredControlEvidenceSurfaceOrder(control string) []string {
	switch {
	case strings.Contains(control, "input") || strings.Contains(control, "trusted-source") || strings.Contains(control, "prompt-injection"):
		return []string{".ariadne/input-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "response") || strings.Contains(control, "triage") || strings.Contains(control, "behavioral") || strings.Contains(control, "session-termination") || strings.Contains(control, "credential-revocation") || strings.Contains(control, "quarantine") || strings.Contains(control, "access-reduction"):
		return []string{".ariadne/response-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "identity") || strings.Contains(control, "credential") || strings.Contains(control, "jit") || strings.Contains(control, "token-lifetime") || strings.Contains(control, "hardware-bound"):
		return []string{".ariadne/identity-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "egress") || strings.Contains(control, "network-restricted") || strings.Contains(control, "webhook") || strings.Contains(control, "per-tool-network"):
		return []string{".ariadne/egress-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "output"):
		return []string{".ariadne/output-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "resource") || strings.Contains(control, "rate-limit") || strings.Contains(control, "spend") || strings.Contains(control, "loop") || strings.Contains(control, "timeout") || strings.Contains(control, "concurrency") || strings.Contains(control, "circuit-breaker"):
		return []string{".ariadne/resource-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "governance") || strings.Contains(control, "inventory") || strings.Contains(control, "owner") || strings.Contains(control, "deployment-approval") || strings.Contains(control, "risk-assessment") || strings.Contains(control, "shadow-ai"):
		return []string{".ariadne/governance-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "config") || strings.Contains(control, "managed-settings") || strings.Contains(control, "immutable-agent-runtime") || strings.Contains(control, "rollback"):
		return []string{".ariadne/integrity-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "delegation") || strings.Contains(control, "delegate") || strings.Contains(control, "subagent") || strings.Contains(control, "agent-to-agent") || strings.Contains(control, "origin-intent"):
		return []string{".ariadne/delegation-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "memory") || strings.Contains(control, "context"):
		return []string{".ariadne/memory-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "authorization") || strings.Contains(control, "abac") || strings.Contains(control, "caller") || strings.Contains(control, "workload") || strings.Contains(control, "privilege-scoping") || strings.Contains(control, "access-revocation"):
		return []string{".ariadne/authorization-policy.json", ".ariadne/workload-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "audit") || strings.Contains(control, "log") || strings.Contains(control, "trace") || strings.Contains(control, "telemetry"):
		return []string{".ariadne/observability-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "tool") || strings.Contains(control, "mcp"):
		return []string{".ariadne/tool-policy.json", ".ariadne/mcp-policy.json", ".ariadne/agent-policy.json"}
	case strings.Contains(control, "ai-bom") || strings.Contains(control, "model") || strings.Contains(control, "training") || strings.Contains(control, "dependency") || strings.Contains(control, "provider") || strings.Contains(control, "artifact") || strings.Contains(control, "runtime-component"):
		return []string{".ariadne/supply-chain-policy.json", ".ariadne/agent-policy.json"}
	default:
		return []string{".ariadne/agent-policy.json"}
	}
}

func firstStrings(items []string, limit int) []string {
	if limit <= 0 || len(items) <= limit {
		return append([]string{}, items...)
	}
	return append([]string{}, items[:limit]...)
}

func controlEvidenceExampleIndicators(control string, indicators []string) []string {
	if len(indicators) > 0 {
		return append([]string{}, indicators...)
	}
	return controlRecognizedIndicators(control)
}

func controlEvidenceExampleBody(surface string, indicators []string) string {
	if len(indicators) == 0 {
		return "{}"
	}
	if strings.HasSuffix(surface, ".toml") || strings.Contains(surface, "config.toml") {
		var lines []string
		for _, indicator := range indicators {
			key, value := controlEvidenceExampleKeyValue(indicator)
			lines = append(lines, fmt.Sprintf("%s = %s", key, value))
		}
		return strings.Join(lines, "\n")
	}
	if strings.HasSuffix(surface, ".md") {
		var lines []string
		for _, indicator := range indicators {
			lines = append(lines, "- "+indicator)
		}
		return strings.Join(lines, "\n")
	}
	var parts []string
	for _, indicator := range indicators {
		key, value := controlEvidenceExampleKeyValue(indicator)
		parts = append(parts, fmt.Sprintf("%q: %s", key, value))
	}
	return "{\n  " + strings.Join(parts, ",\n  ") + "\n}"
}

func controlEvidenceExampleKeyValue(indicator string) (string, string) {
	key := indicator
	value := "true"
	if before, after, ok := strings.Cut(indicator, ":"); ok {
		key = before
		switch strings.ToLower(after) {
		case "true", "false":
			value = strings.ToLower(after)
		default:
			value = fmt.Sprintf("%q", after)
		}
	}
	key = strings.TrimSpace(key)
	key = strings.Trim(key, "\"'")
	key = strings.ReplaceAll(key, "-", "_")
	if key == "" {
		key = "control_evidence"
	}
	return key, value
}

func controlEvidenceExampleLines(examples []model.ControlEvidenceExample, limit int) []string {
	if limit <= 0 || limit > len(examples) {
		limit = len(examples)
	}
	var out []string
	for _, example := range examples[:limit] {
		line := strings.TrimSpace(example.Surface)
		if example.Summary != "" {
			if line != "" {
				line += ": "
			}
			line += strings.TrimSpace(example.Summary)
		}
		if example.Example != "" {
			if line != "" {
				line += " "
			}
			line += "Example: " + compactExample(example.Example)
		}
		if line != "" {
			out = append(out, line)
		}
	}
	if len(examples) > limit {
		out = append(out, fmt.Sprintf("%d additional example(s) in JSON output", len(examples)-limit))
	}
	if out == nil {
		return []string{}
	}
	return out
}

func compactExample(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 180 {
		return value[:177] + "..."
	}
	return value
}

func shellQuoteCommandArg(value string) string {
	if value == "" {
		return "''"
	}
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
		return value
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '/' || r == '.' || r == '_' || r == '-' || r == ':' {
			continue
		}
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	return value
}

func buildControlProofSpecs(items []model.ArchitectureClosure) []model.ControlProofSpec {
	var out []model.ControlProofSpec
	seen := map[string]bool{}
	for _, item := range items {
		if item.Control == "" || seen[item.Control] {
			continue
		}
		seen[item.Control] = true
		out = append(out, model.ControlProofSpec{
			Control:              item.Control,
			EvidenceKind:         controlEvidenceKind(item.Control),
			ProofSurfaces:        uniqueSortedStrings(item.EvidenceSurfaces),
			RecognizedIndicators: controlRecognizedIndicators(item.Control),
			Notes:                controlProofNotes(item.Control),
			Limitations: []string{
				"Ariadne treats these as deterministic declared or observed evidence indicators; it does not prove live enforcement unless a collector observes runtime enforcement evidence.",
			},
		})
	}
	if out == nil {
		return []model.ControlProofSpec{}
	}
	return out
}

func controlEvidenceKind(control string) string {
	switch control {
	case "control:agent-action-log-evidence",
		"control:approval-log-evidence",
		"control:observed-request-traceability",
		"control:tool-call-audit-evidence":
		return "observed_log_or_transcript_metadata"
	case "control:telemetry-export", "control:immutable-audit-log":
		return "declared_or_observed_observability_evidence"
	default:
		return "declared_control_evidence"
	}
}

func controlProofNotes(control string) []string {
	switch control {
	case "control:input-isolation", "control:trusted-source-policy":
		return []string{"Input isolation or trusted-source policy can break untrusted instruction influence when connected to authority-bearing runtime paths."}
	case "control:cryptographic-identity", "control:credential-isolation", "control:short-lived-credential", "control:hardware-bound-credential", "control:jit-access":
		return []string{"Identity controls are strongest when agent identity and credential scoping are both present."}
	case "control:network-restricted", "control:egress-destination-allowlist", "control:webhook-allowlist", "control:per-tool-network-scope":
		return []string{"Egress controls are strongest when private-data access and arbitrary external communication cannot exist in the same path."}
	case "control:approval-log-evidence", "control:approval-required":
		return []string{"Approval evidence needs both a pre-action gate and reconstructable approval decision metadata."}
	default:
		return []string{}
	}
}

func controlRecognizedIndicators(control string) []string {
	switch control {
	case "control:input-isolation":
		return []string{"input_isolation", "instruction_isolation", "treat_untrusted_as_data", "data_only_context"}
	case "control:trusted-source-policy":
		return []string{"trusted_instruction_sources", "trusted_sources", "allowed_instruction_sources", "allow_untrusted_instructions:false"}
	case "control:deny-by-default", "control:deny-by-default-permissions":
		return []string{"deny_by_default", "default_policy:deny", "default_deny:true", "deny-by-default"}
	case "control:least-agency-policy":
		return []string{"least_agency", "least_privilege", "tool_scope", "permission_scope"}
	case "control:scoped-permissions":
		return []string{"scoped_permissions", "permission_scope", "tool_scope", "deny_read", "sandbox_mode:workspace-write", "sandbox_mode:read-only"}
	case "control:mcp-reviewed-pinned":
		return []string{"require_pinned_packages", "pinned_packages", "package_digest", "reviewed_mcp_servers", "mcp_review_required"}
	case "control:tool-allowlist":
		return []string{"approved_tools", "allowed_tools", "tool_allowlist", "approved_mcp_servers", "mcp_allowlist"}
	case "control:tool-descriptor-integrity":
		return []string{"tool_descriptor_integrity", "descriptor_integrity", "tool_schema_integrity", "descriptor_signature"}
	case "control:tool-argument-validation":
		return []string{"tool_argument_validation", "argument_validation", "validate_tool_arguments", "pre_tool_use"}
	case "control:tool-auth-required":
		return []string{"tool_auth_required", "tool_authentication", "mcp_auth_required", "oauth_tool_auth", "short_lived_tool_token"}
	case "control:signed-tool-artifacts":
		return []string{"signed_tool_artifacts", "signed_mcp_servers", "tool_signature", "cosign", "sigstore"}
	case "control:tool-deployment-verification":
		return []string{"tool_deployment_verification", "mcp_deployment_verification", "reject_unsigned_tools", "tool_admission_verification"}
	case "control:tool-sandbox-execution":
		return []string{"tool_sandbox_execution", "sandboxed_tool_execution", "mcp_sandbox", "tool_filesystem_isolation"}
	case "control:network-restricted":
		return []string{"network_access:false", "external_network:false", "block_external_network", "deny_network"}
	case "control:egress-destination-allowlist":
		return []string{"egress_destination_allowlist", "external_destination_allowlist", "allowed_destinations", "allowed_domains"}
	case "control:webhook-allowlist":
		return []string{"webhook_allowlist", "allowed_webhooks", "approved_webhooks", "webhook_destinations"}
	case "control:per-tool-network-scope":
		return []string{"per_tool_network_scope", "tool_network_scope", "tool_egress_scope", "allowed_network_by_tool"}
	case "control:egress-content-filter":
		return []string{"egress_content_filter", "external_content_filter", "sensitive_output_filter", "block_secret_like"}
	case "control:egress-audit":
		return []string{"egress_audit", "outbound_audit", "external_communication_logging", "egress_log"}
	case "control:output-sensitive-data-filter":
		return []string{"output_sensitive_data_filter", "sensitive_output_filter", "output_dlp", "credential_filter"}
	case "control:output-redaction":
		return []string{"output_redaction", "redact_outputs", "block_sensitive_output", "redact_secret_like", "output_delivery_gate"}
	case "control:output-filter-logging":
		return []string{"output_filter_logging", "output_control_audit", "filtering_events", "redaction_logging"}
	case "control:semantic-output-analysis":
		return []string{"semantic_output_analysis", "output_semantic_review", "semantic_dlp", "encoded_secret_detection"}
	case "control:high-risk-output-review":
		return []string{"high_risk_output_review", "human_review_for_high_risk_output", "output_approval", "approve_sensitive_output"}
	case "control:cryptographic-identity":
		return []string{"cryptographic_identity", "workload_identity", "agent_certificate", "spiffe", "spiffe_id", "mtls"}
	case "control:credential-isolation":
		return []string{"credential_isolation", "per_agent_credentials", "unique_agent_credentials", "agent_scoped_credentials", "no_shared_credentials"}
	case "control:short-lived-credential":
		return []string{"oauth", "oidc", "short_lived", "federated_identity", "jit_access"}
	case "control:hardware-bound-credential":
		return []string{"hardware_bound", "hardware_backed", "passkey", "fido2", "secure_enclave", "tpm"}
	case "control:jit-access", "control:jit-elevation":
		return []string{"jit_access", "just_in_time", "jit_elevation", "privilege_elevation_ttl", "standing_access:false"}
	case "control:token-lifetime-policy":
		return []string{"token_lifetime", "credential_ttl", "max_token_ttl", "max_session_duration", "ttl_minutes"}
	case "control:identity-lifecycle":
		return []string{"identity_lifecycle", "credential_rotation", "certificate_lifecycle", "revocation:true", "revoke_on_exit"}
	case "control:credential-helper":
		return []string{"credential_helper", "credential_process", "secret_manager", "vault", "keychain"}
	case "control:identity-based-isolation":
		return []string{"identity_based_isolation", "workload_isolation", "identity_aware_proxy"}
	case "control:named-caller-allowlist":
		return []string{"named_callers", "allowed_callers", "caller_allowlist", "allowed_principals"}
	case "control:abac-policy":
		return []string{"abac", "attribute_based", "subject_attributes", "resource_attributes", "context_attributes", "policy_conditions"}
	case "control:network-segmentation":
		return []string{"network_segmentation", "microsegmentation"}
	case "control:tool-scope-policy":
		return []string{"tool_scope", "tool_scopes", "per_tool_scope", "allowed_tools", "permission_scope"}
	case "control:per-action-authorization":
		return []string{"per_action_authorization", "authorize_each_action", "per_tool_authorization", "authorize_tool_call"}
	case "control:continuous-authorization":
		return []string{"continuous_authorization", "real_time_policy_evaluation", "policy_evaluation_per_action", "reauthorize_on_risk_change"}
	case "control:dynamic-privilege-scoping":
		return []string{"dynamic_privilege_scoping", "dynamic_permission_scope", "just_enough_access", "task_scoped_privileges"}
	case "control:automatic-access-revocation":
		return []string{"automatic_access_revocation", "auto_revoke_access", "revoke_on_risk_change", "revoke_after_task", "policy_failure_revocation"}
	case "control:approval-required":
		return []string{"approval_policy:on-request", "approval_policy:on-failure", "approval_required:true", "require_approval:true", "pretooluse"}
	case "control:approval-log-evidence":
		return []string{"approval_logging", "approval decision event shape", "permission decision event shape", "timestamp"}
	case "control:agent-action-log-evidence":
		return []string{"tool_call_logging", "agent action event shape", "request_id", "trace_id", "timestamp"}
	case "control:tool-call-audit-evidence":
		return []string{"tool_call_logging", "tool call event shape", "tool name", "timestamp"}
	case "control:observed-request-traceability":
		return []string{"request_id", "trace_id", "correlation_id", "distributed_tracing", "input_to_output_trace"}
	case "control:telemetry-export":
		return []string{"telemetry_export", "siem_export", "otlp", "opentelemetry", "exporters"}
	case "control:immutable-audit-log":
		return []string{"immutable_audit", "append_only", "object_lock", "worm", "tamper_resistant"}
	case "control:tool-rate-limit":
		return []string{"tool_rate_limit", "rate_limits", "api_call_limit", "requests_per_minute"}
	case "control:spend-limit":
		return []string{"spend_limit", "budget_limit", "cost_limit", "token_budget", "quota_limit"}
	case "control:loop-guard":
		return []string{"loop_guard", "loop_detection", "max_iterations", "recursion_limit", "repeat_call_guard"}
	case "control:tool-timeout":
		return []string{"tool_timeout", "timeout_seconds", "execution_timeout", "max_tool_runtime"}
	case "control:concurrency-limit":
		return []string{"concurrency_limit", "max_concurrency", "parallel_tool_limit", "worker_limit"}
	case "control:tool-circuit-breaker":
		return []string{"tool_circuit_breaker", "circuit_breaker", "rate_limit", "spend_limit", "usage_limit"}
	case "control:resource-usage-audit":
		return []string{"resource_usage_audit", "usage_logging", "cost_logging", "budget_alert", "quota_alert"}
	case "control:automated-triage":
		return []string{"automated_triage", "first_pass_investigation", "alert_triage", "siem_triage"}
	case "control:behavioral-monitoring":
		return []string{"behavioral_monitoring", "anomaly_detection", "behavior_baseline", "dwell_time"}
	case "control:session-termination":
		return []string{"session_termination", "terminate_session", "kill_session", "end_agent_session"}
	case "control:credential-revocation":
		return []string{"credential_revocation", "revoke_credentials", "revoke_tokens", "token_revocation"}
	case "control:containment-quarantine":
		return []string{"containment_quarantine", "automatic_containment", "quarantine_agent", "network_quarantine"}
	case "control:dynamic-access-reduction":
		return []string{"dynamic_access_reduction", "privilege_reduction", "downscope_on_risk"}
	case "control:response-escalation":
		return []string{"response_escalation", "escalation_paths", "incident_response_runbook"}
	case "control:agent-inventory":
		return []string{"agent_inventory", "agent_registry", "registered_agents", "ai_inventory"}
	case "control:accountable-owner", "control:deployment-owner":
		return []string{"deployment_owner", "accountable_owner", "security_owner", "responsible_team"}
	case "control:deployment-approval":
		return []string{"deployment_approval", "new_agent_approval", "governance_approval", "approved_deployment"}
	case "control:risk-assessment":
		return []string{"risk_assessment", "risk_tier", "data_classification", "business_impact"}
	case "control:governance-review", "control:governance-audit":
		return []string{"governance_review", "policy_review", "periodic_review", "compliance_review", "review_cadence"}
	case "control:shadow-ai-discovery":
		return []string{"shadow_ai_detection", "shadow_ai_discovery", "unauthorized_llm_detection", "unmanaged_agent_detection"}
	case "control:context-retention":
		return []string{"context_retention", "retention_days", "memory_retention", "transcript_retention"}
	case "control:memory-isolation":
		return []string{"memory_isolation", "context_isolation", "tenant_memory_isolation", "isolated_memory"}
	case "control:context-integrity":
		return []string{"context_integrity", "memory_integrity", "context_hash", "context_signature"}
	case "control:context-provenance":
		return []string{"context_provenance", "memory_provenance", "context_source", "source_attribution"}
	case "control:config-version-control":
		return []string{"version_controlled_config", "config_version_control", "config_in_git", "change_history"}
	case "control:config-review-required":
		return []string{"config_review_required", "required_review", "pull_request_required", "code_owner_review"}
	case "control:signed-config":
		return []string{"signed_config", "config_signature", "policy_signature", "signature_required"}
	case "control:config-deployment-verification":
		return []string{"config_deployment_verification", "verify_before_deploy", "reject_unsigned", "admission_verification"}
	case "control:managed-settings-enforced":
		return []string{"managed_settings_enforced", "managed_only", "users_cannot_override", "mdm_enforced"}
	case "control:immutable-agent-runtime":
		return []string{"immutable_runtime", "immutable_agent_runtime", "ephemeral_vm", "attested_image"}
	case "control:config-rollback-procedure":
		return []string{"rollback_procedure", "documented_rollback", "restore_previous_config", "previous_versions"}
	case "control:automated-config-rollback":
		return []string{"automated_rollback", "auto_rollback", "rollback_on_failure", "self_healing"}
	case "control:ai-bom":
		return []string{"ai_bom", "ai-bom", "ml_bom", "cyclonedx", "bill_of_materials"}
	case "control:model-provenance":
		return []string{"model_provenance", "model_provider", "model_version", "model_digest", "model_lineage"}
	case "control:training-data-lineage":
		return []string{"training_data_lineage", "dataset_lineage", "fine_tuning_data"}
	case "control:dependency-health-scan":
		return []string{"dependency_health", "openssf_scorecard", "dependency_scan", "vulnerability_scan"}
	case "control:provider-risk-review":
		return []string{"provider_risk_review", "vendor_risk_review", "security_review", "model_provider_review"}
	case "control:signed-ai-artifacts":
		return []string{"signed_ai_artifacts", "model_signature", "dataset_signature", "cosign", "sigstore"}
	case "control:runtime-component-validation":
		return []string{"runtime_component_validation", "component_integrity", "runtime_attestation", "verify_runtime_components"}
	case "control:dependency-reachability-analysis":
		return []string{"reachability_analysis", "dependency_reachability", "reachable_vulnerabilities"}
	default:
		if strings.HasPrefix(control, "control:") {
			return []string{strings.ReplaceAll(strings.TrimPrefix(control, "control:"), "-", "_")}
		}
		return []string{control}
	}
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

type architectureClosureInput struct {
	TargetID string
	Flaws    []model.ZeroTrustArchitecture
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

type architectureFrameworkDefinition struct {
	ID          string
	Area        string
	Source      string
	Tier        string
	CheckIDs    []string
	Limitations []string
}

func buildArchitectureFrameworkCoverage(inputs []architectureCoverageInput) []model.ArchitectureFrameworkArea {
	byID := map[string]*architectureFrameworkAreaBuilder{}
	for _, def := range architectureFrameworkDefinitions() {
		byID[def.ID] = &architectureFrameworkAreaBuilder{
			ID:       def.ID,
			Area:     def.Area,
			Source:   def.Source,
			Tier:     def.Tier,
			checkIDs: map[string]bool{},
			targets:  map[string]bool{},
			flaws:    map[string]bool{},
		}
		for _, checkID := range def.CheckIDs {
			if checkID != "" {
				byID[def.ID].checkIDs[checkID] = true
			}
		}
		byID[def.ID].Limitations = append(byID[def.ID].Limitations, def.Limitations...)
	}
	for _, input := range inputs {
		targetID := input.TargetID
		if targetID == "" {
			targetID = "target"
		}
		gapsByCheck := architectureGapsByCheck(input.ZeroTrust.Coverage.GapDetails)
		controlEvidenceByCheck, _ := architectureContractsByCheck(input.ZeroTrust.ArchitectureFlaws)
		flawsByCheck := architectureFlawsByCheck(input.ZeroTrust.ArchitectureFlaws)
		for _, def := range architectureFrameworkDefinitions() {
			builder := byID[def.ID]
			if builder == nil {
				continue
			}
			for _, check := range input.ZeroTrust.Checks {
				if !stringSliceContains(def.CheckIDs, check.ID) {
					continue
				}
				incrementZeroTrustSummary(&builder.StatusCounts, check.Status)
				builder.targets[targetID] = true
				builder.EvidenceSources = append(builder.EvidenceSources, zeroTrustEvidenceSources(check.Evidence)...)
				builder.Controls = append(builder.Controls, check.Controls...)
				builder.ControlEvidenceNeeded = append(builder.ControlEvidenceNeeded, controlEvidenceByCheck[check.ID]...)
				builder.Limitations = append(builder.Limitations, check.Limitations...)
				for _, gap := range gapsByCheck[check.ID] {
					builder.MissingEvidence = append(builder.MissingEvidence, gap.MissingEvidence...)
					if gap.NextCollector != "" {
						builder.NextCollectors = append(builder.NextCollectors, gap.NextCollector)
					}
				}
				for _, flaw := range flawsByCheck[check.ID] {
					title := flaw.Title
					if title == "" {
						title = flaw.ID
					}
					if title != "" {
						builder.flaws[title] = true
					}
					builder.EvidenceSources = append(builder.EvidenceSources, zeroTrustEvidenceSources(flaw.Evidence)...)
					builder.ControlEvidenceNeeded = append(builder.ControlEvidenceNeeded, flaw.ControlEvidenceNeeded...)
					builder.Limitations = append(builder.Limitations, flaw.Limitations...)
				}
			}
		}
	}
	out := make([]model.ArchitectureFrameworkArea, 0, len(byID))
	for _, def := range architectureFrameworkDefinitions() {
		builder := byID[def.ID]
		if builder == nil {
			continue
		}
		area := model.ArchitectureFrameworkArea{
			ID:                    builder.ID,
			Area:                  builder.Area,
			Source:                builder.Source,
			Tier:                  builder.Tier,
			StatusCounts:          builder.StatusCounts,
			TargetCount:           len(builder.targets),
			Targets:               mapKeysSorted(builder.targets),
			CheckIDs:              mapKeysSorted(builder.checkIDs),
			Flaws:                 mapKeysSorted(builder.flaws),
			EvidenceSources:       uniqueSortedStrings(builder.EvidenceSources),
			Controls:              uniqueSortedStrings(builder.Controls),
			ControlEvidenceNeeded: uniqueSortedStrings(builder.ControlEvidenceNeeded),
			MissingEvidence:       uniqueSortedStrings(builder.MissingEvidence),
			NextCollectors:        uniqueSortedStrings(builder.NextCollectors),
			Limitations:           uniqueSortedStrings(builder.Limitations),
		}
		out = append(out, area)
	}
	if out == nil {
		return []model.ArchitectureFrameworkArea{}
	}
	return out
}

func architectureFrameworkDefinitions() []architectureFrameworkDefinition {
	return []architectureFrameworkDefinition{
		{
			ID:       "agent-identity-authentication",
			Area:     "Agent identity and authentication",
			Source:   "Zero Trust for AI Agents, Part III: Agent identity and authentication",
			Tier:     "foundation",
			CheckIDs: []string{"zt:identity-boundary"},
		},
		{
			ID:       "access-privilege-management",
			Area:     "Access control and privilege management",
			Source:   "Zero Trust for AI Agents, Part III: Access control and privilege management",
			Tier:     "foundation",
			CheckIDs: []string{"zt:authority-boundary", "zt:workload-authorization-boundary", "zt:continuous-authorization-boundary", "zt:approval-boundary"},
		},
		{
			ID:       "resource-boundaries",
			Area:     "Resource boundaries",
			Source:   "Zero Trust for AI Agents, Part III: Resource boundaries",
			Tier:     "foundation",
			CheckIDs: []string{"zt:workload-authorization-boundary", "zt:egress-boundary", "zt:sensitive-boundary", "zt:resource-exhaustion-boundary"},
		},
		{
			ID:       "observability-auditing",
			Area:     "Observability and auditing",
			Source:   "Zero Trust for AI Agents, Part III: Observability and auditing",
			Tier:     "foundation",
			CheckIDs: []string{"zt:observability-boundary", "zt:approval-boundary"},
		},
		{
			ID:       "behavior-monitoring-response",
			Area:     "Behavioral monitoring and response",
			Source:   "Zero Trust for AI Agents, Part III: Behavioral monitoring and response",
			Tier:     "foundation",
			CheckIDs: []string{"zt:response-boundary", "zt:resource-exhaustion-boundary", "zt:observability-boundary"},
			Limitations: []string{
				"Ariadne detects declared monitoring and response controls, but does not compute behavioral baselines or measure dwell-time telemetry from live systems.",
			},
		},
		{
			ID:       "input-output-controls",
			Area:     "Input validation and output controls",
			Source:   "Zero Trust for AI Agents, Part III: Input validation and output controls",
			Tier:     "foundation",
			CheckIDs: []string{"zt:influence-boundary", "zt:output-boundary", "zt:egress-boundary"},
		},
		{
			ID:       "integrity-recovery",
			Area:     "Integrity and recovery",
			Source:   "Zero Trust for AI Agents, Part III: Integrity and recovery",
			Tier:     "foundation",
			CheckIDs: []string{"zt:config-integrity-boundary", "zt:supply-chain-boundary", "zt:tool-integrity-boundary"},
			Limitations: []string{
				"Ariadne detects declared integrity and rollback evidence, but does not validate live signature checks, deployment admission, or recovery execution.",
			},
		},
		{
			ID:       "governance-policy",
			Area:     "AI governance policies",
			Source:   "Zero Trust for AI Agents, Part III: AI governance policies",
			Tier:     "foundation",
			CheckIDs: []string{"zt:governance-boundary"},
		},
		{
			ID:       "supply-chain-management",
			Area:     "Supply chain risk management",
			Source:   "Zero Trust for AI Agents, Part IV: Manage supply chain risks",
			Tier:     "foundation",
			CheckIDs: []string{"zt:supply-chain-boundary", "zt:tool-integrity-boundary", "zt:tool-boundary"},
		},
		{
			ID:       "agent-boundaries-prompt-injection",
			Area:     "Agent boundaries and prompt-injection defense",
			Source:   "Zero Trust for AI Agents, Part IV: Define agent boundaries and defend against prompt injection",
			Tier:     "foundation",
			CheckIDs: []string{"zt:influence-boundary", "zt:authority-boundary", "zt:control-strength"},
		},
		{
			ID:       "tool-access-security",
			Area:     "Secure tool access",
			Source:   "Zero Trust for AI Agents, Part IV: Secure tool access",
			Tier:     "foundation",
			CheckIDs: []string{"zt:tool-boundary", "zt:tool-integrity-boundary", "zt:approval-boundary", "zt:resource-exhaustion-boundary"},
		},
		{
			ID:       "credential-protection",
			Area:     "Protect agent credentials",
			Source:   "Zero Trust for AI Agents, Part IV: Protect agent credentials",
			Tier:     "foundation",
			CheckIDs: []string{"zt:identity-boundary", "zt:continuous-authorization-boundary", "zt:memory-boundary"},
		},
		{
			ID:       "memory-context-security",
			Area:     "Safeguard agent memory",
			Source:   "Zero Trust for AI Agents, Part IV: Safeguard agent memory",
			Tier:     "enterprise",
			CheckIDs: []string{"zt:memory-boundary", "zt:influence-boundary"},
		},
		{
			ID:       "multi-agent-delegation",
			Area:     "Multi-agent delegation boundaries",
			Source:   "Zero Trust for AI Agents, Part II and Part IV: Multi-agent coordination and explicit trust boundaries",
			Tier:     "enterprise",
			CheckIDs: []string{"zt:delegation-boundary", "zt:identity-boundary", "zt:workload-authorization-boundary"},
		},
		{
			ID:       "defensive-operations",
			Area:     "Defensive operations for autonomous threats",
			Source:   "Zero Trust for AI Agents, Part V: Defensive operations at autonomous speed",
			Tier:     "enterprise",
			CheckIDs: []string{"zt:response-boundary", "zt:observability-boundary", "zt:governance-boundary"},
			Limitations: []string{
				"Ariadne reports declared defensive-operation readiness, but does not exercise SOAR workflows, MITRE ATT&CK coverage, or emergency authorization paths.",
			},
		},
	}
}

func buildArchitectureEvidencePlan(inputs []architectureCoverageInput) []model.ArchitectureEvidencePlan {
	byCollector := map[string]*architectureEvidencePlanBuilder{}
	for _, input := range inputs {
		targetID := input.TargetID
		if targetID == "" {
			targetID = "target"
		}
		for _, gap := range input.ZeroTrust.Coverage.GapDetails {
			collector := strings.TrimSpace(gap.NextCollector)
			if collector == "" {
				collector = "Collector not mapped"
			}
			item := byCollector[collector]
			if item == nil {
				item = &architectureEvidencePlanBuilder{
					NextCollector: collector,
					targets:       map[string]bool{},
					boundaries:    map[string]bool{},
					checkIDs:      map[string]bool{},
					whyItMatters:  map[string]bool{},
				}
				byCollector[collector] = item
			}
			item.GapCount++
			incrementZeroTrustSummary(&item.StatusCounts, gap.Status)
			item.targets[targetID] = true
			if gap.Boundary != "" {
				item.boundaries[gap.Boundary] = true
			}
			if gap.CheckID != "" {
				item.checkIDs[gap.CheckID] = true
			}
			if gap.WhyItMatters != "" {
				item.whyItMatters[gap.WhyItMatters] = true
			}
			item.MissingEvidence = append(item.MissingEvidence, gap.MissingEvidence...)
		}
	}
	out := make([]model.ArchitectureEvidencePlan, 0, len(byCollector))
	for _, item := range byCollector {
		plan := model.ArchitectureEvidencePlan{
			NextCollector:   item.NextCollector,
			GapCount:        item.GapCount,
			TargetCount:     len(item.targets),
			StatusCounts:    item.StatusCounts,
			Boundaries:      mapKeysSorted(item.boundaries),
			CheckIDs:        mapKeysSorted(item.checkIDs),
			Targets:         mapKeysSorted(item.targets),
			MissingEvidence: uniqueSortedStrings(item.MissingEvidence),
			WhyItMatters:    mapKeysSorted(item.whyItMatters),
		}
		out = append(out, plan)
	}
	sort.Slice(out, func(i, j int) bool {
		left := architectureEvidencePlanRank(out[i])
		right := architectureEvidencePlanRank(out[j])
		if left == right {
			return out[i].NextCollector < out[j].NextCollector
		}
		return left > right
	})
	if out == nil {
		return []model.ArchitectureEvidencePlan{}
	}
	return out
}

func buildArchitectureClosurePlan(inputs []architectureClosureInput) []model.ArchitectureClosure {
	byControl := map[string]*architectureClosureBuilder{}
	for _, input := range inputs {
		targetID := input.TargetID
		if targetID == "" {
			targetID = "target"
		}
		for _, flaw := range input.Flaws {
			for _, control := range flaw.ControlTest.MissingHardBarriers {
				if control == "" {
					continue
				}
				item := byControl[control]
				if item == nil {
					item = &architectureClosureBuilder{
						Control:           control,
						ControlTestResult: "missing_hard_barrier",
						Severity:          flaw.Severity,
						flaws:             map[string]bool{},
						checkIDs:          map[string]bool{},
						targets:           map[string]bool{},
					}
					byControl[control] = item
				}
				if severityRank(flaw.Severity) > severityRank(item.Severity) {
					item.Severity = flaw.Severity
				}
				flawTitle := flaw.Title
				if flawTitle == "" {
					flawTitle = flaw.ID
				}
				if flawTitle != "" {
					item.flaws[flawTitle] = true
				}
				for _, id := range flaw.CheckIDs {
					if id != "" {
						item.checkIDs[id] = true
					}
				}
				item.targets[targetID] = true
				item.EvidenceSources = append(item.EvidenceSources, zeroTrustEvidenceSources(flaw.Evidence)...)
				item.EvidenceReferences = append(item.EvidenceReferences, evidenceReferencesForFlaw(targetID, flaw)...)
				item.EvidenceSurfaces = append(item.EvidenceSurfaces, flaw.EvidenceSurfaces...)
				item.Actions = append(item.Actions, flaw.Actions...)
			}
		}
	}
	out := make([]model.ArchitectureClosure, 0, len(byControl))
	for _, item := range byControl {
		closure := model.ArchitectureClosure{
			Control:            item.Control,
			ControlTestResult:  item.ControlTestResult,
			Severity:           item.Severity,
			FlawCount:          len(item.flaws),
			TargetCount:        len(item.targets),
			Flaws:              mapKeysSorted(item.flaws),
			CheckIDs:           mapKeysSorted(item.checkIDs),
			Targets:            mapKeysSorted(item.targets),
			EvidenceSources:    uniqueSortedStrings(item.EvidenceSources),
			EvidenceReferences: dedupeEvidenceReferences(item.EvidenceReferences),
			EvidenceSurfaces:   uniqueSortedStrings(item.EvidenceSurfaces),
			Actions:            uniqueSortedStrings(item.Actions),
		}
		out = append(out, closure)
	}
	sort.Slice(out, func(i, j int) bool {
		left := architectureClosureRank(out[i])
		right := architectureClosureRank(out[j])
		if left == right {
			return out[i].Control < out[j].Control
		}
		return left > right
	})
	if out == nil {
		return []model.ArchitectureClosure{}
	}
	return out
}

func buildArchitectureClosureFamilies(items []model.ArchitectureClosure) []model.ArchitectureClosureFamily {
	byFamily := map[string]*architectureClosureFamilyBuilder{}
	for _, item := range items {
		familyID, familyTitle := architectureControlFamily(item.Control)
		builder := byFamily[familyID]
		if builder == nil {
			builder = &architectureClosureFamilyBuilder{
				ID:                 familyID,
				Title:              familyTitle,
				Severity:           item.Severity,
				controls:           map[string]bool{},
				flaws:              map[string]bool{},
				checkIDs:           map[string]bool{},
				targets:            map[string]bool{},
				EvidenceSources:    []string{},
				EvidenceReferences: []model.EvidenceReference{},
				EvidenceSurfaces:   []string{},
				Actions:            []string{},
			}
			byFamily[familyID] = builder
		}
		if severityRank(item.Severity) > severityRank(builder.Severity) {
			builder.Severity = item.Severity
		}
		if item.Control != "" {
			builder.controls[item.Control] = true
		}
		for _, flaw := range item.Flaws {
			if flaw != "" {
				builder.flaws[flaw] = true
			}
		}
		for _, checkID := range item.CheckIDs {
			if checkID != "" {
				builder.checkIDs[checkID] = true
			}
		}
		for _, target := range item.Targets {
			if target != "" {
				builder.targets[target] = true
			}
		}
		builder.EvidenceSources = append(builder.EvidenceSources, item.EvidenceSources...)
		builder.EvidenceReferences = append(builder.EvidenceReferences, item.EvidenceReferences...)
		builder.EvidenceSurfaces = append(builder.EvidenceSurfaces, item.EvidenceSurfaces...)
		builder.Actions = append(builder.Actions, item.Actions...)
	}
	out := make([]model.ArchitectureClosureFamily, 0, len(byFamily))
	for _, builder := range byFamily {
		family := model.ArchitectureClosureFamily{
			ID:                 builder.ID,
			Title:              builder.Title,
			Severity:           builder.Severity,
			ControlCount:       len(builder.controls),
			FlawCount:          len(builder.flaws),
			TargetCount:        len(builder.targets),
			Controls:           mapKeysSorted(builder.controls),
			Flaws:              mapKeysSorted(builder.flaws),
			CheckIDs:           mapKeysSorted(builder.checkIDs),
			Targets:            mapKeysSorted(builder.targets),
			EvidenceSources:    uniqueSortedStrings(builder.EvidenceSources),
			EvidenceReferences: dedupeEvidenceReferences(builder.EvidenceReferences),
			EvidenceSurfaces:   uniqueSortedStrings(builder.EvidenceSurfaces),
			Actions:            uniqueSortedStrings(builder.Actions),
		}
		out = append(out, family)
	}
	sort.Slice(out, func(i, j int) bool {
		left := architectureClosureFamilyRank(out[i])
		right := architectureClosureFamilyRank(out[j])
		if left == right {
			return out[i].Title < out[j].Title
		}
		return left > right
	})
	if out == nil {
		return []model.ArchitectureClosureFamily{}
	}
	return out
}

type architectureClosureBuilder struct {
	Control            string
	ControlTestResult  string
	Severity           string
	flaws              map[string]bool
	checkIDs           map[string]bool
	targets            map[string]bool
	EvidenceSources    []string
	EvidenceReferences []model.EvidenceReference
	EvidenceSurfaces   []string
	Actions            []string
}

type architectureEvidencePlanBuilder struct {
	NextCollector   string
	GapCount        int
	StatusCounts    model.ZeroTrustSummary
	targets         map[string]bool
	boundaries      map[string]bool
	checkIDs        map[string]bool
	MissingEvidence []string
	whyItMatters    map[string]bool
}

type architectureClosureFamilyBuilder struct {
	ID                 string
	Title              string
	Severity           string
	controls           map[string]bool
	flaws              map[string]bool
	checkIDs           map[string]bool
	targets            map[string]bool
	EvidenceSources    []string
	EvidenceReferences []model.EvidenceReference
	EvidenceSurfaces   []string
	Actions            []string
}

type architectureFrameworkAreaBuilder struct {
	ID                    string
	Area                  string
	Source                string
	Tier                  string
	StatusCounts          model.ZeroTrustSummary
	targets               map[string]bool
	checkIDs              map[string]bool
	flaws                 map[string]bool
	EvidenceSources       []string
	Controls              []string
	ControlEvidenceNeeded []string
	MissingEvidence       []string
	NextCollectors        []string
	Limitations           []string
}

func architectureClosureRank(item model.ArchitectureClosure) int {
	return severityRank(item.Severity)*100000 + item.TargetCount*1000 + item.FlawCount
}

func architectureEvidencePlanRank(item model.ArchitectureEvidencePlan) int {
	return item.TargetCount*100000 + item.GapCount*1000 + item.StatusCounts.Unknown*100 + item.StatusCounts.NotObserved*10
}

func architectureClosureFamilyRank(item model.ArchitectureClosureFamily) int {
	return severityRank(item.Severity)*100000 + item.TargetCount*1000 + item.FlawCount*10 + item.ControlCount
}

func architectureControlFamily(control string) (string, string) {
	switch control {
	case "control:input-isolation",
		"control:trusted-source-policy",
		"control:instruction-provenance",
		"control:untrusted-input-delimiting",
		"control:prompt-injection-filter",
		"control:input-validation":
		return "input-trust-boundary", "Input Trust Boundary"
	case "control:deny-by-default",
		"control:deny-by-default-permissions",
		"control:least-agency-policy",
		"control:scoped-permissions",
		"control:deny-secret-read",
		"deny rules",
		"allowlists",
		"isolation controls",
		"scoped credentials",
		"capability-removing break controls":
		return "least-agency-authority", "Least Agency And Authority Scope"
	case "control:mcp-reviewed-pinned",
		"control:tool-allowlist",
		"control:tool-descriptor-integrity",
		"control:tool-argument-validation",
		"control:tool-auth-required",
		"control:signed-tool-artifacts",
		"control:tool-deployment-verification",
		"control:tool-sandbox-execution":
		return "tool-mcp-integrity", "Tool And MCP Integrity"
	case "control:ai-bom",
		"control:model-provenance",
		"control:training-data-lineage",
		"control:dependency-health-scan",
		"control:provider-risk-review",
		"control:signed-ai-artifacts",
		"control:runtime-component-validation",
		"control:dependency-reachability-analysis":
		return "ai-supply-chain", "AI Supply Chain"
	case "control:delegation-scope",
		"control:delegation-allowlist",
		"control:agent-to-agent-authorization",
		"control:origin-intent-verification",
		"control:delegated-credential-scope",
		"control:subagent-context-isolation",
		"control:delegation-audit":
		return "agent-delegation", "Agent Delegation"
	case "control:network-restricted",
		"control:egress-destination-allowlist",
		"control:webhook-allowlist",
		"control:per-tool-network-scope",
		"control:egress-content-filter",
		"control:egress-audit",
		"control:output-sensitive-data-filter",
		"control:output-redaction",
		"control:output-filter-logging",
		"control:semantic-output-analysis",
		"control:high-risk-output-review":
		return "egress-output-boundary", "Egress And Output Boundary"
	case "control:cryptographic-identity",
		"control:credential-isolation",
		"control:short-lived-credential",
		"control:hardware-bound-credential",
		"control:jit-access",
		"control:token-lifetime-policy",
		"control:credential-helper",
		"control:identity-lifecycle":
		return "identity-credentials", "Identity And Credentials"
	case "control:identity-based-isolation",
		"control:named-caller-allowlist",
		"control:abac-policy",
		"control:network-segmentation",
		"control:tool-scope-policy",
		"control:per-action-authorization",
		"control:continuous-authorization",
		"control:dynamic-privilege-scoping",
		"control:jit-elevation",
		"control:standing-access-denied",
		"control:automatic-access-revocation":
		return "workload-authorization", "Workload And Continuous Authorization"
	case "control:approval-required",
		"control:approval-log-evidence",
		"control:audit-logging",
		"control:request-traceability",
		"control:observed-request-traceability",
		"control:agent-action-log-evidence",
		"control:tool-call-audit-evidence",
		"control:telemetry-export",
		"control:immutable-audit-log":
		return "observability-approval", "Observability And Approval"
	case "control:tool-rate-limit",
		"control:spend-limit",
		"control:loop-guard",
		"control:tool-timeout",
		"control:concurrency-limit",
		"control:tool-circuit-breaker",
		"control:resource-usage-audit",
		"control:automated-triage",
		"control:behavioral-monitoring",
		"control:session-termination",
		"control:credential-revocation",
		"control:containment-quarantine",
		"control:dynamic-access-reduction",
		"control:response-escalation":
		return "response-resource-control", "Response And Resource Control"
	case "control:context-retention",
		"control:memory-isolation",
		"control:context-integrity",
		"control:context-provenance":
		return "memory-context", "Memory And Context"
	case "control:agent-inventory",
		"control:accountable-owner",
		"control:deployment-owner",
		"control:deployment-approval",
		"control:risk-assessment",
		"control:governance-review",
		"control:governance-audit",
		"control:shadow-ai-discovery",
		"control:config-version-control",
		"control:config-review-required",
		"control:signed-config",
		"control:config-deployment-verification",
		"control:managed-settings-enforced",
		"control:managed-runtime-settings",
		"control:immutable-agent-runtime",
		"control:config-rollback-procedure",
		"control:automated-config-rollback":
		return "governance-config-integrity", "Governance And Configuration Integrity"
	default:
		return "other-hard-barriers", "Other Hard Barriers"
	}
}

func mapKeysSorted(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	if out == nil {
		return []string{}
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

func architectureFlawsByCheck(flaws []model.ZeroTrustArchitecture) map[string][]model.ZeroTrustArchitecture {
	out := map[string][]model.ZeroTrustArchitecture{}
	for _, flaw := range flaws {
		for _, checkID := range flaw.CheckIDs {
			out[checkID] = append(out[checkID], flaw)
		}
	}
	return out
}

func architectureGapsByCheck(gaps []model.ZeroTrustGap) map[string][]model.ZeroTrustGap {
	out := map[string][]model.ZeroTrustGap{}
	for _, gap := range gaps {
		out[gap.CheckID] = append(out[gap.CheckID], gap)
	}
	return out
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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

func evidenceReferencesFromZeroTrust(target string, evidence []model.ZeroTrustEvidence) []model.EvidenceReference {
	var out []model.EvidenceReference
	for _, item := range evidence {
		if item.ID == "evidence:omitted" {
			continue
		}
		ref := model.EvidenceReference{
			Target:  target,
			ID:      item.ID,
			Kind:    item.Kind,
			Source:  item.Source,
			Summary: item.Summary,
		}
		if ref.ID == "" {
			ref.ID = ref.Source
		}
		if ref.ID == "" {
			ref.ID = ref.Kind
		}
		if ref.Summary == "" {
			ref.Summary = ref.Source
		}
		if ref.Summary == "" {
			ref.Summary = ref.ID
		}
		if ref.ID == "" && ref.Kind == "" && ref.Source == "" && ref.Summary == "" {
			continue
		}
		out = append(out, ref)
	}
	return dedupeEvidenceReferences(out)
}

func evidenceReferencesForFlaw(target string, flaw model.ZeroTrustArchitecture) []model.EvidenceReference {
	refs := evidenceReferencesFromZeroTrust(target, flaw.Evidence)
	if len(refs) > 0 {
		return refs
	}
	source := flaw.ID
	if len(flaw.CheckIDs) > 0 && flaw.CheckIDs[0] != "" {
		source = flaw.CheckIDs[0]
	}
	summary := flaw.Finding
	if summary == "" {
		summary = flaw.Title
	}
	if summary == "" {
		summary = flaw.ID
	}
	return []model.EvidenceReference{{
		Target:  target,
		ID:      flaw.ID,
		Kind:    "architecture_flaw",
		Source:  source,
		Summary: summary,
	}}
}

func dedupeEvidenceReferences(values []model.EvidenceReference) []model.EvidenceReference {
	seen := map[string]bool{}
	var out []model.EvidenceReference
	for _, value := range values {
		key := value.Target + "|" + value.ID + "|" + value.Kind + "|" + value.Source + "|" + value.Summary
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	if out == nil {
		return []model.EvidenceReference{}
	}
	return out
}

func evidenceReferenceLines(values []model.EvidenceReference, limit int) []string {
	values = dedupeEvidenceReferences(values)
	if len(values) == 0 {
		return []string{}
	}
	if limit <= 0 || limit > len(values) {
		limit = len(values)
	}
	lines := make([]string, 0, limit+1)
	for _, value := range values[:limit] {
		lines = append(lines, evidenceReferenceLine(value))
	}
	if len(values) > limit {
		lines = append(lines, fmt.Sprintf("%d more evidence reference(s) in JSON", len(values)-limit))
	}
	return lines
}

func evidenceReferenceLine(value model.EvidenceReference) string {
	source := value.Source
	if source == "" {
		source = value.ID
	}
	if source == "" {
		source = value.Kind
	}
	prefix := source
	if value.Target != "" {
		prefix = value.Target + ": " + prefix
	}
	summary := strings.TrimSpace(value.Summary)
	if len(summary) > 120 {
		summary = summary[:117] + "..."
	}
	if summary == "" || summary == source {
		if value.Kind != "" {
			return fmt.Sprintf("%s [%s]", prefix, value.Kind)
		}
		return prefix
	}
	if value.Kind != "" {
		return fmt.Sprintf("%s [%s] %s", prefix, value.Kind, summary)
	}
	return prefix + " " + summary
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
