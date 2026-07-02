package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

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

func RenderAssess(w io.Writer, inventory model.InventoryReport, r model.Report, format string, statusFilter string) error {
	assess, err := BuildAssessReport(inventory, r, statusFilter)
	if err != nil {
		return err
	}
	return renderAssess(w, assess, format)
}

func RenderAssessFocused(w io.Writer, inventory model.InventoryReport, r model.Report, format string, statusFilter string, focus AssessFocus) error {
	assess, err := BuildAssessReport(inventory, r, statusFilter, focus)
	if err != nil {
		return err
	}
	return renderAssess(w, assess, format)
}

func RenderAssessScan(w io.Writer, r model.ScanReport, format string, statusFilter string) error {
	assess, err := BuildAssessScanReport(r, statusFilter)
	if err != nil {
		return err
	}
	return renderAssess(w, assess, format)
}

func RenderAssessScanFocused(w io.Writer, r model.ScanReport, format string, statusFilter string, focus AssessFocus) error {
	assess, err := BuildAssessScanReport(r, statusFilter, focus)
	if err != nil {
		return err
	}
	return renderAssess(w, assess, format)
}

type AssessFocus struct {
	CaseFilter    string
	ControlFilter string
}

func normalizeAssessFocus(options ...AssessFocus) AssessFocus {
	if len(options) == 0 {
		return AssessFocus{}
	}
	focus := options[0]
	focus.CaseFilter = strings.TrimSpace(focus.CaseFilter)
	focus.ControlFilter = normalizeAssessControlFilter(focus.ControlFilter)
	return focus
}

func normalizeAssessControlFilter(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "control:") {
		return value
	}
	return "control:" + value
}

func applyAssessFocusToCaseBoard(catalog *model.ControlCatalogReport, focus AssessFocus) error {
	caseFilter := strings.TrimSpace(focus.CaseFilter)
	controlFilter := normalizeAssessControlFilter(focus.ControlFilter)
	if controlFilter != "" {
		selected, ok := assessFindCaseForControl(catalog.OperatorCases, caseFilter, controlFilter)
		if !ok {
			if caseFilter != "" {
				return fmt.Errorf("control %q not found in operator case %q", controlFilter, caseFilter)
			}
			return fmt.Errorf("control %q not found in operator cases", controlFilter)
		}
		caseFilter = selected.ID
	}
	if caseFilter != "" {
		if err := filterControlCaseBoard(catalog, caseFilter); err != nil {
			return err
		}
	}
	if controlFilter != "" {
		if err := focusControlCaseBoard(catalog, controlFilter); err != nil {
			return err
		}
	}
	return nil
}

func assessFindCaseForControl(cases []model.ControlOperatorCase, caseFilter string, control string) (model.ControlOperatorCase, bool) {
	for _, item := range cases {
		if caseFilter != "" && !controlOperatorCaseMatches(item, caseFilter) {
			continue
		}
		if controlOperatorCaseHasControl(item, control) {
			return item, true
		}
	}
	return model.ControlOperatorCase{}, false
}

func controlOperatorCaseHasControl(item model.ControlOperatorCase, control string) bool {
	for _, candidate := range item.StartingControls {
		if candidate == control {
			return true
		}
	}
	for _, patch := range item.ProofPatches {
		if patch.Control == control {
			return true
		}
	}
	return false
}

func focusControlCaseBoard(catalog *model.ControlCatalogReport, control string) error {
	control = normalizeAssessControlFilter(control)
	if control == "" {
		return nil
	}
	if len(catalog.OperatorCases) == 0 {
		return fmt.Errorf("control %q has no focused operator case", control)
	}
	selected := catalog.OperatorCases[0]
	if !controlOperatorCaseHasControl(selected, control) {
		return fmt.Errorf("control %q not found in operator case %q", control, selected.ID)
	}
	tasks := focusControlVerificationTasks(catalog.VerificationTasks, control)
	selected.StartingControls = []string{control}
	selected.StartingTaskIDs = controlVerificationTaskIDs(tasks)
	selected.ProofPatches = focusControlProofPatches(selected.ProofPatches, control)
	selected.ProofSurfaces = focusControlProofSurfaces(selected.ProofSurfaces, selected.ProofPatches, tasks)
	if len(tasks) > 0 {
		selected.EvidenceExamples = dedupeControlEvidenceExamples(tasks[0].EvidenceExamples)
	}
	selected.ControlCount = 1
	selected.NextStep = assessFocusedControlNextStep(control, selected.ProofSurfaces, selected.EvidenceExamples)
	catalog.OperatorCases = []model.ControlOperatorCase{selected}
	catalog.Controls = focusArchitectureClosures(catalog.Controls, control)
	catalog.Families = focusArchitectureClosureFamilies(catalog.Families, control)
	catalog.Workstreams = focusControlBreakPathWorkstreams(catalog.Workstreams, control, tasks)
	catalog.ProofSpecs = focusControlProofSpecs(catalog.ProofSpecs, control)
	catalog.VerificationTasks = nonNilControlVerificationTasks(tasks)
	catalog.Summary = summarizeControlCatalog(catalog.Controls)
	return nil
}

func focusControlVerificationTasks(items []model.ControlVerificationTask, control string) []model.ControlVerificationTask {
	var out []model.ControlVerificationTask
	for _, item := range items {
		if item.Control == control {
			out = append(out, item)
		}
	}
	return nonNilControlVerificationTasks(out)
}

func controlVerificationTaskIDs(items []model.ControlVerificationTask) []string {
	var out []string
	for _, item := range items {
		if item.ID != "" {
			out = append(out, item.ID)
		}
	}
	return uniqueStrings(out)
}

func focusControlProofPatches(items []model.ControlProofPatch, control string) []model.ControlProofPatch {
	var out []model.ControlProofPatch
	for _, item := range items {
		if item.Control == control {
			out = append(out, item)
		}
	}
	return dedupeControlProofPatches(out)
}

func focusControlProofSurfaces(existing []string, patches []model.ControlProofPatch, tasks []model.ControlVerificationTask) []string {
	var out []string
	for _, patch := range patches {
		if patch.Surface != "" {
			out = append(out, patch.Surface)
		}
	}
	for _, task := range tasks {
		out = append(out, task.ProofSurfaces...)
	}
	if len(out) == 0 {
		out = append(out, existing...)
	}
	return uniqueStrings(out)
}

func focusArchitectureClosures(items []model.ArchitectureClosure, control string) []model.ArchitectureClosure {
	var out []model.ArchitectureClosure
	for _, item := range items {
		if item.Control == control {
			out = append(out, item)
		}
	}
	return nonNilArchitectureClosures(out)
}

func focusArchitectureClosureFamilies(items []model.ArchitectureClosureFamily, control string) []model.ArchitectureClosureFamily {
	var out []model.ArchitectureClosureFamily
	for _, item := range items {
		if !containsReportString(item.Controls, control) {
			continue
		}
		item.Controls = []string{control}
		item.ControlCount = 1
		out = append(out, item)
	}
	return nonNilArchitectureClosureFamilies(out)
}

func focusControlBreakPathWorkstreams(items []model.ControlBreakPathWorkstream, control string, tasks []model.ControlVerificationTask) []model.ControlBreakPathWorkstream {
	var out []model.ControlBreakPathWorkstream
	taskIDs := controlVerificationTaskIDs(tasks)
	for _, item := range items {
		if !containsReportString(item.Controls, control) && !containsReportString(item.StartingControls, control) {
			continue
		}
		item.Controls = []string{control}
		item.StartingControls = []string{control}
		item.StartingTaskIDs = taskIDs
		item.ControlCount = 1
		out = append(out, item)
	}
	return nonNilControlBreakPathWorkstreams(out)
}

func focusControlProofSpecs(items []model.ControlProofSpec, control string) []model.ControlProofSpec {
	var out []model.ControlProofSpec
	for _, item := range items {
		if item.Control == control {
			out = append(out, item)
		}
	}
	return nonNilControlProofSpecs(out)
}

func assessFocusedControlNextStep(control string, proofSurfaces []string, examples []model.ControlEvidenceExample) string {
	surface := firstString(proofSurfaces)
	if len(examples) > 0 && examples[0].Surface != "" {
		surface = examples[0].Surface
	}
	if surface != "" {
		return fmt.Sprintf("Add or verify %s evidence at %s, then rerun this case.", control, surface)
	}
	return fmt.Sprintf("Add or verify %s evidence, then rerun this case.", control)
}

func containsReportString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func BuildAssessReport(inventory model.InventoryReport, r model.Report, statusFilter string, focusOptions ...AssessFocus) (model.AssessReport, error) {
	focus := normalizeAssessFocus(focusOptions...)
	architecture, err := BuildArchitectureReport(r, statusFilter)
	if err != nil {
		return model.AssessReport{}, err
	}
	caseBoard := BuildControlCaseBoardReport(architecture)
	if err := applyAssessFocusToCaseBoard(&caseBoard, focus); err != nil {
		if focus.ControlFilter == "" {
			if closed, ok, closedErr := buildFocusedClosedCaseBoardReport(r, statusFilter, focus.CaseFilter); closedErr != nil {
				return model.AssessReport{}, closedErr
			} else if ok {
				caseBoard = closed
			} else {
				return model.AssessReport{}, err
			}
		} else {
			return model.AssessReport{}, err
		}
	}
	if caseBoard.CaseFilter != "" {
		focus.CaseFilter = caseBoard.CaseFilter
	}
	exposures := reportExposures(r)
	exposure := buildAssessExposure(exposures)
	closureEvidence := buildAssessClosureEvidence(exposures, []assessClosureTarget{{TargetID: "target", Flaws: r.ZeroTrust.ArchitectureFlaws}})
	inventorySummary := buildAssessInventory(inventory)
	summary := buildAssessSummary(inventorySummary, exposure, architecture.Summary, caseBoard.Summary, caseBoard.OperatorCases)
	topCases := topControlOperatorCases(caseBoard.OperatorCases, 5)
	topCaseProofPlan := buildTopCaseProofPlan(caseBoard)
	firstAction := buildAssessFirstAction(topCases, topCaseProofPlan)
	closurePlan := buildAssessClosurePlan(topCases, 5)
	triage := buildAssessTriage(summary, inventorySummary, exposure, closureEvidence, firstAction, architecture.Flaws)
	nextCommands := assessPathCommands(r.TargetPath, r.Story.Mode, r.Story.Runtime, architecture.StatusFilter, caseBoard.OperatorCases, focus)
	return model.AssessReport{
		SchemaVersion:    model.SchemaVersion,
		RunID:            r.RunID,
		GeneratedAt:      r.GeneratedAt,
		RunKind:          "assess",
		TargetPath:       r.TargetPath,
		Mode:             r.Story.Mode,
		Agent:            r.Story.Runtime,
		StatusFilter:     architecture.StatusFilter,
		CaseFilter:       caseBoard.CaseFilter,
		ControlFilter:    focus.ControlFilter,
		Summary:          summary,
		Triage:           triage,
		Inventory:        inventorySummary,
		Exposure:         exposure,
		ClosureEvidence:  closureEvidence,
		Architecture:     &architecture,
		CaseBoard:        caseBoard,
		TopCases:         topCases,
		TopCaseProofPlan: topCaseProofPlan,
		FirstAction:      firstAction,
		ClosurePlan:      closurePlan,
		NextCommands:     nextCommands,
		Redaction:        r.Redaction,
		Warnings:         uniqueSortedStrings(append(append([]string{}, inventory.Warnings...), r.Warnings...)),
		Limitations:      uniqueSortedStrings(append(append([]string{}, inventory.Limitations...), r.Limitations...)),
	}, nil
}

func BuildAssessScanReport(r model.ScanReport, statusFilter string, focusOptions ...AssessFocus) (model.AssessReport, error) {
	focus := normalizeAssessFocus(focusOptions...)
	architecture, err := BuildArchitectureScanReport(r, statusFilter)
	if err != nil {
		return model.AssessReport{}, err
	}
	caseBoard := BuildControlCaseBoardScanReport(architecture)
	if err := applyAssessFocusToCaseBoard(&caseBoard, focus); err != nil {
		if focus.ControlFilter == "" {
			if closed, ok, closedErr := buildFocusedClosedCaseBoardScanReport(r, statusFilter, focus.CaseFilter); closedErr != nil {
				return model.AssessReport{}, closedErr
			} else if ok {
				caseBoard = closed
			} else {
				return model.AssessReport{}, err
			}
		} else {
			return model.AssessReport{}, err
		}
	}
	if caseBoard.CaseFilter != "" {
		focus.CaseFilter = caseBoard.CaseFilter
	}
	var exposures []model.ExposureResult
	var closureTargets []assessClosureTarget
	for _, target := range r.Targets {
		if target.Error != "" {
			continue
		}
		exposures = append(exposures, reportExposures(target.Report)...)
		closureTargets = append(closureTargets, assessClosureTarget{TargetID: target.Target.ID, Flaws: target.Report.ZeroTrust.ArchitectureFlaws})
	}
	exposure := model.AssessExposure{
		Paths:        r.Summary.ExposurePaths,
		Exposed:      r.Summary.Exposed,
		Protected:    r.Summary.Protected,
		Inconclusive: r.Summary.Inconclusive,
		TopPaths:     []model.ExposureResult{},
	}
	inventorySummary := buildAssessScanInventory(r)
	summary := buildAssessSummary(inventorySummary, exposure, zeroTrustSummaryFromArchitectureScan(architecture.Summary), caseBoard.Summary, caseBoard.OperatorCases)
	summary.Targets = r.Summary.Targets
	summary.CompletedTargets = r.Summary.Completed
	summary.Errors = r.Summary.Errors
	targets := make([]model.ScanTarget, 0, len(r.Targets))
	for _, target := range r.Targets {
		targets = append(targets, target.Target)
	}
	topCases := topControlOperatorCases(caseBoard.OperatorCases, 5)
	topCaseProofPlan := buildTopCaseProofPlan(caseBoard)
	firstAction := buildAssessFirstAction(topCases, topCaseProofPlan)
	closurePlan := buildAssessClosurePlan(topCases, 5)
	closureEvidence := buildAssessClosureEvidence(exposures, closureTargets)
	triage := buildAssessTriage(summary, inventorySummary, exposure, closureEvidence, firstAction, assessScanArchitectureFlaws(architecture))
	nextCommands := assessScanCommands(r.TargetsFile, r.Mode, r.Agent, architecture.StatusFilter, caseBoard.OperatorCases, focus)
	return model.AssessReport{
		SchemaVersion:    model.SchemaVersion,
		RunID:            r.RunID,
		GeneratedAt:      r.GeneratedAt,
		RunKind:          "assess_scan",
		TargetsFile:      r.TargetsFile,
		Targets:          targets,
		Mode:             r.Mode,
		Agent:            r.Agent,
		StatusFilter:     architecture.StatusFilter,
		CaseFilter:       caseBoard.CaseFilter,
		ControlFilter:    focus.ControlFilter,
		Summary:          summary,
		Triage:           triage,
		Inventory:        inventorySummary,
		Exposure:         exposure,
		ClosureEvidence:  closureEvidence,
		ArchitectureScan: &architecture,
		CaseBoard:        caseBoard,
		TopCases:         topCases,
		TopCaseProofPlan: topCaseProofPlan,
		FirstAction:      firstAction,
		ClosurePlan:      closurePlan,
		NextCommands:     nextCommands,
		Redaction:        r.Redaction,
		Warnings:         append([]string{}, r.Warnings...),
		Limitations:      uniqueSortedStrings(append(append([]string{}, r.Limitations...), inventorySummary.Limitations...)),
	}, nil
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

func RenderCases(w io.Writer, r model.Report, format string, statusFilter string, caseFilter string) error {
	architecture, err := BuildArchitectureReport(r, statusFilter)
	if err != nil {
		return err
	}
	catalog := BuildControlCaseBoardReport(architecture)
	if err := filterControlCaseBoard(&catalog, caseFilter); err != nil {
		if closed, ok, closedErr := buildFocusedClosedCaseBoardReport(r, statusFilter, caseFilter); closedErr != nil {
			return closedErr
		} else if ok {
			catalog = closed
		} else {
			return err
		}
	}
	return renderControlCaseBoard(w, catalog, format)
}

func RenderCasesScan(w io.Writer, r model.ScanReport, format string, statusFilter string, caseFilter string) error {
	architecture, err := BuildArchitectureScanReport(r, statusFilter)
	if err != nil {
		return err
	}
	catalog := BuildControlCaseBoardScanReport(architecture)
	if err := filterControlCaseBoard(&catalog, caseFilter); err != nil {
		if closed, ok, closedErr := buildFocusedClosedCaseBoardScanReport(r, statusFilter, caseFilter); closedErr != nil {
			return closedErr
		} else if ok {
			catalog = closed
		} else {
			return err
		}
	}
	return renderControlCaseBoard(w, catalog, format)
}

func RenderProofs(w io.Writer, r model.Report, format string, statusFilter string, caseFilter string) error {
	plan, err := BuildProofPlanForReport(r, statusFilter, caseFilter)
	if err != nil {
		return err
	}
	return renderProofPlan(w, plan, format)
}

func BuildProofPlanForReport(r model.Report, statusFilter string, caseFilter string) (model.ProofPlanReport, error) {
	architecture, err := BuildArchitectureReport(r, statusFilter)
	if err != nil {
		return model.ProofPlanReport{}, err
	}
	catalog := BuildControlCaseBoardReport(architecture)
	if err := filterControlCaseBoard(&catalog, caseFilter); err != nil {
		if closed, ok, closedErr := buildFocusedClosedCaseBoardReport(r, statusFilter, caseFilter); closedErr != nil {
			return model.ProofPlanReport{}, closedErr
		} else if ok {
			catalog = closed
		} else {
			return model.ProofPlanReport{}, err
		}
	}
	return BuildProofPlanReport(catalog), nil
}

func RenderProofsScan(w io.Writer, r model.ScanReport, format string, statusFilter string, caseFilter string) error {
	plan, err := BuildProofPlanForScanReport(r, statusFilter, caseFilter)
	if err != nil {
		return err
	}
	return renderProofPlan(w, plan, format)
}

func BuildProofPlanForScanReport(r model.ScanReport, statusFilter string, caseFilter string) (model.ProofPlanReport, error) {
	architecture, err := BuildArchitectureScanReport(r, statusFilter)
	if err != nil {
		return model.ProofPlanReport{}, err
	}
	catalog := BuildControlCaseBoardScanReport(architecture)
	if err := filterControlCaseBoard(&catalog, caseFilter); err != nil {
		if closed, ok, closedErr := buildFocusedClosedCaseBoardScanReport(r, statusFilter, caseFilter); closedErr != nil {
			return model.ProofPlanReport{}, closedErr
		} else if ok {
			catalog = closed
		} else {
			return model.ProofPlanReport{}, err
		}
	}
	return BuildProofPlanReport(catalog), nil
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
	attachOperatorCaseCompareCommands(&catalog)
	return catalog
}

func BuildControlCaseBoardReport(r model.ArchitectureReport) model.ControlCatalogReport {
	catalog := BuildControlCatalogReport(r)
	catalog.RunKind = "case_board"
	rewriteControlCatalogAsCaseBoard(&catalog)
	return catalog
}

func BuildProofPlanReport(catalog model.ControlCatalogReport) model.ProofPlanReport {
	var patches []model.ControlProofPatch
	var evidenceRefs []model.EvidenceReference
	var rerunCommands []string
	var successCriteria []string
	targets := map[string]bool{}
	flaws := map[string]bool{}
	controls := map[string]bool{}
	for _, item := range catalog.OperatorCases {
		patches = append(patches, item.ProofPatches...)
		evidenceRefs = append(evidenceRefs, item.EvidenceReferences...)
		rerunCommands = append(rerunCommands, item.RerunCommands...)
		successCriteria = append(successCriteria, item.SuccessCriteria...)
		for _, target := range item.Targets {
			targets[target] = true
		}
		for _, flaw := range item.Flaws {
			flaws[flaw] = true
		}
		for _, control := range item.StartingControls {
			controls[control] = true
		}
	}
	if len(catalog.OperatorCases) == 0 {
		for _, task := range catalog.VerificationTasks {
			patches = append(patches, task.ProofPatches...)
			evidenceRefs = append(evidenceRefs, task.EvidenceReferences...)
			rerunCommands = append(rerunCommands, task.RerunCommands...)
			successCriteria = append(successCriteria, task.SuccessCriteria...)
			if task.Control != "" {
				controls[task.Control] = true
			}
			for _, target := range task.Targets {
				targets[target] = true
			}
		}
	}
	patches = dedupeControlProofPatches(patches)
	evidenceRefs = dedupeEvidenceReferences(evidenceRefs)
	rerunCommands = uniqueStrings(rerunCommands)
	successCriteria = uniqueStrings(successCriteria)
	compareCommands := proofPlanCompareCommands(catalog)
	patchExportCommand := ""
	if len(patches) > 0 {
		patchExportCommand = proofPlanPatchExportCommand(catalog)
	}
	cases := append([]model.ControlOperatorCase{}, catalog.OperatorCases...)
	if cases == nil {
		cases = []model.ControlOperatorCase{}
	}
	if patches == nil {
		patches = []model.ControlProofPatch{}
	}
	if evidenceRefs == nil {
		evidenceRefs = []model.EvidenceReference{}
	}
	if rerunCommands == nil {
		rerunCommands = []string{}
	}
	if successCriteria == nil {
		successCriteria = []string{}
	}
	if compareCommands == nil {
		compareCommands = []string{}
	}
	workflow := buildProofPlanWorkflow(cases, patches, evidenceRefs, rerunCommands, compareCommands, patchExportCommand, successCriteria)
	limitations := uniqueSortedStrings(append([]string{
		"Proof plans are deterministic evidence plans; they do not prove live enforcement unless Ariadne also observes runtime enforcement evidence.",
		"Add proof only when the named control is actually implemented or enforced in the environment.",
	}, catalog.Limitations...))
	runKind := "proof_plan"
	if catalog.RunKind == "case_board_scan" || catalog.RunKind == "control_catalog_scan" {
		runKind = "proof_plan_scan"
	}
	return model.ProofPlanReport{
		SchemaVersion:      model.SchemaVersion,
		RunID:              catalog.RunID,
		GeneratedAt:        catalog.GeneratedAt,
		RunKind:            runKind,
		TargetPath:         catalog.TargetPath,
		TargetsFile:        catalog.TargetsFile,
		Mode:               catalog.Mode,
		Agent:              catalog.Agent,
		StatusFilter:       catalog.StatusFilter,
		CaseFilter:         catalog.CaseFilter,
		Summary:            model.ProofPlanSummary{Cases: len(catalog.OperatorCases), ProofPatches: len(patches), EvidenceReferences: len(evidenceRefs), Controls: len(controls), Targets: len(targets), Flaws: len(flaws)},
		Cases:              cases,
		ProofPatches:       patches,
		EvidenceReferences: evidenceRefs,
		RerunCommands:      rerunCommands,
		CompareCommands:    compareCommands,
		PatchExportCommand: patchExportCommand,
		SuccessCriteria:    successCriteria,
		Workflow:           workflow,
		Redaction:          catalog.Redaction,
		Limitations:        limitations,
	}
}

func proofPlanCommand(catalog model.ControlCatalogReport, caseID string) string {
	mode := firstNonEmpty(catalog.Mode, "repo")
	agent := firstNonEmpty(catalog.Agent, "all")
	status := firstNonEmpty(catalog.StatusFilter, "breaking")
	var command string
	switch catalog.RunKind {
	case "case_board_scan", "control_catalog_scan":
		command = fmt.Sprintf("ariadne proofs --targets %s --mode %s --agent %s --status %s", targetsFileCommandArg(catalog.TargetsFile), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(status))
	default:
		path := firstNonEmpty(catalog.TargetPath, "<target-path>")
		command = fmt.Sprintf("ariadne proofs --path %s --mode %s --agent %s --status %s", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(status))
	}
	caseID = strings.TrimSpace(caseID)
	if caseID != "" {
		command += " --case " + shellQuoteCommandArg(caseID)
	}
	return command
}

func proofPlanPatchExportCommand(catalog model.ControlCatalogReport) string {
	switch catalog.RunKind {
	case "case_board_scan", "control_catalog_scan":
		return ""
	}
	caseID := strings.TrimSpace(catalog.CaseFilter)
	if caseID == "" && len(catalog.OperatorCases) == 1 {
		caseID = catalog.OperatorCases[0].ID
	}
	return proofPlanCommand(catalog, caseID) + " --patch-dir proof-patches"
}

func proofPlanCompareCommands(catalog model.ControlCatalogReport) []string {
	before := "before-proof.json"
	after := "after-proof.json"
	caseID := strings.TrimSpace(catalog.CaseFilter)
	if caseID == "" && len(catalog.OperatorCases) == 1 {
		caseID = catalog.OperatorCases[0].ID
	}
	proofCommand := func(out string) string {
		return proofPlanCommand(catalog, caseID) + " --format json --out " + shellQuoteCommandArg(out)
	}
	return []string{
		proofCommand(before),
		proofCommand(after),
		fmt.Sprintf("ariadne compare --before %s --after %s --format html --out case-compare.html", shellQuoteCommandArg(before), shellQuoteCommandArg(after)),
	}
}

func buildProofPlanWorkflow(cases []model.ControlOperatorCase, patches []model.ControlProofPatch, evidenceRefs []model.EvidenceReference, rerunCommands []string, compareCommands []string, patchExportCommand string, successCriteria []string) []model.ProofWorkflowStep {
	proofSurfaces := proofWorkflowSurfaces(cases, patches)
	beforeCommands := firstStrings(compareCommands, 1)
	afterCompareCommands := []string{}
	if len(compareCommands) > 1 {
		afterCompareCommands = append(afterCompareCommands, compareCommands[1:]...)
	}
	addProofCommands := nonNilStrings(nonEmptyStrings(patchExportCommand))
	addProofSummary := "Add or verify the parser-recognized control evidence that should break the selected path."
	addProofLimitations := []string{"Only add proof when the named control is actually implemented or enforced in the environment."}
	if len(patches) == 0 {
		addProofSummary = "No proof patch is needed for the selected case because Ariadne already observes matching control evidence or no parser-recognized patch applies."
		addProofLimitations = []string{"No patch means there is no generated evidence file to apply; inspect the case state and evidence references instead."}
	}
	workflow := []model.ProofWorkflowStep{
		{
			ID:                 "save-baseline",
			Title:              "Save Baseline Proof",
			Summary:            "Run the first proof command before changing evidence so compare has a baseline artifact.",
			Commands:           nonNilStrings(beforeCommands),
			EvidenceReferences: dedupeEvidenceReferences(evidenceRefs),
			ProofSurfaces:      nonNilStrings(proofSurfaces),
			SuccessCriteria:    []string{"before-proof.json represents the current open or controlled state before evidence changes."},
			Limitations:        []string{"The baseline is a structured Ariadne proof artifact; it does not execute the agent or prove live exploitability."},
		},
		{
			ID:                 "add-or-verify-proof",
			Title:              "Add Or Verify Proof",
			Summary:            addProofSummary,
			Commands:           addProofCommands,
			EvidenceReferences: dedupeEvidenceReferences(evidenceRefs),
			ProofSurfaces:      nonNilStrings(proofSurfaces),
			SuccessCriteria:    []string{"The named control evidence exists at a parser-recognized proof surface and reflects a real implemented control."},
			Limitations:        addProofLimitations,
		},
		{
			ID:                 "rerun-case",
			Title:              "Rerun Case",
			Summary:            "Rerun the focused case or architecture command after evidence changes so Ariadne recomputes facts, graph paths, and missing controls.",
			Commands:           nonNilStrings(rerunCommands),
			EvidenceReferences: []model.EvidenceReference{},
			ProofSurfaces:      nonNilStrings(proofSurfaces),
			SuccessCriteria:    nonNilStrings(successCriteria),
			Limitations:        []string{"Rerun results are deterministic local analysis of collected evidence."},
		},
		{
			ID:                 "compare-before-after",
			Title:              "Compare Before And After",
			Summary:            "Save the after proof artifact and compare it with the baseline to prove whether the case closed, reopened, or stayed open.",
			Commands:           nonNilStrings(afterCompareCommands),
			EvidenceReferences: []model.EvidenceReference{},
			ProofSurfaces:      nonNilStrings(proofSurfaces),
			SuccessCriteria:    nonNilStrings(successCriteria),
			Limitations:        []string{"Compare uses structured Ariadne JSON only; it does not rerun collectors or prove live enforcement."},
		},
	}
	for i := range workflow {
		workflow[i].Commands = uniqueStrings(workflow[i].Commands)
		workflow[i].EvidenceReferences = dedupeEvidenceReferences(workflow[i].EvidenceReferences)
		workflow[i].ProofSurfaces = uniqueStrings(workflow[i].ProofSurfaces)
		workflow[i].SuccessCriteria = uniqueStrings(workflow[i].SuccessCriteria)
		workflow[i].Limitations = uniqueStrings(workflow[i].Limitations)
	}
	return workflow
}

func proofWorkflowSurfaces(cases []model.ControlOperatorCase, patches []model.ControlProofPatch) []string {
	var surfaces []string
	surfaces = append(surfaces, proofPatchSurfaceLines(patches)...)
	for _, item := range cases {
		surfaces = append(surfaces, item.ProofSurfaces...)
	}
	return uniqueStrings(surfaces)
}

func operatorCaseCompareCommands(catalog model.ControlCatalogReport, caseID string) []string {
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return []string{}
	}
	focused := catalog
	focused.CaseFilter = caseID
	return proofPlanCompareCommands(focused)
}

func attachOperatorCaseCompareCommands(catalog *model.ControlCatalogReport) {
	if catalog == nil {
		return
	}
	for i := range catalog.OperatorCases {
		catalog.OperatorCases[i].CompareCommands = operatorCaseCompareCommands(*catalog, catalog.OperatorCases[i].ID)
	}
}

func BuildCaseCompareReport(beforeRaw []byte, afterRaw []byte, beforeSource string, afterSource string) (model.CaseCompareReport, error) {
	beforeCases, err := extractComparableCases(beforeRaw)
	if err != nil {
		return model.CaseCompareReport{}, fmt.Errorf("before report: %w", err)
	}
	afterCases, err := extractComparableCases(afterRaw)
	if err != nil {
		return model.CaseCompareReport{}, fmt.Errorf("after report: %w", err)
	}
	beforeByID := casesByID(beforeCases)
	afterByID := casesByID(afterCases)
	idSet := map[string]bool{}
	for id := range beforeByID {
		idSet[id] = true
	}
	for id := range afterByID {
		idSet[id] = true
	}
	ids := mapKeysSorted(idSet)
	out := model.CaseCompareReport{
		SchemaVersion: model.SchemaVersion,
		RunKind:       "case_compare",
		BeforeSource:  beforeSource,
		AfterSource:   afterSource,
		Limitations: []string{
			"Compare uses structured Ariadne JSON only; it does not rerun collectors or prove live enforcement.",
			"Closed means the after report contains deterministic closed/control evidence for the case, or the case stayed closed in the compared artifact.",
		},
	}
	for _, id := range ids {
		before, beforeOK := beforeByID[id]
		after, afterOK := afterByID[id]
		item := compareCase(before, beforeOK, after, afterOK)
		out.Cases = append(out.Cases, item)
		incrementCaseCompareSummary(&out.Summary, item.Disposition)
	}
	out.Summary.Cases = len(out.Cases)
	if out.Cases == nil {
		out.Cases = []model.CaseCompareResult{}
	}
	out.Outcome = buildCaseCompareOutcome(out.Cases, out.Summary)
	return out, nil
}

func RenderCaseCompare(w io.Writer, r model.CaseCompareReport, format string) error {
	switch strings.ToLower(format) {
	case "", "table":
		return renderCaseCompareTable(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "html", "dashboard":
		return renderCaseCompareDashboard(w, r)
	default:
		return fmt.Errorf("unknown compare format: %s", format)
	}
}

type caseReportEnvelope struct {
	RunKind       string                      `json:"run_kind"`
	Cases         []model.ControlOperatorCase `json:"cases"`
	OperatorCases []model.ControlOperatorCase `json:"operator_cases"`
	CaseBoard     *model.ControlCatalogReport `json:"case_board"`
}

func extractComparableCases(raw []byte) ([]model.ControlOperatorCase, error) {
	var env caseReportEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Cases != nil {
		return nonNilControlOperatorCases(env.Cases), nil
	}
	if env.OperatorCases != nil {
		return nonNilControlOperatorCases(env.OperatorCases), nil
	}
	if env.CaseBoard != nil {
		return nonNilControlOperatorCases(env.CaseBoard.OperatorCases), nil
	}
	return nil, fmt.Errorf("unsupported report shape; expected proofs.cases, cases.operator_cases, or assess.case_board.operator_cases")
}

func casesByID(items []model.ControlOperatorCase) map[string]model.ControlOperatorCase {
	out := map[string]model.ControlOperatorCase{}
	for _, item := range items {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		if _, exists := out[id]; exists {
			continue
		}
		out[id] = item
	}
	return out
}

func compareCase(before model.ControlOperatorCase, beforeOK bool, after model.ControlOperatorCase, afterOK bool) model.CaseCompareResult {
	beforeState := normalizedCaseState(before, beforeOK)
	afterState := normalizedCaseState(after, afterOK)
	item := model.CaseCompareResult{
		ID:                    firstNonEmpty(caseIDOrEmpty(after, afterOK), caseIDOrEmpty(before, beforeOK)),
		Title:                 firstNonEmpty(caseTitleOrEmpty(after, afterOK), caseTitleOrEmpty(before, beforeOK)),
		Severity:              firstNonEmpty(caseSeverityOrEmpty(after, afterOK), caseSeverityOrEmpty(before, beforeOK)),
		BeforeState:           beforeState,
		AfterState:            afterState,
		BeforeStateReason:     caseStateReasonOrEmpty(before, beforeOK),
		AfterStateReason:      caseStateReasonOrEmpty(after, afterOK),
		BeforeControls:        normalizedCaseControls(before, beforeOK),
		AfterControls:         normalizedCaseControls(after, afterOK),
		BeforeProofPatches:    caseProofPatchCount(before, beforeOK),
		AfterProofPatches:     caseProofPatchCount(after, afterOK),
		BeforeEvidenceRefs:    caseEvidenceRefCount(before, beforeOK),
		AfterEvidenceRefs:     caseEvidenceRefCount(after, afterOK),
		BeforeEvidence:        caseEvidenceReferences(before, beforeOK),
		AfterEvidence:         caseEvidenceReferences(after, afterOK),
		BeforeTargets:         normalizedCaseTargets(before, beforeOK),
		AfterTargets:          normalizedCaseTargets(after, afterOK),
		BeforeFlaws:           normalizedCaseFlaws(before, beforeOK),
		AfterFlaws:            normalizedCaseFlaws(after, afterOK),
		BeforeRerunCommands:   caseRerunCommands(before, beforeOK),
		AfterRerunCommands:    caseRerunCommands(after, afterOK),
		BeforeCompareCommands: caseCompareCommands(before, beforeOK),
		AfterCompareCommands:  caseCompareCommands(after, afterOK),
		BeforeNextStep:        caseNextStepOrEmpty(before, beforeOK),
		AfterNextStep:         caseNextStepOrEmpty(after, afterOK),
	}
	item.AddedControls = subtractStrings(item.AfterControls, item.BeforeControls)
	item.RemovedControls = subtractStrings(item.BeforeControls, item.AfterControls)
	item.AddedEvidence = subtractEvidenceReferences(item.AfterEvidence, item.BeforeEvidence)
	item.RemovedEvidence = subtractEvidenceReferences(item.BeforeEvidence, item.AfterEvidence)
	item.Disposition = caseCompareDisposition(beforeOK, beforeState, before, afterOK, afterState, after, item)
	return item
}

func caseCompareDisposition(beforeOK bool, beforeState string, before model.ControlOperatorCase, afterOK bool, afterState string, after model.ControlOperatorCase, item model.CaseCompareResult) string {
	if !beforeOK && afterOK {
		return "added"
	}
	if beforeOK && !afterOK {
		return "removed"
	}
	if beforeState == "open" && afterState == "closed" {
		return "closed"
	}
	if beforeState == "closed" && afterState == "open" {
		return "reopened"
	}
	changed := caseCompareChanged(before, after, item)
	if beforeState == "closed" && afterState == "closed" {
		if changed {
			return "changed"
		}
		return "stayed_closed"
	}
	if beforeState == "open" && afterState == "open" {
		if changed {
			return "changed"
		}
		return "stayed_open"
	}
	if changed {
		return "changed"
	}
	return "changed"
}

func caseCompareChanged(before model.ControlOperatorCase, after model.ControlOperatorCase, item model.CaseCompareResult) bool {
	return !equalStrings(item.BeforeControls, item.AfterControls) ||
		!equalStrings(item.BeforeTargets, item.AfterTargets) ||
		!equalStrings(item.BeforeFlaws, item.AfterFlaws) ||
		item.BeforeProofPatches != item.AfterProofPatches ||
		item.BeforeEvidenceRefs != item.AfterEvidenceRefs ||
		!equalEvidenceReferences(item.BeforeEvidence, item.AfterEvidence) ||
		strings.TrimSpace(before.StateReason) != strings.TrimSpace(after.StateReason) ||
		strings.TrimSpace(before.NextStep) != strings.TrimSpace(after.NextStep)
}

func normalizedCaseState(item model.ControlOperatorCase, ok bool) string {
	if !ok {
		return "absent"
	}
	state := strings.ToLower(strings.TrimSpace(item.State))
	switch state {
	case "closed", "controlled", "no_missing_hard_barrier":
		return "closed"
	case "open":
		return "open"
	}
	if item.ControlCount == 0 && len(item.ProofPatches) == 0 && len(item.StartingControls) > 0 {
		return "closed"
	}
	return "open"
}

func normalizedCaseControls(item model.ControlOperatorCase, ok bool) []string {
	if !ok {
		return []string{}
	}
	return uniqueSortedStrings(item.StartingControls)
}

func normalizedCaseTargets(item model.ControlOperatorCase, ok bool) []string {
	if !ok {
		return []string{}
	}
	return uniqueSortedStrings(item.Targets)
}

func normalizedCaseFlaws(item model.ControlOperatorCase, ok bool) []string {
	if !ok {
		return []string{}
	}
	return uniqueSortedStrings(item.Flaws)
}

func caseIDOrEmpty(item model.ControlOperatorCase, ok bool) string {
	if !ok {
		return ""
	}
	return item.ID
}

func caseTitleOrEmpty(item model.ControlOperatorCase, ok bool) string {
	if !ok {
		return ""
	}
	return item.Title
}

func caseSeverityOrEmpty(item model.ControlOperatorCase, ok bool) string {
	if !ok {
		return ""
	}
	return item.Severity
}

func caseStateReasonOrEmpty(item model.ControlOperatorCase, ok bool) string {
	if !ok {
		return ""
	}
	return item.StateReason
}

func caseNextStepOrEmpty(item model.ControlOperatorCase, ok bool) string {
	if !ok {
		return ""
	}
	return item.NextStep
}

func caseProofPatchCount(item model.ControlOperatorCase, ok bool) int {
	if !ok {
		return 0
	}
	return len(item.ProofPatches)
}

func caseEvidenceRefCount(item model.ControlOperatorCase, ok bool) int {
	if !ok {
		return 0
	}
	return len(dedupeEvidenceReferences(item.EvidenceReferences))
}

func caseEvidenceReferences(item model.ControlOperatorCase, ok bool) []model.EvidenceReference {
	if !ok {
		return []model.EvidenceReference{}
	}
	return dedupeEvidenceReferences(item.EvidenceReferences)
}

func caseRerunCommands(item model.ControlOperatorCase, ok bool) []string {
	if !ok {
		return []string{}
	}
	return uniqueStrings(item.RerunCommands)
}

func caseCompareCommands(item model.ControlOperatorCase, ok bool) []string {
	if !ok {
		return []string{}
	}
	return uniqueStrings(item.CompareCommands)
}

func subtractEvidenceReferences(values []model.EvidenceReference, remove []model.EvidenceReference) []model.EvidenceReference {
	removed := map[string]bool{}
	for _, item := range dedupeEvidenceReferences(remove) {
		removed[evidenceReferenceKey(item)] = true
	}
	var out []model.EvidenceReference
	for _, item := range dedupeEvidenceReferences(values) {
		if !removed[evidenceReferenceKey(item)] {
			out = append(out, item)
		}
	}
	if out == nil {
		return []model.EvidenceReference{}
	}
	return out
}

func equalEvidenceReferences(a []model.EvidenceReference, b []model.EvidenceReference) bool {
	a = dedupeEvidenceReferences(a)
	b = dedupeEvidenceReferences(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if evidenceReferenceKey(a[i]) != evidenceReferenceKey(b[i]) {
			return false
		}
	}
	return true
}

func evidenceReferenceKey(value model.EvidenceReference) string {
	return value.Target + "|" + value.ID + "|" + value.Kind + "|" + value.Source + "|" + value.Summary
}

func incrementCaseCompareSummary(summary *model.CaseCompareSummary, disposition string) {
	switch disposition {
	case "closed":
		summary.Closed++
	case "reopened":
		summary.Reopened++
	case "stayed_open":
		summary.StayedOpen++
	case "stayed_closed":
		summary.StayedClosed++
	case "changed":
		summary.Changed++
	case "added":
		summary.Added++
	case "removed":
		summary.Removed++
	}
}

func buildCaseCompareOutcome(cases []model.CaseCompareResult, summary model.CaseCompareSummary) model.CaseCompareOutcome {
	out := model.CaseCompareOutcome{
		TotalCases:      len(cases),
		MaterialChanges: summary.Closed + summary.Reopened + summary.Changed + summary.Added + summary.Removed,
	}
	for _, item := range cases {
		caseSummary := caseCompareOutcomeCase(item)
		switch item.AfterState {
		case "open":
			out.AfterOpen++
			out.ActionCases = append(out.ActionCases, caseSummary)
		case "closed":
			out.AfterClosed++
			out.ClosedCases = append(out.ClosedCases, caseSummary)
		case "absent":
			out.AfterAbsent++
			out.AbsentCases = append(out.AbsentCases, caseSummary)
		}
	}
	out.Summary = fmt.Sprintf("%d case(s) compared: %d open after rerun, %d closed after rerun, %d absent after rerun, %d material change(s).",
		out.TotalCases,
		out.AfterOpen,
		out.AfterClosed,
		out.AfterAbsent,
		out.MaterialChanges,
	)
	out.NextAction = caseCompareOutcomeNextAction(out)
	if out.ActionCases == nil {
		out.ActionCases = []model.CaseCompareOutcomeCase{}
	}
	if out.ClosedCases == nil {
		out.ClosedCases = []model.CaseCompareOutcomeCase{}
	}
	if out.AbsentCases == nil {
		out.AbsentCases = []model.CaseCompareOutcomeCase{}
	}
	return out
}

func caseCompareOutcomeCase(item model.CaseCompareResult) model.CaseCompareOutcomeCase {
	nextStep := item.AfterNextStep
	if nextStep == "" && item.AfterState == "open" {
		nextStep = item.BeforeNextStep
	}
	return model.CaseCompareOutcomeCase{
		ID:                item.ID,
		Title:             item.Title,
		Severity:          item.Severity,
		Disposition:       item.Disposition,
		BeforeState:       item.BeforeState,
		AfterState:        item.AfterState,
		StateReason:       firstNonEmpty(item.AfterStateReason, item.BeforeStateReason),
		NextStep:          nextStep,
		AfterEvidenceRefs: item.AfterEvidenceRefs,
		AfterProofPatches: item.AfterProofPatches,
	}
}

func caseCompareOutcomeNextAction(out model.CaseCompareOutcome) string {
	if len(out.ActionCases) > 0 {
		item := out.ActionCases[0]
		return fmt.Sprintf("%s: %s", firstNonEmpty(item.ID, item.Title, "case"), firstNonEmpty(item.NextStep, item.StateReason, "case remains open in the after artifact"))
	}
	if out.TotalCases == 0 {
		return "No comparable cases found; create before/after Ariadne JSON for the same case scope."
	}
	if out.AfterAbsent > 0 {
		return "No open case remains in the after artifact; confirm absent cases are expected scope changes before treating them as resolved."
	}
	return "No open case remains in the after artifact."
}

func caseCompareOutcomeCaseLines(cases []model.CaseCompareOutcomeCase, limit int) []string {
	var out []string
	for _, item := range limitCaseCompareOutcomeCases(cases, limit) {
		out = append(out, fmt.Sprintf("%s %s (%s): %s -> %s",
			strings.ToUpper(strings.ReplaceAll(item.Disposition, "_", " ")),
			firstNonEmpty(item.Title, item.ID),
			item.ID,
			item.BeforeState,
			item.AfterState,
		))
	}
	if limit > 0 && len(cases) > limit {
		out = append(out, fmt.Sprintf("%d more case(s) omitted", len(cases)-limit))
	}
	if out == nil {
		return []string{}
	}
	return out
}

func limitCaseCompareOutcomeCases(cases []model.CaseCompareOutcomeCase, limit int) []model.CaseCompareOutcomeCase {
	if limit <= 0 || len(cases) <= limit {
		return cases
	}
	return cases[:limit]
}

func renderCaseCompareTable(w io.Writer, r model.CaseCompareReport) error {
	fmt.Fprintf(w, "Ariadne case compare:\n")
	fmt.Fprintf(w, "  Before: %s\n", firstNonEmpty(r.BeforeSource, "<before>"))
	fmt.Fprintf(w, "  After: %s\n", firstNonEmpty(r.AfterSource, "<after>"))
	fmt.Fprintf(w, "  Summary: %d case(s); %d closed, %d reopened, %d stayed open, %d stayed closed, %d changed, %d added, %d removed\n\n",
		r.Summary.Cases,
		r.Summary.Closed,
		r.Summary.Reopened,
		r.Summary.StayedOpen,
		r.Summary.StayedClosed,
		r.Summary.Changed,
		r.Summary.Added,
		r.Summary.Removed,
	)
	fmt.Fprintf(w, "Outcome:\n")
	fmt.Fprintf(w, "  %s\n", firstNonEmpty(r.Outcome.Summary, "No outcome summary recorded."))
	fmt.Fprintf(w, "  Next action: %s\n", firstNonEmpty(r.Outcome.NextAction, "No next action recorded."))
	if len(r.Outcome.ActionCases) > 0 {
		fmt.Fprintf(w, "  Still open after rerun:\n")
		for _, line := range caseCompareOutcomeCaseLines(r.Outcome.ActionCases, 5) {
			fmt.Fprintf(w, "    - %s\n", line)
		}
	}
	if len(r.Outcome.ClosedCases) > 0 {
		fmt.Fprintf(w, "  Closed after rerun:\n")
		for _, line := range caseCompareOutcomeCaseLines(r.Outcome.ClosedCases, 5) {
			fmt.Fprintf(w, "    - %s\n", line)
		}
	}
	if len(r.Outcome.AbsentCases) > 0 {
		fmt.Fprintf(w, "  Absent after rerun:\n")
		for _, line := range caseCompareOutcomeCaseLines(r.Outcome.AbsentCases, 5) {
			fmt.Fprintf(w, "    - %s\n", line)
		}
	}
	fmt.Fprintln(w)
	if len(r.Cases) == 0 {
		fmt.Fprintf(w, "Cases:\n  - no comparable cases found\n\n")
		return nil
	}
	fmt.Fprintf(w, "Cases:\n")
	for _, item := range r.Cases {
		fmt.Fprintf(w, "  - %s %s (%s): %s -> %s\n", strings.ToUpper(item.Disposition), firstNonEmpty(item.Title, item.ID), item.ID, item.BeforeState, item.AfterState)
		if item.AfterStateReason != "" {
			fmt.Fprintf(w, "    After reason: %s\n", item.AfterStateReason)
		}
		if len(item.BeforeControls) > 0 {
			fmt.Fprintf(w, "    Before controls: %s\n", strings.Join(item.BeforeControls, "; "))
		}
		if len(item.AfterControls) > 0 {
			fmt.Fprintf(w, "    After controls: %s\n", strings.Join(item.AfterControls, "; "))
		}
		if len(item.AddedControls) > 0 {
			fmt.Fprintf(w, "    Added controls: %s\n", strings.Join(item.AddedControls, "; "))
		}
		if len(item.RemovedControls) > 0 {
			fmt.Fprintf(w, "    Removed controls: %s\n", strings.Join(item.RemovedControls, "; "))
		}
		fmt.Fprintf(w, "    Proof patches: %d -> %d; evidence refs: %d -> %d\n", item.BeforeProofPatches, item.AfterProofPatches, item.BeforeEvidenceRefs, item.AfterEvidenceRefs)
		if len(item.AfterEvidence) > 0 {
			fmt.Fprintf(w, "    After evidence: %s\n", strings.Join(evidenceReferenceLines(item.AfterEvidence, 3), "; "))
		}
		if len(item.AddedEvidence) > 0 {
			fmt.Fprintf(w, "    Added evidence: %s\n", strings.Join(evidenceReferenceLines(item.AddedEvidence, 3), "; "))
		}
		if len(item.RemovedEvidence) > 0 {
			fmt.Fprintf(w, "    Removed evidence: %s\n", strings.Join(evidenceReferenceLines(item.RemovedEvidence, 3), "; "))
		}
		if item.AfterNextStep != "" {
			fmt.Fprintf(w, "    After next step: %s\n", item.AfterNextStep)
		}
		if len(item.AfterRerunCommands) > 0 {
			fmt.Fprintf(w, "    After rerun: %s\n", strings.Join(limitStrings(item.AfterRerunCommands, 2), "; "))
		}
		if len(item.AfterCompareCommands) > 0 {
			fmt.Fprintf(w, "    After compare loop: %s\n", strings.Join(limitStrings(item.AfterCompareCommands, 3), "; "))
		}
	}
	if len(r.Limitations) > 0 {
		fmt.Fprintf(w, "\nLimitations:\n")
		for _, limitation := range limitStrings(r.Limitations, 4) {
			fmt.Fprintf(w, "  - %s\n", limitation)
		}
	}
	fmt.Fprintln(w)
	return nil
}

func BuildControlCatalogScanReport(r model.ArchitectureScanReport) model.ControlCatalogReport {
	proofSpecs := buildControlProofSpecs(r.ClosurePlan)
	verificationTasks := buildControlVerificationTasks(r.ClosurePlan, proofSpecs, controlVerificationCommandContext{RunKind: "control_catalog_scan", TargetsFile: r.TargetsFile, Mode: r.Mode, Agent: r.Agent, StatusFilter: r.StatusFilter})
	workstreams := buildControlBreakPathWorkstreams(r.ClosureFamilies, verificationTasks)
	catalog := model.ControlCatalogReport{
		SchemaVersion:     model.SchemaVersion,
		RunID:             r.RunID,
		GeneratedAt:       r.GeneratedAt,
		RunKind:           "control_catalog_scan",
		TargetsFile:       r.TargetsFile,
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
	attachOperatorCaseCompareCommands(&catalog)
	return catalog
}

func BuildControlCaseBoardScanReport(r model.ArchitectureScanReport) model.ControlCatalogReport {
	catalog := BuildControlCatalogScanReport(r)
	catalog.RunKind = "case_board_scan"
	rewriteControlCatalogAsCaseBoard(&catalog)
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
		TargetsFile:   r.TargetsFile,
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
	case "html", "dashboard":
		return renderInventoryDashboard(w, r)
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

func renderAssess(w io.Writer, r model.AssessReport, format string) error {
	switch strings.ToLower(format) {
	case "", "table":
		return renderAssessTable(w, r)
	case "action":
		return renderAssessAction(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "html", "dashboard":
		return renderAssessDashboard(w, r)
	default:
		return fmt.Errorf("unknown assess format: %s", format)
	}
}

func renderAssessAction(w io.Writer, r model.AssessReport) error {
	fmt.Fprintf(w, "Ariadne Action\n\n")
	if r.RunKind == "assess_scan" {
		fmt.Fprintf(w, "Targets: %d completed, %d errors, %d total\n", r.Summary.CompletedTargets, r.Summary.Errors, r.Summary.Targets)
	} else {
		fmt.Fprintf(w, "Target: %s\n", r.TargetPath)
	}
	fmt.Fprintf(w, "Filter: %s\n", r.StatusFilter)
	renderAssessFocusLine(w, r)
	caseLabel := "Open cases"
	if assessFirstActionClosed(r.FirstAction) {
		caseLabel = "Focused cases"
	}
	fmt.Fprintf(w, "%s: %d; missing hard barriers: %d; exposed paths: %d\n\n", caseLabel, r.Summary.OperatorCases, r.Summary.MissingHardBarrierControls, r.Summary.Exposed)

	renderAssessInventorySummary(w, r.Inventory, 4)
	renderAssessTriage(w, r.Triage)
	renderAssessClosurePlan(w, r.ClosurePlan, 3)
	action := r.FirstAction
	if !action.Available {
		fmt.Fprintf(w, "Current action:\n  - none\n\n")
		renderAssessActionLimitations(w, r.Limitations)
		return nil
	}
	fmt.Fprintf(w, "Case:\n")
	fmt.Fprintf(w, "  - %s (%s)\n", action.Title, action.CaseID)
	if action.WhyFirst != "" {
		fmt.Fprintf(w, "  - %s\n", action.WhyFirst)
	}
	if action.CurrentAction.Available {
		fmt.Fprintf(w, "\nCurrent action:\n")
		fmt.Fprintf(w, "  - Step: %s\n", firstNonEmpty(action.CurrentAction.WorkflowStepTitle, "not recorded"))
		if action.CurrentAction.Control != "" {
			fmt.Fprintf(w, "  - Control: %s\n", action.CurrentAction.Control)
		}
		if action.CurrentAction.Surface != "" {
			fmt.Fprintf(w, "  - Proof surface: %s\n", action.CurrentAction.Surface)
		}
		if action.CurrentAction.Instruction != "" {
			fmt.Fprintf(w, "  - Instruction: %s\n", action.CurrentAction.Instruction)
		}
	}
	if len(action.CurrentAction.EvidenceReferences) > 0 {
		fmt.Fprintf(w, "\nEvidence to inspect:\n")
		for _, line := range evidenceReferenceLinesBySource(action.CurrentAction.EvidenceReferences, 4) {
			fmt.Fprintf(w, "  - %s\n", line)
		}
	}
	if example := assessCurrentEvidenceExampleLine(action); example != "" {
		fmt.Fprintf(w, "\nAccepted evidence:\n  - %s\n", example)
	}
	if patch := assessCurrentProofPatchLine(action); patch != "" {
		fmt.Fprintf(w, "\nProof patch:\n  - %s\n", patch)
	}
	if action.CurrentAction.PatchExportCommand != "" {
		fmt.Fprintf(w, "\nExport suggested files:\n  - %s\n", action.CurrentAction.PatchExportCommand)
	}
	if rerun := assessCurrentRerunCommand(action); rerun != "" {
		fmt.Fprintf(w, "\nRerun:\n  - %s\n", rerun)
	}
	if len(action.CompareCommands) > 0 {
		fmt.Fprintf(w, "\nCompare loop:\n")
		for _, command := range limitStrings(action.CompareCommands, 3) {
			fmt.Fprintf(w, "  - %s\n", command)
		}
	} else if action.CurrentAction.CompareCommand != "" {
		fmt.Fprintf(w, "\nCompare loop:\n  - %s\n", action.CurrentAction.CompareCommand)
	}
	if len(action.SuccessCriteria) > 0 {
		fmt.Fprintf(w, "\nDone when:\n")
		for _, criterion := range limitStrings(action.SuccessCriteria, 3) {
			fmt.Fprintf(w, "  - %s\n", criterion)
		}
	}
	renderAssessActionLimitations(w, r.Limitations)
	return nil
}

func assessCurrentEvidenceExampleLine(action model.AssessFirstAction) string {
	if action.CurrentAction.EvidenceExample != nil {
		lines := controlEvidenceExampleLines([]model.ControlEvidenceExample{*action.CurrentAction.EvidenceExample}, 1)
		if len(lines) > 0 {
			return lines[0]
		}
	}
	index := action.CurrentAction.EvidenceExampleIndex
	if index < 0 || index >= len(action.EvidenceExamples) {
		return ""
	}
	lines := controlEvidenceExampleLines([]model.ControlEvidenceExample{action.EvidenceExamples[index]}, 1)
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

func assessCurrentProofPatchLine(action model.AssessFirstAction) string {
	if action.CurrentAction.ProofPatch != nil {
		lines := controlProofPatchLines([]model.ControlProofPatch{*action.CurrentAction.ProofPatch}, 1)
		if len(lines) > 0 {
			return lines[0]
		}
	}
	index := action.CurrentAction.ProofPatchIndex
	if index < 0 || index >= len(action.ProofPatches) {
		return ""
	}
	lines := controlProofPatchLines([]model.ControlProofPatch{action.ProofPatches[index]}, 1)
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

func assessCurrentRerunCommand(action model.AssessFirstAction) string {
	if action.CurrentAction.RerunCommand != "" {
		return action.CurrentAction.RerunCommand
	}
	if len(action.RerunCommands) > 0 {
		return action.RerunCommands[0]
	}
	return ""
}

func renderAssessActionLimitations(w io.Writer, limitations []string) {
	if len(limitations) == 0 {
		return
	}
	fmt.Fprintf(w, "\nLimitations:\n")
	for _, limitation := range limitStrings(limitations, 3) {
		fmt.Fprintf(w, "  - %s\n", limitation)
	}
}

func buildAssessInventory(r model.InventoryReport) model.AssessInventory {
	return model.AssessInventory{
		TargetPath:        r.TargetPath,
		Surfaces:          len(r.Collection.Surfaces),
		Facts:             len(r.Collection.Facts),
		GraphNodes:        len(r.Graph.Nodes),
		GraphEdges:        len(r.Graph.Edges),
		Runtimes:          len(r.Collection.Runtimes),
		TrustInputs:       len(r.Collection.TrustInputs),
		Tools:             len(r.Collection.Tools),
		Authorities:       len(r.Collection.Authorities),
		Controls:          len(r.Collection.Controls),
		Boundaries:        len(r.Collection.Boundaries),
		SurfaceCategories: assessSurfaceCounts(r.Collection.Surfaces, func(surface model.Surface) string { return surface.Category }),
		HandlingModes:     assessSurfaceCounts(r.Collection.Surfaces, func(surface model.Surface) string { return surface.HandlingMode }),
		SurfaceMap:        append([]model.SurfaceMap{}, r.SurfaceMap...),
		FactHighlights:    assessFactHighlights(r.Collection.Facts, 12),
		Limitations:       append([]string{}, r.Limitations...),
	}
}

type assessScanSurfaceGroup struct {
	Runtime      string
	Scope        string
	SourceRefs   map[string]bool
	Categories   map[string]int
	Authorities  map[string]bool
	Tools        map[string]bool
	Controls     map[string]bool
	BoundaryRefs map[string]bool
}

func buildAssessScanInventory(r model.ScanReport) model.AssessInventory {
	inventory := model.AssessInventory{
		TargetPath:        r.TargetsFile,
		SurfaceCategories: []model.AssessCount{},
		HandlingModes:     []model.AssessCount{},
		SurfaceMap:        []model.SurfaceMap{},
		FactHighlights:    []model.AssessFact{},
		Limitations: []string{
			"Fleet inspected summary is aggregated from completed target reports.",
			"Surface counts are unique target/source references, not raw file counts.",
			"Low-level collector handling modes are unavailable in scan assessment reports.",
		},
	}
	sourceRefs := map[string]bool{}
	categoryCounts := map[string]int{}
	runtimes := map[string]bool{}
	trustInputs := map[string]bool{}
	tools := map[string]bool{}
	authorities := map[string]bool{}
	controls := map[string]bool{}
	boundaries := map[string]bool{}
	groups := map[string]*assessScanSurfaceGroup{}
	for _, target := range r.Targets {
		if target.Error != "" {
			continue
		}
		targetID := assessScanTargetID(target)
		inventory.Facts += len(target.Report.Evidence)
		inventory.GraphNodes += len(target.Report.Graph.Nodes)
		inventory.GraphEdges += len(target.Report.Graph.Edges)
		for _, evidence := range target.Report.Evidence {
			kind := strings.TrimSpace(evidence.Kind)
			if kind != "" {
				categoryCounts[kind]++
			}
			source := strings.TrimSpace(evidence.Source)
			if source == "" {
				continue
			}
			ref := assessScanSourceRef(targetID, source)
			sourceRefs[ref] = true
			group := assessScanSurfaceGroupFor(groups, assessScanRuntime(evidence.Runtime, source), "fleet")
			group.SourceRefs[ref] = true
			if kind != "" {
				group.Categories[kind]++
			}
		}
		for _, node := range target.Report.Graph.Nodes {
			nodeKey := assessScanSourceRef(targetID, firstNonEmpty(node.ID, node.Label, node.Type))
			nodeType := strings.TrimSpace(node.Type)
			switch {
			case nodeType == "runtime":
				runtimes[nodeKey] = true
			case nodeType == "trust-input" || nodeType == "trust_input":
				trustInputs[nodeKey] = true
			case nodeType == "tool" || nodeType == "mcp-tool-config" || nodeType == "agent-delegation":
				tools[nodeKey] = true
			case nodeType == "authority":
				authorities[nodeKey] = true
			case nodeType == "control":
				controls[nodeKey] = true
			case nodeType == "boundary" || nodeType == "sensitive-boundary":
				boundaries[nodeKey] = true
			}
			source := strings.TrimSpace(node.Source)
			runtime := assessScanRuntime(node.Runtime, source)
			if source != "" {
				ref := assessScanSourceRef(targetID, source)
				sourceRefs[ref] = true
				group := assessScanSurfaceGroupFor(groups, runtime, "fleet")
				group.SourceRefs[ref] = true
				switch {
				case nodeType == "boundary" || nodeType == "sensitive-boundary":
					group.BoundaryRefs[ref] = true
				}
			}
			group := assessScanSurfaceGroupFor(groups, runtime, "fleet")
			name := assessScanNodeName(node)
			switch {
			case nodeType == "tool" || nodeType == "mcp-tool-config" || nodeType == "agent-delegation":
				group.Tools[name] = true
			case nodeType == "authority":
				group.Authorities[name] = true
			case nodeType == "control":
				group.Controls[name] = true
			}
		}
	}
	inventory.Surfaces = len(sourceRefs)
	inventory.Runtimes = len(runtimes)
	inventory.TrustInputs = len(trustInputs)
	inventory.Tools = len(tools)
	inventory.Authorities = len(authorities)
	inventory.Controls = len(controls)
	inventory.Boundaries = len(boundaries)
	inventory.SurfaceCategories = assessCountsFromMap(categoryCounts)
	inventory.SurfaceMap = assessScanSurfaceMaps(groups)
	inventory.FactHighlights = assessScanFactHighlights(r, 5)
	return inventory
}

func assessFactHighlights(facts []model.Fact, limit int) []model.AssessFact {
	if limit <= 0 || limit > len(facts) {
		limit = len(facts)
	}
	out := make([]model.AssessFact, 0, limit)
	for _, fact := range facts[:limit] {
		out = append(out, model.AssessFact{
			ID:            fact.ID,
			Type:          fact.Type,
			Runtime:       fact.Runtime,
			Scope:         fact.Scope,
			Source:        fact.Source,
			EvidenceGrade: fact.EvidenceGrade,
			Redaction:     fact.Redaction,
			Summary:       fact.Summary,
			Limitations:   nonNilStrings(fact.Limitations),
		})
	}
	if out == nil {
		return []model.AssessFact{}
	}
	return out
}

func assessScanFactHighlights(r model.ScanReport, perTargetLimit int) []model.AssessFact {
	if perTargetLimit <= 0 {
		perTargetLimit = 5
	}
	var groups [][]model.AssessFact
	maxGroup := 0
	for _, target := range r.Targets {
		if target.Error != "" {
			continue
		}
		targetID := assessScanTargetID(target)
		group := assessScanTargetFactHighlights(targetID, target.Report.Evidence, perTargetLimit)
		if len(group) == 0 {
			continue
		}
		if len(group) > maxGroup {
			maxGroup = len(group)
		}
		groups = append(groups, group)
	}
	out := make([]model.AssessFact, 0, len(groups)*perTargetLimit)
	for i := 0; i < maxGroup; i++ {
		for _, group := range groups {
			if i < len(group) {
				out = append(out, group[i])
			}
		}
	}
	if out == nil {
		return []model.AssessFact{}
	}
	return out
}

func assessScanTargetFactHighlights(targetID string, evidence []model.Evidence, limit int) []model.AssessFact {
	out := make([]model.AssessFact, 0, limit)
	seenControlSources := map[string]bool{}
	seenKeys := map[string]bool{}
	for _, item := range evidence {
		kind := strings.TrimSpace(item.Kind)
		source := strings.TrimSpace(item.Source)
		summary := strings.TrimSpace(item.Summary)
		if kind == "" && source == "" && summary == "" {
			continue
		}
		if kind == "control" && source != "" {
			if seenControlSources[source] {
				continue
			}
			seenControlSources[source] = true
		}
		key := kind + "\x00" + source + "\x00" + summary
		if seenKeys[key] {
			continue
		}
		seenKeys[key] = true
		out = append(out, model.AssessFact{
			ID:            item.ID,
			Type:          firstNonEmpty(kind, "evidence"),
			Runtime:       item.Runtime,
			Scope:         "fleet",
			Target:        targetID,
			Source:        source,
			EvidenceGrade: firstNonEmpty(item.Grade, "observed"),
			Redaction:     "summary-only",
			Summary:       summary,
			Limitations: []string{
				"Derived from scan report evidence; raw collector redaction status is not retained in fleet assessment.",
			},
		})
		if len(out) >= limit {
			break
		}
	}
	if out == nil {
		return []model.AssessFact{}
	}
	return out
}

func assessScanSurfaceGroupFor(groups map[string]*assessScanSurfaceGroup, runtime string, scope string) *assessScanSurfaceGroup {
	runtime = firstNonEmpty(strings.TrimSpace(runtime), "generic")
	scope = firstNonEmpty(strings.TrimSpace(scope), "fleet")
	key := runtime + "\x00" + scope
	group, ok := groups[key]
	if ok {
		return group
	}
	group = &assessScanSurfaceGroup{
		Runtime:      runtime,
		Scope:        scope,
		SourceRefs:   map[string]bool{},
		Categories:   map[string]int{},
		Authorities:  map[string]bool{},
		Tools:        map[string]bool{},
		Controls:     map[string]bool{},
		BoundaryRefs: map[string]bool{},
	}
	groups[key] = group
	return group
}

func assessScanSurfaceMaps(groups map[string]*assessScanSurfaceGroup) []model.SurfaceMap {
	items := make([]model.SurfaceMap, 0, len(groups))
	for _, group := range groups {
		if len(group.SourceRefs) == 0 && len(group.Authorities) == 0 && len(group.Tools) == 0 && len(group.Controls) == 0 {
			continue
		}
		items = append(items, model.SurfaceMap{
			Runtime:            group.Runtime,
			Scope:              group.Scope,
			SurfaceCount:       len(group.SourceRefs),
			BoundaryIndicators: len(group.BoundaryRefs),
			SourceRefs:         mapKeysSorted(group.SourceRefs),
			Categories:         assessCountsFromMap(group.Categories),
			Authorities:        mapKeysSorted(group.Authorities),
			Tools:              mapKeysSorted(group.Tools),
			Controls:           mapKeysSorted(group.Controls),
			Limitations: []string{
				"Aggregated from scan report graph and evidence references.",
			},
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].SurfaceCount == items[j].SurfaceCount {
			if items[i].Runtime == items[j].Runtime {
				return items[i].Scope < items[j].Scope
			}
			return items[i].Runtime < items[j].Runtime
		}
		return items[i].SurfaceCount > items[j].SurfaceCount
	})
	if items == nil {
		return []model.SurfaceMap{}
	}
	return items
}

func assessCountsFromMap(counts map[string]int) []model.AssessCount {
	normalized := map[string]int{}
	for key, count := range counts {
		key = strings.TrimSpace(key)
		if key != "" && count > 0 {
			normalized[key] += count
		}
	}
	keys := make([]string, 0, len(normalized))
	for key := range normalized {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]model.AssessCount, 0, len(keys))
	for _, key := range keys {
		out = append(out, model.AssessCount{Name: key, Count: normalized[key]})
	}
	if out == nil {
		return []model.AssessCount{}
	}
	return out
}

func assessScanTargetID(target model.ScanTargetResult) string {
	return firstNonEmpty(target.Target.ID, target.Target.Path, "target")
}

func assessScanSourceRef(targetID string, source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	return firstNonEmpty(strings.TrimSpace(targetID), "target") + ":" + source
}

func assessScanRuntime(runtime string, source string) string {
	if strings.TrimSpace(runtime) != "" {
		return strings.TrimSpace(runtime)
	}
	source = strings.ToLower(strings.TrimSpace(source))
	switch {
	case strings.Contains(source, ".claude/") || strings.HasPrefix(source, ".claude/"):
		return "claude"
	case strings.Contains(source, ".codex/") || strings.HasPrefix(source, ".codex/"):
		return "codex"
	case strings.Contains(source, ".cursor/"),
		strings.HasPrefix(source, ".cursor/"),
		source == ".cursorrules",
		strings.HasSuffix(source, "/.cursorrules"):
		return "cursor"
	case strings.Contains(source, ".windsurf/"),
		strings.HasPrefix(source, ".windsurf/"),
		source == ".windsurfrules",
		strings.HasSuffix(source, "/.windsurfrules"):
		return "windsurf"
	case strings.Contains(source, ".continue/") || strings.HasPrefix(source, ".continue/"):
		return "continue"
	case strings.Contains(source, ".aider") || strings.HasPrefix(source, ".aider"):
		return "aider"
	case strings.Contains(source, ".gemini/") || strings.HasPrefix(source, ".gemini/"):
		return "gemini"
	case strings.Contains(source, "opencode") || strings.Contains(source, ".opencode/"):
		return "opencode"
	case source == "mcp.json",
		source == ".mcp.json",
		strings.HasSuffix(source, "/mcp.json"),
		strings.HasSuffix(source, "/.mcp.json"),
		strings.Contains(source, "mcp-policy"):
		return "mcp"
	default:
		return "generic"
	}
}

func assessScanNodeName(node model.Node) string {
	value := firstNonEmpty(node.Label, node.ID, node.Type)
	if idx := strings.Index(value, ":"); idx >= 0 && idx+1 < len(value) {
		value = value[idx+1:]
	}
	return value
}

func buildAssessExposure(exposures []model.ExposureResult) model.AssessExposure {
	out := model.AssessExposure{Paths: len(exposures)}
	for _, exposure := range exposures {
		switch exposure.Status {
		case model.StatusExposed:
			out.Exposed++
		case model.StatusProtected:
			out.Protected++
		case model.StatusInconclusive:
			out.Inconclusive++
		}
	}
	out.TopPaths = append([]model.ExposureResult{}, exposures...)
	if len(out.TopPaths) > 5 {
		out.TopPaths = out.TopPaths[:5]
	}
	if out.TopPaths == nil {
		out.TopPaths = []model.ExposureResult{}
	}
	return out
}

type assessClosureTarget struct {
	TargetID string
	Flaws    []model.ZeroTrustArchitecture
}

func buildAssessClosureEvidence(exposures []model.ExposureResult, targets []assessClosureTarget) model.AssessClosureEvidence {
	out := model.AssessClosureEvidence{}
	for _, exposure := range exposures {
		if exposure.Status == model.StatusProtected {
			out.ProtectedExposurePaths++
		}
	}
	for _, target := range targets {
		for _, flaw := range target.Flaws {
			path := assessClosurePath(target.TargetID, flaw)
			switch {
			case flaw.Status == model.ZeroTrustControlled || flaw.ControlTest.Result == "hard_barrier_observed":
				out.ControlledArchitectureFlaws++
				out.ControlledPaths = append(out.ControlledPaths, path)
				out.HardBarriersObserved = append(out.HardBarriersObserved, flaw.ControlTest.HardBarriersObserved...)
			case flaw.ControlTest.Result == "partial_or_friction_only":
				out.PartialArchitectureFlaws++
				out.PartialPaths = append(out.PartialPaths, path)
				out.PartialOrFrictionControls = append(out.PartialOrFrictionControls, flaw.ControlTest.PartialOrFrictionControls...)
				out.RemainingMissingHardBarriers = append(out.RemainingMissingHardBarriers, flaw.ControlTest.MissingHardBarriers...)
			}
		}
	}
	out.HardBarriersObserved = uniqueSortedStrings(out.HardBarriersObserved)
	out.PartialOrFrictionControls = uniqueSortedStrings(out.PartialOrFrictionControls)
	out.RemainingMissingHardBarriers = uniqueSortedStrings(out.RemainingMissingHardBarriers)
	if out.ControlledPaths == nil {
		out.ControlledPaths = []model.AssessClosurePath{}
	}
	if out.PartialPaths == nil {
		out.PartialPaths = []model.AssessClosurePath{}
	}
	return out
}

func assessClosurePath(targetID string, flaw model.ZeroTrustArchitecture) model.AssessClosurePath {
	return model.AssessClosurePath{
		Target:                       targetID,
		ID:                           flaw.ID,
		Title:                        flaw.Title,
		Status:                       flaw.Status,
		ControlTestResult:            flaw.ControlTest.Result,
		Controls:                     nonNilStrings(flaw.Controls),
		HardBarriersObserved:         nonNilStrings(flaw.ControlTest.HardBarriersObserved),
		PartialOrFrictionControls:    nonNilStrings(flaw.ControlTest.PartialOrFrictionControls),
		RemainingMissingHardBarriers: nonNilStrings(flaw.ControlTest.MissingHardBarriers),
		GraphEdges:                   nonNilStrings(flaw.GraphEdges),
		EvidenceReferences:           assessEvidenceReferences(targetID, flaw.Evidence),
	}
}

func assessEvidenceReferences(targetID string, evidence []model.ZeroTrustEvidence) []model.EvidenceReference {
	refs := make([]model.EvidenceReference, 0, len(evidence))
	for _, item := range evidence {
		refs = append(refs, model.EvidenceReference{
			Target:  targetID,
			ID:      item.ID,
			Kind:    item.Kind,
			Source:  item.Source,
			Summary: item.Summary,
		})
	}
	return dedupeEvidenceReferences(refs)
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string{}, values...)
}

func buildAssessSummary(inventory model.AssessInventory, exposure model.AssessExposure, architecture model.ZeroTrustSummary, controls model.ControlCatalogSummary, cases []model.ControlOperatorCase) model.AssessSummary {
	summary := model.AssessSummary{
		Targets:                      1,
		CompletedTargets:             1,
		Surfaces:                     inventory.Surfaces,
		Facts:                        inventory.Facts,
		GraphNodes:                   inventory.GraphNodes,
		GraphEdges:                   inventory.GraphEdges,
		ExposurePaths:                exposure.Paths,
		Exposed:                      exposure.Exposed,
		Protected:                    exposure.Protected,
		Inconclusive:                 exposure.Inconclusive,
		ArchitectureFlaws:            architecture.Total,
		BreakingArchitectureFlaws:    architecture.Breaking,
		ControlledArchitectureFlaws:  architecture.Controlled,
		UnknownArchitectureFlaws:     architecture.Unknown,
		NotObservedArchitectureFlaws: architecture.NotObserved,
		OperatorCases:                len(cases),
		MissingHardBarrierControls:   controls.Controls,
		CriticalMissingHardBarriers:  controls.Critical,
		HighMissingHardBarriers:      controls.High,
		MediumMissingHardBarriers:    controls.Medium,
		LowMissingHardBarriers:       controls.Low,
	}
	if len(cases) > 0 {
		summary.TopCaseID = cases[0].ID
		summary.TopCaseTitle = cases[0].Title
		summary.TopCaseNextStep = cases[0].NextStep
	}
	return summary
}

func buildAssessTriage(summary model.AssessSummary, inventory model.AssessInventory, exposure model.AssessExposure, closure model.AssessClosureEvidence, action model.AssessFirstAction, flaws []model.ZeroTrustArchitecture) model.AssessTriage {
	closedAction := assessFirstActionClosed(action)
	triage := model.AssessTriage{
		Status:                    assessTriageStatus(summary, exposure, action),
		HardRiskSignals:           []string{},
		NormalCapabilities:        []string{},
		MissingHardBarriers:       []string{},
		PartialOrFrictionControls: []string{},
		PresentHardBarriers:       []string{},
		UnknownEvidence:           []string{},
		SignalDetails:             []model.AssessSignal{},
		EvidenceReferences:        []model.EvidenceReference{},
		ProofLoop:                 []string{},
	}
	if action.Available {
		triage.StartHere = action.CaseID
		if closedAction {
			triage.Headline = fmt.Sprintf("%s is closed because Ariadne observed hard-barrier evidence.", firstNonEmpty(action.Title, action.CaseID))
		} else {
			triage.Headline = fmt.Sprintf("Start with %s because Ariadne ranked it as the first open operator case.", firstNonEmpty(action.Title, action.CaseID))
		}
		triage.NextAction = action.NextStep
		triage.EvidenceReferences = dedupeEvidenceReferences(action.EvidenceReferences)
		if closedAction {
			triage.PresentHardBarriers = append(triage.PresentHardBarriers, action.StartingControls...)
		} else {
			if action.WhyFirst != "" {
				triage.HardRiskSignals = append(triage.HardRiskSignals, action.WhyFirst)
			}
			if len(action.EvidenceReferences) > 0 {
				triage.HardRiskSignals = append(triage.HardRiskSignals, fmt.Sprintf("%d evidence reference(s) support the top case.", len(dedupeEvidenceReferences(action.EvidenceReferences))))
			}
			triage.MissingHardBarriers = append(triage.MissingHardBarriers, action.StartingControls...)
		}
		triage.ProofLoop = assessTriageProofLoop(action)
	} else {
		triage.Headline = "No open operator case matched this filter."
		triage.NextAction = "Review controlled, unknown, or not-observed results if the question is evidence coverage rather than active break paths."
	}
	if !closedAction && summary.BreakingArchitectureFlaws > 0 {
		triage.HardRiskSignals = append(triage.HardRiskSignals, fmt.Sprintf("%d breaking architecture flaw(s) remain after deterministic graph correlation.", summary.BreakingArchitectureFlaws))
	}
	if !closedAction && exposure.Exposed > 0 {
		triage.HardRiskSignals = append(triage.HardRiskSignals, fmt.Sprintf("%d exposed path(s) reach a sensitive boundary without a breaking control.", exposure.Exposed))
	}
	if !closedAction && summary.MissingHardBarrierControls > 0 {
		triage.HardRiskSignals = append(triage.HardRiskSignals, fmt.Sprintf("%d missing hard-barrier control(s) are keeping cases open.", summary.MissingHardBarrierControls))
	}
	triage.NormalCapabilities = assessNormalCapabilityLines(inventory)
	if !closedAction {
		triage.MissingHardBarriers = append(triage.MissingHardBarriers, closure.RemainingMissingHardBarriers...)
	}
	triage.MissingHardBarriers = uniqueStrings(triage.MissingHardBarriers)
	triage.PartialOrFrictionControls = uniqueStrings(closure.PartialOrFrictionControls)
	triage.PresentHardBarriers = uniqueStrings(append(triage.PresentHardBarriers, closure.HardBarriersObserved...))
	if !closedAction && summary.UnknownArchitectureFlaws > 0 {
		triage.UnknownEvidence = append(triage.UnknownEvidence, fmt.Sprintf("%d architecture flaw(s) need more deterministic evidence before Ariadne can classify them.", summary.UnknownArchitectureFlaws))
	}
	if !closedAction && exposure.Inconclusive > 0 {
		triage.UnknownEvidence = append(triage.UnknownEvidence, fmt.Sprintf("%d exposure path(s) are inconclusive because authority, boundary, or control evidence is incomplete.", exposure.Inconclusive))
	}
	if !closedAction && summary.NotObservedArchitectureFlaws > 0 {
		triage.UnknownEvidence = append(triage.UnknownEvidence, fmt.Sprintf("%d architecture area(s) were not observed in collected surfaces.", summary.NotObservedArchitectureFlaws))
	}
	triage.HardRiskSignals = uniqueStrings(triage.HardRiskSignals)
	triage.UnknownEvidence = uniqueStrings(triage.UnknownEvidence)
	if triage.Headline == "" {
		triage.Headline = assessTriageHeadline(triage.Status)
	}
	if triage.NextAction == "" {
		triage.NextAction = assessTriageNextAction(triage.Status)
	}
	triage.SignalDetails = buildAssessSignalDetails(summary, inventory, exposure, closure, action, triage, flaws)
	return triage
}

func buildAssessSignalDetails(summary model.AssessSummary, inventory model.AssessInventory, exposure model.AssessExposure, closure model.AssessClosureEvidence, action model.AssessFirstAction, triage model.AssessTriage, flaws []model.ZeroTrustArchitecture) []model.AssessSignal {
	var signals []model.AssessSignal
	actionEvidence := dedupeEvidenceReferences(action.EvidenceReferences)
	actionGraphEdges := assessGraphEdgesForCase(action, flaws, exposure.TopPaths)
	closedAction := assessFirstActionClosed(action)
	if closedAction && len(actionGraphEdges) == 0 {
		actionGraphEdges = assessClosurePathGraphEdges(closure.ControlledPaths)
	}
	if action.Available {
		category := "risk"
		disposition := "action_required"
		summaryText := fmt.Sprintf("%s (%s) is the highest-ranked open operator case.", firstNonEmpty(action.Title, action.CaseID), action.CaseID)
		whyItMatters := firstNonEmpty(action.WhyFirst, "The ranked case board correlated influence, authority, boundary reachability, and missing hard barriers.")
		if closedAction {
			category = "present_control"
			disposition = "breaks_path"
			summaryText = fmt.Sprintf("%s (%s) is closed with observed hard-barrier evidence.", firstNonEmpty(action.Title, action.CaseID), action.CaseID)
			whyItMatters = firstNonEmpty(action.WhyFirst, "Ariadne observed deterministic control evidence for this focused case, so the case is not part of the missing-hard-barrier queue.")
		}
		signals = append(signals, model.AssessSignal{
			ID:                 "signal:top-operator-case",
			Category:           category,
			Disposition:        disposition,
			Summary:            summaryText,
			WhyItMatters:       whyItMatters,
			GraphEdges:         actionGraphEdges,
			EvidenceReferences: actionEvidence,
			RelatedControls:    uniqueStrings(action.StartingControls),
			Limitations:        []string{},
		})
	}
	if !closedAction && summary.BreakingArchitectureFlaws > 0 {
		signals = append(signals, model.AssessSignal{
			ID:                 "signal:breaking-architecture-paths",
			Category:           "risk",
			Disposition:        "action_required",
			Summary:            fmt.Sprintf("%d breaking architecture flaw(s) remain after deterministic graph correlation.", summary.BreakingArchitectureFlaws),
			WhyItMatters:       "A breaking architecture path means Ariadne found a supported path that still lacks the hard barrier modeled for that path.",
			GraphEdges:         assessGraphEdgesForStatus(flaws, model.ZeroTrustBreaking),
			EvidenceReferences: actionEvidence,
			RelatedControls:    uniqueStrings(triage.MissingHardBarriers),
			Limitations:        []string{},
		})
	}
	if !closedAction && exposure.Exposed > 0 {
		signals = append(signals, model.AssessSignal{
			ID:                 "signal:exposed-boundary-paths",
			Category:           "risk",
			Disposition:        "action_required",
			Summary:            fmt.Sprintf("%d exposed path(s) reach a sensitive boundary without a breaking control.", exposure.Exposed),
			WhyItMatters:       "Exposure is reported only after influence, runtime authority, boundary reachability, and missing control evidence are connected.",
			GraphEdges:         assessExposureGraphEdges(exposure.TopPaths, model.StatusExposed),
			EvidenceReferences: actionEvidence,
			RelatedControls:    uniqueStrings(triage.MissingHardBarriers),
			Limitations:        []string{},
		})
	}
	if inventory.Runtimes+inventory.Authorities+inventory.Tools+inventory.TrustInputs > 0 {
		signals = append(signals, model.AssessSignal{
			ID:          "signal:normal-agent-capability",
			Category:    "normal_capability",
			Disposition: "expected_capability",
			Summary: fmt.Sprintf("Observed %d runtime, %d authority, %d tool, and %d trust-input surface(s).",
				inventory.Runtimes, inventory.Authorities, inventory.Tools, inventory.TrustInputs),
			WhyItMatters: "These are expected for useful agents; Ariadne treats them as risk only when graph correlation shows untrusted influence can reach sensitive boundaries without hard barriers.",
			Limitations:  []string{"Normal capability counts come from inventory summaries; inspect inventory JSON for the full surface map."},
		})
	}
	if !closedAction && len(triage.MissingHardBarriers) > 0 {
		missingSummary := fmt.Sprintf("%d starting hard-barrier control(s) are missing or unproven for the top case.", len(triage.MissingHardBarriers))
		if summary.MissingHardBarrierControls > len(triage.MissingHardBarriers) {
			missingSummary = fmt.Sprintf("%s %d missing hard-barrier control instance(s) remain across all open cases.", missingSummary, summary.MissingHardBarrierControls)
		}
		signals = append(signals, model.AssessSignal{
			ID:                 "signal:missing-hard-barriers",
			Category:           "missing_control",
			Disposition:        "missing_hard_barrier",
			Summary:            missingSummary,
			WhyItMatters:       "Ariadne prioritizes controls that break the modeled path, not soft guidance or friction-only mitigations.",
			GraphEdges:         actionGraphEdges,
			EvidenceReferences: actionEvidence,
			RelatedControls:    uniqueStrings(triage.MissingHardBarriers),
			Limitations:        []string{},
		})
	}
	if len(closure.HardBarriersObserved) > 0 {
		signals = append(signals, model.AssessSignal{
			ID:                 "signal:present-hard-barriers",
			Category:           "present_control",
			Disposition:        "breaks_path",
			Summary:            fmt.Sprintf("%d hard-barrier control(s) were observed closing supported paths.", len(closure.HardBarriersObserved)),
			WhyItMatters:       "Observed hard barriers explain why some paths are protected or controlled instead of open.",
			GraphEdges:         assessClosurePathGraphEdges(closure.ControlledPaths),
			EvidenceReferences: assessClosurePathEvidenceReferences(closure.ControlledPaths),
			RelatedControls:    uniqueStrings(closure.HardBarriersObserved),
			Limitations:        []string{},
		})
	}
	if len(closure.PartialOrFrictionControls) > 0 {
		signals = append(signals, model.AssessSignal{
			ID:                 "signal:partial-friction-controls",
			Category:           "partial_control",
			Disposition:        "does_not_break_path",
			Summary:            fmt.Sprintf("%d partial or friction-only control(s) were observed.", len(closure.PartialOrFrictionControls)),
			WhyItMatters:       "Partial controls may reduce misuse but do not by themselves close the modeled exposure path.",
			GraphEdges:         assessClosurePathGraphEdges(closure.PartialPaths),
			EvidenceReferences: assessClosurePathEvidenceReferences(closure.PartialPaths),
			RelatedControls:    uniqueStrings(closure.PartialOrFrictionControls),
			Limitations:        []string{},
		})
	}
	if len(triage.UnknownEvidence) > 0 {
		signals = append(signals, model.AssessSignal{
			ID:           "signal:unknown-evidence-gaps",
			Category:     "evidence_gap",
			Disposition:  "needs_evidence",
			Summary:      fmt.Sprintf("%d evidence gap(s) remain before Ariadne can classify every path.", len(triage.UnknownEvidence)),
			WhyItMatters: "Unknown evidence should not be treated as either safe or exposed until the deterministic collector observes enough authority, boundary, or control facts.",
			Limitations:  uniqueStrings(triage.UnknownEvidence),
		})
	}
	return nonNilAssessSignals(signals)
}

func assessClosurePathEvidenceReferences(paths []model.AssessClosurePath) []model.EvidenceReference {
	var refs []model.EvidenceReference
	for _, path := range paths {
		refs = append(refs, path.EvidenceReferences...)
	}
	return dedupeEvidenceReferences(refs)
}

func assessClosurePathGraphEdges(paths []model.AssessClosurePath) []string {
	var out []string
	for _, path := range paths {
		out = append(out, path.GraphEdges...)
	}
	return uniqueStrings(out)
}

func assessScanArchitectureFlaws(architecture model.ArchitectureScanReport) []model.ZeroTrustArchitecture {
	var out []model.ZeroTrustArchitecture
	for _, target := range architecture.Targets {
		out = append(out, target.Flaws...)
	}
	if out == nil {
		return []model.ZeroTrustArchitecture{}
	}
	return out
}

func assessGraphEdgesForCase(action model.AssessFirstAction, flaws []model.ZeroTrustArchitecture, exposures []model.ExposureResult) []string {
	var out []string
	caseFlaws := map[string]bool{}
	for _, flaw := range action.Flaws {
		caseFlaws[flaw] = true
	}
	for _, flaw := range flaws {
		if len(caseFlaws) > 0 && !caseFlaws[flaw.ID] && !caseFlaws[flaw.Title] {
			continue
		}
		out = append(out, flaw.GraphEdges...)
	}
	if len(out) == 0 {
		out = append(out, assessExposureGraphEdges(exposures, model.StatusExposed)...)
	}
	return uniqueStrings(out)
}

func assessGraphEdgesForStatus(flaws []model.ZeroTrustArchitecture, status model.ZeroTrustStatus) []string {
	var out []string
	for _, flaw := range flaws {
		if flaw.Status == status {
			out = append(out, flaw.GraphEdges...)
		}
	}
	return uniqueStrings(out)
}

func assessExposureGraphEdges(exposures []model.ExposureResult, status model.Status) []string {
	var out []string
	for _, exposure := range exposures {
		if exposure.Status == status {
			out = append(out, exposure.PathEdges...)
		}
	}
	return uniqueStrings(out)
}

func nonNilAssessSignals(items []model.AssessSignal) []model.AssessSignal {
	if items == nil {
		return []model.AssessSignal{}
	}
	for idx := range items {
		items[idx].GraphEdges = uniqueStrings(items[idx].GraphEdges)
		items[idx].EvidenceReferences = dedupeEvidenceReferences(items[idx].EvidenceReferences)
		items[idx].RelatedControls = uniqueStrings(items[idx].RelatedControls)
		items[idx].Limitations = uniqueStrings(items[idx].Limitations)
		if items[idx].GraphEdges == nil {
			items[idx].GraphEdges = []string{}
		}
		if items[idx].EvidenceReferences == nil {
			items[idx].EvidenceReferences = []model.EvidenceReference{}
		}
		if items[idx].RelatedControls == nil {
			items[idx].RelatedControls = []string{}
		}
		if items[idx].Limitations == nil {
			items[idx].Limitations = []string{}
		}
	}
	return items
}

func assessTriageStatus(summary model.AssessSummary, exposure model.AssessExposure, action model.AssessFirstAction) string {
	if assessFirstActionClosed(action) {
		return "controlled"
	}
	if action.Available || summary.MissingHardBarrierControls > 0 || summary.BreakingArchitectureFlaws > 0 || exposure.Exposed > 0 {
		return "action_required"
	}
	if summary.UnknownArchitectureFlaws > 0 || exposure.Inconclusive > 0 {
		return "needs_evidence"
	}
	if summary.ControlledArchitectureFlaws > 0 || exposure.Protected > 0 {
		return "controlled"
	}
	return "no_supported_signal"
}

func assessFirstActionClosed(action model.AssessFirstAction) bool {
	if !action.Available {
		return false
	}
	state := strings.ToLower(strings.TrimSpace(action.State))
	return state == "closed" || state == "controlled" || state == "no_missing_hard_barrier"
}

func assessTriageHeadline(status string) string {
	switch status {
	case "action_required":
		return "Ariadne found graph-backed signal that needs an operator action."
	case "needs_evidence":
		return "Ariadne needs more deterministic evidence before prioritizing a closure case."
	case "controlled":
		return "Ariadne observed controls that close the supported paths for this filter."
	default:
		return "Ariadne did not find a supported exposure or architecture break path for this filter."
	}
}

func assessTriageNextAction(status string) string {
	switch status {
	case "action_required":
		return "Inspect the top case evidence, add or verify the suggested proof evidence, then rerun and compare."
	case "needs_evidence":
		return "Collect the missing deterministic evidence before treating this as either exposed or protected."
	case "controlled":
		return "Save the controlled evidence and rerun after material config changes."
	default:
		return "Run inventory or broaden the target if you expected AI-agent surfaces."
	}
}

func assessNormalCapabilityLines(inventory model.AssessInventory) []string {
	var lines []string
	if inventory.Runtimes > 0 {
		lines = append(lines, fmt.Sprintf("%d agent runtime surface(s) were observed; runtime presence is expected and is not a finding by itself.", inventory.Runtimes))
	}
	if inventory.Authorities > 0 {
		lines = append(lines, fmt.Sprintf("%d authority surface(s) were observed; authority is normal for useful agents but becomes risk when untrusted influence can reach sensitive boundaries without hard barriers.", inventory.Authorities))
	}
	if inventory.Tools > 0 {
		lines = append(lines, fmt.Sprintf("%d tool surface(s) were observed; tools are normal capability unless scope, integrity, approval, or egress controls are missing.", inventory.Tools))
	}
	if inventory.TrustInputs > 0 {
		lines = append(lines, fmt.Sprintf("%d trust input surface(s) were observed; instructions are expected inputs unless they can steer privileged runtime authority.", inventory.TrustInputs))
	}
	if len(lines) == 0 {
		lines = append(lines, "No standalone normal-capability counts are available in this view; triage is based on case-board and closure evidence.")
	}
	return lines
}

func assessTriageProofLoop(action model.AssessFirstAction) []string {
	var out []string
	if command := assessProofActionCommand(action); command != "" {
		out = append(out, "Open focused proof action: "+command)
	}
	if action.CurrentAction.PatchExportCommand != "" {
		out = append(out, "Export suggested proof files: "+action.CurrentAction.PatchExportCommand)
	} else if action.PatchExportCommand != "" {
		out = append(out, "Export suggested proof files: "+action.PatchExportCommand)
	}
	if rerun := assessCurrentRerunCommand(action); rerun != "" {
		out = append(out, "Rerun after evidence changes: "+rerun)
	}
	for _, command := range limitStrings(action.CompareCommands, 3) {
		out = append(out, "Compare proof state: "+command)
	}
	if out == nil {
		return []string{}
	}
	return out
}

func assessProofActionCommand(action model.AssessFirstAction) string {
	if action.CurrentAction.PatchExportCommand != "" {
		return proofActionCommandFromPatchExport(action.CurrentAction.PatchExportCommand)
	}
	if action.PatchExportCommand != "" {
		return proofActionCommandFromPatchExport(action.PatchExportCommand)
	}
	return ""
}

func proofActionCommandFromPatchExport(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	if strings.Contains(command, " --format action") {
		return command
	}
	if idx := strings.Index(command, " --patch-dir "); idx >= 0 {
		return strings.TrimSpace(command[:idx]) + " --format action"
	}
	return command + " --format action"
}

func zeroTrustSummaryFromArchitectureScan(summary model.ArchitectureScanSummary) model.ZeroTrustSummary {
	return model.ZeroTrustSummary{
		Total:       summary.MatchingFlaws,
		Breaking:    summary.Breaking,
		Controlled:  summary.Controlled,
		Unknown:     summary.Unknown,
		NotObserved: summary.NotObserved,
	}
}

func assessSurfaceCounts(surfaces []model.Surface, keyFn func(model.Surface) string) []model.AssessCount {
	counts := map[string]int{}
	for _, surface := range surfaces {
		key := strings.TrimSpace(keyFn(surface))
		if key == "" {
			key = "unknown"
		}
		counts[key]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]model.AssessCount, 0, len(keys))
	for _, key := range keys {
		out = append(out, model.AssessCount{Name: key, Count: counts[key]})
	}
	if out == nil {
		return []model.AssessCount{}
	}
	return out
}

func buildTopCaseProofPlan(catalog model.ControlCatalogReport) *model.ProofPlanReport {
	if len(catalog.OperatorCases) == 0 {
		return nil
	}
	focused := catalog
	if err := filterControlCaseBoard(&focused, catalog.OperatorCases[0].ID); err != nil {
		return nil
	}
	plan := BuildProofPlanReport(focused)
	return &plan
}

func buildAssessFirstAction(cases []model.ControlOperatorCase, proofPlan *model.ProofPlanReport) model.AssessFirstAction {
	action := model.AssessFirstAction{
		Available:          false,
		EvidenceReferences: []model.EvidenceReference{},
		StartingControls:   []string{},
		ProofSurfaces:      []string{},
		EvidenceExamples:   []model.ControlEvidenceExample{},
		ProofPatches:       []model.ControlProofPatch{},
		RerunCommands:      []string{},
		CompareCommands:    []string{},
		PatchExportCommand: "",
		SuccessCriteria:    []string{},
		Targets:            []string{},
		Flaws:              []string{},
		Workflow:           []model.AssessWorkflowStep{},
		CurrentAction:      emptyAssessCurrentAction(),
	}
	if len(cases) == 0 {
		return action
	}
	item := cases[0]
	action.Available = true
	action.CaseID = item.ID
	action.Title = item.Title
	action.Severity = item.Severity
	action.State = item.State
	action.WhyFirst = item.PriorityReason
	action.NextStep = item.NextStep
	action.Targets = append([]string{}, item.Targets...)
	action.Flaws = append([]string{}, item.Flaws...)
	action.EvidenceReferences = append([]model.EvidenceReference{}, item.EvidenceReferences...)
	action.StartingControls = append([]string{}, item.StartingControls...)
	action.ProofSurfaces = append([]string{}, item.ProofSurfaces...)
	action.EvidenceExamples = append([]model.ControlEvidenceExample{}, item.EvidenceExamples...)
	action.ProofPatches = append([]model.ControlProofPatch{}, item.ProofPatches...)
	action.RerunCommands = append([]string{}, item.RerunCommands...)
	action.CompareCommands = append([]string{}, item.CompareCommands...)
	action.SuccessCriteria = append([]string{}, item.SuccessCriteria...)
	if proofPlan != nil {
		if len(action.RerunCommands) == 0 {
			action.RerunCommands = append([]string{}, proofPlan.RerunCommands...)
		}
		if len(action.CompareCommands) == 0 {
			action.CompareCommands = append([]string{}, proofPlan.CompareCommands...)
		}
		action.PatchExportCommand = proofPlan.PatchExportCommand
	}
	if action.EvidenceReferences == nil {
		action.EvidenceReferences = []model.EvidenceReference{}
	}
	if action.StartingControls == nil {
		action.StartingControls = []string{}
	}
	if action.ProofSurfaces == nil {
		action.ProofSurfaces = []string{}
	}
	if action.EvidenceExamples == nil {
		action.EvidenceExamples = []model.ControlEvidenceExample{}
	}
	if action.ProofPatches == nil {
		action.ProofPatches = []model.ControlProofPatch{}
	}
	if action.RerunCommands == nil {
		action.RerunCommands = []string{}
	}
	if action.CompareCommands == nil {
		action.CompareCommands = []string{}
	}
	if action.SuccessCriteria == nil {
		action.SuccessCriteria = []string{}
	}
	if action.Targets == nil {
		action.Targets = []string{}
	}
	if action.Flaws == nil {
		action.Flaws = []string{}
	}
	action.Workflow = buildAssessFirstActionWorkflow(action)
	action.CurrentAction = buildAssessCurrentAction(action)
	return action
}

func buildAssessClosurePlan(cases []model.ControlOperatorCase, limit int) []model.AssessClosurePlanItem {
	if limit <= 0 {
		limit = 5
	}
	var out []model.AssessClosurePlanItem
	seen := map[string]bool{}
	for _, item := range cases {
		control := firstString(item.StartingControls)
		if control == "" && len(item.ProofPatches) > 0 {
			control = item.ProofPatches[0].Control
		}
		if control == "" {
			continue
		}
		key := item.ID + "\x00" + control
		if seen[key] {
			continue
		}
		seen[key] = true
		patch := assessClosurePlanProofPatch(control, item.ProofPatches)
		proofSurface := assessClosurePlanProofSurface(item, patch)
		planItem := model.AssessClosurePlanItem{
			Rank:               len(out) + 1,
			Control:            control,
			CaseID:             item.ID,
			CaseTitle:          item.Title,
			Severity:           item.Severity,
			State:              item.State,
			WhyThisControl:     assessClosurePlanWhy(item, control),
			WhatItCloses:       assessClosurePlanCloses(item),
			AffectedFlaws:      item.FlawCount,
			AffectedTargets:    item.TargetCount,
			EvidenceReferences: dedupeEvidenceReferences(item.EvidenceReferences),
			ProofSurface:       proofSurface,
			ProofPatch:         patch,
			RerunCommand:       firstString(item.RerunCommands),
			CompareCommand:     assessClosurePlanCompareCommand(item.CompareCommands),
			DoneCriteria:       nonNilStrings(item.SuccessCriteria),
			Limitations:        nonNilStrings(item.Limitations),
		}
		if len(planItem.DoneCriteria) == 0 {
			planItem.DoneCriteria = []string{"The case no longer appears as open for the selected status filter after rerun.", "The selected control is no longer returned as a missing hard barrier."}
		}
		out = append(out, planItem)
		if len(out) >= limit {
			break
		}
	}
	if out == nil {
		return []model.AssessClosurePlanItem{}
	}
	return out
}

func assessClosurePlanProofPatch(control string, patches []model.ControlProofPatch) *model.ControlProofPatch {
	if len(patches) == 0 {
		return nil
	}
	for _, patch := range patches {
		if patch.Control == control {
			item := patch
			return &item
		}
	}
	item := patches[0]
	return &item
}

func assessClosurePlanProofSurface(item model.ControlOperatorCase, patch *model.ControlProofPatch) string {
	if patch != nil && patch.Surface != "" {
		return patch.Surface
	}
	if controlOperatorCaseIsClosed(item) {
		if source := firstControlEvidenceReferenceSource(item.EvidenceReferences); source != "" {
			return source
		}
	}
	return firstString(item.ProofSurfaces)
}

func firstControlEvidenceReferenceSource(refs []model.EvidenceReference) string {
	if source := firstString(evidenceReferenceSources(refs, true)); source != "" {
		return source
	}
	return firstString(evidenceReferenceSources(refs, false))
}

func assessActionEvidenceSurfaces(action model.AssessFirstAction) []string {
	surfaces := evidenceReferenceSources(action.EvidenceReferences, true)
	if len(surfaces) == 0 {
		surfaces = evidenceReferenceSources(action.EvidenceReferences, false)
	}
	if len(surfaces) == 0 {
		surfaces = append(surfaces, action.ProofSurfaces...)
	}
	return uniqueStrings(surfaces)
}

func evidenceReferenceSources(refs []model.EvidenceReference, controlsOnly bool) []string {
	var out []string
	for _, ref := range refs {
		source := strings.TrimSpace(ref.Source)
		if source == "" {
			continue
		}
		if controlsOnly && !strings.EqualFold(strings.TrimSpace(ref.Kind), "control") {
			continue
		}
		out = append(out, source)
	}
	return uniqueStrings(out)
}

func evidenceReferenceSourcesForControl(refs []model.EvidenceReference, control string) []string {
	control = strings.TrimSpace(control)
	var out []string
	for _, ref := range refs {
		source := strings.TrimSpace(ref.Source)
		if source == "" || control == "" {
			continue
		}
		if ref.ID == control || strings.Contains(ref.ID, control) || strings.Contains(ref.Summary, strings.TrimPrefix(control, "control:")) {
			out = append(out, source)
		}
	}
	return uniqueStrings(out)
}

func assessClosurePlanCompareCommand(commands []string) string {
	if len(commands) == 0 {
		return ""
	}
	return commands[len(commands)-1]
}

func assessClosurePlanWhy(item model.ControlOperatorCase, control string) string {
	if controlOperatorCaseIsClosed(item) {
		return fmt.Sprintf("%s is already closed for this focused view. Keep %s evidence in place and rerun if the repo, runtime, or policy evidence changes.", firstNonEmpty(item.Title, item.ID), control)
	}
	reason := item.PriorityReason
	if reason == "" {
		reason = fmt.Sprintf("%s is the highest ranked available case for this closure row.", firstNonEmpty(item.Title, item.ID))
	}
	return fmt.Sprintf("%s Start with %s because it is the first parser-recognized hard-barrier proof task for this case.", reason, control)
}

func assessClosurePlanCloses(item model.ControlOperatorCase) string {
	title := firstNonEmpty(item.Title, item.ID)
	if controlOperatorCaseIsClosed(item) {
		return fmt.Sprintf("%s has observed hard-barrier evidence across %d affected architecture flaw(s) and %d target(s); no proof patch is needed while that evidence remains present.", title, item.FlawCount, item.TargetCount)
	}
	return fmt.Sprintf("%s covers %d affected architecture flaw(s) across %d target(s); the case is closed only when rerun evidence removes the missing hard barrier.", title, item.FlawCount, item.TargetCount)
}

func emptyAssessCurrentAction() model.AssessCurrentAction {
	return model.AssessCurrentAction{
		Available:            false,
		EvidenceReferences:   []model.EvidenceReference{},
		ProofPatchIndex:      -1,
		EvidenceExampleIndex: -1,
		SuccessCriteria:      []string{},
	}
}

func buildAssessCurrentAction(action model.AssessFirstAction) model.AssessCurrentAction {
	current := emptyAssessCurrentAction()
	if !action.Available {
		return current
	}
	step, ok := currentAssessWorkflowStep(action.Workflow)
	if !ok {
		return current
	}
	current.Available = true
	current.WorkflowStepID = step.ID
	current.WorkflowStepTitle = step.Title
	current.Instruction = firstNonEmpty(action.NextStep, step.Summary)
	current.EvidenceReferences = append([]model.EvidenceReference{}, action.EvidenceReferences...)
	current.SuccessCriteria = append([]string{}, action.SuccessCriteria...)
	if assessFirstActionClosed(action) {
		current.Control = firstString(action.StartingControls)
		current.Surface = firstControlEvidenceReferenceSource(action.EvidenceReferences)
	}
	if len(action.ProofPatches) > 0 {
		patch := action.ProofPatches[0]
		current.ProofPatchIndex = 0
		current.ProofPatch = &patch
		current.Control = patch.Control
		current.Surface = patch.Surface
		if current.Instruction == "" {
			current.Instruction = patch.Summary
		}
	}
	if len(action.EvidenceExamples) > 0 {
		example := action.EvidenceExamples[0]
		current.EvidenceExampleIndex = 0
		current.EvidenceExample = &example
		if current.Surface == "" {
			current.Surface = example.Surface
		}
	}
	if len(action.RerunCommands) > 0 {
		current.RerunCommand = action.RerunCommands[0]
	}
	if len(action.CompareCommands) > 0 {
		current.CompareCommand = action.CompareCommands[len(action.CompareCommands)-1]
	}
	current.PatchExportCommand = action.PatchExportCommand
	return current
}

func buildAssessFirstActionWorkflow(action model.AssessFirstAction) []model.AssessWorkflowStep {
	if !action.Available {
		return []model.AssessWorkflowStep{}
	}
	if assessFirstActionClosed(action) {
		proofSurfaces := assessActionEvidenceSurfaces(action)
		return []model.AssessWorkflowStep{
			{
				ID:                 "inspect_evidence",
				Title:              "Inspect Evidence",
				Summary:            "Review the deterministic hard-barrier evidence that closed this focused case.",
				Current:            true,
				EvidenceReferences: append([]model.EvidenceReference{}, action.EvidenceReferences...),
				StartingControls:   append([]string{}, action.StartingControls...),
				ProofSurfaces:      append([]string{}, proofSurfaces...),
				Commands:           []string{},
				SuccessCriteria:    []string{},
			},
			{
				ID:                 "add_or_verify_proof",
				Title:              "Add Or Verify Proof",
				Summary:            firstNonEmpty(action.NextStep, "No proof patch is needed for this focused case while observed hard-barrier evidence remains present."),
				Current:            false,
				EvidenceReferences: []model.EvidenceReference{},
				StartingControls:   append([]string{}, action.StartingControls...),
				ProofSurfaces:      append([]string{}, proofSurfaces...),
				Commands:           []string{},
				SuccessCriteria:    []string{},
			},
			{
				ID:                 "rerun_case",
				Title:              "Rerun Case",
				Summary:            "Rerun the focused case if evidence changes so Ariadne can confirm it remains closed.",
				Current:            false,
				EvidenceReferences: []model.EvidenceReference{},
				StartingControls:   []string{},
				ProofSurfaces:      []string{},
				Commands:           append([]string{}, action.RerunCommands...),
				SuccessCriteria:    []string{},
			},
			{
				ID:                 "compare_before_after",
				Title:              "Compare Before And After",
				Summary:            "Compare proof artifacts if controls or evidence change to prove the case stayed closed.",
				Current:            false,
				EvidenceReferences: []model.EvidenceReference{},
				StartingControls:   []string{},
				ProofSurfaces:      []string{},
				Commands:           append([]string{}, action.CompareCommands...),
				SuccessCriteria:    append([]string{}, action.SuccessCriteria...),
			},
		}
	}
	return []model.AssessWorkflowStep{
		{
			ID:                 "inspect_evidence",
			Title:              "Inspect Evidence",
			Summary:            "Review the source-backed facts that caused Ariadne to prioritize this case.",
			Current:            false,
			EvidenceReferences: append([]model.EvidenceReference{}, action.EvidenceReferences...),
			StartingControls:   []string{},
			ProofSurfaces:      []string{},
			Commands:           []string{},
			SuccessCriteria:    []string{},
		},
		{
			ID:                 "add_or_verify_proof",
			Title:              "Add Or Verify Proof",
			Summary:            firstNonEmpty(action.NextStep, "Add or verify parser-recognized evidence for the starting controls."),
			Current:            true,
			EvidenceReferences: []model.EvidenceReference{},
			StartingControls:   append([]string{}, action.StartingControls...),
			ProofSurfaces:      append([]string{}, action.ProofSurfaces...),
			Commands:           []string{},
			SuccessCriteria:    []string{},
		},
		{
			ID:                 "rerun_case",
			Title:              "Rerun Case",
			Summary:            "Rerun the focused case after evidence changes so Ariadne can recompute facts and graph paths.",
			Current:            false,
			EvidenceReferences: []model.EvidenceReference{},
			StartingControls:   []string{},
			ProofSurfaces:      []string{},
			Commands:           append([]string{}, action.RerunCommands...),
			SuccessCriteria:    []string{},
		},
		{
			ID:                 "compare_before_after",
			Title:              "Compare Before And After",
			Summary:            "Save before and after proof artifacts, then compare them to prove the case state changed.",
			Current:            false,
			EvidenceReferences: []model.EvidenceReference{},
			StartingControls:   []string{},
			ProofSurfaces:      []string{},
			Commands:           append([]string{}, action.CompareCommands...),
			SuccessCriteria:    append([]string{}, action.SuccessCriteria...),
		},
	}
}

func topControlOperatorCases(cases []model.ControlOperatorCase, limit int) []model.ControlOperatorCase {
	if limit <= 0 || limit > len(cases) {
		limit = len(cases)
	}
	out := append([]model.ControlOperatorCase{}, cases[:limit]...)
	if out == nil {
		return []model.ControlOperatorCase{}
	}
	return out
}

func reportExposures(r model.Report) []model.ExposureResult {
	if len(r.Exposures) > 0 {
		return append([]model.ExposureResult{}, r.Exposures...)
	}
	if r.Exposure.ID != "" {
		return []model.ExposureResult{r.Exposure}
	}
	return []model.ExposureResult{}
}

func assessPathCommands(path, mode, agent, statusFilter string, cases []model.ControlOperatorCase, focus AssessFocus) []string {
	base := assessFocusCommand(fmt.Sprintf("ariadne assess --path %s --mode %s --agent %s --status %s", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(statusFilter)), focus)
	commands := []string{base}
	if len(cases) > 0 {
		commands = append(commands, fmt.Sprintf("ariadne cases --path %s --mode %s --agent %s --status %s --case %s", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(statusFilter), shellQuoteCommandArg(cases[0].ID)))
		commands = append(commands, fmt.Sprintf("ariadne proofs --path %s --mode %s --agent %s --status %s --case %s --format action", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(statusFilter), shellQuoteCommandArg(cases[0].ID)))
	}
	commands = append(commands,
		fmt.Sprintf("ariadne controls --path %s --mode %s --agent %s --status %s", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(statusFilter)),
		fmt.Sprintf("ariadne architecture --path %s --mode %s --agent %s --status all", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent)),
	)
	return commands
}

func assessScanCommands(targetsFile, mode, agent, statusFilter string, cases []model.ControlOperatorCase, focus AssessFocus) []string {
	targetsArg := targetsFileCommandArg(targetsFile)
	base := assessFocusCommand(fmt.Sprintf("ariadne assess --targets %s --mode %s --agent %s --status %s", targetsArg, shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(statusFilter)), focus)
	commands := []string{base}
	if len(cases) > 0 {
		commands = append(commands, fmt.Sprintf("ariadne cases --targets %s --mode %s --agent %s --status %s --case %s", targetsArg, shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(statusFilter), shellQuoteCommandArg(cases[0].ID)))
		commands = append(commands, fmt.Sprintf("ariadne proofs --targets %s --mode %s --agent %s --status %s --case %s --format action", targetsArg, shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(statusFilter), shellQuoteCommandArg(cases[0].ID)))
	}
	commands = append(commands,
		fmt.Sprintf("ariadne controls --targets %s --mode %s --agent %s --status %s", targetsArg, shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(statusFilter)),
		fmt.Sprintf("ariadne architecture --targets %s --mode %s --agent %s --status all", targetsArg, shellQuoteCommandArg(mode), shellQuoteCommandArg(agent)),
	)
	return commands
}

func assessFocusCommand(command string, focus AssessFocus) string {
	if focus.CaseFilter != "" {
		command += " --case " + shellQuoteCommandArg(focus.CaseFilter)
	}
	if focus.ControlFilter != "" {
		command += " --control " + shellQuoteCommandArg(focus.ControlFilter)
	}
	return command
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

func renderAssessTable(w io.Writer, r model.AssessReport) error {
	fmt.Fprintf(w, "Ariadne Assess\n\n")
	if r.RunKind == "assess_scan" {
		fmt.Fprintf(w, "Targets: %d completed, %d errors, %d total\n", r.Summary.CompletedTargets, r.Summary.Errors, r.Summary.Targets)
	} else {
		fmt.Fprintf(w, "Target: %s\n", r.TargetPath)
	}
	fmt.Fprintf(w, "Mode: %s\n", r.Mode)
	fmt.Fprintf(w, "Agent: %s\n", r.Agent)
	fmt.Fprintf(w, "Filter: %s\n", r.StatusFilter)
	renderAssessFocusLine(w, r)
	fmt.Fprintf(w, "Question: Where is Zero Trust agent architecture breaking, and what proof closes the path?\n\n")

	fmt.Fprintf(w, "Readout:\n")
	fmt.Fprintf(w, "  - Architecture: %d matching flaw(s), %d breaking, %d controlled, %d unknown, %d not observed\n",
		r.Summary.ArchitectureFlaws,
		r.Summary.BreakingArchitectureFlaws,
		r.Summary.ControlledArchitectureFlaws,
		r.Summary.UnknownArchitectureFlaws,
		r.Summary.NotObservedArchitectureFlaws,
	)
	fmt.Fprintf(w, "  - Operator cases: %d case(s), %d missing hard-barrier control(s)\n", r.Summary.OperatorCases, r.Summary.MissingHardBarrierControls)
	fmt.Fprintf(w, "  - Exposure paths: %d total, %d exposed, %d protected, %d inconclusive\n", r.Summary.ExposurePaths, r.Summary.Exposed, r.Summary.Protected, r.Summary.Inconclusive)
	if r.Summary.TopCaseID != "" {
		fmt.Fprintf(w, "  - Start here: %s (%s)\n", r.Summary.TopCaseTitle, r.Summary.TopCaseID)
	}
	fmt.Fprintln(w)

	renderAssessTriage(w, r.Triage)
	renderAssessClosurePlan(w, r.ClosurePlan, 5)
	renderAssessFirstAction(w, r.FirstAction)

	renderAssessInventorySummary(w, r.Inventory, 5)

	renderAssessClosureEvidence(w, r.ClosureEvidence)
	renderAssessArchitectureBreaks(w, r)
	renderControlOperatorCases(w, r.CaseBoard.OperatorCases, 5)
	renderAssessTopCaseProofPacket(w, r.TopCaseProofPlan)
	fmt.Fprintln(w)

	if len(r.NextCommands) > 0 {
		fmt.Fprintf(w, "Next commands:\n")
		for _, command := range r.NextCommands {
			fmt.Fprintf(w, "  - %s\n", command)
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

func renderAssessTriage(w io.Writer, triage model.AssessTriage) {
	if triage.Status == "" && triage.Headline == "" {
		return
	}
	fmt.Fprintf(w, "Signal triage:\n")
	if triage.Status != "" {
		fmt.Fprintf(w, "  - Status: %s\n", readableToken(triage.Status))
	}
	if triage.Headline != "" {
		fmt.Fprintf(w, "  - Readout: %s\n", triage.Headline)
	}
	if triage.StartHere != "" {
		fmt.Fprintf(w, "  - Start here: %s\n", triage.StartHere)
	}
	renderAssessSignalDetails(w, triage.SignalDetails, 6)
	renderAssessTriageLines(w, "Hard signal", triage.HardRiskSignals, 6)
	renderAssessTriageLines(w, "Normal capability", triage.NormalCapabilities, 4)
	renderAssessTriageLines(w, "Missing hard barrier", triage.MissingHardBarriers, 6)
	renderAssessTriageLines(w, "Partial/friction control", triage.PartialOrFrictionControls, 6)
	renderAssessTriageLines(w, "Present hard barrier", triage.PresentHardBarriers, 6)
	renderAssessTriageLines(w, "Unknown evidence", triage.UnknownEvidence, 4)
	if len(triage.EvidenceReferences) > 0 {
		fmt.Fprintf(w, "  - Evidence: %s\n", strings.Join(evidenceReferenceLinesBySource(triage.EvidenceReferences, 3), "; "))
	}
	if triage.NextAction != "" {
		fmt.Fprintf(w, "  - Next action: %s\n", triage.NextAction)
	}
	renderAssessTriageLines(w, "Proof loop", triage.ProofLoop, 6)
	fmt.Fprintln(w)
}

func renderAssessSignalDetails(w io.Writer, signals []model.AssessSignal, limit int) {
	if len(signals) == 0 {
		return
	}
	if limit <= 0 || limit > len(signals) {
		limit = len(signals)
	}
	fmt.Fprintf(w, "  - Signal details:\n")
	for _, signal := range signals[:limit] {
		fmt.Fprintf(w, "    - %s [%s/%s]: %s\n", signal.ID, readableToken(signal.Category), readableToken(signal.Disposition), signal.Summary)
		if signal.WhyItMatters != "" {
			fmt.Fprintf(w, "      Why it matters: %s\n", signal.WhyItMatters)
		}
		if len(signal.GraphEdges) > 0 {
			fmt.Fprintf(w, "      Graph: %s\n", strings.Join(limitStrings(signal.GraphEdges, 4), "; "))
		}
		if len(signal.RelatedControls) > 0 {
			fmt.Fprintf(w, "      Controls: %s\n", strings.Join(limitStrings(signal.RelatedControls, 4), ", "))
		}
		if len(signal.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "      Evidence: %s\n", strings.Join(evidenceReferenceLinesBySource(signal.EvidenceReferences, 3), "; "))
		}
		if len(signal.Limitations) > 0 {
			fmt.Fprintf(w, "      Limitations: %s\n", strings.Join(limitStrings(signal.Limitations, 2), "; "))
		}
	}
}

func renderAssessFocusLine(w io.Writer, r model.AssessReport) {
	if r.CaseFilter == "" && r.ControlFilter == "" {
		return
	}
	var parts []string
	if r.CaseFilter != "" {
		parts = append(parts, "case="+r.CaseFilter)
	}
	if r.ControlFilter != "" {
		parts = append(parts, "control="+r.ControlFilter)
	}
	fmt.Fprintf(w, "Focus: %s\n", strings.Join(parts, "; "))
}

func renderAssessTriageLines(w io.Writer, label string, values []string, limit int) {
	if len(values) == 0 {
		return
	}
	for _, value := range limitStrings(values, limit) {
		fmt.Fprintf(w, "  - %s: %s\n", label, value)
	}
}

func renderAssessClosurePlan(w io.Writer, plan []model.AssessClosurePlanItem, limit int) {
	if len(plan) == 0 {
		return
	}
	if limit <= 0 || limit > len(plan) {
		limit = len(plan)
	}
	fmt.Fprintf(w, "Closure plan:\n")
	for _, item := range plan[:limit] {
		fmt.Fprintf(w, "  - #%d %s -> %s (%s)\n", item.Rank, item.Control, firstNonEmpty(item.CaseTitle, item.CaseID), strings.ToUpper(item.Severity))
		if item.WhyThisControl != "" {
			fmt.Fprintf(w, "    Why this control: %s\n", item.WhyThisControl)
		}
		if item.WhatItCloses != "" {
			fmt.Fprintf(w, "    What it closes: %s\n", item.WhatItCloses)
		}
		if len(item.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "    Evidence: %s\n", strings.Join(evidenceReferenceLinesBySource(item.EvidenceReferences, 2), "; "))
		}
		if item.ProofSurface != "" {
			fmt.Fprintf(w, "    Prove at: %s\n", item.ProofSurface)
		}
		if item.ProofPatch != nil && item.ProofPatch.Summary != "" {
			fmt.Fprintf(w, "    Proof patch: %s\n", item.ProofPatch.Summary)
		}
		if item.RerunCommand != "" {
			fmt.Fprintf(w, "    Rerun: %s\n", item.RerunCommand)
		}
		if item.CompareCommand != "" {
			fmt.Fprintf(w, "    Compare: %s\n", item.CompareCommand)
		}
		if len(item.DoneCriteria) > 0 {
			fmt.Fprintf(w, "    Done when: %s\n", strings.Join(limitStrings(item.DoneCriteria, 2), "; "))
		}
	}
	if len(plan) > limit {
		fmt.Fprintf(w, "  - %d more closure plan item(s) in JSON output\n", len(plan)-limit)
	}
	fmt.Fprintln(w)
}

func renderAssessFirstAction(w io.Writer, action model.AssessFirstAction) {
	if !action.Available {
		return
	}
	fmt.Fprintf(w, "First action:\n")
	fmt.Fprintf(w, "  - Case: %s (%s)\n", action.Title, action.CaseID)
	if action.WhyFirst != "" {
		fmt.Fprintf(w, "  - Why first: %s\n", action.WhyFirst)
	}
	if action.NextStep != "" {
		fmt.Fprintf(w, "  - Next step: %s\n", action.NextStep)
	}
	renderAssessCurrentAction(w, action.CurrentAction)
	renderAssessFirstActionWorkflow(w, action.Workflow)
	if len(action.EvidenceReferences) > 0 {
		fmt.Fprintf(w, "  - Evidence to inspect: %s\n", strings.Join(evidenceReferenceLinesBySource(action.EvidenceReferences, 3), "; "))
	}
	if len(action.ProofSurfaces) > 0 {
		fmt.Fprintf(w, "  - Prove at: %s\n", strings.Join(limitStrings(action.ProofSurfaces, 4), "; "))
	}
	if len(action.EvidenceExamples) > 0 {
		fmt.Fprintf(w, "  - Accepted evidence: %s\n", strings.Join(controlEvidenceExampleLines(action.EvidenceExamples, 1), "; "))
	}
	if len(action.ProofPatches) > 0 {
		fmt.Fprintf(w, "  - Proof patch: %s\n", strings.Join(controlProofPatchLines(action.ProofPatches, 1), "; "))
	}
	if len(action.RerunCommands) > 0 {
		fmt.Fprintf(w, "  - Rerun: %s\n", action.RerunCommands[0])
	}
	if len(action.CompareCommands) > 0 {
		fmt.Fprintf(w, "  - Compare loop: %s\n", strings.Join(limitStrings(action.CompareCommands, 3), "; "))
	}
	fmt.Fprintln(w)
}

func renderAssessCurrentAction(w io.Writer, action model.AssessCurrentAction) {
	if !action.Available {
		return
	}
	parts := []string{}
	if action.Control != "" {
		parts = append(parts, action.Control)
	}
	if action.Surface != "" {
		parts = append(parts, "at "+action.Surface)
	}
	if action.ProofPatchIndex >= 0 {
		parts = append(parts, fmt.Sprintf("proof patch #%d", action.ProofPatchIndex+1))
	}
	line := strings.Join(parts, " ")
	if line == "" {
		line = firstNonEmpty(action.Instruction, action.WorkflowStepTitle)
	}
	fmt.Fprintf(w, "  - Current action: %s\n", line)
	if action.RerunCommand != "" {
		fmt.Fprintf(w, "    After proof: %s\n", action.RerunCommand)
	}
}

func renderAssessFirstActionWorkflow(w io.Writer, workflow []model.AssessWorkflowStep) {
	if len(workflow) == 0 {
		return
	}
	if current, ok := currentAssessWorkflowStep(workflow); ok {
		fmt.Fprintf(w, "  - Current workflow step: %s - %s\n", current.Title, current.Summary)
	}
	fmt.Fprintf(w, "  - Workflow:\n")
	for i, step := range workflow {
		marker := ""
		if step.Current {
			marker = " [current]"
		}
		fmt.Fprintf(w, "    %d. %s%s: %s\n", i+1, step.Title, marker, step.Summary)
		if len(step.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "       Evidence: %s\n", strings.Join(evidenceReferenceLinesBySource(step.EvidenceReferences, 2), "; "))
		}
		if len(step.ProofSurfaces) > 0 {
			fmt.Fprintf(w, "       Prove at: %s\n", strings.Join(limitStrings(step.ProofSurfaces, 3), "; "))
		}
		if len(step.Commands) > 0 {
			fmt.Fprintf(w, "       Command: %s\n", strings.Join(limitStrings(step.Commands, 3), "; "))
		}
		if len(step.SuccessCriteria) > 0 {
			fmt.Fprintf(w, "       Done when: %s\n", strings.Join(limitStrings(step.SuccessCriteria, 2), "; "))
		}
	}
}

func currentAssessWorkflowStep(workflow []model.AssessWorkflowStep) (model.AssessWorkflowStep, bool) {
	for _, step := range workflow {
		if step.Current {
			return step, true
		}
	}
	return model.AssessWorkflowStep{}, false
}

func renderAssessTopCaseProofPacket(w io.Writer, plan *model.ProofPlanReport) {
	if plan == nil {
		return
	}
	fmt.Fprintf(w, "\nTop case proof packet:\n")
	if plan.CaseFilter != "" {
		fmt.Fprintf(w, "  - Case: %s\n", plan.CaseFilter)
	}
	fmt.Fprintf(w, "  - Evidence references: %d; proof patches: %d\n", plan.Summary.EvidenceReferences, plan.Summary.ProofPatches)
	if len(plan.EvidenceReferences) > 0 {
		fmt.Fprintf(w, "  - Evidence to inspect: %s\n", strings.Join(evidenceReferenceLines(plan.EvidenceReferences, 3), "; "))
	}
	if len(plan.ProofPatches) > 0 {
		fmt.Fprintf(w, "  - Prove at: %s\n", strings.Join(limitStrings(proofPatchSurfaceLines(plan.ProofPatches), 4), "; "))
	}
	if len(plan.CompareCommands) > 0 {
		fmt.Fprintf(w, "  - Compare loop: %s\n", strings.Join(limitStrings(plan.CompareCommands, 3), "; "))
	}
}

func proofPatchSurfaceLines(patches []model.ControlProofPatch) []string {
	var surfaces []string
	for _, patch := range patches {
		if patch.Surface != "" {
			surfaces = append(surfaces, patch.Surface)
		}
	}
	return uniqueStrings(surfaces)
}

func renderAssessClosureEvidence(w io.Writer, closure model.AssessClosureEvidence) {
	if !assessClosureEvidenceHasData(closure) {
		return
	}
	fmt.Fprintf(w, "Closure evidence observed:\n")
	fmt.Fprintf(w, "  - Protected exposure paths: %d\n", closure.ProtectedExposurePaths)
	fmt.Fprintf(w, "  - Controlled architecture flaws: %d\n", closure.ControlledArchitectureFlaws)
	fmt.Fprintf(w, "  - Partial/friction-only architecture flaws: %d\n", closure.PartialArchitectureFlaws)
	if len(closure.HardBarriersObserved) > 0 {
		fmt.Fprintf(w, "  - Hard barriers observed: %s\n", strings.Join(limitStrings(closure.HardBarriersObserved, 6), "; "))
	}
	if len(closure.PartialOrFrictionControls) > 0 {
		fmt.Fprintf(w, "  - Partial/friction controls observed: %s\n", strings.Join(limitStrings(closure.PartialOrFrictionControls, 6), "; "))
	}
	if len(closure.RemainingMissingHardBarriers) > 0 {
		fmt.Fprintf(w, "  - Still missing: %s\n", strings.Join(limitStrings(closure.RemainingMissingHardBarriers, 6), "; "))
	}
	for _, item := range limitAssessClosurePaths(closure.ControlledPaths, 3) {
		fmt.Fprintf(w, "  - CONTROLLED %s: %s\n", item.Title, readableToken(item.ControlTestResult))
		if len(item.HardBarriersObserved) > 0 {
			fmt.Fprintf(w, "    Hard barriers: %s\n", strings.Join(limitStrings(item.HardBarriersObserved, 5), "; "))
		}
		if len(item.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "    Evidence: %s\n", strings.Join(evidenceReferenceLines(item.EvidenceReferences, 3), "; "))
		}
	}
	for _, item := range limitAssessClosurePaths(closure.PartialPaths, 3) {
		fmt.Fprintf(w, "  - PARTIAL %s: %s\n", item.Title, readableToken(item.ControlTestResult))
		if len(item.PartialOrFrictionControls) > 0 {
			fmt.Fprintf(w, "    Observed: %s\n", strings.Join(limitStrings(item.PartialOrFrictionControls, 5), "; "))
		}
		if len(item.RemainingMissingHardBarriers) > 0 {
			fmt.Fprintf(w, "    Still missing: %s\n", strings.Join(limitStrings(item.RemainingMissingHardBarriers, 5), "; "))
		}
		if len(item.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "    Evidence: %s\n", strings.Join(evidenceReferenceLines(item.EvidenceReferences, 3), "; "))
		}
	}
	fmt.Fprintln(w)
}

func assessClosureEvidenceHasData(closure model.AssessClosureEvidence) bool {
	return closure.ProtectedExposurePaths > 0 ||
		closure.ControlledArchitectureFlaws > 0 ||
		closure.PartialArchitectureFlaws > 0 ||
		len(closure.HardBarriersObserved) > 0 ||
		len(closure.PartialOrFrictionControls) > 0 ||
		len(closure.RemainingMissingHardBarriers) > 0 ||
		len(closure.ControlledPaths) > 0 ||
		len(closure.PartialPaths) > 0
}

func limitAssessClosurePaths(items []model.AssessClosurePath, limit int) []model.AssessClosurePath {
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	if limit == 0 {
		return []model.AssessClosurePath{}
	}
	return items[:limit]
}

func renderAssessArchitectureBreaks(w io.Writer, r model.AssessReport) {
	fmt.Fprintf(w, "Architecture break paths:\n")
	switch {
	case r.Architecture != nil:
		if len(r.Architecture.Flaws) == 0 {
			fmt.Fprintf(w, "  - no architecture flaws matched status filter %q\n\n", r.StatusFilter)
			return
		}
		limit := len(r.Architecture.Flaws)
		if limit > 5 {
			limit = 5
		}
		for _, flaw := range r.Architecture.Flaws[:limit] {
			fmt.Fprintf(w, "  - %s %s: %s\n", statusLabel(string(flaw.Status)), flaw.Title, flaw.Finding)
			if len(flaw.Evidence) > 0 {
				fmt.Fprintf(w, "    Evidence: %s\n", zeroTrustEvidenceLine(flaw.Evidence, 3))
			}
			if len(flaw.ControlEvidenceNeeded) > 0 {
				fmt.Fprintf(w, "    Breaks when: %s\n", strings.Join(limitStrings(flaw.ControlEvidenceNeeded, 4), "; "))
			}
		}
		if len(r.Architecture.Flaws) > limit {
			fmt.Fprintf(w, "  - %d more architecture flaw(s) in JSON or dashboard output\n", len(r.Architecture.Flaws)-limit)
		}
	case r.ArchitectureScan != nil:
		if len(r.ArchitectureScan.Groups) == 0 {
			fmt.Fprintf(w, "  - no fleet architecture flaw groups matched status filter %q\n\n", r.StatusFilter)
			return
		}
		limit := len(r.ArchitectureScan.Groups)
		if limit > 5 {
			limit = 5
		}
		for _, group := range r.ArchitectureScan.Groups[:limit] {
			fmt.Fprintf(w, "  - %s %s: %d target(s), %d breaking occurrence(s)\n", strings.ToUpper(group.Severity), group.Title, group.TargetCount, group.StatusCounts.Breaking)
			if len(group.EvidenceSources) > 0 {
				fmt.Fprintf(w, "    Evidence: %s\n", strings.Join(limitStrings(group.EvidenceSources, 3), "; "))
			}
			if len(group.ControlEvidenceNeeded) > 0 {
				fmt.Fprintf(w, "    Breaks when: %s\n", strings.Join(limitStrings(group.ControlEvidenceNeeded, 4), "; "))
			}
		}
		if len(r.ArchitectureScan.Groups) > limit {
			fmt.Fprintf(w, "  - %d more architecture flaw group(s) in JSON or dashboard output\n", len(r.ArchitectureScan.Groups)-limit)
		}
	default:
		fmt.Fprintf(w, "  - no architecture report attached\n")
	}
	fmt.Fprintln(w)
}

func assessCountLine(items []model.AssessCount) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s=%d", item.Name, item.Count))
	}
	return strings.Join(parts, "; ")
}

func renderAssessInventorySummary(w io.Writer, inventory model.AssessInventory, surfaceMapLimit int) {
	if inventory.Surfaces == 0 && inventory.Facts == 0 && inventory.GraphNodes == 0 {
		return
	}
	fmt.Fprintf(w, "What was inspected:\n")
	fmt.Fprintf(w, "  - AI surfaces: %d; typed facts: %d; graph: %d node(s), %d edge(s)\n", inventory.Surfaces, inventory.Facts, inventory.GraphNodes, inventory.GraphEdges)
	fmt.Fprintf(w, "  - Runtimes: %d; trust inputs: %d; tools: %d; authorities: %d; controls: %d; boundaries: %d\n", inventory.Runtimes, inventory.TrustInputs, inventory.Tools, inventory.Authorities, inventory.Controls, inventory.Boundaries)
	if len(inventory.SurfaceCategories) > 0 {
		fmt.Fprintf(w, "  - Surface categories: %s\n", assessCountLine(inventory.SurfaceCategories))
	}
	if len(inventory.HandlingModes) > 0 {
		fmt.Fprintf(w, "  - Handling modes: %s\n", assessCountLine(inventory.HandlingModes))
	}
	if len(inventory.SurfaceMap) > 0 {
		fmt.Fprintf(w, "  - Runtime surface map: %s\n", strings.Join(limitStrings(surfaceMapSummaryLines(inventory.SurfaceMap), surfaceMapLimit), "; "))
	}
	if len(inventory.FactHighlights) > 0 {
		fmt.Fprintf(w, "  - Fact highlights:\n")
		for _, line := range limitStrings(assessFactHighlightLines(inventory.FactHighlights), 8) {
			fmt.Fprintf(w, "    - %s\n", line)
		}
	}
	fmt.Fprintln(w)
}

func assessFactHighlightLines(items []model.AssessFact) []string {
	lines := make([]string, 0, len(items))
	for _, item := range items {
		parts := []string{firstNonEmpty(item.Type, "fact")}
		source := strings.TrimSpace(item.Source)
		if item.Target != "" && source != "" {
			source = item.Target + ":" + source
		}
		if source != "" {
			parts = append(parts, "from "+source)
		}
		if item.EvidenceGrade != "" || item.Redaction != "" {
			parts = append(parts, "["+strings.Join(nonEmptyStrings(item.EvidenceGrade, item.Redaction), "/")+"]")
		}
		line := strings.Join(parts, " ")
		if item.Summary != "" {
			line += ": " + item.Summary
		}
		lines = append(lines, line)
	}
	if lines == nil {
		return []string{}
	}
	return lines
}

func surfaceMapSummaryLines(items []model.SurfaceMap) []string {
	lines := make([]string, 0, len(items))
	for _, item := range items {
		parts := []string{fmt.Sprintf("%s/%s surfaces=%d", item.Runtime, item.Scope, item.SurfaceCount)}
		if item.Parsed > 0 {
			parts = append(parts, fmt.Sprintf("parse=%d", item.Parsed))
		}
		if item.Summarized > 0 {
			parts = append(parts, fmt.Sprintf("summarize=%d", item.Summarized))
		}
		if item.BoundaryIndicators > 0 {
			parts = append(parts, fmt.Sprintf("boundary=%d", item.BoundaryIndicators))
		}
		if item.Skipped > 0 {
			parts = append(parts, fmt.Sprintf("skip=%d", item.Skipped))
		}
		if len(item.SourceRefs) > 0 {
			parts = append(parts, "refs="+strings.Join(limitStrings(item.SourceRefs, 3), ", "))
		}
		if len(item.Authorities) > 0 {
			parts = append(parts, "authorities="+strings.Join(limitStrings(item.Authorities, 3), ", "))
		}
		if len(item.Tools) > 0 {
			parts = append(parts, "tools="+strings.Join(limitStrings(item.Tools, 3), ", "))
		}
		if len(item.Controls) > 0 {
			parts = append(parts, "controls="+strings.Join(limitStrings(item.Controls, 3), ", "))
		}
		lines = append(lines, strings.Join(parts, " "))
	}
	return lines
}

func renderInventoryTable(w io.Writer, r model.InventoryReport) error {
	fmt.Fprintf(w, "Ariadne Inventory\n\n")
	fmt.Fprintf(w, "Target: %s\n", r.TargetPath)
	fmt.Fprintf(w, "Mode: %s\n", r.Mode)
	fmt.Fprintf(w, "Agent: %s\n\n", r.Agent)
	fmt.Fprintf(w, "Runtime surface map:\n")
	if len(r.SurfaceMap) == 0 {
		fmt.Fprintf(w, "  - no runtime surface groups built\n")
	} else {
		for _, group := range r.SurfaceMap {
			fmt.Fprintf(w, "  - %s/%s: surfaces=%d parse=%d summarize=%d boundary=%d skip=%d\n", group.Runtime, group.Scope, group.SurfaceCount, group.Parsed, group.Summarized, group.BoundaryIndicators, group.Skipped)
			if len(group.SourceRefs) > 0 {
				fmt.Fprintf(w, "    Sources: %s\n", strings.Join(limitStrings(group.SourceRefs, 6), "; "))
			}
			if len(group.Authorities) > 0 {
				fmt.Fprintf(w, "    Authorities: %s\n", strings.Join(limitStrings(group.Authorities, 5), "; "))
			}
			if len(group.Tools) > 0 {
				fmt.Fprintf(w, "    Tools: %s\n", strings.Join(limitStrings(group.Tools, 5), "; "))
			}
			if len(group.Controls) > 0 {
				fmt.Fprintf(w, "    Controls: %s\n", strings.Join(limitStrings(group.Controls, 5), "; "))
			}
			if len(group.Limitations) > 0 {
				fmt.Fprintf(w, "    Limits: %s\n", strings.Join(limitStrings(group.Limitations, 3), "; "))
			}
		}
	}
	fmt.Fprintln(w)
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
		if len(exposure.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "Evidence to inspect:\n")
			for _, line := range evidenceReferenceLines(exposure.EvidenceReferences, 6) {
				fmt.Fprintf(w, "  - %s\n", line)
			}
			fmt.Fprintln(w)
		}
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
	renderArchitectureCaseWorkflow(w, r.ClosureFamilies, controlVerificationCommandContext{RunKind: "case_board", Path: r.TargetPath, Mode: r.Mode, Agent: r.Agent, StatusFilter: r.StatusFilter}, 6)
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
	renderArchitectureCaseWorkflow(w, r.ClosureFamilies, controlVerificationCommandContext{RunKind: "case_board_scan", TargetsFile: r.TargetsFile, Mode: r.Mode, Agent: r.Agent, StatusFilter: r.StatusFilter}, 8)
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

func renderControlCaseBoard(w io.Writer, r model.ControlCatalogReport, format string) error {
	switch strings.ToLower(format) {
	case "", "table":
		return renderControlCaseBoardTable(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "html", "dashboard":
		return renderControlCaseBoardDashboard(w, r)
	default:
		return fmt.Errorf("unknown cases format: %s", format)
	}
}

func renderProofPlan(w io.Writer, r model.ProofPlanReport, format string) error {
	switch strings.ToLower(format) {
	case "", "table":
		return renderProofPlanTable(w, r)
	case "action":
		return renderProofPlanAction(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "html", "dashboard":
		return renderProofPlanDashboard(w, r)
	default:
		return fmt.Errorf("unknown proofs format: %s", format)
	}
}

func renderProofPlanAction(w io.Writer, r model.ProofPlanReport) error {
	fmt.Fprintf(w, "Ariadne Proof Action\n\n")
	if r.TargetsFile != "" {
		fmt.Fprintf(w, "Targets file: %s\n", r.TargetsFile)
	} else if r.TargetPath != "" {
		fmt.Fprintf(w, "Target: %s\n", r.TargetPath)
	}
	fmt.Fprintf(w, "Filter: %s\n", r.StatusFilter)
	if r.CaseFilter != "" {
		fmt.Fprintf(w, "Case filter: %s\n", r.CaseFilter)
	}
	fmt.Fprintf(w, "Proof queue: %d case(s); %d proof patch(es); %d evidence reference(s)\n\n", r.Summary.Cases, r.Summary.ProofPatches, r.Summary.EvidenceReferences)

	item, hasCase := firstProofPlanCase(r)
	patch, hasPatch := firstProofPlanPatch(r)
	if hasCase {
		fmt.Fprintf(w, "Case:\n")
		fmt.Fprintf(w, "  - %s (%s)\n", controlOperatorCaseDisplayTitle(item), item.ID)
		if item.State != "" {
			fmt.Fprintf(w, "  - State: %s - %s\n", item.State, item.StateReason)
		}
		if item.PriorityReason != "" {
			fmt.Fprintf(w, "  - Priority: %s\n", item.PriorityReason)
		}
		if item.NextStep != "" {
			fmt.Fprintf(w, "  - Next step: %s\n", item.NextStep)
		}
	} else {
		fmt.Fprintf(w, "Case:\n  - none\n")
	}

	evidenceRefs := r.EvidenceReferences
	if hasCase && len(item.EvidenceReferences) > 0 {
		evidenceRefs = item.EvidenceReferences
	}
	if len(evidenceRefs) > 0 {
		fmt.Fprintf(w, "\nEvidence to inspect:\n")
		for _, line := range evidenceReferenceLinesBySource(evidenceRefs, 4) {
			fmt.Fprintf(w, "  - %s\n", line)
		}
	}

	if hasPatch {
		fmt.Fprintf(w, "\nProof to add or verify:\n")
		fmt.Fprintf(w, "  - Control: %s\n", patch.Control)
		fmt.Fprintf(w, "  - Proof surface: %s\n", patch.Surface)
		if len(patch.Fields) > 0 {
			fmt.Fprintf(w, "  - Fields: %s\n", strings.Join(controlProofPatchFieldLines(patch.Fields), "; "))
		}
		if patch.Example != "" {
			fmt.Fprintf(w, "  - Example: %s\n", compactExample(patch.Example))
		}
		if patch.Summary != "" {
			fmt.Fprintf(w, "  - Patch: %s\n", patch.Summary)
		}
	} else {
		fmt.Fprintf(w, "\nProof to add or verify:\n")
		fmt.Fprintf(w, "  - No proof patch is needed for this case.\n")
		if hasCase && len(item.StartingControls) > 0 {
			fmt.Fprintf(w, "  - Observed controls: %s\n", strings.Join(limitStrings(item.StartingControls, 5), "; "))
		}
	}

	if r.PatchExportCommand != "" && hasPatch {
		fmt.Fprintf(w, "\nExport suggested files:\n  - %s\n", r.PatchExportCommand)
	}

	rerunCommands := r.RerunCommands
	if hasPatch && len(patch.RerunCommands) > 0 {
		rerunCommands = patch.RerunCommands
	} else if hasCase && len(item.RerunCommands) > 0 {
		rerunCommands = item.RerunCommands
	}
	if len(rerunCommands) > 0 {
		fmt.Fprintf(w, "\nRerun:\n")
		for _, command := range limitStrings(rerunCommands, 2) {
			fmt.Fprintf(w, "  - %s\n", command)
		}
	}

	if len(r.CompareCommands) > 0 {
		fmt.Fprintf(w, "\nCompare loop:\n")
		for _, command := range limitStrings(r.CompareCommands, 3) {
			fmt.Fprintf(w, "  - %s\n", command)
		}
	}

	successCriteria := r.SuccessCriteria
	if hasPatch && len(patch.SuccessCriteria) > 0 {
		successCriteria = patch.SuccessCriteria
	} else if hasCase && len(item.SuccessCriteria) > 0 {
		successCriteria = item.SuccessCriteria
	}
	if len(successCriteria) > 0 {
		fmt.Fprintf(w, "\nDone when:\n")
		for _, criterion := range limitStrings(successCriteria, 3) {
			fmt.Fprintf(w, "  - %s\n", criterion)
		}
	}

	limitations := r.Limitations
	if hasPatch && len(patch.Limitations) > 0 {
		limitations = uniqueStrings(append(append([]string{}, patch.Limitations...), limitations...))
	}
	if len(limitations) > 0 {
		fmt.Fprintf(w, "\nLimitations:\n")
		for _, limitation := range limitStrings(limitations, 3) {
			fmt.Fprintf(w, "  - %s\n", limitation)
		}
	}
	fmt.Fprintln(w)
	return nil
}

func renderProofPlanTable(w io.Writer, r model.ProofPlanReport) error {
	fmt.Fprintf(w, "Ariadne proof plan:\n")
	fmt.Fprintf(w, "  Run: %s  Mode: %s  Agent: %s  Filter: %s\n", empty(r.RunKind, "proof_plan"), empty(r.Mode, "unknown"), empty(r.Agent, "unknown"), r.StatusFilter)
	if r.TargetPath != "" {
		fmt.Fprintf(w, "  Target: %s\n", r.TargetPath)
	}
	if r.CaseFilter != "" {
		fmt.Fprintf(w, "  Case: %s\n", r.CaseFilter)
	}
	fmt.Fprintf(w, "  Proof queue: %d case(s), %d proof patch(es), %d evidence reference(s), %d control(s), %d target(s), %d flaw(s)\n\n",
		r.Summary.Cases,
		r.Summary.ProofPatches,
		r.Summary.EvidenceReferences,
		r.Summary.Controls,
		r.Summary.Targets,
		r.Summary.Flaws,
	)
	if len(r.Cases) > 0 {
		fmt.Fprintf(w, "Cases:\n")
		for _, item := range limitProofPlanCases(r.Cases, 5) {
			fmt.Fprintf(w, "  - %s %s (%s)\n", strings.ToUpper(item.Severity), controlOperatorCaseDisplayTitle(item), item.ID)
			if item.State != "" {
				fmt.Fprintf(w, "    State: %s - %s\n", item.State, item.StateReason)
			}
			if item.NextStep != "" {
				fmt.Fprintf(w, "    Next step: %s\n", item.NextStep)
			}
			if len(item.EvidenceReferences) > 0 {
				fmt.Fprintf(w, "    Evidence to inspect: %s\n", strings.Join(evidenceReferenceLines(item.EvidenceReferences, 3), "; "))
			}
		}
		if len(r.Cases) > 5 {
			fmt.Fprintf(w, "  - %d more case(s) in JSON output\n", len(r.Cases)-5)
		}
		fmt.Fprintln(w)
	}
	if len(r.ProofPatches) == 0 {
		fmt.Fprintf(w, "Proof patches:\n")
		fmt.Fprintf(w, "  - no proof patches matched this filter\n\n")
	} else {
		fmt.Fprintf(w, "Proof patches:\n")
		for _, patch := range limitProofPlanPatches(r.ProofPatches, 12) {
			fmt.Fprintf(w, "  - %s -> %s (%s)\n", patch.Control, patch.Surface, patch.Operation)
			if len(patch.Fields) > 0 {
				fmt.Fprintf(w, "    Fields: %s\n", strings.Join(controlProofPatchFieldLines(patch.Fields), "; "))
			}
			if patch.Example != "" {
				fmt.Fprintf(w, "    Example: %s\n", compactExample(patch.Example))
			}
			if len(patch.RerunCommands) > 0 {
				fmt.Fprintf(w, "    Rerun: %s\n", strings.Join(limitStrings(patch.RerunCommands, 2), "; "))
			}
			if len(patch.SuccessCriteria) > 0 {
				fmt.Fprintf(w, "    Done when: %s\n", strings.Join(limitStrings(patch.SuccessCriteria, 2), "; "))
			}
			if len(patch.Limitations) > 0 {
				fmt.Fprintf(w, "    Limitation: %s\n", patch.Limitations[0])
			}
		}
		if len(r.ProofPatches) > 12 {
			fmt.Fprintf(w, "  - %d more proof patch(es) in JSON output\n", len(r.ProofPatches)-12)
		}
	}
	renderProofPlanWorkflow(w, r.Workflow)
	if len(r.CompareCommands) > 0 {
		fmt.Fprintf(w, "\nCompare loop:\n")
		for _, command := range limitStrings(r.CompareCommands, 3) {
			fmt.Fprintf(w, "  - %s\n", command)
		}
	}
	if r.PatchExportCommand != "" {
		fmt.Fprintf(w, "\nExport suggested files:\n")
		fmt.Fprintf(w, "  - %s\n", r.PatchExportCommand)
	}
	if len(r.Limitations) > 0 {
		fmt.Fprintf(w, "\nLimitations:\n")
		for _, limitation := range limitStrings(r.Limitations, 5) {
			fmt.Fprintf(w, "  - %s\n", limitation)
		}
	}
	fmt.Fprintln(w)
	return nil
}

func renderProofPlanWorkflow(w io.Writer, workflow []model.ProofWorkflowStep) {
	if len(workflow) == 0 {
		return
	}
	fmt.Fprintf(w, "\nProof workflow:\n")
	for i, step := range workflow {
		fmt.Fprintf(w, "  %d. %s: %s\n", i+1, firstNonEmpty(step.Title, step.ID), step.Summary)
		if len(step.Commands) > 0 {
			fmt.Fprintf(w, "     Command: %s\n", strings.Join(limitStrings(step.Commands, 3), "; "))
		}
		if len(step.ProofSurfaces) > 0 {
			fmt.Fprintf(w, "     Proof surfaces: %s\n", strings.Join(limitStrings(step.ProofSurfaces, 4), "; "))
		}
		if len(step.EvidenceReferences) > 0 {
			fmt.Fprintf(w, "     Evidence: %s\n", strings.Join(evidenceReferenceLines(step.EvidenceReferences, 3), "; "))
		}
		if len(step.SuccessCriteria) > 0 {
			fmt.Fprintf(w, "     Done when: %s\n", strings.Join(limitStrings(step.SuccessCriteria, 3), "; "))
		}
	}
}

func controlProofPatchFieldLines(fields []model.ControlProofPatchField) []string {
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		name := field.Name
		if name == "" {
			name = field.Indicator
		}
		if field.ValueJSON != "" {
			out = append(out, name+"="+field.ValueJSON)
			continue
		}
		out = append(out, name)
	}
	return out
}

func limitProofPlanCases(items []model.ControlOperatorCase, limit int) []model.ControlOperatorCase {
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	if limit == 0 {
		return []model.ControlOperatorCase{}
	}
	return items[:limit]
}

func limitProofPlanPatches(items []model.ControlProofPatch, limit int) []model.ControlProofPatch {
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	if limit == 0 {
		return []model.ControlProofPatch{}
	}
	return items[:limit]
}

func renderControlCaseBoardTable(w io.Writer, r model.ControlCatalogReport) error {
	fmt.Fprintf(w, "Ariadne operator case board:\n")
	if r.TargetPath != "" {
		fmt.Fprintf(w, "  Target: %s\n", r.TargetPath)
	}
	fmt.Fprintf(w, "  Run: %s  Mode: %s  Agent: %s  Filter: %s\n", empty(r.RunKind, "case_board"), empty(r.Mode, "unknown"), empty(r.Agent, "unknown"), r.StatusFilter)
	if r.CaseFilter != "" {
		fmt.Fprintf(w, "  Case: %s\n", r.CaseFilter)
	}
	fmt.Fprintf(w, "  Case queue: %d case(s); %d missing hard-barrier controls; %d critical, %d high, %d medium, %d low; %d target(s); %d flaw(s)\n",
		len(r.OperatorCases),
		r.Summary.Controls,
		r.Summary.Critical,
		r.Summary.High,
		r.Summary.Medium,
		r.Summary.Low,
		r.Summary.Targets,
		r.Summary.Flaws,
	)
	if len(r.OperatorCases) == 0 {
		fmt.Fprintf(w, "  - no operator cases matched status filter %q\n\n", r.StatusFilter)
		return nil
	}
	renderControlOperatorCases(w, r.OperatorCases, 10)
	fmt.Fprintf(w, "  Evidence model:\n")
	fmt.Fprintf(w, "    - Cases are derived from deterministic facts, graph edges, architecture flaws, and missing hard-barrier controls.\n")
	fmt.Fprintf(w, "    - Use `ariadne proofs --case <case-id>` for the focused proof patches and rerun criteria for one case.\n")
	fmt.Fprintf(w, "    - Use `ariadne controls --format json` for the full control catalog and lower-level verification tasks.\n")
	fmt.Fprintln(w)
	return nil
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

func rewriteControlCatalogAsCaseBoard(catalog *model.ControlCatalogReport) {
	for i := range catalog.OperatorCases {
		catalog.OperatorCases[i].RerunCommands = caseBoardRerunCommands(catalog.OperatorCases[i].RerunCommands)
		catalog.OperatorCases[i].ProofPatches = proofPatchesWithRerunCommands(catalog.OperatorCases[i].ProofPatches, caseBoardRerunCommands)
		catalog.OperatorCases[i].CompareCommands = operatorCaseCompareCommands(*catalog, catalog.OperatorCases[i].ID)
		catalog.OperatorCases[i].SuccessCriteria = caseBoardSuccessCriteria(catalog.OperatorCases[i].SuccessCriteria)
	}
	for i := range catalog.Workstreams {
		catalog.Workstreams[i].SuccessCriteria = caseBoardSuccessCriteria(catalog.Workstreams[i].SuccessCriteria)
	}
	for i := range catalog.VerificationTasks {
		catalog.VerificationTasks[i].RerunCommands = caseBoardRerunCommands(catalog.VerificationTasks[i].RerunCommands)
		catalog.VerificationTasks[i].ProofPatches = proofPatchesWithRerunCommands(catalog.VerificationTasks[i].ProofPatches, caseBoardRerunCommands)
		catalog.VerificationTasks[i].SuccessCriteria = caseBoardSuccessCriteria(catalog.VerificationTasks[i].SuccessCriteria)
	}
}

func filterControlCaseBoard(catalog *model.ControlCatalogReport, caseFilter string) error {
	caseFilter = strings.TrimSpace(caseFilter)
	if caseFilter == "" {
		return nil
	}
	var selected model.ControlOperatorCase
	found := false
	for _, item := range catalog.OperatorCases {
		if controlOperatorCaseMatches(item, caseFilter) {
			selected = item
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("operator case %q not found", caseFilter)
	}
	catalog.CaseFilter = selected.ID
	selected.RerunCommands = caseBoardFocusedRerunCommands(selected.RerunCommands, selected.ID)
	selected.ProofPatches = proofPatchesWithRerunCommands(selected.ProofPatches, func(commands []string) []string {
		return caseBoardFocusedRerunCommands(commands, selected.ID)
	})
	caseID := strings.TrimPrefix(selected.ID, "case:")
	controls := map[string]bool{}
	taskIDs := map[string]bool{}
	for _, control := range selected.StartingControls {
		controls[control] = true
	}
	for _, taskID := range selected.StartingTaskIDs {
		taskIDs[taskID] = true
	}
	var workstreams []model.ControlBreakPathWorkstream
	for _, workstream := range catalog.Workstreams {
		if workstream.ID != caseID {
			continue
		}
		workstreams = append(workstreams, workstream)
		for _, control := range workstream.Controls {
			controls[control] = true
		}
		for _, taskID := range workstream.StartingTaskIDs {
			taskIDs[taskID] = true
		}
	}
	var families []model.ArchitectureClosureFamily
	for _, family := range catalog.Families {
		if family.ID != caseID {
			continue
		}
		families = append(families, family)
		for _, control := range family.Controls {
			controls[control] = true
		}
	}
	var closurePlan []model.ArchitectureClosure
	for _, item := range catalog.Controls {
		if controls[item.Control] {
			closurePlan = append(closurePlan, item)
		}
	}
	var proofSpecs []model.ControlProofSpec
	for _, item := range catalog.ProofSpecs {
		if controls[item.Control] {
			proofSpecs = append(proofSpecs, item)
		}
	}
	var tasks []model.ControlVerificationTask
	for _, item := range catalog.VerificationTasks {
		if controls[item.Control] || taskIDs[item.ID] {
			item.RerunCommands = caseBoardFocusedRerunCommands(item.RerunCommands, selected.ID)
			item.ProofPatches = proofPatchesWithRerunCommands(item.ProofPatches, func(commands []string) []string {
				return caseBoardFocusedRerunCommands(commands, selected.ID)
			})
			tasks = append(tasks, item)
		}
	}
	catalog.OperatorCases = []model.ControlOperatorCase{selected}
	catalog.Workstreams = nonNilControlBreakPathWorkstreams(workstreams)
	catalog.Families = nonNilArchitectureClosureFamilies(families)
	catalog.Controls = nonNilArchitectureClosures(closurePlan)
	catalog.ProofSpecs = nonNilControlProofSpecs(proofSpecs)
	catalog.VerificationTasks = nonNilControlVerificationTasks(tasks)
	catalog.Summary = summarizeControlCatalog(catalog.Controls)
	return nil
}

type focusedClosedCaseTarget struct {
	TargetID string
	Flaws    []model.ZeroTrustArchitecture
	Graph    model.Graph
}

func buildFocusedClosedCaseBoardReport(r model.Report, statusFilter string, caseFilter string) (model.ControlCatalogReport, bool, error) {
	familyID := normalizeControlOperatorCaseID(caseFilter)
	if familyID == "" {
		return model.ControlCatalogReport{}, false, nil
	}
	architecture, err := BuildArchitectureReport(r, "all")
	if err != nil {
		return model.ControlCatalogReport{}, false, err
	}
	ctx := controlVerificationCommandContext{
		RunKind:      "case_board",
		Path:         architecture.TargetPath,
		Mode:         architecture.Mode,
		Agent:        architecture.Agent,
		StatusFilter: firstNonEmpty(statusFilter, "breaking"),
	}
	item, ok := buildFocusedClosedOperatorCase(familyID, []focusedClosedCaseTarget{{TargetID: "target", Flaws: architecture.Flaws, Graph: r.Graph}}, ctx)
	if !ok {
		return model.ControlCatalogReport{}, false, nil
	}
	return focusedClosedCaseCatalog(architecture.RunID, architecture.GeneratedAt, "case_board", architecture.TargetPath, "", architecture.Mode, architecture.Agent, ctx.StatusFilter, item, architecture.Redaction, architecture.Limitations), true, nil
}

func buildFocusedClosedCaseBoardScanReport(r model.ScanReport, statusFilter string, caseFilter string) (model.ControlCatalogReport, bool, error) {
	familyID := normalizeControlOperatorCaseID(caseFilter)
	if familyID == "" {
		return model.ControlCatalogReport{}, false, nil
	}
	architecture, err := BuildArchitectureScanReport(r, "all")
	if err != nil {
		return model.ControlCatalogReport{}, false, err
	}
	var targets []focusedClosedCaseTarget
	for _, target := range architecture.Targets {
		if target.Error != "" {
			continue
		}
		targetID := target.Target.ID
		if targetID == "" {
			targetID = "target"
		}
		var graph model.Graph
		for _, scanTarget := range r.Targets {
			if firstNonEmpty(scanTarget.Target.ID, "target") == targetID {
				graph = scanTarget.Report.Graph
				break
			}
		}
		targets = append(targets, focusedClosedCaseTarget{TargetID: targetID, Flaws: target.Flaws, Graph: graph})
	}
	ctx := controlVerificationCommandContext{
		RunKind:      "case_board_scan",
		TargetsFile:  architecture.TargetsFile,
		Mode:         architecture.Mode,
		Agent:        architecture.Agent,
		StatusFilter: firstNonEmpty(statusFilter, "breaking"),
	}
	item, ok := buildFocusedClosedOperatorCase(familyID, targets, ctx)
	if !ok {
		return model.ControlCatalogReport{}, false, nil
	}
	return focusedClosedCaseCatalog(architecture.RunID, architecture.GeneratedAt, "case_board_scan", "", architecture.TargetsFile, architecture.Mode, architecture.Agent, ctx.StatusFilter, item, architecture.Redaction, architecture.Limitations), true, nil
}

func focusedClosedCaseCatalog(runID string, generatedAt time.Time, runKind string, targetPath string, targetsFile string, mode string, agent string, statusFilter string, item model.ControlOperatorCase, redaction model.RedactionInfo, limitations []string) model.ControlCatalogReport {
	catalog := model.ControlCatalogReport{
		SchemaVersion:     model.SchemaVersion,
		RunID:             runID,
		GeneratedAt:       generatedAt,
		RunKind:           runKind,
		TargetPath:        targetPath,
		TargetsFile:       targetsFile,
		Mode:              mode,
		Agent:             agent,
		StatusFilter:      firstNonEmpty(statusFilter, "breaking"),
		CaseFilter:        item.ID,
		Summary:           model.ControlCatalogSummary{Targets: item.TargetCount, Flaws: item.FlawCount},
		Controls:          []model.ArchitectureClosure{},
		Families:          []model.ArchitectureClosureFamily{},
		OperatorCases:     []model.ControlOperatorCase{item},
		Workstreams:       []model.ControlBreakPathWorkstream{},
		ProofSpecs:        []model.ControlProofSpec{},
		VerificationTasks: []model.ControlVerificationTask{},
		Redaction:         redaction,
		Limitations:       append([]string{}, limitations...),
	}
	attachOperatorCaseCompareCommands(&catalog)
	return catalog
}

func buildFocusedClosedOperatorCase(familyID string, targets []focusedClosedCaseTarget, ctx controlVerificationCommandContext) (model.ControlOperatorCase, bool) {
	targetSet := map[string]bool{}
	flawSet := map[string]bool{}
	var evidenceRefs []model.EvidenceReference
	var observedControls []string
	var proofSurfaces []string
	title := ""
	severity := ""
	controlledFlaws := 0
	for _, target := range targets {
		targetID := target.TargetID
		if targetID == "" {
			targetID = "target"
		}
		for _, flaw := range target.Flaws {
			matchedTitle, controls, ok := controlledFlawMatchesFamily(flaw, familyID)
			if !ok {
				continue
			}
			if title == "" {
				title = matchedTitle
			}
			if severityRank(flaw.Severity) > severityRank(severity) {
				severity = flaw.Severity
			}
			controlledFlaws++
			targetSet[targetID] = true
			flawTitle := firstNonEmpty(flaw.Title, flaw.ID)
			if flawTitle != "" {
				flawSet[flawTitle] = true
			}
			observedControls = append(observedControls, controls...)
			evidenceRefs = append(evidenceRefs, evidenceReferencesForFlaw(targetID, flaw)...)
			evidenceRefs = append(evidenceRefs, controlEvidenceReferencesFromGraph(targetID, controls, target.Graph)...)
			proofSurfaces = append(proofSurfaces, flaw.EvidenceSurfaces...)
			proofSurfaces = append(proofSurfaces, zeroTrustEvidenceSources(flaw.Evidence)...)
		}
	}
	if controlledFlaws == 0 {
		return model.ControlOperatorCase{}, false
	}
	caseID := "case:" + familyID
	targetList := mapKeysSorted(targetSet)
	flawList := mapKeysSorted(flawSet)
	observedControls = uniqueSortedStrings(observedControls)
	evidenceRefs = dedupeEvidenceReferences(evidenceRefs)
	observedProofSurfaces := evidenceReferenceSources(evidenceRefs, true)
	if len(observedProofSurfaces) == 0 {
		observedProofSurfaces = evidenceReferenceSources(evidenceRefs, false)
	}
	if len(observedProofSurfaces) == 0 {
		observedProofSurfaces = uniqueSortedStrings(proofSurfaces)
	}
	return model.ControlOperatorCase{
		ID:                 caseID,
		Title:              firstNonEmpty(title, familyID),
		Severity:           firstNonEmpty(severity, "info"),
		PriorityReason:     "Closed cases are shown because the requested case no longer appears in the missing-hard-barrier queue and controlled evidence was observed.",
		State:              "closed",
		StateReason:        fmt.Sprintf("%d controlled architecture flaw(s) have observed hard-barrier evidence and no missing hard barriers for this focused case.", controlledFlaws),
		Question:           fmt.Sprintf("What evidence proves the %s break path is closed?", firstNonEmpty(title, familyID)),
		Finding:            fmt.Sprintf("This focused case is absent from the missing-hard-barrier board because Ariadne observed hard-barrier evidence for: %s", strings.Join(limitStrings(flawList, 3), "; ")),
		NextStep:           "No proof patch is needed for this case. Keep the observed hard-barrier evidence in place and rerun if the repo, runtime, or policy evidence changes.",
		TargetCount:        len(targetList),
		FlawCount:          len(flawList),
		ControlCount:       0,
		Targets:            targetList,
		Flaws:              flawList,
		EvidenceReferences: evidenceRefs,
		StartingControls:   observedControls,
		StartingTaskIDs:    []string{},
		ProofSurfaces:      observedProofSurfaces,
		EvidenceExamples:   []model.ControlEvidenceExample{},
		ProofPatches:       []model.ControlProofPatch{},
		RerunCommands:      focusedClosedCaseCommands(ctx, caseID),
		SuccessCriteria: []string{
			"The focused case remains absent from the missing-hard-barrier operator case board.",
			"Matching architecture flaws remain controlled with hard_barriers_observed and no missing_hard_barriers.",
			"Evidence references continue to point to the controls that close the path.",
		},
		Limitations: []string{
			"Closed means deterministic hard-barrier evidence was observed; Ariadne still does not prove live enforcement unless runtime enforcement evidence is collected.",
		},
	}, true
}

func controlEvidenceReferencesFromGraph(target string, controls []string, graph model.Graph) []model.EvidenceReference {
	controlSet := map[string]bool{}
	for _, control := range controls {
		controlSet[control] = true
	}
	var refs []model.EvidenceReference
	for _, node := range graph.Nodes {
		if !controlSet[node.ID] || node.Type != "control" || node.Source == "" {
			continue
		}
		summary := "Control evidence was observed."
		if node.Label != "" {
			summary = fmt.Sprintf("Control evidence was observed for %s.", node.Label)
		}
		refs = append(refs, model.EvidenceReference{
			Target:  target,
			ID:      node.ID,
			Kind:    "control",
			Source:  node.Source,
			Summary: summary,
		})
	}
	return dedupeEvidenceReferences(refs)
}

func controlledFlawMatchesFamily(flaw model.ZeroTrustArchitecture, familyID string) (string, []string, bool) {
	if flaw.Status != model.ZeroTrustControlled || len(flaw.ControlTest.MissingHardBarriers) > 0 {
		return "", nil, false
	}
	controls := append([]string{}, flaw.ControlTest.HardBarriersObserved...)
	if len(controls) == 0 {
		controls = append(controls, flaw.Controls...)
	}
	for _, control := range append(append([]string{}, controls...), flaw.Controls...) {
		id, title := architectureControlFamily(control)
		if id == familyID {
			return title, controls, true
		}
	}
	return "", nil, false
}

func focusedClosedCaseCommands(ctx controlVerificationCommandContext, caseID string) []string {
	mode := firstNonEmpty(ctx.Mode, "repo")
	agent := firstNonEmpty(ctx.Agent, "all")
	status := firstNonEmpty(ctx.StatusFilter, "breaking")
	if ctx.RunKind == "case_board_scan" {
		targetsArg := targetsFileCommandArg(ctx.TargetsFile)
		return []string{
			fmt.Sprintf("ariadne cases --targets %s --mode %s --agent %s --status %s --case %s", targetsArg, shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(status), shellQuoteCommandArg(caseID)),
			fmt.Sprintf("ariadne architecture --targets %s --mode %s --agent %s --status all", targetsArg, shellQuoteCommandArg(mode), shellQuoteCommandArg(agent)),
		}
	}
	path := firstNonEmpty(ctx.Path, "<target-path>")
	return []string{
		fmt.Sprintf("ariadne cases --path %s --mode %s --agent %s --status %s --case %s", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(status), shellQuoteCommandArg(caseID)),
		fmt.Sprintf("ariadne architecture --path %s --mode %s --agent %s --status all", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent)),
	}
}

func proofPatchesWithRerunCommands(patches []model.ControlProofPatch, rewrite func([]string) []string) []model.ControlProofPatch {
	if len(patches) == 0 {
		return []model.ControlProofPatch{}
	}
	out := make([]model.ControlProofPatch, 0, len(patches))
	for _, patch := range patches {
		patch.RerunCommands = rewrite(patch.RerunCommands)
		out = append(out, patch)
	}
	return out
}

func caseBoardFocusedRerunCommands(commands []string, caseID string) []string {
	out := make([]string, 0, len(commands))
	for _, command := range commands {
		if strings.HasPrefix(command, "ariadne cases ") && !strings.Contains(command, " --case ") {
			command += " --case " + shellQuoteCommandArg(caseID)
		}
		out = append(out, command)
	}
	return out
}

func controlOperatorCaseMatches(item model.ControlOperatorCase, filter string) bool {
	normalized := normalizeControlOperatorCaseID(filter)
	return normalized != "" && (normalizeControlOperatorCaseID(item.ID) == normalized || normalizeControlOperatorCaseID(item.Title) == normalized)
}

func normalizeControlOperatorCaseID(value string) string {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "case:")
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if b.Len() > 0 && !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

func nonNilArchitectureClosures(items []model.ArchitectureClosure) []model.ArchitectureClosure {
	if items == nil {
		return []model.ArchitectureClosure{}
	}
	return items
}

func nonNilArchitectureClosureFamilies(items []model.ArchitectureClosureFamily) []model.ArchitectureClosureFamily {
	if items == nil {
		return []model.ArchitectureClosureFamily{}
	}
	return items
}

func nonNilControlBreakPathWorkstreams(items []model.ControlBreakPathWorkstream) []model.ControlBreakPathWorkstream {
	if items == nil {
		return []model.ControlBreakPathWorkstream{}
	}
	return items
}

func nonNilControlProofSpecs(items []model.ControlProofSpec) []model.ControlProofSpec {
	if items == nil {
		return []model.ControlProofSpec{}
	}
	return items
}

func nonNilControlVerificationTasks(items []model.ControlVerificationTask) []model.ControlVerificationTask {
	if items == nil {
		return []model.ControlVerificationTask{}
	}
	return items
}

func nonNilControlOperatorCases(items []model.ControlOperatorCase) []model.ControlOperatorCase {
	if items == nil {
		return []model.ControlOperatorCase{}
	}
	return items
}

func caseBoardRerunCommands(commands []string) []string {
	out := make([]string, 0, len(commands))
	for _, command := range commands {
		out = append(out, strings.ReplaceAll(command, "ariadne controls", "ariadne cases"))
	}
	return out
}

func caseBoardSuccessCriteria(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.ReplaceAll(item, "control catalog workstreams", "operator case board")
		item = strings.ReplaceAll(item, "controls output", "case board")
		out = append(out, item)
	}
	return out
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

func renderArchitectureCaseWorkflow(w io.Writer, families []model.ArchitectureClosureFamily, ctx controlVerificationCommandContext, limit int) {
	if len(families) == 0 {
		return
	}
	fmt.Fprintf(w, "  Operator case workflow:\n")
	fmt.Fprintf(w, "    Board: %s\n", architectureCaseBoardCommand(ctx))
	fmt.Fprintf(w, "    Focus cases:\n")
	if limit <= 0 || limit > len(families) {
		limit = len(families)
	}
	for _, family := range families[:limit] {
		fmt.Fprintf(w, "      - %s %s (%s): %s\n",
			strings.ToUpper(family.Severity),
			family.Title,
			architectureCaseID(family),
			architectureCaseFocusCommand(ctx, family),
		)
	}
	if len(families) > limit {
		fmt.Fprintf(w, "      - %d more operator cases in `ariadne cases` output\n", len(families)-limit)
	}
}

func architectureCaseBoardCommand(ctx controlVerificationCommandContext) string {
	mode := firstNonEmpty(ctx.Mode, "repo")
	agent := firstNonEmpty(ctx.Agent, "all")
	status := firstNonEmpty(ctx.StatusFilter, "breaking")
	if ctx.RunKind == "case_board_scan" {
		return fmt.Sprintf("ariadne cases --targets %s --mode %s --agent %s --status %s", targetsFileCommandArg(ctx.TargetsFile), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(status))
	}
	path := firstNonEmpty(ctx.Path, "<target-path>")
	return fmt.Sprintf("ariadne cases --path %s --mode %s --agent %s --status %s", shellQuoteCommandArg(path), shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(status))
}

func architectureCaseFocusCommand(ctx controlVerificationCommandContext, family model.ArchitectureClosureFamily) string {
	return architectureCaseBoardCommand(ctx) + " --case " + shellQuoteCommandArg(architectureCaseID(family))
}

func architectureCaseID(family model.ArchitectureClosureFamily) string {
	if strings.HasPrefix(family.ID, "case:") {
		return family.ID
	}
	return "case:" + family.ID
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
			controlOperatorCaseDisplayTitle(item),
			item.ID,
			item.ControlCount,
			item.FlawCount,
			item.TargetCount,
		)
		if item.Question != "" {
			fmt.Fprintf(w, "      Question: %s\n", item.Question)
		}
		if item.State != "" {
			fmt.Fprintf(w, "      State: %s - %s\n", item.State, item.StateReason)
		}
		if item.PriorityReason != "" {
			fmt.Fprintf(w, "      Priority: %s\n", item.PriorityReason)
		}
		if item.Finding != "" {
			fmt.Fprintf(w, "      Why this case exists: %s\n", item.Finding)
		}
		if item.NextStep != "" {
			fmt.Fprintf(w, "      Next step: %s\n", item.NextStep)
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
		if len(item.ProofPatches) > 0 {
			fmt.Fprintf(w, "      Proof patches: %s\n", strings.Join(controlProofPatchLines(item.ProofPatches, 2), "; "))
		}
		if len(item.RerunCommands) > 0 {
			fmt.Fprintf(w, "      Rerun: %s\n", strings.Join(limitStrings(item.RerunCommands, 2), "; "))
		}
		if len(item.CompareCommands) > 0 {
			fmt.Fprintf(w, "      Compare loop: %s\n", strings.Join(limitStrings(item.CompareCommands, 3), "; "))
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
			State:              controlOperatorCaseState(workstream),
			StateReason:        controlOperatorCaseStateReason(workstream),
			Question:           controlOperatorCaseQuestion(workstream),
			Finding:            workstream.Rationale,
			NextStep:           controlOperatorCaseNextStep(selectedTasks, workstream),
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
		var proofPatches []model.ControlProofPatch
		var limitations []string
		for _, task := range selectedTasks {
			examples = append(examples, task.EvidenceExamples...)
			proofPatches = append(proofPatches, task.ProofPatches...)
			limitations = append(limitations, task.Limitations...)
		}
		caseItem.EvidenceExamples = dedupeControlEvidenceExamples(examples)
		caseItem.ProofPatches = dedupeControlProofPatches(proofPatches)
		caseItem.Limitations = uniqueSortedStrings(append(caseItem.Limitations, limitations...))
		if len(caseItem.Limitations) == 0 {
			caseItem.Limitations = []string{"Operator cases are deterministic proof guides; they do not prove live enforcement unless Ariadne observes runtime enforcement evidence or the missing hard barriers disappear."}
		}
		out = append(out, caseItem)
	}
	if out == nil {
		return []model.ControlOperatorCase{}
	}
	for i := range out {
		out[i].Rank = i + 1
		out[i].PriorityReason = controlOperatorCasePriorityReason(out[i])
	}
	return out
}

func controlOperatorCaseQuestion(workstream model.ControlBreakPathWorkstream) string {
	if workstream.Title == "" {
		return "What evidence proves this architecture break path is closed?"
	}
	return fmt.Sprintf("What evidence proves the %s break path is closed?", workstream.Title)
}

func controlOperatorCaseState(workstream model.ControlBreakPathWorkstream) string {
	if workstream.ControlCount > 0 {
		return "open"
	}
	return "no_missing_hard_barrier"
}

func controlOperatorCasePriorityReason(item model.ControlOperatorCase) string {
	return fmt.Sprintf("Ranked #%d by deterministic closure priority: %s severity, %d affected flaw(s), %d affected target(s), and %d missing hard-barrier control(s).", item.Rank, strings.ToUpper(item.Severity), item.FlawCount, item.TargetCount, item.ControlCount)
}

func controlOperatorCaseStateReason(workstream model.ControlBreakPathWorkstream) string {
	if workstream.ControlCount == 0 {
		return "No missing hard-barrier controls were returned for this break path."
	}
	return fmt.Sprintf("%d missing hard-barrier control(s) remain for %d architecture flaw(s) across %d target(s).", workstream.ControlCount, workstream.FlawCount, workstream.TargetCount)
}

func controlOperatorCaseDisplayTitle(item model.ControlOperatorCase) string {
	if item.Rank > 0 {
		return fmt.Sprintf("#%d %s", item.Rank, item.Title)
	}
	return item.Title
}

func controlOperatorCaseIsClosed(item model.ControlOperatorCase) bool {
	state := strings.ToLower(strings.TrimSpace(item.State))
	return state == "closed" || state == "controlled"
}

func controlOperatorCaseNextStep(tasks []model.ControlVerificationTask, workstream model.ControlBreakPathWorkstream) string {
	if len(tasks) > 0 {
		task := tasks[0]
		surface := firstString(task.ProofSurfaces)
		if len(task.EvidenceExamples) > 0 && task.EvidenceExamples[0].Surface != "" {
			surface = task.EvidenceExamples[0].Surface
		}
		if task.Control != "" && surface != "" {
			return fmt.Sprintf("Add or verify %s evidence at %s, then rerun this case.", task.Control, surface)
		}
		if task.Control != "" {
			return fmt.Sprintf("Add or verify %s evidence, then rerun this case.", task.Control)
		}
	}
	if len(workstream.StartingControls) > 0 {
		return fmt.Sprintf("Start by proving %s, then rerun this case.", workstream.StartingControls[0])
	}
	return "Review the evidence references and add proof for the missing hard-barrier controls."
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

func dedupeControlProofPatches(items []model.ControlProofPatch) []model.ControlProofPatch {
	seen := map[string]bool{}
	var out []model.ControlProofPatch
	for _, item := range items {
		key := item.Control + "\x00" + item.Surface + "\x00" + item.Operation + "\x00" + item.Example
		if key == "\x00\x00\x00" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	if out == nil {
		return []model.ControlProofPatch{}
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
		if len(task.ProofPatches) > 0 {
			fmt.Fprintf(w, "      Proof patches: %s\n", strings.Join(controlProofPatchLines(task.ProofPatches, 2), "; "))
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
	TargetsFile  string
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
		rerunCommands := controlVerificationCommands(ctx)
		successCriteria := controlVerificationSuccessCriteria(item.Control)
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
			ProofPatches:         controlProofPatches(item.Control, proofSurfaces, proof.RecognizedIndicators, rerunCommands, successCriteria),
			Actions:              append([]string{}, item.Actions...),
			RerunCommands:        rerunCommands,
			SuccessCriteria:      successCriteria,
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
		targetsArg := targetsFileCommandArg(ctx.TargetsFile)
		return []string{
			fmt.Sprintf("ariadne controls --targets %s --mode %s --agent %s --status %s", targetsArg, shellQuoteCommandArg(mode), shellQuoteCommandArg(agent), shellQuoteCommandArg(status)),
			fmt.Sprintf("ariadne architecture --targets %s --mode %s --agent %s --status all", targetsArg, shellQuoteCommandArg(mode), shellQuoteCommandArg(agent)),
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

func controlProofPatches(control string, proofSurfaces []string, indicators []string, rerunCommands []string, successCriteria []string) []model.ControlProofPatch {
	surface := preferredControlEvidenceExampleSurface(control, proofSurfaces)
	if surface == "" {
		surface = "supported control evidence surface"
	}
	fields := controlProofPatchFields(firstStrings(controlEvidenceExampleIndicators(control, indicators), 2))
	if len(fields) == 0 {
		return []model.ControlProofPatch{}
	}
	return []model.ControlProofPatch{
		{
			Control:         control,
			Surface:         surface,
			Format:          controlProofPatchFormat(surface),
			Operation:       "add_or_update_declared_evidence",
			Summary:         fmt.Sprintf("Add parser-recognized declared evidence for %s, then rerun Ariadne to verify the graph path changes.", control),
			Fields:          fields,
			Example:         controlEvidenceExampleBody(surface, controlProofPatchIndicators(fields)),
			RerunCommands:   append([]string{}, rerunCommands...),
			SuccessCriteria: append([]string{}, successCriteria...),
			Limitations: []string{
				"Proof patches declare evidence Ariadne can parse; they do not prove live enforcement unless Ariadne also observes runtime enforcement evidence.",
			},
		},
	}
}

func controlProofPatchFields(indicators []string) []model.ControlProofPatchField {
	var fields []model.ControlProofPatchField
	for _, indicator := range indicators {
		name, value := controlEvidenceExampleKeyValue(indicator)
		fields = append(fields, model.ControlProofPatchField{
			Indicator: indicator,
			Name:      name,
			ValueJSON: value,
		})
	}
	if fields == nil {
		return []model.ControlProofPatchField{}
	}
	return fields
}

func controlProofPatchIndicators(fields []model.ControlProofPatchField) []string {
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		out = append(out, field.Indicator)
	}
	return out
}

func controlProofPatchFormat(surface string) string {
	switch {
	case strings.HasSuffix(surface, ".toml") || strings.Contains(surface, "config.toml"):
		return "toml_snippet"
	case strings.HasSuffix(surface, ".md"):
		return "markdown_list"
	case strings.HasSuffix(surface, ".json"):
		return "json_merge_object"
	default:
		return "declared_evidence"
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

func firstString(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return items[0]
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

func controlProofPatchLines(patches []model.ControlProofPatch, limit int) []string {
	if limit <= 0 || limit > len(patches) {
		limit = len(patches)
	}
	var out []string
	for _, patch := range patches[:limit] {
		line := strings.TrimSpace(patch.Surface)
		if line == "" {
			line = strings.TrimSpace(patch.Control)
		}
		var fields []string
		for _, field := range patch.Fields {
			fields = append(fields, field.Name+"="+field.ValueJSON)
		}
		if len(fields) > 0 {
			line += " " + patch.Operation + " " + strings.Join(limitStrings(fields, 3), ", ")
		} else if patch.Operation != "" {
			line += " " + patch.Operation
		}
		if patch.Example != "" {
			line += " Example: " + compactExample(patch.Example)
		}
		out = append(out, strings.TrimSpace(line))
	}
	if len(patches) > limit {
		out = append(out, fmt.Sprintf("%d additional proof patch(es) in JSON output", len(patches)-limit))
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

func targetsFileCommandArg(value string) string {
	return shellQuoteCommandArg(firstNonEmpty(value, "<targets-file>"))
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

func subtractStrings(left []string, right []string) []string {
	rightSet := map[string]bool{}
	for _, value := range right {
		value = strings.TrimSpace(value)
		if value != "" {
			rightSet[value] = true
		}
	}
	var out []string
	for _, value := range left {
		value = strings.TrimSpace(value)
		if value == "" || rightSet[value] {
			continue
		}
		out = append(out, value)
	}
	return uniqueSortedStrings(out)
}

func equalStrings(left []string, right []string) bool {
	left = uniqueSortedStrings(left)
	right = uniqueSortedStrings(right)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
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

func evidenceReferenceLinesBySource(values []model.EvidenceReference, limit int) []string {
	values = dedupeEvidenceReferences(values)
	if len(values) == 0 {
		return []string{}
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
	lines := evidenceReferenceLines(compact, limit)
	if len(values) > len(compact) && limit > 0 && len(compact) > limit {
		lines[len(lines)-1] = fmt.Sprintf("%d more evidence source(s) in JSON", len(compact)-limit)
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
	if out == nil {
		return []string{}
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
