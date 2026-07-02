package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/prove"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/report"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/storylab"
)

const agentHelp = "agent runtime to inspect: all, claude, codex, cursor, windsurf, continue, aider, gemini, opencode, github-actions"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stdout)
		os.Exit(0)
	}
	switch os.Args[1] {
	case "assess":
		runAssess(os.Args[2:])
	case "self":
		runSelf(os.Args[2:])
	case "prove":
		runProve(os.Args[2:])
	case "architecture":
		runArchitecture(os.Args[2:])
	case "cases":
		runCases(os.Args[2:])
	case "proofs":
		runProofs(os.Args[2:])
	case "controls":
		runControls(os.Args[2:])
	case "compare":
		runCompare(os.Args[2:])
	case "inventory":
		runInventory(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "dashboard":
		runDashboard(os.Args[2:])
	case "stories":
		runStories(os.Args[2:])
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func runAssess(args []string) {
	fs := flag.NewFlagSet("assess", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of assessment targets, one path per line or id,path")
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to assess")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	status := fs.String("status", "breaking", "architecture flaw status filter: breaking, controlled, unknown, not_observed, observed, all")
	caseID := fs.String("case", "", "operator case id to focus, e.g. case:input-trust-boundary")
	controlID := fs.String("control", "", "missing hard-barrier control to focus, e.g. control:input-isolation")
	format := fs.String("format", "summary", "output format: summary, operator, operator-json, table, action, json, html")
	outPath := fs.String("out", "", "write output to file")
	rulesPath := fs.String("rules", "", "custom deterministic rule policy JSON")
	interpretMode := fs.String("interpret", "deterministic", "interpretation mode: deterministic, llm")
	llmReview := fs.String("llm-review", "", "LLM review JSON file to ingest")
	llmCommand := fs.String("llm-command", "", "local LLM reviewer command; reads request JSON on stdin and writes review JSON on stdout")
	llmRequestOut := fs.String("llm-request-out", "", "write redacted LLM review request JSON to file")
	llmTimeout := fs.Int("llm-timeout-seconds", 60, "timeout for --llm-command")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if *targetsFile != "" {
		r, err := prove.RunScan(prove.Options{
			TargetsFile:           *targetsFile,
			Path:                  *path,
			Agent:                 *agent,
			Mode:                  *mode,
			RulesPath:             *rulesPath,
			InterpretMode:         *interpretMode,
			LLMReviewPath:         *llmReview,
			LLMCommand:            *llmCommand,
			LLMRequestOut:         *llmRequestOut,
			LLMTimeout:            time.Duration(*llmTimeout) * time.Second,
			IncludeSensitivePaths: *includeSensitive,
		})
		if err != nil {
			fatal(err)
		}
		if err := report.RenderAssessScanFocused(writer, r, *format, *status, report.AssessFocus{CaseFilter: *caseID, ControlFilter: *controlID}); err != nil {
			fatal(err)
		}
		return
	}
	inventory, err := prove.RunInventory(prove.Options{Path: *path, Agent: *agent, Mode: *mode, IncludeSensitivePaths: *includeSensitive})
	if err != nil {
		fatal(err)
	}
	r, err := prove.RunPath(prove.Options{
		Path:                  *path,
		Agent:                 *agent,
		Mode:                  *mode,
		RulesPath:             *rulesPath,
		InterpretMode:         *interpretMode,
		LLMReviewPath:         *llmReview,
		LLMCommand:            *llmCommand,
		LLMRequestOut:         *llmRequestOut,
		LLMTimeout:            time.Duration(*llmTimeout) * time.Second,
		IncludeSensitivePaths: *includeSensitive,
	})
	if err != nil {
		fatal(err)
	}
	if err := report.RenderAssessFocused(writer, inventory, r, *format, *status, report.AssessFocus{CaseFilter: *caseID, ControlFilter: *controlID}); err != nil {
		fatal(err)
	}
}

func runSelf(args []string) {
	fs := flag.NewFlagSet("self", flag.ExitOnError)
	path := fs.String("path", "", "developer home or mounted endpoint snapshot to assess; defaults to HOME")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "endpoint", "collection mode: endpoint, repo")
	status := fs.String("status", "breaking", "architecture flaw status filter: breaking, controlled, unknown, not_observed, observed, all")
	caseID := fs.String("case", "", "operator case id to focus, e.g. case:identity-credentials")
	controlID := fs.String("control", "", "missing hard-barrier control to focus, e.g. control:credential-isolation")
	format := fs.String("format", "summary", "output format: summary, operator, operator-json, table, action, json, html")
	outPath := fs.String("out", "", "write output to file")
	rulesPath := fs.String("rules", "", "custom deterministic rule policy JSON")
	interpretMode := fs.String("interpret", "deterministic", "interpretation mode: deterministic, llm")
	llmReview := fs.String("llm-review", "", "LLM review JSON file to ingest")
	llmCommand := fs.String("llm-command", "", "local LLM reviewer command; reads request JSON on stdin and writes review JSON on stdout")
	llmRequestOut := fs.String("llm-request-out", "", "write redacted LLM review request JSON to file")
	llmTimeout := fs.Int("llm-timeout-seconds", 60, "timeout for --llm-command")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	bundleDir := fs.String("bundle-dir", "", "write a first-run evidence bundle with summary, runbook, operator packet, dashboard, inventory, cases, and proof plan")
	fs.Parse(args)
	targetPath := strings.TrimSpace(*path)
	if targetPath == "" {
		targetPath = os.Getenv("HOME")
	}
	if targetPath == "" {
		fatal(fmt.Errorf("HOME is not set; pass --path <developer-home-or-endpoint-snapshot>"))
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	inventory, err := prove.RunInventory(prove.Options{Path: targetPath, Agent: *agent, Mode: *mode, IncludeSensitivePaths: *includeSensitive})
	if err != nil {
		fatal(err)
	}
	r, err := prove.RunPath(prove.Options{
		Path:                  targetPath,
		Agent:                 *agent,
		Mode:                  *mode,
		RulesPath:             *rulesPath,
		InterpretMode:         *interpretMode,
		LLMReviewPath:         *llmReview,
		LLMCommand:            *llmCommand,
		LLMRequestOut:         *llmRequestOut,
		LLMTimeout:            time.Duration(*llmTimeout) * time.Second,
		IncludeSensitivePaths: *includeSensitive,
	})
	if err != nil {
		fatal(err)
	}
	focus := report.AssessFocus{CaseFilter: *caseID, ControlFilter: *controlID}
	if *bundleDir != "" {
		exported, err := writeSelfAssessmentBundle(*bundleDir, inventory, r, *status, focus)
		if err != nil {
			fatal(err)
		}
		renderSelfAssessmentBundleSummary(os.Stderr, exported)
	}
	if err := report.RenderAssessFocused(writer, inventory, r, *format, *status, focus); err != nil {
		fatal(err)
	}
}

type selfAssessmentBundleResult struct {
	Directory     string                     `json:"directory"`
	TargetPath    string                     `json:"target_path"`
	Mode          string                     `json:"mode"`
	Agent         string                     `json:"agent"`
	StatusFilter  string                     `json:"status_filter"`
	CaseFilter    string                     `json:"case_filter,omitempty"`
	ControlFilter string                     `json:"control_filter,omitempty"`
	TopCaseID     string                     `json:"top_case_id,omitempty"`
	ReviewOrder   []string                   `json:"review_order"`
	ProofLoop     []string                   `json:"proof_loop"`
	Limitations   []string                   `json:"limitations"`
	Files         []selfAssessmentBundleFile `json:"files"`
}

type selfAssessmentBundleFile struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Description string `json:"description"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
}

func writeSelfAssessmentBundle(dir string, inventory model.InventoryReport, r model.Report, status string, focus report.AssessFocus) (selfAssessmentBundleResult, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return selfAssessmentBundleResult{}, fmt.Errorf("--bundle-dir requires a directory")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}
	assess, err := report.BuildAssessReport(inventory, r, status, focus)
	if err != nil {
		return selfAssessmentBundleResult{}, err
	}
	topCaseID := selfAssessmentBundleCaseID(assess, focus)
	result := selfAssessmentBundleResult{
		Directory:     absDir,
		TargetPath:    r.TargetPath,
		Mode:          r.Story.Mode,
		Agent:         r.Story.Runtime,
		StatusFilter:  assess.StatusFilter,
		CaseFilter:    assess.CaseFilter,
		ControlFilter: assess.ControlFilter,
		TopCaseID:     topCaseID,
		ReviewOrder:   selfAssessmentBundleReviewOrder(),
		ProofLoop:     selfAssessmentBundleProofLoop(r.TargetPath, r.Story.Mode, r.Story.Runtime, assess.StatusFilter, topCaseID),
		Limitations:   selfAssessmentBundleLimitations(),
		Files: []selfAssessmentBundleFile{
			{Name: "assessment.txt", Path: filepath.Join(absDir, "assessment.txt"), Description: "Compact human readout with the decision, evidence, first action, and rerun commands."},
			{Name: "assessment.json", Path: filepath.Join(absDir, "assessment.json"), Description: "Structured assessment contract for automation and UI consumers."},
			{Name: "runbook.txt", Path: filepath.Join(absDir, "runbook.txt"), Description: "Action-first operator runbook with open-first evidence, current step, next step, commands, and closure workflow."},
			{Name: "runbook.json", Path: filepath.Join(absDir, "runbook.json"), Description: "Structured operator runbook for workflow systems and managed UI clients."},
			{Name: "operator-packet.txt", Path: filepath.Join(absDir, "operator-packet.txt"), Description: "Small ticket-style handoff with source refs, graph path, controls, proof checkpoint, commands, and done criteria."},
			{Name: "operator-packet.json", Path: filepath.Join(absDir, "operator-packet.json"), Description: "Structured operator packet for ticketing, workflow systems, and automation."},
			{Name: "dashboard.html", Path: filepath.Join(absDir, "dashboard.html"), Description: "Local operator dashboard with the same assessment evidence."},
			{Name: "inventory.json", Path: filepath.Join(absDir, "inventory.json"), Description: "Deterministic AI surface inventory facts without exposure classification."},
			{Name: "cases.txt", Path: filepath.Join(absDir, "cases.txt"), Description: "Operator case board showing the prioritized closure work."},
			{Name: "cases.json", Path: filepath.Join(absDir, "cases.json"), Description: "Structured operator case board."},
			{Name: "proof-action.txt", Path: filepath.Join(absDir, "proof-action.txt"), Description: "Focused proof action for the top case or selected case."},
			{Name: "proof-plan.json", Path: filepath.Join(absDir, "proof-plan.json"), Description: "Structured proof plan for the top case or selected case."},
			{Name: "README.md", Path: filepath.Join(absDir, "README.md"), Description: "Bundle guide with suggested review order."},
			{Name: "manifest.json", Path: filepath.Join(absDir, "manifest.json"), Description: "Machine-readable list of bundle files. The manifest entry itself is intentionally not self-hashed."},
		},
	}
	add := func(name string, recordMetadata bool, render func(io.Writer) error) error {
		fullPath := filepath.Join(absDir, name)
		if err := writeRenderedFile(fullPath, render); err != nil {
			return err
		}
		if recordMetadata {
			if err := recordSelfAssessmentBundleFileMetadata(&result, name, fullPath); err != nil {
				return err
			}
		}
		return nil
	}
	if err := add("assessment.txt", true, func(w io.Writer) error {
		return report.RenderAssessFocused(w, inventory, r, "summary", status, focus)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("assessment.json", true, func(w io.Writer) error {
		return report.RenderAssessFocused(w, inventory, r, "json", status, focus)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("runbook.txt", true, func(w io.Writer) error {
		return renderSelfAssessmentRunbook(w, assess.OperatorWorkbench.Runbook)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("runbook.json", true, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(assess.OperatorWorkbench.Runbook)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("operator-packet.txt", true, func(w io.Writer) error {
		return report.RenderAssessFocused(w, inventory, r, "operator", status, focus)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("operator-packet.json", true, func(w io.Writer) error {
		return report.RenderAssessFocused(w, inventory, r, "operator-json", status, focus)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("dashboard.html", true, func(w io.Writer) error {
		return report.RenderAssessFocused(w, inventory, r, "html", status, focus)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("inventory.json", true, func(w io.Writer) error {
		return report.RenderInventory(w, inventory, "json")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("cases.txt", true, func(w io.Writer) error {
		return report.RenderCases(w, r, "table", status, focus.CaseFilter)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("cases.json", true, func(w io.Writer) error {
		return report.RenderCases(w, r, "json", status, focus.CaseFilter)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("proof-action.txt", true, func(w io.Writer) error {
		return report.RenderProofs(w, r, "action", status, topCaseID)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("proof-plan.json", true, func(w io.Writer) error {
		return report.RenderProofs(w, r, "json", status, topCaseID)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("README.md", true, func(w io.Writer) error {
		_, err := io.WriteString(w, selfAssessmentBundleReadme(result))
		return err
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("manifest.json", false, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	return result, nil
}

func recordSelfAssessmentBundleFileMetadata(result *selfAssessmentBundleResult, name string, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(contents)
	for idx := range result.Files {
		if result.Files[idx].Name == name {
			result.Files[idx].SizeBytes = info.Size()
			result.Files[idx].SHA256 = fmt.Sprintf("%x", sum[:])
			return nil
		}
	}
	return fmt.Errorf("self-assessment bundle metadata target not found: %s", name)
}

func selfAssessmentBundleCaseID(assess model.AssessReport, focus report.AssessFocus) string {
	for _, candidate := range []string{
		focus.CaseFilter,
		assess.CaseFilter,
		assess.Decision.TopCaseID,
		assess.FirstAction.CaseID,
	} {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate)
		}
	}
	if len(assess.TopCases) > 0 {
		return assess.TopCases[0].ID
	}
	return ""
}

func selfAssessmentBundleReviewOrder() []string {
	return []string{
		"Read `assessment.txt` for the executive readout, decision, signal/noise boundary, and first action.",
		"Use `runbook.txt` as the action-first operator workflow: open-first evidence, current step, commands, artifacts, and closure workflow. Use `runbook.json` for UI clients and workflow automation.",
		"Use `operator-packet.txt` as the compact ticket or handoff: source refs, graph path, controls, proof checkpoint, commands, and done criteria. Use `operator-packet.json` for automation.",
		"Open `dashboard.html` for the operator dashboard with evidence links, proof bundle rows, lifecycle, and case queue.",
		"Use `proof-action.txt` to inspect the exact proof evidence Ariadne expects for the focused case.",
		"Use `proof-plan.json`, `assessment.json`, `inventory.json`, and `cases.json` for automation, ticket metadata, or deeper review.",
		"Run the proof loop commands below only after reviewing generated proof evidence and deciding what should be applied.",
	}
}

func selfAssessmentBundleProofLoop(targetPath string, mode string, agent string, status string, caseID string) []string {
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return []string{}
	}
	base := fmt.Sprintf("ariadne proofs --path %s --mode %s --agent %s --status %s --case %s",
		selfBundleShellQuoteArg(targetPath),
		selfBundleShellQuoteArg(selfBundleFirstNonEmpty(mode, "endpoint")),
		selfBundleShellQuoteArg(selfBundleFirstNonEmpty(agent, "all")),
		selfBundleShellQuoteArg(selfBundleFirstNonEmpty(status, "breaking")),
		selfBundleShellQuoteArg(caseID),
	)
	return []string{
		base + " --format action",
		base + " --format json --out before-proof.json",
		base + " --patch-dir proof-patches",
		base + " --format json --out after-proof.json",
		"ariadne compare --before before-proof.json --after after-proof.json --format html --out case-compare.html",
	}
}

func renderSelfAssessmentRunbook(w io.Writer, runbook model.AssessOperatorRunbook) error {
	fmt.Fprintf(w, "Ariadne Operator Runbook\n")
	if !runbook.Available {
		fmt.Fprintf(w, "No operator runbook is available for the current assessment filter.\n")
		return nil
	}
	fmt.Fprintf(w, "Case: %s", selfBundleFirstNonEmpty(runbook.Case.ID, "not recorded"))
	if runbook.Case.Title != "" {
		fmt.Fprintf(w, " (%s)", runbook.Case.Title)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "State: %s\n", selfBundleFirstNonEmpty(runbook.Case.State, "unknown"))
	if runbook.CurrentControl != "" {
		fmt.Fprintf(w, "Control: %s\n", runbook.CurrentControl)
	}
	if runbook.ProofSurface != "" {
		fmt.Fprintf(w, "Proof surface: %s\n", runbook.ProofSurface)
	}
	fmt.Fprintf(w, "\nOpen first:\n")
	if len(runbook.OpenFirst) == 0 {
		fmt.Fprintf(w, "  - none\n")
	} else {
		for _, ref := range runbook.OpenFirst {
			fmt.Fprintf(w, "  - %s\n", selfAssessmentRunbookEvidenceLine(ref))
		}
	}
	fmt.Fprintf(w, "\nWhy this case:\n")
	renderSelfAssessmentStringList(w, runbook.WhyThisCase)
	fmt.Fprintf(w, "\nDo next:\n")
	renderSelfAssessmentStepLine(w, runbook.CurrentStep)
	if runbook.NextStep.ID != "" {
		renderSelfAssessmentStepLine(w, runbook.NextStep)
	}
	fmt.Fprintf(w, "\nFiles:\n")
	renderSelfAssessmentStringList(w, runbook.Files)
	fmt.Fprintf(w, "\nArtifacts:\n")
	renderSelfAssessmentStringList(w, runbook.Artifacts)
	fmt.Fprintf(w, "\nCommands:\n")
	renderSelfAssessmentStringList(w, runbook.Commands)
	fmt.Fprintf(w, "\nDone when:\n")
	renderSelfAssessmentStringList(w, runbook.DoneCriteria)
	fmt.Fprintf(w, "\nClosure workflow:\n")
	if len(runbook.ClosureWorkflow) == 0 {
		fmt.Fprintf(w, "  - none\n")
	} else {
		for _, step := range runbook.ClosureWorkflow {
			renderSelfAssessmentStepLine(w, step)
		}
	}
	if len(runbook.Limitations) > 0 {
		fmt.Fprintf(w, "\nLimits:\n")
		renderSelfAssessmentStringList(w, runbook.Limitations)
	}
	return nil
}

func selfAssessmentRunbookEvidenceLine(ref model.EvidenceReference) string {
	source := selfBundleFirstNonEmpty(ref.Source, ref.ID, ref.Kind, "not recorded")
	if ref.LineStart > 0 && ref.LineEnd > ref.LineStart {
		source = fmt.Sprintf("%s:%d-%d", source, ref.LineStart, ref.LineEnd)
	} else if ref.LineStart > 0 {
		source = fmt.Sprintf("%s:%d", source, ref.LineStart)
	}
	fact := selfBundleFirstNonEmpty(ref.Summary, ref.Kind)
	if fact == "" {
		return source
	}
	return fmt.Sprintf("%s - %s", source, fact)
}

func renderSelfAssessmentStepLine(w io.Writer, step model.AssessClosureLoopStep) {
	if step.ID == "" {
		return
	}
	label := selfBundleFirstNonEmpty(step.Title, step.ID)
	status := selfBundleFirstNonEmpty(step.Status, "unknown")
	if step.Step > 0 {
		fmt.Fprintf(w, "  - %d. %s [%s]", step.Step, label, status)
	} else {
		fmt.Fprintf(w, "  - %s [%s]", label, status)
	}
	if step.Summary != "" {
		fmt.Fprintf(w, ": %s", step.Summary)
	}
	fmt.Fprintln(w)
}

func renderSelfAssessmentStringList(w io.Writer, items []string) {
	if len(items) == 0 {
		fmt.Fprintf(w, "  - none\n")
		return
	}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		fmt.Fprintf(w, "  - %s\n", item)
	}
}

func selfAssessmentBundleLimitations() []string {
	return []string{
		"The bundle is generated from deterministic local facts, typed parsers, and graph evidence; it does not execute agents, MCP servers, package managers, or tools.",
		"Proof patches are suggested evidence files for review. Exporting or copying them does not prove live enforcement by itself.",
		"Treat `case-compare.html` as the closure readout after rerunning Ariadne against the changed target.",
		"Private histories, transcripts, paste caches, and sensitive files are summarized or path-modeled; Ariadne does not emit secret values.",
	}
}

func selfBundleFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func selfBundleShellQuoteArg(value string) string {
	value = strings.TrimSpace(value)
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

func writeRenderedFile(path string, render func(io.Writer) error) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return render(file)
}

func selfAssessmentBundleReadme(result selfAssessmentBundleResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Ariadne Self-Assessment Bundle\n\n")
	fmt.Fprintf(&b, "Target: `%s`\n", result.TargetPath)
	fmt.Fprintf(&b, "Mode: `%s`  Agent: `%s`  Filter: `%s`\n", result.Mode, result.Agent, result.StatusFilter)
	if result.TopCaseID != "" {
		fmt.Fprintf(&b, "Start case: `%s`\n", result.TopCaseID)
	}
	if result.ControlFilter != "" {
		fmt.Fprintf(&b, "Focused control: `%s`\n", result.ControlFilter)
	}
	fmt.Fprintf(&b, "\n## What This Bundle Answers\n\n")
	fmt.Fprintf(&b, "Ariadne collected deterministic target facts, built the agent exposure graph, ranked the first operator case, and generated the proof workflow for closing or downgrading that case. The bundle is intended for local review, ticket attachment, or handoff to another operator.\n")
	fmt.Fprintf(&b, "\n## Suggested Review Order\n\n")
	for idx, item := range result.ReviewOrder {
		fmt.Fprintf(&b, "%d. %s\n", idx+1, item)
	}
	if len(result.ProofLoop) > 0 {
		fmt.Fprintf(&b, "\n## Proof Loop Commands\n\n")
		fmt.Fprintf(&b, "Run these from a working directory where you want `before-proof.json`, `after-proof.json`, `proof-patches/`, and `case-compare.html` written.\n\n")
		for _, command := range result.ProofLoop {
			fmt.Fprintf(&b, "```bash\n%s\n```\n\n", command)
		}
	}
	fmt.Fprintf(&b, "## Files\n\n")
	for _, file := range result.Files {
		if file.SHA256 != "" {
			fmt.Fprintf(&b, "- `%s`: %s (SHA-256 `%s`, %d bytes.)\n", file.Name, file.Description, file.SHA256, file.SizeBytes)
			continue
		}
		fmt.Fprintf(&b, "- `%s`: %s\n", file.Name, file.Description)
	}
	if len(result.Limitations) > 0 {
		fmt.Fprintf(&b, "\n## Limits And Privacy\n\n")
		for _, limitation := range result.Limitations {
			fmt.Fprintf(&b, "- %s\n", limitation)
		}
	}
	return b.String()
}

func renderSelfAssessmentBundleSummary(w io.Writer, result selfAssessmentBundleResult) {
	fmt.Fprintf(w, "Exported Ariadne self-assessment bundle to %s\n", result.Directory)
	if result.TopCaseID != "" {
		fmt.Fprintf(w, "Top case: %s\n", result.TopCaseID)
	}
	fmt.Fprintf(w, "Open first: %s\n", filepath.Join(result.Directory, "assessment.txt"))
	fmt.Fprintf(w, "Runbook: %s\n", filepath.Join(result.Directory, "runbook.txt"))
	fmt.Fprintf(w, "Runbook JSON: %s\n", filepath.Join(result.Directory, "runbook.json"))
	fmt.Fprintf(w, "Operator packet: %s\n", filepath.Join(result.Directory, "operator-packet.txt"))
	fmt.Fprintf(w, "Operator packet JSON: %s\n", filepath.Join(result.Directory, "operator-packet.json"))
	fmt.Fprintf(w, "Dashboard: %s\n", filepath.Join(result.Directory, "dashboard.html"))
	fmt.Fprintf(w, "Proof action: %s\n", filepath.Join(result.Directory, "proof-action.txt"))
}

func runCases(args []string) {
	fs := flag.NewFlagSet("cases", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of operator case targets, one path per line or id,path")
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to inspect")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	status := fs.String("status", "breaking", "architecture flaw status filter: breaking, controlled, unknown, not_observed, observed, all")
	caseID := fs.String("case", "", "operator case id to focus, e.g. case:input-trust-boundary")
	format := fs.String("format", "table", "output format: table, json, html")
	outPath := fs.String("out", "", "write output to file")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	if *targetsFile != "" {
		r, err := prove.RunScan(prove.Options{
			TargetsFile:           *targetsFile,
			Agent:                 *agent,
			Mode:                  *mode,
			IncludeSensitivePaths: *includeSensitive,
		})
		if err != nil {
			fatal(err)
		}
		writer, closeFn, err := outputWriter(*outPath)
		if err != nil {
			fatal(err)
		}
		defer closeFn()
		if err := report.RenderCasesScan(writer, r, *format, *status, *caseID); err != nil {
			fatal(err)
		}
		return
	}
	r, err := prove.RunPath(prove.Options{
		Path:                  *path,
		Agent:                 *agent,
		Mode:                  *mode,
		IncludeSensitivePaths: *includeSensitive,
	})
	if err != nil {
		fatal(err)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderCases(writer, r, *format, *status, *caseID); err != nil {
		fatal(err)
	}
}

func runProofs(args []string) {
	fs := flag.NewFlagSet("proofs", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of proof-plan targets, one path per line or id,path")
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to inspect")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	status := fs.String("status", "breaking", "architecture flaw status filter: breaking, controlled, unknown, not_observed, observed, all")
	caseID := fs.String("case", "", "operator case id to focus, e.g. case:input-trust-boundary")
	format := fs.String("format", "table", "output format: table, action, json, html")
	outPath := fs.String("out", "", "write output to file")
	patchDir := fs.String("patch-dir", "", "write suggested proof patch files and manifest to this directory")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	if *targetsFile != "" {
		if *patchDir != "" {
			fatal(fmt.Errorf("--patch-dir is only supported with --path, not --targets"))
		}
		r, err := prove.RunScan(prove.Options{
			TargetsFile:           *targetsFile,
			Agent:                 *agent,
			Mode:                  *mode,
			IncludeSensitivePaths: *includeSensitive,
		})
		if err != nil {
			fatal(err)
		}
		writer, closeFn, err := outputWriter(*outPath)
		if err != nil {
			fatal(err)
		}
		defer closeFn()
		if err := report.RenderProofsScan(writer, r, *format, *status, *caseID); err != nil {
			fatal(err)
		}
		return
	}
	r, err := prove.RunPath(prove.Options{
		Path:                  *path,
		Agent:                 *agent,
		Mode:                  *mode,
		IncludeSensitivePaths: *includeSensitive,
	})
	if err != nil {
		fatal(err)
	}
	if *patchDir != "" {
		plan, err := report.BuildProofPlanForReport(r, *status, *caseID)
		if err != nil {
			fatal(err)
		}
		exported, err := report.ExportProofPatchFiles(*patchDir, plan)
		if err != nil {
			fatal(err)
		}
		renderProofPatchExportSummary(os.Stderr, exported)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderProofs(writer, r, *format, *status, *caseID); err != nil {
		fatal(err)
	}
}

func renderProofPatchExportSummary(w io.Writer, exported report.ProofPatchExportResult) {
	fmt.Fprintf(w, "Exported %d proof patch(es) to %s\n", exported.PatchCount, exported.Directory)
	if exported.ManifestPath != "" {
		fmt.Fprintf(w, "Manifest: %s\n", exported.ManifestPath)
	}
	if exported.ReadmePath != "" {
		fmt.Fprintf(w, "README: %s\n", exported.ReadmePath)
	}
	if len(exported.ClosureControls) > 0 || len(exported.ClosureFiles) > 0 || exported.ClosureRule != "" {
		fmt.Fprintf(w, "Closure bundle:\n")
		if len(exported.ClosureControls) > 0 {
			fmt.Fprintf(w, "  Controls: %s\n", strings.Join(exported.ClosureControls, ", "))
		}
		if len(exported.ClosureFiles) > 0 {
			fmt.Fprintf(w, "  Generated files: %s\n", strings.Join(exported.ClosureFiles, ", "))
		}
		if exported.ClosureRule != "" {
			fmt.Fprintf(w, "  Rule: %s\n", exported.ClosureRule)
		}
	}
	if len(exported.FileDetails) == 0 {
		return
	}
	fmt.Fprintf(w, "Generated proof files:\n")
	for _, file := range exported.FileDetails {
		generatedPath := file.GeneratedPath
		if generatedPath == "" {
			generatedPath = filepath.Join(exported.Directory, file.Path)
		}
		destination := file.DestinationPath
		if destination == "" {
			destination = file.SuggestedDestination
		}
		if destination != "" {
			fmt.Fprintf(w, "  - %s -> %s\n", generatedPath, destination)
		} else {
			fmt.Fprintf(w, "  - %s\n", generatedPath)
		}
		if file.Surface != "" {
			fmt.Fprintf(w, "    Surface: %s (%s)\n", file.Surface, file.Format)
		}
		if len(file.Controls) > 0 {
			fmt.Fprintf(w, "    Controls: %s\n", strings.Join(file.Controls, ", "))
		}
		if file.ApplyCommand != "" {
			fmt.Fprintf(w, "    Review/apply: %s\n", file.ApplyCommand)
		}
	}
	fmt.Fprintf(w, "Review generated proof evidence before applying it; export does not prove live enforcement.\n")
}

func runControls(args []string) {
	fs := flag.NewFlagSet("controls", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of control catalog targets, one path per line or id,path")
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to inspect")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	status := fs.String("status", "breaking", "architecture flaw status filter: breaking, controlled, unknown, not_observed, observed, all")
	format := fs.String("format", "table", "output format: table, json, html")
	outPath := fs.String("out", "", "write output to file")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	if *targetsFile != "" {
		r, err := prove.RunScan(prove.Options{
			TargetsFile:           *targetsFile,
			Agent:                 *agent,
			Mode:                  *mode,
			IncludeSensitivePaths: *includeSensitive,
		})
		if err != nil {
			fatal(err)
		}
		writer, closeFn, err := outputWriter(*outPath)
		if err != nil {
			fatal(err)
		}
		defer closeFn()
		if err := report.RenderControlsScan(writer, r, *format, *status); err != nil {
			fatal(err)
		}
		return
	}
	r, err := prove.RunPath(prove.Options{
		Path:                  *path,
		Agent:                 *agent,
		Mode:                  *mode,
		IncludeSensitivePaths: *includeSensitive,
	})
	if err != nil {
		fatal(err)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderControls(writer, r, *format, *status); err != nil {
		fatal(err)
	}
}

func runArchitecture(args []string) {
	fs := flag.NewFlagSet("architecture", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of architecture scan targets, one path per line or id,path")
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to inspect")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	status := fs.String("status", "breaking", "architecture flaw status filter: breaking, controlled, unknown, not_observed, observed, all")
	format := fs.String("format", "table", "output format: table, json, html")
	outPath := fs.String("out", "", "write output to file")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	if *targetsFile != "" {
		r, err := prove.RunScan(prove.Options{
			TargetsFile:           *targetsFile,
			Agent:                 *agent,
			Mode:                  *mode,
			IncludeSensitivePaths: *includeSensitive,
		})
		if err != nil {
			fatal(err)
		}
		writer, closeFn, err := outputWriter(*outPath)
		if err != nil {
			fatal(err)
		}
		defer closeFn()
		if err := report.RenderArchitectureScan(writer, r, *format, *status); err != nil {
			fatal(err)
		}
		return
	}
	r, err := prove.RunPath(prove.Options{
		Path:                  *path,
		Agent:                 *agent,
		Mode:                  *mode,
		IncludeSensitivePaths: *includeSensitive,
	})
	if err != nil {
		fatal(err)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderArchitecture(writer, r, *format, *status); err != nil {
		fatal(err)
	}
}

func runCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	beforePath := fs.String("before", "", "earlier Ariadne proofs/cases/assess JSON file")
	afterPath := fs.String("after", "", "later Ariadne proofs/cases/assess JSON file")
	format := fs.String("format", "table", "output format: table, json, html")
	outPath := fs.String("out", "", "write output to file")
	fs.Parse(args)
	if *beforePath == "" || *afterPath == "" {
		fatal(fmt.Errorf("usage: ariadne compare --before before.json --after after.json [--format table|json|html]"))
	}
	beforeRaw, err := os.ReadFile(*beforePath)
	if err != nil {
		fatal(err)
	}
	afterRaw, err := os.ReadFile(*afterPath)
	if err != nil {
		fatal(err)
	}
	compare, err := report.BuildCaseCompareReport(beforeRaw, afterRaw, *beforePath, *afterPath)
	if err != nil {
		fatal(err)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderCaseCompare(writer, compare, *format); err != nil {
		fatal(err)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of scan targets, one path per line or id,path")
	path := fs.String("path", "", "single target path to scan")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	format := fs.String("format", "table", "output format: table, json, dot, mermaid")
	outPath := fs.String("out", "", "write output to file")
	rulesPath := fs.String("rules", "", "custom deterministic rule policy JSON")
	interpretMode := fs.String("interpret", "deterministic", "interpretation mode: deterministic, llm")
	llmReview := fs.String("llm-review", "", "LLM review JSON file to ingest")
	llmCommand := fs.String("llm-command", "", "local LLM reviewer command; reads request JSON on stdin and writes review JSON on stdout")
	llmRequestOut := fs.String("llm-request-out", "", "write redacted LLM review request JSON to file")
	llmTimeout := fs.Int("llm-timeout-seconds", 60, "timeout for --llm-command")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	r, err := prove.RunScan(prove.Options{
		TargetsFile:           *targetsFile,
		Path:                  *path,
		Agent:                 *agent,
		Mode:                  *mode,
		RulesPath:             *rulesPath,
		InterpretMode:         *interpretMode,
		LLMReviewPath:         *llmReview,
		LLMCommand:            *llmCommand,
		LLMRequestOut:         *llmRequestOut,
		LLMTimeout:            time.Duration(*llmTimeout) * time.Second,
		IncludeSensitivePaths: *includeSensitive,
	})
	if err != nil {
		fatal(err)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderScan(writer, r, *format); err != nil {
		fatal(err)
	}
}

func runInventory(args []string) {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to inventory")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	format := fs.String("format", "table", "output format: table, json, html, dot, mermaid")
	outPath := fs.String("out", "", "write output to file")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	r, err := prove.RunInventory(prove.Options{Path: *path, Agent: *agent, Mode: *mode, IncludeSensitivePaths: *includeSensitive})
	if err != nil {
		fatal(err)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderInventory(writer, r, *format); err != nil {
		fatal(err)
	}
}

func runProve(args []string) {
	fs := flag.NewFlagSet("prove", flag.ExitOnError)
	storyID := fs.String("story", "", "story id to prove")
	storyRoot := fs.String("story-root", "testdata/storylab", "story lab root")
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to prove when --story is not set")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	format := fs.String("format", "table", "output format: table, json, dot, mermaid")
	outPath := fs.String("out", "", "write output to file")
	rulesPath := fs.String("rules", "", "custom deterministic rule policy JSON")
	interpretMode := fs.String("interpret", "deterministic", "interpretation mode: deterministic, llm")
	llmReview := fs.String("llm-review", "", "LLM review JSON file to ingest")
	llmCommand := fs.String("llm-command", "", "local LLM reviewer command; reads request JSON on stdin and writes review JSON on stdout")
	llmRequestOut := fs.String("llm-request-out", "", "write redacted LLM review request JSON to file")
	llmTimeout := fs.Int("llm-timeout-seconds", 60, "timeout for --llm-command")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	var r model.Report
	var err error
	if *storyID != "" {
		resolvedStoryRoot, rootErr := storyRootFromFlag(fs, *storyRoot)
		if rootErr != nil {
			fatal(rootErr)
		}
		r, err = prove.RunStory(prove.Options{
			StoryRoot:             resolvedStoryRoot,
			StoryID:               *storyID,
			RulesPath:             *rulesPath,
			InterpretMode:         *interpretMode,
			LLMReviewPath:         *llmReview,
			LLMCommand:            *llmCommand,
			LLMRequestOut:         *llmRequestOut,
			LLMTimeout:            time.Duration(*llmTimeout) * time.Second,
			IncludeSensitivePaths: *includeSensitive,
		})
	} else {
		r, err = prove.RunPath(prove.Options{
			Path:                  *path,
			Agent:                 *agent,
			Mode:                  *mode,
			RulesPath:             *rulesPath,
			InterpretMode:         *interpretMode,
			LLMReviewPath:         *llmReview,
			LLMCommand:            *llmCommand,
			LLMRequestOut:         *llmRequestOut,
			LLMTimeout:            time.Duration(*llmTimeout) * time.Second,
			IncludeSensitivePaths: *includeSensitive,
		})
	}
	if err != nil {
		fatal(err)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.Render(writer, r, *format); err != nil {
		fatal(err)
	}
	if r.RunKind == "story" && !r.Matched {
		os.Exit(1)
	}
}

func runDashboard(args []string) {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of scan targets, one path per line or id,path")
	path := fs.String("path", ".", "single target path to inspect")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	outPath := fs.String("out", "ariadne-dashboard.html", "write HTML dashboard to file")
	view := fs.String("view", "assessment", "dashboard view: assessment, exposure")
	status := fs.String("status", "breaking", "architecture flaw status filter for assessment view: breaking, controlled, unknown, not_observed, observed, all")
	caseID := fs.String("case", "", "operator case id to focus in assessment view, e.g. case:input-trust-boundary")
	controlID := fs.String("control", "", "missing hard-barrier control to focus in assessment view, e.g. control:input-isolation")
	rulesPath := fs.String("rules", "", "custom deterministic rule policy JSON")
	interpretMode := fs.String("interpret", "deterministic", "interpretation mode: deterministic, llm")
	llmReview := fs.String("llm-review", "", "LLM review JSON file to ingest")
	llmCommand := fs.String("llm-command", "", "local LLM reviewer command; reads request JSON on stdin and writes review JSON on stdout")
	llmRequestOut := fs.String("llm-request-out", "", "write redacted LLM review request JSON to file")
	llmTimeout := fs.Int("llm-timeout-seconds", 60, "timeout for --llm-command")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	dashboardView := strings.ToLower(strings.TrimSpace(*view))
	if dashboardView == "" {
		dashboardView = "assessment"
	}
	if *targetsFile != "" {
		r, err := prove.RunScan(prove.Options{
			TargetsFile:           *targetsFile,
			Path:                  *path,
			Agent:                 *agent,
			Mode:                  *mode,
			RulesPath:             *rulesPath,
			InterpretMode:         *interpretMode,
			LLMReviewPath:         *llmReview,
			LLMCommand:            *llmCommand,
			LLMRequestOut:         *llmRequestOut,
			LLMTimeout:            time.Duration(*llmTimeout) * time.Second,
			IncludeSensitivePaths: *includeSensitive,
		})
		if err != nil {
			fatal(err)
		}
		var renderErr error
		switch dashboardView {
		case "assessment", "assess", "operator":
			renderErr = report.RenderAssessScanFocused(writer, r, "html", *status, report.AssessFocus{CaseFilter: *caseID, ControlFilter: *controlID})
		case "exposure", "legacy":
			renderErr = report.RenderScan(writer, r, "html")
		default:
			renderErr = fmt.Errorf("unknown dashboard view: %s", *view)
		}
		if renderErr != nil {
			fatal(renderErr)
		}
		return
	}
	r, err := prove.RunPath(prove.Options{
		Path:                  *path,
		Agent:                 *agent,
		Mode:                  *mode,
		RulesPath:             *rulesPath,
		InterpretMode:         *interpretMode,
		LLMReviewPath:         *llmReview,
		LLMCommand:            *llmCommand,
		LLMRequestOut:         *llmRequestOut,
		LLMTimeout:            time.Duration(*llmTimeout) * time.Second,
		IncludeSensitivePaths: *includeSensitive,
	})
	if err != nil {
		fatal(err)
	}
	var renderErr error
	switch dashboardView {
	case "assessment", "assess", "operator":
		inventory, err := prove.RunInventory(prove.Options{Path: *path, Agent: *agent, Mode: *mode, IncludeSensitivePaths: *includeSensitive})
		if err != nil {
			fatal(err)
		}
		renderErr = report.RenderAssessFocused(writer, inventory, r, "html", *status, report.AssessFocus{CaseFilter: *caseID, ControlFilter: *controlID})
	case "exposure", "legacy":
		renderErr = report.Render(writer, r, "html")
	default:
		renderErr = fmt.Errorf("unknown dashboard view: %s", *view)
	}
	if renderErr != nil {
		fatal(renderErr)
	}
}

func runStories(args []string) {
	if len(args) == 0 || args[0] != "list" {
		fatal(fmt.Errorf("usage: ariadne stories list [--story-root testdata/storylab]"))
	}
	fs := flag.NewFlagSet("stories list", flag.ExitOnError)
	storyRoot := fs.String("story-root", "testdata/storylab", "story lab root")
	fs.Parse(args[1:])
	resolvedStoryRoot, err := storyRootFromFlag(fs, *storyRoot)
	if err != nil {
		fatal(err)
	}
	stories, err := storylab.List(resolvedStoryRoot)
	if err != nil {
		fatal(err)
	}
	for _, story := range stories {
		fmt.Printf("%s\t%s\t%s\n", story.Manifest.ID, story.Manifest.Expected.Status, story.Manifest.Title)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, strings.TrimSpace(`ariadne: local agent exposure prover

Commands:
  assess        Assess one path or target list and show the first-run Zero Trust case board
  self          Assess this developer machine/home as an endpoint
  architecture   Show Zero Trust agent architecture flaws, filtered to breaking by default
  cases          Show the operator case board for architecture break paths
  proofs         Show focused proof patches for closing operator cases
  controls       Show missing hard-barrier controls and where to prove them
  compare        Compare two Ariadne JSON reports and show case state changes
  inventory      Collect deterministic AI surface facts without classifying exposure
  prove          Prove supported exposure paths for a real path or Story Lab scenario
  scan           Run exposure analysis across one or more local/mounted targets
  dashboard      Write a local HTML operator dashboard for one target or a target list
  stories list   List Story Lab scenarios

Examples:
  ariadne self
  ariadne self --bundle-dir ariadne-self
  ariadne self --format html --out ariadne-self-assessment.html
  ariadne self --case case:identity-credentials
  ariadne assess --path .
  ariadne assess --path . --format operator
  ariadne assess --path . --format operator-json --out operator-packet.json
  ariadne assess --path . --format table
  ariadne assess --path . --format action
  ariadne assess --path . --format html --out ariadne-assessment.html
  ariadne assess --targets targets.txt --format json
  ariadne stories list
  ariadne architecture --path .
  ariadne architecture --targets targets.txt
  ariadne architecture --path . --mode endpoint --include-sensitive-paths
  ariadne architecture --path . --status all --format json
  ariadne architecture --path . --format html --out architecture-dashboard.html
  ariadne cases --path .
  ariadne cases --path . --case case:input-trust-boundary
  ariadne cases --path . --format html --out cases-dashboard.html
  ariadne cases --targets targets.txt
  ariadne proofs --path . --case case:input-trust-boundary
  ariadne proofs --path . --case case:input-trust-boundary --format action
  ariadne proofs --path . --case case:input-trust-boundary --format json
  ariadne proofs --path . --case case:input-trust-boundary --format html --out proof-plan.html
  ariadne proofs --path . --case case:input-trust-boundary --patch-dir proof-patches
  ariadne compare --before before-proof.json --after after-proof.json
  ariadne compare --before before-proof.json --after after-proof.json --format html --out case-compare.html
  ariadne controls --path .
  ariadne controls --path . --format json
  ariadne controls --path . --format html --out controls-dashboard.html
  ariadne controls --targets targets.txt
  ariadne inventory --path .
  ariadne inventory --path . --mode endpoint --format json
  ariadne inventory --path . --format html --out inventory-dashboard.html
  ariadne inventory --path . --format mermaid --out graph.mmd
  ariadne prove --path .
  ariadne dashboard --path . --out ariadne-dashboard.html
  ariadne dashboard --path . --view exposure --out exposure-dashboard.html
  ariadne dashboard --targets targets.txt --out fleet-dashboard.html
  ariadne prove --path . --format dot --out graph.dot
  ariadne scan --targets targets.txt --format json
  ariadne scan --targets targets.txt --format html --out fleet-dashboard.html
  ariadne prove --path . --agent codex --format json
  ariadne prove --path . --rules .ariadne/rules.json
  ariadne prove --path . --llm-request-out llm-request.json
  ariadne prove --path . --interpret llm --llm-review llm-review.json
  ariadne prove --story local-agent-secret-exposed
  ariadne prove --story local-agent-secret-exposed --format json`))
}

func outputWriter(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}

func storyRootFromFlag(fs *flag.FlagSet, value string) (string, error) {
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "story-root" {
			explicit = true
		}
	})
	if explicit {
		return value, nil
	}
	return resolveDefaultStoryRoot(value)
}

func resolveDefaultStoryRoot(defaultValue string) (string, error) {
	var candidates []string
	if env := os.Getenv("ARIADNE_STORY_ROOT"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, defaultValue, filepath.Join("ariadne-prove", defaultValue))
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "..", defaultValue),
			filepath.Join(exeDir, "..", "ariadne-prove", defaultValue),
		)
	}
	seen := make(map[string]bool)
	var tried []string
	for _, candidate := range candidates {
		cleaned := filepath.Clean(candidate)
		if seen[cleaned] {
			continue
		}
		seen[cleaned] = true
		tried = append(tried, cleaned)
		if info, err := os.Stat(cleaned); err == nil && info.IsDir() {
			return cleaned, nil
		}
	}
	return "", fmt.Errorf("story lab root not found; tried %s; set --story-root or ARIADNE_STORY_ROOT", strings.Join(tried, ", "))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ariadne:", err)
	os.Exit(2)
}
