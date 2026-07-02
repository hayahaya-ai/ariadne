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
	case "closure":
		runClosure(os.Args[2:])
	case "inventory":
		runInventory(os.Args[2:])
	case "review-packet":
		runReviewPacket(os.Args[2:])
	case "review-check":
		runReviewCheck(os.Args[2:])
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
	format := fs.String("format", "summary", "output format: summary, runbook, runbook-json, operator, operator-json, table, action, json, html")
	outPath := fs.String("out", "", "write output to file")
	rulesPath := fs.String("rules", "", "custom deterministic rule policy JSON")
	interpretMode := fs.String("interpret", "deterministic", "interpretation mode: deterministic, llm")
	llmReview := fs.String("llm-review", "", "LLM review JSON file to ingest")
	llmCommand := fs.String("llm-command", "", "local LLM reviewer command; reads request JSON on stdin and writes review JSON on stdout")
	llmRequestOut := fs.String("llm-request-out", "", "write redacted LLM review request JSON to file")
	llmReviewProfile := fs.String("llm-review-profile", "follow-up", "LLM review profile: follow-up, inventory-blind")
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
			LLMReviewProfile:      *llmReviewProfile,
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
		LLMReviewProfile:      *llmReviewProfile,
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
	format := fs.String("format", "summary", "output format: summary, runbook, runbook-json, operator, operator-json, table, action, json, html")
	outPath := fs.String("out", "", "write output to file")
	rulesPath := fs.String("rules", "", "custom deterministic rule policy JSON")
	interpretMode := fs.String("interpret", "deterministic", "interpretation mode: deterministic, llm")
	llmReview := fs.String("llm-review", "", "LLM review JSON file to ingest")
	llmCommand := fs.String("llm-command", "", "local LLM reviewer command; reads request JSON on stdin and writes review JSON on stdout")
	llmRequestOut := fs.String("llm-request-out", "", "write redacted LLM review request JSON to file")
	llmReviewProfile := fs.String("llm-review-profile", "follow-up", "LLM review profile: follow-up, inventory-blind")
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
		LLMReviewProfile:      *llmReviewProfile,
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

type closureWorkspaceResult struct {
	SchemaVersion string                      `json:"schema_version"`
	RunKind       string                      `json:"run_kind"`
	GeneratedAt   time.Time                   `json:"generated_at"`
	Directory     string                      `json:"directory"`
	TargetPath    string                      `json:"target_path"`
	Mode          string                      `json:"mode"`
	Agent         string                      `json:"agent"`
	StatusFilter  string                      `json:"status_filter"`
	CaseID        string                      `json:"case_id"`
	ProofLoop     []closureWorkspaceCommand   `json:"proof_loop"`
	PatchFiles    []closureWorkspacePatchFile `json:"patch_files"`
	Limitations   []string                    `json:"limitations"`
	Files         []selfAssessmentBundleFile  `json:"files"`
}

type closureWorkspaceCommand struct {
	Step        int    `json:"step"`
	ID          string `json:"id"`
	Title       string `json:"title"`
	Command     string `json:"command"`
	Output      string `json:"output,omitempty"`
	Description string `json:"description"`
}

type closureWorkspacePatchFile struct {
	Path                 string   `json:"path"`
	GeneratedPath        string   `json:"generated_path"`
	Surface              string   `json:"surface"`
	SuggestedDestination string   `json:"suggested_destination"`
	DestinationPath      string   `json:"destination_path,omitempty"`
	ApplyCommand         string   `json:"apply_command,omitempty"`
	Format               string   `json:"format"`
	Controls             []string `json:"controls"`
	PatchCount           int      `json:"patch_count"`
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
		return report.RenderAssessRunbook(w, assess.OperatorWorkbench.Runbook)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("runbook.json", true, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report.BuildAssessOperatorRunbookReport(assess))
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

func writeClosureWorkspace(dir string, r model.Report, assess model.AssessReport, plan model.ProofPlanReport, status string, caseID string) (closureWorkspaceResult, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return closureWorkspaceResult{}, fmt.Errorf("--dir requires a directory")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return closureWorkspaceResult{}, err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return closureWorkspaceResult{}, fmt.Errorf("closure workspace requires a case id")
	}
	result := closureWorkspaceResult{
		SchemaVersion: model.SchemaVersion,
		RunKind:       "closure_workspace",
		GeneratedAt:   time.Now().UTC(),
		Directory:     absDir,
		TargetPath:    r.TargetPath,
		Mode:          selfBundleFirstNonEmpty(r.Story.Mode, plan.Mode, "repo"),
		Agent:         selfBundleFirstNonEmpty(r.Story.Runtime, plan.Agent, "all"),
		StatusFilter:  selfBundleFirstNonEmpty(status, plan.StatusFilter, "breaking"),
		CaseID:        caseID,
		ProofLoop:     closureWorkspaceProofLoop(r.TargetPath, selfBundleFirstNonEmpty(r.Story.Mode, plan.Mode, "repo"), selfBundleFirstNonEmpty(r.Story.Runtime, plan.Agent, "all"), selfBundleFirstNonEmpty(status, plan.StatusFilter, "breaking"), caseID, absDir),
		Limitations:   closureWorkspaceLimitations(),
		Files: []selfAssessmentBundleFile{
			{Name: "runbook.txt", Path: filepath.Join(absDir, "runbook.txt"), Description: "Action-first workflow for this closure case."},
			{Name: "runbook.json", Path: filepath.Join(absDir, "runbook.json"), Description: "Structured operator runbook for UI and workflow clients."},
			{Name: "before-proof.json", Path: filepath.Join(absDir, "before-proof.json"), Description: "Baseline proof state before changing evidence."},
			{Name: "proof-action.txt", Path: filepath.Join(absDir, "proof-action.txt"), Description: "Human proof action for the focused closure case."},
			{Name: "proof-plan.html", Path: filepath.Join(absDir, "proof-plan.html"), Description: "Focused proof-plan dashboard for reviewing evidence, patches, commands, and success criteria."},
			{Name: "proof-patches/README.md", Path: filepath.Join(absDir, "proof-patches", "README.md"), Description: "Review guide for suggested proof evidence files."},
			{Name: "proof-patches/manifest.json", Path: filepath.Join(absDir, "proof-patches", "manifest.json"), Description: "Structured manifest for suggested proof evidence files."},
			{Name: "README.md", Path: filepath.Join(absDir, "README.md"), Description: "Closure workspace guide and after/compare commands."},
			{Name: "manifest.json", Path: filepath.Join(absDir, "manifest.json"), Description: "Machine-readable closure workspace manifest. The manifest entry itself is intentionally not self-hashed."},
		},
	}
	add := func(name string, recordMetadata bool, render func(io.Writer) error) error {
		fullPath := filepath.Join(absDir, name)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return err
		}
		if err := writeRenderedFile(fullPath, render); err != nil {
			return err
		}
		if recordMetadata {
			if err := recordClosureWorkspaceFileMetadata(&result, name, fullPath); err != nil {
				return err
			}
		}
		return nil
	}
	if err := add("runbook.txt", true, func(w io.Writer) error {
		return report.RenderAssessRunbook(w, assess.OperatorWorkbench.Runbook)
	}); err != nil {
		return closureWorkspaceResult{}, err
	}
	if err := add("runbook.json", true, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report.BuildAssessOperatorRunbookReport(assess))
	}); err != nil {
		return closureWorkspaceResult{}, err
	}
	if err := add("before-proof.json", true, func(w io.Writer) error {
		return report.RenderProofs(w, r, "json", status, caseID)
	}); err != nil {
		return closureWorkspaceResult{}, err
	}
	if err := add("proof-action.txt", true, func(w io.Writer) error {
		return report.RenderProofs(w, r, "action", status, caseID)
	}); err != nil {
		return closureWorkspaceResult{}, err
	}
	if err := add("proof-plan.html", true, func(w io.Writer) error {
		return report.RenderProofs(w, r, "html", status, caseID)
	}); err != nil {
		return closureWorkspaceResult{}, err
	}
	patchDir := filepath.Join(absDir, "proof-patches")
	exported, err := report.ExportProofPatchFiles(patchDir, plan)
	if err != nil {
		return closureWorkspaceResult{}, err
	}
	for _, file := range exported.FileDetails {
		name := filepath.ToSlash(filepath.Join("proof-patches", file.Path))
		result.Files = append(result.Files, selfAssessmentBundleFile{
			Name:        name,
			Path:        file.GeneratedPath,
			Description: "Suggested proof evidence file. Review before copying into the target.",
		})
		result.PatchFiles = append(result.PatchFiles, closureWorkspacePatchFile{
			Path:                 name,
			GeneratedPath:        file.GeneratedPath,
			Surface:              file.Surface,
			SuggestedDestination: file.SuggestedDestination,
			DestinationPath:      file.DestinationPath,
			ApplyCommand:         file.ApplyCommand,
			Format:               file.Format,
			Controls:             file.Controls,
			PatchCount:           file.PatchCount,
		})
		if err := recordClosureWorkspaceFileMetadata(&result, name, file.GeneratedPath); err != nil {
			return closureWorkspaceResult{}, err
		}
	}
	if exported.ReadmePath != "" {
		if err := recordClosureWorkspaceFileMetadata(&result, "proof-patches/README.md", exported.ReadmePath); err != nil {
			return closureWorkspaceResult{}, err
		}
	}
	if exported.ManifestPath != "" {
		if err := recordClosureWorkspaceFileMetadata(&result, "proof-patches/manifest.json", exported.ManifestPath); err != nil {
			return closureWorkspaceResult{}, err
		}
	}
	if err := add("README.md", true, func(w io.Writer) error {
		_, err := io.WriteString(w, closureWorkspaceReadme(result))
		return err
	}); err != nil {
		return closureWorkspaceResult{}, err
	}
	if err := add("manifest.json", false, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}); err != nil {
		return closureWorkspaceResult{}, err
	}
	return result, nil
}

func recordClosureWorkspaceFileMetadata(result *closureWorkspaceResult, name string, path string) error {
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
	return fmt.Errorf("closure workspace metadata target not found: %s", name)
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
	closure := fmt.Sprintf("ariadne closure --path %s --mode %s --agent %s --status %s --case %s --dir ariadne-closure",
		selfBundleShellQuoteArg(targetPath),
		selfBundleShellQuoteArg(selfBundleFirstNonEmpty(mode, "endpoint")),
		selfBundleShellQuoteArg(selfBundleFirstNonEmpty(agent, "all")),
		selfBundleShellQuoteArg(selfBundleFirstNonEmpty(status, "breaking")),
		selfBundleShellQuoteArg(caseID),
	)
	return []string{
		closure,
		base + " --format action",
		base + " --format json --out before-proof.json",
		base + " --patch-dir proof-patches",
		base + " --format json --out after-proof.json",
		"ariadne compare --before before-proof.json --after after-proof.json --format html --out case-compare.html",
	}
}

func closureWorkspaceProofLoop(targetPath string, mode string, agent string, status string, caseID string, dir string) []closureWorkspaceCommand {
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return []closureWorkspaceCommand{}
	}
	beforePath := filepath.Join(dir, "before-proof.json")
	afterPath := filepath.Join(dir, "after-proof.json")
	comparePath := filepath.Join(dir, "case-compare.html")
	patchDir := filepath.Join(dir, "proof-patches")
	base := fmt.Sprintf("ariadne proofs --path %s --mode %s --agent %s --status %s --case %s",
		selfBundleShellQuoteArg(targetPath),
		selfBundleShellQuoteArg(selfBundleFirstNonEmpty(mode, "repo")),
		selfBundleShellQuoteArg(selfBundleFirstNonEmpty(agent, "all")),
		selfBundleShellQuoteArg(selfBundleFirstNonEmpty(status, "breaking")),
		selfBundleShellQuoteArg(caseID),
	)
	return []closureWorkspaceCommand{
		{Step: 1, ID: "save_baseline_proof", Title: "Save baseline proof", Command: base + " --format json --out " + selfBundleShellQuoteArg(beforePath), Output: beforePath, Description: "Already created when this workspace was generated."},
		{Step: 2, ID: "review_proof_patches", Title: "Review suggested proof files", Command: base + " --patch-dir " + selfBundleShellQuoteArg(patchDir), Output: patchDir, Description: "Already created when this workspace was generated; review before applying anything to the target."},
		{Step: 3, ID: "save_after_proof", Title: "Save after proof", Command: base + " --format json --out " + selfBundleShellQuoteArg(afterPath), Output: afterPath, Description: "Run after evidence has been changed or verified."},
		{Step: 4, ID: "compare_state", Title: "Compare before and after", Command: fmt.Sprintf("ariadne compare --before %s --after %s --format html --out %s", selfBundleShellQuoteArg(beforePath), selfBundleShellQuoteArg(afterPath), selfBundleShellQuoteArg(comparePath)), Output: comparePath, Description: "Run after saving after-proof.json; this is the closure readout."},
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

func closureWorkspaceLimitations() []string {
	return []string{
		"The closure workspace is generated from deterministic local facts, graph evidence, and proof-plan contracts.",
		"Suggested proof files are review-first evidence artifacts. Ariadne does not mutate the scanned target.",
		"before-proof.json is a baseline from workspace creation time; after-proof.json must be generated after evidence is changed or verified.",
		"case-compare.html is the closure readout after the after-proof artifact exists.",
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

func closureWorkspaceReadme(result closureWorkspaceResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Ariadne Closure Workspace\n\n")
	fmt.Fprintf(&b, "Target: `%s`\n", result.TargetPath)
	fmt.Fprintf(&b, "Case: `%s`\n", result.CaseID)
	fmt.Fprintf(&b, "Mode: `%s`  Agent: `%s`  Filter: `%s`\n", result.Mode, result.Agent, result.StatusFilter)
	fmt.Fprintf(&b, "\n## What This Workspace Is\n\n")
	fmt.Fprintf(&b, "This folder is the before/change/after/compare loop for one Ariadne operator case. Ariadne already saved the baseline proof and exported suggested proof evidence. Review the evidence before applying anything to the target.\n")
	fmt.Fprintf(&b, "\n## Review Order\n\n")
	fmt.Fprintf(&b, "1. Open `runbook.txt` for the action-first workflow.\n")
	fmt.Fprintf(&b, "2. Open `proof-action.txt` for the exact proof evidence Ariadne expects.\n")
	fmt.Fprintf(&b, "3. Review `proof-patches/README.md` and `proof-patches/manifest.json` before copying any suggested evidence file.\n")
	fmt.Fprintf(&b, "4. After evidence is changed or verified, run the after-proof command below.\n")
	fmt.Fprintf(&b, "5. Run the compare command and use `case-compare.html` as the closure readout.\n")
	if len(result.ProofLoop) > 0 {
		fmt.Fprintf(&b, "\n## Proof Loop\n\n")
		for _, command := range result.ProofLoop {
			fmt.Fprintf(&b, "### %d. %s\n\n", command.Step, command.Title)
			if command.Description != "" {
				fmt.Fprintf(&b, "%s\n\n", command.Description)
			}
			fmt.Fprintf(&b, "```bash\n%s\n```\n\n", command.Command)
			if command.Output != "" {
				fmt.Fprintf(&b, "Output: `%s`\n\n", command.Output)
			}
		}
	}
	if len(result.PatchFiles) > 0 {
		fmt.Fprintf(&b, "## Suggested Proof Files\n\n")
		for _, file := range result.PatchFiles {
			fmt.Fprintf(&b, "- `%s` -> `%s`", file.GeneratedPath, selfBundleFirstNonEmpty(file.DestinationPath, file.SuggestedDestination))
			if len(file.Controls) > 0 {
				fmt.Fprintf(&b, " (%s)", strings.Join(file.Controls, ", "))
			}
			fmt.Fprintf(&b, "\n")
		}
	}
	fmt.Fprintf(&b, "\n## Files\n\n")
	for _, file := range result.Files {
		if file.SHA256 != "" {
			fmt.Fprintf(&b, "- `%s`: %s (SHA-256 `%s`, %d bytes.)\n", file.Name, file.Description, file.SHA256, file.SizeBytes)
			continue
		}
		fmt.Fprintf(&b, "- `%s`: %s\n", file.Name, file.Description)
	}
	if len(result.Limitations) > 0 {
		fmt.Fprintf(&b, "\n## Limits\n\n")
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

func renderClosureWorkspaceSummary(w io.Writer, result closureWorkspaceResult) {
	fmt.Fprintf(w, "Created Ariadne closure workspace at %s\n", result.Directory)
	fmt.Fprintf(w, "Case: %s\n", result.CaseID)
	fmt.Fprintf(w, "Open first: %s\n", filepath.Join(result.Directory, "runbook.txt"))
	fmt.Fprintf(w, "Baseline proof: %s\n", filepath.Join(result.Directory, "before-proof.json"))
	fmt.Fprintf(w, "Suggested proof files: %s\n", filepath.Join(result.Directory, "proof-patches"))
	for _, command := range result.ProofLoop {
		if command.ID == "save_after_proof" {
			fmt.Fprintf(w, "After changes: %s\n", command.Command)
		}
		if command.ID == "compare_state" {
			fmt.Fprintf(w, "Compare: %s\n", command.Command)
		}
	}
	fmt.Fprintf(w, "Guide: %s\n", filepath.Join(result.Directory, "README.md"))
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

func runClosure(args []string) {
	fs := flag.NewFlagSet("closure", flag.ExitOnError)
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to close")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	status := fs.String("status", "breaking", "architecture flaw status filter: breaking, controlled, unknown, not_observed, observed, all")
	caseID := fs.String("case", "", "operator case id to close; defaults to the top ranked case")
	dir := fs.String("dir", "ariadne-closure", "write closure workspace to this directory")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	inventory, err := prove.RunInventory(prove.Options{Path: *path, Agent: *agent, Mode: *mode, IncludeSensitivePaths: *includeSensitive})
	if err != nil {
		fatal(err)
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
	focus := report.AssessFocus{CaseFilter: strings.TrimSpace(*caseID)}
	assess, err := report.BuildAssessReport(inventory, r, *status, focus)
	if err != nil {
		fatal(err)
	}
	resolvedCaseID := strings.TrimSpace(*caseID)
	if resolvedCaseID == "" {
		resolvedCaseID = selfAssessmentBundleCaseID(assess, focus)
	}
	if resolvedCaseID == "" {
		fatal(fmt.Errorf("no operator case is available for status %q", *status))
	}
	focus.CaseFilter = resolvedCaseID
	assess, err = report.BuildAssessReport(inventory, r, *status, focus)
	if err != nil {
		fatal(err)
	}
	plan, err := report.BuildProofPlanForReport(r, *status, resolvedCaseID)
	if err != nil {
		fatal(err)
	}
	workspace, err := writeClosureWorkspace(*dir, r, assess, plan, *status, resolvedCaseID)
	if err != nil {
		fatal(err)
	}
	renderClosureWorkspaceSummary(os.Stdout, workspace)
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
	llmReviewProfile := fs.String("llm-review-profile", "follow-up", "LLM review profile: follow-up, inventory-blind")
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
		LLMReviewProfile:      *llmReviewProfile,
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

func runReviewPacket(args []string) {
	fs := flag.NewFlagSet("review-packet", flag.ExitOnError)
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to review")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	profile := fs.String("profile", "follow-up", "review profile: follow-up, inventory-blind")
	format := fs.String("format", "summary", "output format: summary, json")
	outPath := fs.String("out", "", "write command output to file")
	packetOut := fs.String("packet-out", "", "write review packet JSON to file while rendering summary")
	rulesPath := fs.String("rules", "", "custom deterministic rule policy JSON")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	request, payload, digest, err := prove.RunReviewPacket(prove.Options{
		Path:                  *path,
		Agent:                 *agent,
		Mode:                  *mode,
		RulesPath:             *rulesPath,
		LLMReviewProfile:      *profile,
		IncludeSensitivePaths: *includeSensitive,
	})
	if err != nil {
		fatal(err)
	}
	if *packetOut != "" {
		if err := os.WriteFile(*packetOut, append(payload, '\n'), 0o644); err != nil {
			fatal(err)
		}
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "", "summary", "table":
		if err := report.RenderLLMReviewRequestSummary(writer, request, digest, *packetOut); err != nil {
			fatal(err)
		}
	case "json":
		if _, err := writer.Write(append(payload, '\n')); err != nil {
			fatal(err)
		}
	default:
		fatal(fmt.Errorf("unknown review-packet format: %s", *format))
	}
}

func runReviewCheck(args []string) {
	fs := flag.NewFlagSet("review-check", flag.ExitOnError)
	packetPath := fs.String("packet", "", "review packet JSON produced by ariadne review-packet")
	reviewPath := fs.String("review", "", "review response JSON using ariadne.llm_review/v1")
	format := fs.String("format", "summary", "output format: summary, json")
	outPath := fs.String("out", "", "write output to file")
	fs.Parse(args)
	check, err := prove.RunReviewCheck(*packetPath, *reviewPath)
	if err != nil {
		fatal(err)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderLLMReviewCheck(writer, check, *format); err != nil {
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
	llmReviewProfile := fs.String("llm-review-profile", "follow-up", "LLM review profile: follow-up, inventory-blind")
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
			LLMReviewProfile:      *llmReviewProfile,
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
			LLMReviewProfile:      *llmReviewProfile,
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
	llmReviewProfile := fs.String("llm-review-profile", "follow-up", "LLM review profile: follow-up, inventory-blind")
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
			LLMReviewProfile:      *llmReviewProfile,
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
		LLMReviewProfile:      *llmReviewProfile,
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
  closure        Create a local before/change/after/compare closure workspace
  inventory      Collect deterministic AI surface facts without classifying exposure
  review-packet  Create a fact-bound review packet for human or LLM inspection
  review-check   Validate a reviewer response against an exact review packet
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
  ariadne assess --path . --format runbook
  ariadne assess --path . --format runbook-json --out operator-runbook.json
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
  ariadne closure --path . --case case:input-trust-boundary --dir ariadne-closure
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
  ariadne review-packet --path . --profile follow-up --packet-out llm-request.json
  ariadne review-packet --path . --profile inventory-blind --format json --out llm-request.json
  ariadne review-check --packet llm-request.json --review llm-review.json
  ariadne prove --path .
  ariadne dashboard --path . --out ariadne-dashboard.html
  ariadne dashboard --path . --view exposure --out exposure-dashboard.html
  ariadne dashboard --targets targets.txt --out fleet-dashboard.html
  ariadne prove --path . --format dot --out graph.dot
  ariadne scan --targets targets.txt --format json
  ariadne scan --targets targets.txt --format html --out fleet-dashboard.html
  ariadne prove --path . --agent codex --format json
  ariadne prove --path . --rules .ariadne/rules.json
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
