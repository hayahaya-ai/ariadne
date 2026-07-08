package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/prove"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/report"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/storylab"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/verdict"
)

const agentHelp = "agent runtime to inspect: all, claude, codex, cursor, windsurf, continue, aider, gemini, opencode, github-actions, gitlab-ci"

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
	case "bundle":
		runBundle(os.Args[2:])
	case "inventory":
		runInventory(os.Args[2:])
	case "review-packet":
		runReviewPacket(os.Args[2:])
	case "review-check":
		runReviewCheck(os.Args[2:])
	case "review-run":
		runReviewRun(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "dashboard":
		runDashboard(os.Args[2:])
	case "stories":
		runStories(os.Args[2:])
	case "verdict":
		runVerdict(os.Args[2:])
	case "ls":
		runLs(os.Args[2:])
	case "show":
		runShow(os.Args[2:])
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
	format := fs.String("format", "readout", "output format: readout, summary, source-inspection, source-inspection-json, runbook, runbook-json, operator, operator-json, table, action, json, html")
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
	if err := renderAssessOrReadout(writer, inventory, r, *format, *status, report.AssessFocus{CaseFilter: *caseID, ControlFilter: *controlID}); err != nil {
		fatal(err)
	}
}

// renderAssessOrReadout dispatches "readout" (the new self/assess default) to
// the compact one-screen verdict.RenderReadout, and everything else
// (including the previous default, now reachable via --format summary) to
// the existing report.RenderAssessFocused switch. It does not hijack
// --format json, which keeps rendering the full model.AssessReport.
func renderAssessOrReadout(w io.Writer, inventory model.InventoryReport, r model.Report, format string, statusFilter string, focus report.AssessFocus) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "readout":
		v := verdict.Build(inventory, r, r.TargetPath, r.Story.Mode)
		return verdict.RenderReadout(w, v)
	default:
		return report.RenderAssessFocused(w, inventory, r, format, statusFilter, focus)
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
	format := fs.String("format", "readout", "output format: readout, summary, source-inspection, source-inspection-json, runbook, runbook-json, operator, operator-json, table, action, json, html")
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
		exported, err := writeSelfAssessmentBundle(*bundleDir, inventory, r, *status, focus, *rulesPath, *includeSensitive)
		if err != nil {
			fatal(err)
		}
		renderSelfAssessmentBundleSummary(os.Stderr, exported)
	}
	if err := renderAssessOrReadout(writer, inventory, r, *format, *status, focus); err != nil {
		fatal(err)
	}
}

// verdictTargetPath resolves --path the same way runSelf does: explicit
// --path wins, otherwise fall back to HOME (endpoint mode's natural
// default). Repo-mode callers are expected to pass --path explicitly; if
// they don't and HOME is also unset, this returns an error.
func verdictTargetPath(path string) (string, error) {
	targetPath := strings.TrimSpace(path)
	if targetPath == "" {
		targetPath = os.Getenv("HOME")
	}
	if targetPath == "" {
		return "", fmt.Errorf("--path is required (or set HOME for endpoint mode)")
	}
	return targetPath, nil
}

func runVerdict(args []string) {
	fs := flag.NewFlagSet("verdict", flag.ExitOnError)
	path := fs.String("path", "", "repo, workspace, or mounted endpoint home path to assess; defaults to HOME in endpoint mode")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "endpoint", "collection mode: endpoint, repo")
	jsonOut := fs.Bool("json", false, "emit the compact verdict JSON instead of text")
	gate := fs.Bool("gate", false, "exit 3 if the verdict is reckless")
	outPath := fs.String("out", "", "write output to file")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	targetPath, err := verdictTargetPath(*path)
	if err != nil {
		fatal(err)
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
	r, err := prove.RunPath(prove.Options{Path: targetPath, Agent: *agent, Mode: *mode, IncludeSensitivePaths: *includeSensitive})
	if err != nil {
		fatal(err)
	}
	v := verdict.Build(inventory, r, r.TargetPath, r.Story.Mode)
	if *jsonOut {
		if err := verdict.RenderJSON(writer, v); err != nil {
			fatal(err)
		}
	} else {
		if err := verdict.RenderText(writer, v); err != nil {
			fatal(err)
		}
	}
	if *gate && v.VerdictWord == verdict.WordReckless {
		os.Exit(3)
	}
}

var lsResourceKinds = []string{"findings", "agents", "surfaces", "controls", "facts", "cases"}

type lsRow struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

func runLs(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ariadne: usage: ariadne ls <findings|agents|surfaces|controls|facts|cases> [--path P] [--mode M] [--json]")
		os.Exit(2)
	}
	resource := args[0]
	rest := args[1:]
	fs := flag.NewFlagSet("ls "+resource, flag.ExitOnError)
	path := fs.String("path", "", "repo, workspace, or mounted endpoint home path to assess; defaults to HOME in endpoint mode")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "endpoint", "collection mode: endpoint, repo")
	jsonOut := fs.Bool("json", false, "emit a JSON array of {id, summary} instead of tab-separated lines")
	outPath := fs.String("out", "", "write output to file")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(rest)

	if !stringInSlice(resource, lsResourceKinds) {
		fmt.Fprintf(os.Stderr, "ariadne: unknown ls resource: %s; valid: %s\n", resource, strings.Join(lsResourceKinds, ", "))
		os.Exit(2)
	}

	targetPath, err := verdictTargetPath(*path)
	if err != nil {
		fatal(err)
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
	r, err := prove.RunPath(prove.Options{Path: targetPath, Agent: *agent, Mode: *mode, IncludeSensitivePaths: *includeSensitive})
	if err != nil {
		fatal(err)
	}
	v := verdict.Build(inventory, r, r.TargetPath, r.Story.Mode)

	rows := lsRows(resource, inventory, r, v)
	if *jsonOut {
		enc := json.NewEncoder(writer)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fatal(err)
		}
		return
	}
	for _, row := range rows {
		fmt.Fprintf(writer, "%s\t%s\n", row.ID, row.Summary)
	}
}

func lsRows(resource string, inventory model.InventoryReport, r model.Report, v verdict.Verdict) []lsRow {
	collection := inventory.Collection
	rows := make([]lsRow, 0)
	switch resource {
	case "findings":
		for _, f := range v.Reckless {
			rows = append(rows, lsRow{ID: f.ID, Summary: f.Title})
		}
		for _, t := range v.Tradeoffs {
			rows = append(rows, lsRow{ID: t.ID, Summary: t.Summary})
		}
		for _, h := range v.Hardened {
			rows = append(rows, lsRow{ID: h.ID, Summary: h.Summary})
		}
	case "agents":
		for _, rt := range collection.Runtimes {
			rows = append(rows, lsRow{ID: "runtime:" + rt.Kind, Summary: rt.Summary})
		}
	case "surfaces":
		for _, s := range collection.Surfaces {
			rows = append(rows, lsRow{ID: s.Source, Summary: s.Kind})
		}
	case "controls":
		for _, c := range collection.Controls {
			rows = append(rows, lsRow{ID: c.ID, Summary: fmt.Sprintf("%s — %s", c.Enforcement, c.Summary)})
		}
	case "facts":
		for _, f := range collection.Facts {
			rows = append(rows, lsRow{ID: f.ID, Summary: f.Summary})
		}
	case "cases":
		for _, flaw := range r.ZeroTrust.ArchitectureFlaws {
			rows = append(rows, lsRow{ID: flaw.ID, Summary: flaw.Title})
		}
	}
	return rows
}

func stringInSlice(value string, values []string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func runShow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ariadne: usage: ariadne show <id> [--path P] [--mode M] [--json]")
		os.Exit(2)
	}
	id := args[0]
	rest := args[1:]
	fs := flag.NewFlagSet("show "+id, flag.ExitOnError)
	path := fs.String("path", "", "repo, workspace, or mounted endpoint home path to assess; defaults to HOME in endpoint mode")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "endpoint", "collection mode: endpoint, repo")
	jsonOut := fs.Bool("json", false, "emit the resolved object as JSON instead of human lines")
	outPath := fs.String("out", "", "write output to file")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(rest)

	targetPath, err := verdictTargetPath(*path)
	if err != nil {
		fatal(err)
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
	r, err := prove.RunPath(prove.Options{Path: targetPath, Agent: *agent, Mode: *mode, IncludeSensitivePaths: *includeSensitive})
	if err != nil {
		fatal(err)
	}
	v := verdict.Build(inventory, r, r.TargetPath, r.Story.Mode)

	if !renderShow(writer, id, inventory, r, v, *jsonOut) {
		fmt.Fprintf(os.Stderr, "ariadne: unknown id %s; valid prefixes: reckless: tradeoff: hardened: control: fact: runtime: case: or a surface path\n", id)
		os.Exit(1)
	}
}

// renderShow resolves id against the verdict/inventory/report data and
// writes it to w. It returns false if id did not resolve to anything.
func renderShow(w io.Writer, id string, inventory model.InventoryReport, r model.Report, v verdict.Verdict, jsonOut bool) bool {
	collection := inventory.Collection

	switch {
	case strings.HasPrefix(id, "reckless:"):
		for _, f := range v.Reckless {
			if f.ID == id {
				return showJSONOrLines(w, jsonOut, f, []string{
					"id: " + f.ID,
					"exposure_id: " + f.ExposureID,
					"title: " + f.Title,
					fmt.Sprintf("where: %s:%d", f.Where.Source, f.Where.Line),
					"why: " + f.Why,
					"fix: " + f.Fix,
					"attested_only: " + strings.Join(f.AttestedOnly, ", "),
					"evidence_refs: " + evidenceRefsSummary(f.EvidenceRefs),
				})
			}
		}
		return false
	case strings.HasPrefix(id, "tradeoff:"):
		for _, t := range v.Tradeoffs {
			if t.ID == id {
				return showJSONOrLines(w, jsonOut, t, []string{
					"id: " + t.ID,
					"summary: " + t.Summary,
					"source: " + t.Source,
				})
			}
		}
		return false
	case strings.HasPrefix(id, "hardened:"):
		for _, h := range v.Hardened {
			if h.ID == id {
				return showJSONOrLines(w, jsonOut, h, []string{
					"id: " + h.ID,
					"control: " + h.Control,
					"summary: " + h.Summary,
					"source: " + h.Source,
				})
			}
		}
		return false
	case strings.HasPrefix(id, "control:"):
		// The same control ID can be observed on multiple surfaces with
		// different enforcement (e.g. enforced in .claude/settings.json and
		// attested in an .ariadne policy). Show every entry so the reader
		// never mistakes an attested copy for the enforced one.
		var matches []model.Control
		for _, c := range collection.Controls {
			if c.ID == id {
				matches = append(matches, c)
			}
		}
		if len(matches) == 0 {
			return false
		}
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].Enforcement != matches[j].Enforcement {
				return matches[i].Enforcement == model.EnforcementEnforced
			}
			return matches[i].Source < matches[j].Source
		})
		var lines []string
		for i, c := range matches {
			if i > 0 {
				lines = append(lines, "")
			}
			lines = append(lines,
				"id: "+c.ID,
				"kind: "+c.Kind,
				"enforcement: "+c.Enforcement,
				"source: "+c.Source,
				"summary: "+c.Summary,
			)
		}
		return showJSONOrLines(w, jsonOut, matches, lines)
	case strings.HasPrefix(id, "fact:"):
		for _, f := range collection.Facts {
			if f.ID == id {
				return showJSONOrLines(w, jsonOut, f, []string{
					"id: " + f.ID,
					"type: " + f.Type,
					"source: " + f.Source,
					"summary: " + f.Summary,
				})
			}
		}
		return false
	case strings.HasPrefix(id, "runtime:"):
		kind := strings.TrimPrefix(id, "runtime:")
		for _, rt := range collection.Runtimes {
			if rt.Kind == kind || rt.ID == id {
				return showJSONOrLines(w, jsonOut, rt, []string{
					"id: " + rt.ID,
					"kind: " + rt.Kind,
					"source: " + rt.Source,
					"summary: " + rt.Summary,
				})
			}
		}
		return false
	case strings.HasPrefix(id, "case:"), strings.HasPrefix(id, "ztaf:"), strings.HasPrefix(id, "zt:"):
		want := id
		if strings.HasPrefix(id, "case:") {
			want = "ztaf:" + strings.TrimPrefix(id, "case:")
		} else if strings.HasPrefix(id, "zt:") {
			want = "ztaf:" + strings.TrimPrefix(id, "zt:")
		}
		for _, flaw := range r.ZeroTrust.ArchitectureFlaws {
			if flaw.ID == want || flaw.ID == id {
				return showJSONOrLines(w, jsonOut, flaw, []string{
					"id: " + flaw.ID,
					"title: " + flaw.Title,
					"status: " + string(flaw.Status),
					"severity: " + flaw.Severity,
					"finding: " + flaw.Finding,
					"why_it_matters: " + flaw.WhyItMatters,
				})
			}
		}
		return false
	default:
		return showSurface(w, id, inventory, jsonOut)
	}
}

// showSurface resolves id as a surface Source path, listing everything
// derived from that surface: controls, authorities, boundaries, and facts
// whose Source matches.
func showSurface(w io.Writer, id string, inventory model.InventoryReport, jsonOut bool) bool {
	collection := inventory.Collection
	var surface model.Surface
	found := false
	for _, s := range collection.Surfaces {
		if s.Source == id {
			surface = s
			found = true
			break
		}
	}
	if !found {
		return false
	}

	type surfaceDetail struct {
		Surface     model.Surface     `json:"surface"`
		Controls    []model.Control   `json:"controls"`
		Authorities []model.Authority `json:"authorities"`
		Boundaries  []model.Boundary  `json:"boundaries"`
		Facts       []model.Fact      `json:"facts"`
	}
	detail := surfaceDetail{Surface: surface}
	for _, c := range collection.Controls {
		if c.Source == id {
			detail.Controls = append(detail.Controls, c)
		}
	}
	for _, a := range collection.Authorities {
		if a.Source == id {
			detail.Authorities = append(detail.Authorities, a)
		}
	}
	for _, b := range collection.Boundaries {
		if b.Source == id {
			detail.Boundaries = append(detail.Boundaries, b)
		}
	}
	for _, f := range collection.Facts {
		if f.Source == id {
			detail.Facts = append(detail.Facts, f)
		}
	}

	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(detail) == nil
	}
	fmt.Fprintf(w, "source: %s\n", surface.Source)
	fmt.Fprintf(w, "kind: %s\n", surface.Kind)
	fmt.Fprintf(w, "summary: %s\n", surface.Summary)
	fmt.Fprintf(w, "controls: %d\n", len(detail.Controls))
	for _, c := range detail.Controls {
		fmt.Fprintf(w, "  %s (%s) — %s\n", c.ID, c.Enforcement, c.Summary)
	}
	fmt.Fprintf(w, "authorities: %d\n", len(detail.Authorities))
	for _, a := range detail.Authorities {
		fmt.Fprintf(w, "  %s — %s\n", a.ID, a.Summary)
	}
	fmt.Fprintf(w, "boundaries: %d\n", len(detail.Boundaries))
	for _, b := range detail.Boundaries {
		fmt.Fprintf(w, "  %s — %s\n", b.ID, b.Summary)
	}
	fmt.Fprintf(w, "facts: %d\n", len(detail.Facts))
	for _, f := range detail.Facts {
		fmt.Fprintf(w, "  %s — %s\n", f.ID, f.Summary)
	}
	return true
}

func evidenceRefsSummary(refs []model.EvidenceReference) string {
	if len(refs) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts = append(parts, fmt.Sprintf("%s:%d", ref.Source, ref.LineStart))
	}
	return strings.Join(parts, ", ")
}

// showJSONOrLines writes v as indented JSON when jsonOut is set, otherwise
// writes the precomputed human-readable lines. Always returns true (the
// caller already confirmed a match before calling this).
func showJSONOrLines(w io.Writer, jsonOut bool, v interface{}, lines []string) bool {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v) == nil
	}
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return true
}

type selfAssessmentBundleResult struct {
	Directory        string                     `json:"directory"`
	TargetPath       string                     `json:"target_path"`
	Mode             string                     `json:"mode"`
	Agent            string                     `json:"agent"`
	StatusFilter     string                     `json:"status_filter"`
	CaseFilter       string                     `json:"case_filter,omitempty"`
	ControlFilter    string                     `json:"control_filter,omitempty"`
	TopCaseID        string                     `json:"top_case_id,omitempty"`
	IntegrityCommand string                     `json:"integrity_command"`
	ReviewOrder      []string                   `json:"review_order"`
	ProofLoop        []string                   `json:"proof_loop"`
	Limitations      []string                   `json:"limitations"`
	Files            []selfAssessmentBundleFile `json:"files"`
}

type selfAssessmentBundleFile struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Description string `json:"description"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
}

type bundleVerifyManifest struct {
	Directory string                     `json:"directory"`
	Files     []selfAssessmentBundleFile `json:"files"`
}

type bundleVerifyReport struct {
	SchemaVersion string                   `json:"schema_version"`
	RunKind       string                   `json:"run_kind"`
	GeneratedAt   time.Time                `json:"generated_at"`
	ManifestPath  string                   `json:"manifest_path"`
	Directory     string                   `json:"directory"`
	Status        string                   `json:"status"`
	FilesChecked  int                      `json:"files_checked"`
	Passed        int                      `json:"passed"`
	Failed        int                      `json:"failed"`
	Skipped       int                      `json:"skipped"`
	Results       []bundleVerifyFileResult `json:"results"`
	Limitations   []string                 `json:"limitations"`
}

type bundleVerifyFileResult struct {
	Name              string `json:"name"`
	Path              string `json:"path,omitempty"`
	Status            string `json:"status"`
	Reason            string `json:"reason,omitempty"`
	ExpectedSizeBytes int64  `json:"expected_size_bytes,omitempty"`
	ActualSizeBytes   int64  `json:"actual_size_bytes,omitempty"`
	ExpectedSHA256    string `json:"expected_sha256,omitempty"`
	ActualSHA256      string `json:"actual_sha256,omitempty"`
}

type selfAssessmentLLMReviewPackets struct {
	FollowUp        model.LLMReviewRequest
	FollowUpPayload []byte
	FollowUpDigest  string
	Blind           model.LLMReviewRequest
	BlindPayload    []byte
	BlindDigest     string
}

type closureWorkspaceResult struct {
	SchemaVersion    string                      `json:"schema_version"`
	RunKind          string                      `json:"run_kind"`
	GeneratedAt      time.Time                   `json:"generated_at"`
	Directory        string                      `json:"directory"`
	TargetPath       string                      `json:"target_path"`
	Mode             string                      `json:"mode"`
	Agent            string                      `json:"agent"`
	StatusFilter     string                      `json:"status_filter"`
	CaseID           string                      `json:"case_id"`
	IntegrityCommand string                      `json:"integrity_command"`
	ProofLoop        []closureWorkspaceCommand   `json:"proof_loop"`
	PatchFiles       []closureWorkspacePatchFile `json:"patch_files"`
	Limitations      []string                    `json:"limitations"`
	Files            []selfAssessmentBundleFile  `json:"files"`
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

func writeSelfAssessmentBundle(dir string, inventory model.InventoryReport, r model.Report, status string, focus report.AssessFocus, rulesPath string, includeSensitive bool) (selfAssessmentBundleResult, error) {
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
	reviewPackets, err := buildSelfAssessmentLLMReviewPackets(r.TargetPath, r.Story.Mode, r.Story.Runtime, rulesPath, includeSensitive)
	if err != nil {
		return selfAssessmentBundleResult{}, err
	}
	assess.ReviewPackets = buildSelfAssessmentReviewPacketHandoffs(absDir, r.TargetPath, r.Story.Mode, r.Story.Runtime)
	result := selfAssessmentBundleResult{
		Directory:        absDir,
		TargetPath:       r.TargetPath,
		Mode:             r.Story.Mode,
		Agent:            r.Story.Runtime,
		StatusFilter:     assess.StatusFilter,
		CaseFilter:       assess.CaseFilter,
		ControlFilter:    assess.ControlFilter,
		TopCaseID:        topCaseID,
		IntegrityCommand: selfAssessmentBundleIntegrityCommand(absDir),
		ReviewOrder:      selfAssessmentBundleReviewOrder(),
		ProofLoop:        selfAssessmentBundleProofLoop(r.TargetPath, r.Story.Mode, r.Story.Runtime, assess.StatusFilter, topCaseID),
		Limitations:      selfAssessmentBundleLimitations(),
		Files: []selfAssessmentBundleFile{
			{Name: "assessment.txt", Path: filepath.Join(absDir, "assessment.txt"), Description: "Compact human readout with the decision, evidence, first action, and rerun commands."},
			{Name: "assessment.json", Path: filepath.Join(absDir, "assessment.json"), Description: "Structured assessment contract for automation and UI consumers."},
			{Name: "runbook.txt", Path: filepath.Join(absDir, "runbook.txt"), Description: "Action-first operator runbook with open-first evidence, current step, next step, commands, and closure workflow."},
			{Name: "runbook.json", Path: filepath.Join(absDir, "runbook.json"), Description: "Structured operator runbook for workflow systems and managed UI clients."},
			{Name: "operator-packet.txt", Path: filepath.Join(absDir, "operator-packet.txt"), Description: "Small ticket-style handoff with source refs, graph path, controls, proof checkpoint, commands, and done criteria."},
			{Name: "operator-packet.json", Path: filepath.Join(absDir, "operator-packet.json"), Description: "Structured operator packet for ticketing, workflow systems, and automation."},
			{Name: "source-inspection.txt", Path: filepath.Join(absDir, "source-inspection.txt"), Description: "Standalone source action checklist with exact files, line labels, inspect commands, metadata-only handling, and control links."},
			{Name: "source-inspection.json", Path: filepath.Join(absDir, "source-inspection.json"), Description: "Structured source inspection workbench for UI, ticketing, and automation clients."},
			{Name: "dashboard.html", Path: filepath.Join(absDir, "dashboard.html"), Description: "Local operator dashboard with the same assessment evidence."},
			{Name: "inventory-coverage.txt", Path: filepath.Join(absDir, "inventory-coverage.txt"), Description: "Compact fact-only AI runtime coverage matrix."},
			{Name: "inventory.json", Path: filepath.Join(absDir, "inventory.json"), Description: "Deterministic AI surface inventory facts without exposure classification."},
			{Name: "llm-follow-up-request.txt", Path: filepath.Join(absDir, "llm-follow-up-request.txt"), Description: "Fact-bound optional reviewer packet summary for Ariadne exposure IDs and graph evidence."},
			{Name: "llm-follow-up-request.json", Path: filepath.Join(absDir, "llm-follow-up-request.json"), Description: "Redacted optional reviewer packet; ingestible only after review-check validates returned findings against Ariadne evidence."},
			{Name: "llm-inventory-blind-request.txt", Path: filepath.Join(absDir, "llm-inventory-blind-request.txt"), Description: "Lower-bias optional reviewer packet summary for hypotheses and collector-gap review."},
			{Name: "llm-inventory-blind-request.json", Path: filepath.Join(absDir, "llm-inventory-blind-request.json"), Description: "Request-only blind inventory packet; hypotheses must be mapped back to deterministic facts before becoming findings."},
			{Name: "cases.txt", Path: filepath.Join(absDir, "cases.txt"), Description: "Operator case board showing the prioritized closure work."},
			{Name: "cases.json", Path: filepath.Join(absDir, "cases.json"), Description: "Structured operator case board."},
			{Name: "case-action.txt", Path: filepath.Join(absDir, "case-action.txt"), Description: "Focused first-case action handoff for the current operator case."},
			{Name: "case-action.json", Path: filepath.Join(absDir, "case-action.json"), Description: "Structured first-case action handoff for automation and workflow systems."},
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
		return report.RenderAssessReport(w, assess, "summary")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("assessment.json", true, func(w io.Writer) error {
		return report.RenderAssessReport(w, assess, "json")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("runbook.txt", true, func(w io.Writer) error {
		return report.RenderAssessRunbookForTarget(w, assess.OperatorWorkbench.Runbook, assess.TargetPath)
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
		return report.RenderAssessReport(w, assess, "operator")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("operator-packet.json", true, func(w io.Writer) error {
		return report.RenderAssessReport(w, assess, "operator-json")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("source-inspection.txt", true, func(w io.Writer) error {
		return report.RenderAssessReport(w, assess, "source-inspection")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("source-inspection.json", true, func(w io.Writer) error {
		return report.RenderAssessReport(w, assess, "source-inspection-json")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("dashboard.html", true, func(w io.Writer) error {
		return report.RenderAssessReport(w, assess, "html")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("inventory-coverage.txt", true, func(w io.Writer) error {
		return report.RenderInventory(w, inventory, "coverage")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("inventory.json", true, func(w io.Writer) error {
		return report.RenderInventory(w, inventory, "json")
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("llm-follow-up-request.txt", true, func(w io.Writer) error {
		return report.RenderLLMReviewRequestSummary(w, reviewPackets.FollowUp, reviewPackets.FollowUpDigest, filepath.Join(absDir, "llm-follow-up-request.json"))
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("llm-follow-up-request.json", true, func(w io.Writer) error {
		return writeJSONPayload(w, reviewPackets.FollowUpPayload)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("llm-inventory-blind-request.txt", true, func(w io.Writer) error {
		return report.RenderLLMReviewRequestSummary(w, reviewPackets.Blind, reviewPackets.BlindDigest, filepath.Join(absDir, "llm-inventory-blind-request.json"))
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("llm-inventory-blind-request.json", true, func(w io.Writer) error {
		return writeJSONPayload(w, reviewPackets.BlindPayload)
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
	if err := add("case-action.txt", true, func(w io.Writer) error {
		return report.RenderCases(w, r, "action", status, focus.CaseFilter)
	}); err != nil {
		return selfAssessmentBundleResult{}, err
	}
	if err := add("case-action.json", true, func(w io.Writer) error {
		return report.RenderCases(w, r, "action-json", status, focus.CaseFilter)
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

func buildSelfAssessmentLLMReviewPackets(targetPath string, mode string, agent string, rulesPath string, includeSensitive bool) (selfAssessmentLLMReviewPackets, error) {
	opts := prove.Options{
		Path:                  targetPath,
		Agent:                 selfBundleFirstNonEmpty(agent, "all"),
		Mode:                  selfBundleFirstNonEmpty(mode, "endpoint"),
		RulesPath:             rulesPath,
		IncludeSensitivePaths: includeSensitive,
	}
	followUpOpts := opts
	followUpOpts.LLMReviewProfile = "follow-up"
	followUp, followUpPayload, followUpDigest, err := prove.RunReviewPacket(followUpOpts)
	if err != nil {
		return selfAssessmentLLMReviewPackets{}, err
	}
	blindOpts := opts
	blindOpts.LLMReviewProfile = "inventory-blind"
	blind, blindPayload, blindDigest, err := prove.RunReviewPacket(blindOpts)
	if err != nil {
		return selfAssessmentLLMReviewPackets{}, err
	}
	return selfAssessmentLLMReviewPackets{
		FollowUp:        followUp,
		FollowUpPayload: followUpPayload,
		FollowUpDigest:  followUpDigest,
		Blind:           blind,
		BlindPayload:    blindPayload,
		BlindDigest:     blindDigest,
	}, nil
}

func buildSelfAssessmentReviewPacketHandoffs(dir string, targetPath string, mode string, agent string) []model.AssessReviewPacket {
	mode = selfBundleFirstNonEmpty(mode, "endpoint")
	agent = selfBundleFirstNonEmpty(agent, "all")
	followSummary := filepath.Join(dir, "llm-follow-up-request.txt")
	followPacket := filepath.Join(dir, "llm-follow-up-request.json")
	blindSummary := filepath.Join(dir, "llm-inventory-blind-request.txt")
	blindPacket := filepath.Join(dir, "llm-inventory-blind-request.json")
	reviewPath := filepath.Join(dir, "llm-review.json")
	reviewCheckPath := filepath.Join(dir, "review-check.txt")
	inventoryGapPath := filepath.Join(dir, "inventory-gap-check.json")

	return []model.AssessReviewPacket{
		{
			ID:            "llm-follow-up",
			Title:         "Review Ariadne Exposure IDs",
			Profile:       "follow_up",
			Scope:         "Ariadne's deterministic exposure IDs, graph edges, source refs, controls, and limitations.",
			Ingestibility: "yes; only after ariadne review-check validates returned issues against this packet",
			Summary:       "Optional reviewer follow-up over Ariadne's deterministic exposure evidence. The reviewer may prioritize or explain existing paths, but cannot create unsupported findings.",
			SummaryPath:   followSummary,
			PacketPath:    followPacket,
			Commands: nonNilAssessOperatorCommands([]model.AssessOperatorCommand{
				{Step: 1, ID: "open_packet", Title: "Open packet", Files: []string{followSummary, followPacket}},
				{Step: 2, ID: "validate_review", Title: "Validate reviewer output", Command: fmt.Sprintf("ariadne review-check --packet %s --review %s --out %s", selfBundleShellQuoteArg(followPacket), selfBundleShellQuoteArg(reviewPath), selfBundleShellQuoteArg(reviewCheckPath)), Files: []string{reviewCheckPath}},
				{Step: 3, ID: "ingest_validated_review", Title: "Ingest validated review", Command: fmt.Sprintf("ariadne prove --path %s --mode %s --agent %s --interpret llm --llm-review %s --llm-review-profile follow-up", selfBundleShellQuoteArg(targetPath), selfBundleShellQuoteArg(mode), selfBundleShellQuoteArg(agent), selfBundleShellQuoteArg(reviewPath))},
			}),
			DoneCriteria: []string{
				"Reviewer output uses ariadne.llm_review/v1.",
				"review-check accepts every issue against packet exposure IDs and graph edges.",
				"No reviewer claim is treated as fact unless Ariadne validation accepts it.",
			},
			Limitations: []string{
				"Reviewer output is interpretation over packet evidence, not new raw evidence.",
				"Unsupported exposure IDs, statuses, graph edges, severities, priorities, and dispositions are rejected.",
			},
		},
		{
			ID:            "llm-inventory-blind",
			Title:         "Blind Inventory Gap Review",
			Profile:       "inventory_blind",
			Scope:         "Redacted inventory facts and source catalog without Ariadne exposure ranking.",
			Ingestibility: "no; request-only until hypotheses are mapped back to deterministic facts, source refs, and graph edges",
			Summary:       "Lower-bias hypothesis and collector-gap packet. Use it to find missing deterministic coverage, not to create direct findings.",
			SummaryPath:   blindSummary,
			PacketPath:    blindPacket,
			Commands: nonNilAssessOperatorCommands([]model.AssessOperatorCommand{
				{Step: 1, ID: "open_packet", Title: "Open packet", Files: []string{blindSummary, blindPacket}},
				{Step: 2, ID: "rerun_inventory", Title: "Rerun inventory after mapping a hypothesis", Command: fmt.Sprintf("ariadne inventory --path %s --mode %s --agent %s --format json --out %s", selfBundleShellQuoteArg(targetPath), selfBundleShellQuoteArg(mode), selfBundleShellQuoteArg(agent), selfBundleShellQuoteArg(inventoryGapPath)), Files: []string{inventoryGapPath}},
			}),
			DoneCriteria: []string{
				"Every hypothesis is mapped to an existing fact/source/graph ID or recorded as a collector gap.",
				"Any new finding is produced by deterministic Ariadne rerun evidence, not by the blind packet alone.",
			},
			Limitations: []string{
				"Inventory-blind packets are intentionally not ingestible as findings.",
				"Use this profile to improve collectors or test missed surfaces.",
			},
		},
	}
}

func nonNilAssessOperatorCommands(commands []model.AssessOperatorCommand) []model.AssessOperatorCommand {
	if commands == nil {
		return []model.AssessOperatorCommand{}
	}
	out := make([]model.AssessOperatorCommand, 0, len(commands))
	for _, command := range commands {
		command.Files = selfBundleNonEmptyStrings(command.Files...)
		out = append(out, command)
	}
	return out
}

func selfBundleNonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
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
		SchemaVersion:    model.SchemaVersion,
		RunKind:          "closure_workspace",
		GeneratedAt:      time.Now().UTC(),
		Directory:        absDir,
		TargetPath:       r.TargetPath,
		Mode:             selfBundleFirstNonEmpty(r.Story.Mode, plan.Mode, "repo"),
		Agent:            selfBundleFirstNonEmpty(r.Story.Runtime, plan.Agent, "all"),
		StatusFilter:     selfBundleFirstNonEmpty(status, plan.StatusFilter, "breaking"),
		CaseID:           caseID,
		IntegrityCommand: selfAssessmentBundleIntegrityCommand(absDir),
		ProofLoop:        closureWorkspaceProofLoop(r.TargetPath, selfBundleFirstNonEmpty(r.Story.Mode, plan.Mode, "repo"), selfBundleFirstNonEmpty(r.Story.Runtime, plan.Agent, "all"), selfBundleFirstNonEmpty(status, plan.StatusFilter, "breaking"), caseID, absDir),
		Limitations:      closureWorkspaceLimitations(),
		Files: []selfAssessmentBundleFile{
			{Name: "runbook.txt", Path: filepath.Join(absDir, "runbook.txt"), Description: "Action-first workflow for this closure case."},
			{Name: "runbook.json", Path: filepath.Join(absDir, "runbook.json"), Description: "Structured operator runbook for UI and workflow clients."},
			{Name: "source-inspection.txt", Path: filepath.Join(absDir, "source-inspection.txt"), Description: "Focused source action checklist for this closure case."},
			{Name: "source-inspection.json", Path: filepath.Join(absDir, "source-inspection.json"), Description: "Structured source inspection workbench for this closure case."},
			{Name: "before-proof.json", Path: filepath.Join(absDir, "before-proof.json"), Description: "Baseline proof state before changing evidence."},
			{Name: "proof-action.txt", Path: filepath.Join(absDir, "proof-action.txt"), Description: "Human proof action for the focused closure case."},
			{Name: "proof-plan.html", Path: filepath.Join(absDir, "proof-plan.html"), Description: "Focused proof-plan dashboard for reviewing evidence, patches, commands, and success criteria."},
			{Name: "proof-patches/README.md", Path: filepath.Join(absDir, "proof-patches", "README.md"), Description: "Review guide for suggested proof evidence files."},
			{Name: "proof-patches/manifest.json", Path: filepath.Join(absDir, "proof-patches", "manifest.json"), Description: "Structured manifest for suggested proof evidence files."},
			{Name: "README.md", Path: filepath.Join(absDir, "README.md"), Description: "Closure workspace guide and after/receipt/compare commands."},
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
		return report.RenderAssessRunbookForTarget(w, assess.OperatorWorkbench.Runbook, assess.TargetPath)
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
	if err := add("source-inspection.txt", true, func(w io.Writer) error {
		return report.RenderAssessReport(w, assess, "source-inspection")
	}); err != nil {
		return closureWorkspaceResult{}, err
	}
	if err := add("source-inspection.json", true, func(w io.Writer) error {
		return report.RenderAssessReport(w, assess, "source-inspection-json")
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
		"Run `ariadne bundle verify --dir BUNDLE_DIR` before attaching, sharing, or trusting this saved bundle.",
		"Read `assessment.txt` for the executive readout, decision, signal/noise boundary, and first action.",
		"Open `source-inspection.txt` for the exact files, line labels, inspect commands, metadata-only surfaces, and control links behind the current case.",
		"Use `runbook.txt` as the action-first operator workflow: open-first evidence, current step, commands, artifacts, and closure workflow. Use `runbook.json` for UI clients and workflow automation.",
		"Use `operator-packet.txt` as the compact ticket or handoff: source refs, graph path, controls, proof checkpoint, commands, and done criteria. Use `operator-packet.json` for automation.",
		"Use `case-action.txt` for the focused first-case handoff and `case-action.json` for the same case action in a compact automation contract.",
		"Open `dashboard.html` for the operator dashboard with evidence links, proof bundle rows, lifecycle, and case queue.",
		"Use `inventory-coverage.txt` to see which AI runtimes and managed-agent surfaces were discovered, parsed, summarized, or skipped.",
		"Use `llm-follow-up-request.json` for optional reviewer follow-up over Ariadne exposure IDs; validate any returned review with `ariadne review-check` before ingesting it.",
		"Use `llm-inventory-blind-request.json` for lower-bias hypothesis or collector-gap review; it is request-only until hypotheses are mapped back to deterministic facts, source refs, and graph edges.",
		"Use `proof-action.txt` to inspect the exact proof evidence Ariadne expects for the focused case.",
		"Use `proof-plan.json`, `assessment.json`, `inventory.json`, and `cases.json` for broader automation, ticket metadata, or deeper review.",
		"Run the proof loop commands below only after reviewing generated proof evidence and deciding what should be applied; use `closure-receipt.txt` as the ticket-ready closure readout.",
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
		"ariadne compare --before before-proof.json --after after-proof.json --format receipt --out closure-receipt.txt",
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
	receiptPath := filepath.Join(dir, "closure-receipt.txt")
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
		{Step: 4, ID: "closure_receipt", Title: "Create closure receipt", Command: fmt.Sprintf("ariadne compare --before %s --after %s --format receipt --out %s", selfBundleShellQuoteArg(beforePath), selfBundleShellQuoteArg(afterPath), selfBundleShellQuoteArg(receiptPath)), Output: receiptPath, Description: "Run after saving after-proof.json; paste this receipt into the ticket or audit note."},
		{Step: 5, ID: "compare_state", Title: "Create HTML compare", Command: fmt.Sprintf("ariadne compare --before %s --after %s --format html --out %s", selfBundleShellQuoteArg(beforePath), selfBundleShellQuoteArg(afterPath), selfBundleShellQuoteArg(comparePath)), Output: comparePath, Description: "Optional richer review artifact for the same before/after proof state."},
	}
}

func selfAssessmentBundleLimitations() []string {
	return []string{
		"The bundle is generated from deterministic local facts, typed parsers, and graph evidence; it does not execute agents, MCP servers, package managers, or tools.",
		"Proof patches are suggested evidence files for review. Exporting or copying them does not prove live enforcement by itself.",
		"Treat `closure-receipt.txt` as the closure readout after rerunning Ariadne against the changed target; use `case-compare.html` for richer review.",
		"Private histories, transcripts, paste caches, and sensitive files are summarized or path-modeled; Ariadne does not emit secret values.",
	}
}

func closureWorkspaceLimitations() []string {
	return []string{
		"The closure workspace is generated from deterministic local facts, graph evidence, and proof-plan contracts.",
		"Suggested proof files are review-first evidence artifacts. Ariadne does not mutate the scanned target.",
		"before-proof.json is a baseline from workspace creation time; after-proof.json must be generated after evidence is changed or verified.",
		"closure-receipt.txt is the ticket-ready closure readout after the after-proof artifact exists; case-compare.html is the richer review artifact.",
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

func selfAssessmentBundleIntegrityCommand(dir string) string {
	return "ariadne bundle verify --dir " + selfBundleShellQuoteArg(dir)
}

func writeRenderedFile(path string, render func(io.Writer) error) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return render(file)
}

func writeJSONPayload(w io.Writer, payload []byte) error {
	if _, err := w.Write(payload); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
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
	if result.IntegrityCommand != "" {
		fmt.Fprintf(&b, "\n## Bundle Integrity\n\n")
		fmt.Fprintf(&b, "Before attaching, sharing, or trusting this saved bundle, verify the generated file hashes:\n\n")
		fmt.Fprintf(&b, "```bash\n%s\n```\n\n", result.IntegrityCommand)
	}
	fmt.Fprintf(&b, "\n## Suggested Review Order\n\n")
	for idx, item := range result.ReviewOrder {
		fmt.Fprintf(&b, "%d. %s\n", idx+1, item)
	}
	if len(result.ProofLoop) > 0 {
		fmt.Fprintf(&b, "\n## Proof Loop Commands\n\n")
		fmt.Fprintf(&b, "Run these from a working directory where you want `before-proof.json`, `after-proof.json`, `proof-patches/`, `closure-receipt.txt`, and `case-compare.html` written.\n\n")
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
	if result.IntegrityCommand != "" {
		fmt.Fprintf(&b, "\n## Workspace Integrity\n\n")
		fmt.Fprintf(&b, "Before attaching, sharing, or trusting this saved workspace, verify the generated file hashes:\n\n")
		fmt.Fprintf(&b, "```bash\n%s\n```\n\n", result.IntegrityCommand)
	}
	fmt.Fprintf(&b, "\n## Review Order\n\n")
	fmt.Fprintf(&b, "1. Run the workspace integrity command before attaching, sharing, or trusting this saved workspace.\n")
	fmt.Fprintf(&b, "2. Open `runbook.txt` for the action-first workflow.\n")
	fmt.Fprintf(&b, "3. Open `source-inspection.txt` for exact source files, line labels, inspect commands, metadata-only surfaces, and control links.\n")
	fmt.Fprintf(&b, "4. Open `proof-action.txt` for the exact proof evidence Ariadne expects.\n")
	fmt.Fprintf(&b, "5. Review `proof-patches/README.md` and `proof-patches/manifest.json` before copying any suggested evidence file.\n")
	fmt.Fprintf(&b, "6. After evidence is changed or verified, run the after-proof command below.\n")
	fmt.Fprintf(&b, "7. Run the closure receipt command and use `closure-receipt.txt` as the ticket-ready closure readout. Use `case-compare.html` for richer review.\n")
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
	fmt.Fprintf(w, "Source inspection: %s\n", filepath.Join(result.Directory, "source-inspection.txt"))
	fmt.Fprintf(w, "Operator packet: %s\n", filepath.Join(result.Directory, "operator-packet.txt"))
	fmt.Fprintf(w, "Operator packet JSON: %s\n", filepath.Join(result.Directory, "operator-packet.json"))
	fmt.Fprintf(w, "Dashboard: %s\n", filepath.Join(result.Directory, "dashboard.html"))
	fmt.Fprintf(w, "LLM follow-up packet: %s\n", filepath.Join(result.Directory, "llm-follow-up-request.json"))
	fmt.Fprintf(w, "LLM inventory-blind packet: %s\n", filepath.Join(result.Directory, "llm-inventory-blind-request.json"))
	fmt.Fprintf(w, "Proof action: %s\n", filepath.Join(result.Directory, "proof-action.txt"))
	if result.IntegrityCommand != "" {
		fmt.Fprintf(w, "Verify bundle: %s\n", result.IntegrityCommand)
	}
}

func renderClosureWorkspaceSummary(w io.Writer, result closureWorkspaceResult) {
	fmt.Fprintf(w, "Created Ariadne closure workspace at %s\n", result.Directory)
	fmt.Fprintf(w, "Case: %s\n", result.CaseID)
	fmt.Fprintf(w, "Open first: %s\n", filepath.Join(result.Directory, "runbook.txt"))
	fmt.Fprintf(w, "Source inspection: %s\n", filepath.Join(result.Directory, "source-inspection.txt"))
	fmt.Fprintf(w, "Baseline proof: %s\n", filepath.Join(result.Directory, "before-proof.json"))
	fmt.Fprintf(w, "Suggested proof files: %s\n", filepath.Join(result.Directory, "proof-patches"))
	for _, command := range result.ProofLoop {
		if command.ID == "save_after_proof" {
			fmt.Fprintf(w, "After changes: %s\n", command.Command)
		}
		if command.ID == "closure_receipt" {
			fmt.Fprintf(w, "Closure receipt: %s\n", command.Command)
		}
		if command.ID == "compare_state" {
			fmt.Fprintf(w, "Compare HTML: %s\n", command.Command)
		}
	}
	fmt.Fprintf(w, "Guide: %s\n", filepath.Join(result.Directory, "README.md"))
	if result.IntegrityCommand != "" {
		fmt.Fprintf(w, "Verify workspace: %s\n", result.IntegrityCommand)
	}
}

func runBundle(args []string) {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		bundleUsage(os.Stdout)
		return
	}
	switch args[0] {
	case "verify":
		runBundleVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown bundle command: %s\n\n", args[0])
		bundleUsage(os.Stderr)
		os.Exit(2)
	}
}

func runBundleVerify(args []string) {
	fs := flag.NewFlagSet("bundle verify", flag.ExitOnError)
	dir := fs.String("dir", ".", "bundle directory containing manifest.json")
	manifestPath := fs.String("manifest", "", "explicit bundle manifest path")
	format := fs.String("format", "summary", "output format: summary, json")
	outPath := fs.String("out", "", "write output to file")
	fs.Parse(args)
	verify, err := buildBundleVerifyReport(*manifestPath, *dir)
	if err != nil {
		fatal(err)
	}
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	if err := renderBundleVerifyReport(writer, verify, *format); err != nil {
		closeFn()
		fatal(err)
	}
	closeFn()
	if verify.Status != "ok" {
		os.Exit(1)
	}
}

func bundleUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  ariadne bundle verify --dir ariadne-self
  ariadne bundle verify --manifest ariadne-self/manifest.json --format json`)
}

func buildBundleVerifyReport(manifestPath string, dir string) (bundleVerifyReport, error) {
	manifestPath = strings.TrimSpace(manifestPath)
	dir = strings.TrimSpace(dir)
	if manifestPath == "" {
		if dir == "" {
			dir = "."
		}
		manifestPath = filepath.Join(dir, "manifest.json")
	}
	absManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		absManifest = manifestPath
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return bundleVerifyReport{}, err
	}
	var manifest bundleVerifyManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return bundleVerifyReport{}, err
	}
	baseDir := strings.TrimSpace(dir)
	if baseDir == "" || baseDir == "." {
		baseDir = filepath.Dir(absManifest)
	}
	if absBaseDir, err := filepath.Abs(baseDir); err == nil {
		baseDir = absBaseDir
	}
	report := bundleVerifyReport{
		SchemaVersion: model.SchemaVersion,
		RunKind:       "bundle_verify",
		GeneratedAt:   time.Now().UTC(),
		ManifestPath:  absManifest,
		Directory:     baseDir,
		Status:        "ok",
		Limitations: []string{
			"Bundle verification checks generated artifact sizes and SHA-256 hashes recorded in manifest.json.",
			"Files without a manifest hash are skipped; manifest.json is intentionally not self-hashed by generated bundles.",
			"Verification does not inspect original target files or prove live runtime enforcement.",
		},
	}
	for _, file := range manifest.Files {
		result := verifyBundleManifestFile(baseDir, file)
		report.Results = append(report.Results, result)
		switch result.Status {
		case "ok":
			report.Passed++
			report.FilesChecked++
		case "skipped":
			report.Skipped++
		default:
			report.Failed++
			report.FilesChecked++
		}
	}
	if report.Failed > 0 {
		report.Status = "failed"
	}
	return report, nil
}

func verifyBundleManifestFile(baseDir string, file selfAssessmentBundleFile) bundleVerifyFileResult {
	result := bundleVerifyFileResult{
		Name:              file.Name,
		Path:              bundleVerifyResolveFilePath(baseDir, file),
		ExpectedSizeBytes: file.SizeBytes,
		ExpectedSHA256:    file.SHA256,
	}
	if strings.TrimSpace(file.SHA256) == "" {
		result.Status = "skipped"
		result.Reason = "no sha256 recorded in manifest"
		return result
	}
	info, err := os.Stat(result.Path)
	if err != nil {
		result.Status = "missing"
		result.Reason = err.Error()
		return result
	}
	if info.IsDir() {
		result.Status = "failed"
		result.Reason = "expected file but found directory"
		return result
	}
	contents, err := os.ReadFile(result.Path)
	if err != nil {
		result.Status = "failed"
		result.Reason = err.Error()
		return result
	}
	result.ActualSizeBytes = info.Size()
	sum := sha256.Sum256(contents)
	result.ActualSHA256 = fmt.Sprintf("%x", sum[:])
	var reasons []string
	if file.SizeBytes != 0 && info.Size() != file.SizeBytes {
		reasons = append(reasons, "size mismatch")
	}
	if !strings.EqualFold(result.ActualSHA256, strings.TrimSpace(file.SHA256)) {
		reasons = append(reasons, "sha256 mismatch")
	}
	if len(reasons) > 0 {
		result.Status = "failed"
		result.Reason = strings.Join(reasons, "; ")
		return result
	}
	result.Status = "ok"
	return result
}

func bundleVerifyResolveFilePath(baseDir string, file selfAssessmentBundleFile) string {
	name := filepath.FromSlash(strings.TrimSpace(file.Name))
	if name != "" {
		candidate := filepath.Join(baseDir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if strings.TrimSpace(file.Path) != "" {
		return file.Path
	}
	return filepath.Join(baseDir, name)
}

func renderBundleVerifyReport(w io.Writer, report bundleVerifyReport, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "summary", "table":
		renderBundleVerifySummary(w, report)
		return nil
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	default:
		return fmt.Errorf("unknown bundle verify format: %s", format)
	}
}

func renderBundleVerifySummary(w io.Writer, report bundleVerifyReport) {
	fmt.Fprintln(w, "Ariadne Bundle Verify")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Manifest: %s\n", report.ManifestPath)
	fmt.Fprintf(w, "Directory: %s\n", report.Directory)
	fmt.Fprintf(w, "Status: %s\n", report.Status)
	fmt.Fprintf(w, "Files checked: %d\n", report.FilesChecked)
	fmt.Fprintf(w, "Passed: %d\n", report.Passed)
	fmt.Fprintf(w, "Failed: %d\n", report.Failed)
	fmt.Fprintf(w, "Skipped: %d\n", report.Skipped)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Results:")
	for _, result := range report.Results {
		line := fmt.Sprintf("  - %s %s", strings.ToUpper(result.Status), result.Name)
		if result.Reason != "" {
			line += ": " + result.Reason
		}
		if result.ActualSHA256 != "" {
			line += " sha256:" + shortBundleDigest(result.ActualSHA256)
		}
		fmt.Fprintln(w, line)
	}
	if len(report.Limitations) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Limitations:")
		for _, limitation := range report.Limitations {
			fmt.Fprintf(w, "  - %s\n", limitation)
		}
	}
}

func shortBundleDigest(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func runCases(args []string) {
	fs := flag.NewFlagSet("cases", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of operator case targets, one path per line or id,path")
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to inspect")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	status := fs.String("status", "breaking", "architecture flaw status filter: breaking, controlled, unknown, not_observed, observed, all")
	caseID := fs.String("case", "", "operator case id to focus, e.g. case:input-trust-boundary")
	format := fs.String("format", "table", "output format: table, action, action-json, json, html")
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
		fatal(fmt.Errorf("usage: ariadne compare --before before.json --after after.json [--format table|receipt|json|html]"))
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
	format := fs.String("format", "table", "output format: table, coverage, json, html, dot, mermaid")
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

func runReviewRun(args []string) {
	fs := flag.NewFlagSet("review-run", flag.ExitOnError)
	path := fs.String("path", ".", "repo, workspace, or mounted endpoint home path to review")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	command := fs.String("command", "", "local reviewer command; reads request JSON on stdin and writes ariadne.llm_review/v1 JSON on stdout")
	profile := fs.String("profile", "follow-up", "review profile: follow-up")
	dir := fs.String("dir", "ariadne-review", "artifact directory for packet, raw review, and validation output")
	format := fs.String("format", "summary", "output format: summary, json")
	outPath := fs.String("out", "", "write command output to file")
	rulesPath := fs.String("rules", "", "custom deterministic rule policy JSON")
	llmTimeout := fs.Int("timeout-seconds", 60, "timeout for reviewer command")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive paths in output")
	fs.Parse(args)
	run, err := prove.RunReviewRun(prove.Options{
		Path:                  *path,
		Agent:                 *agent,
		Mode:                  *mode,
		RulesPath:             *rulesPath,
		LLMCommand:            *command,
		LLMReviewProfile:      *profile,
		LLMTimeout:            time.Duration(*llmTimeout) * time.Second,
		IncludeSensitivePaths: *includeSensitive,
	}, *dir)
	if err != nil {
		fatal(err)
	}
	checkWriter, checkClose, err := outputWriter(run.CheckSummaryPath)
	if err != nil {
		fatal(err)
	}
	if err := report.RenderLLMReviewCheckSummary(checkWriter, run.Check); err != nil {
		checkClose()
		fatal(err)
	}
	checkClose()
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderLLMReviewRun(writer, run, *format); err != nil {
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
  bundle         Verify generated bundle manifests and file hashes
  inventory      Collect deterministic AI surface facts without classifying exposure
  review-packet  Create a fact-bound review packet for human or LLM inspection
  review-check   Validate a reviewer response against an exact review packet
  review-run     Run a local reviewer command and validate the response
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
  ariadne bundle verify --dir ariadne-self
  ariadne bundle verify --manifest ariadne-closure/manifest.json --format json
  ariadne compare --before before-proof.json --after after-proof.json
  ariadne compare --before before-proof.json --after after-proof.json --format receipt --out closure-receipt.txt
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
  ariadne review-run --path . --command ./security-reviewer --dir ariadne-review
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
