package main

import (
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

const agentHelp = "agent runtime to inspect: all, claude, codex, cursor, windsurf, continue, aider, gemini, opencode"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stdout)
		os.Exit(0)
	}
	switch os.Args[1] {
	case "assess":
		runAssess(os.Args[2:])
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
	path := fs.String("path", ".", "repo or workspace path to assess")
	agent := fs.String("agent", "all", agentHelp)
	mode := fs.String("mode", "repo", "collection mode: repo, endpoint")
	status := fs.String("status", "breaking", "architecture flaw status filter: breaking, controlled, unknown, not_observed, observed, all")
	format := fs.String("format", "table", "output format: table, action, json, html")
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
		if err := report.RenderAssessScan(writer, r, *format, *status); err != nil {
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
	if err := report.RenderAssess(writer, inventory, r, *format, *status); err != nil {
		fatal(err)
	}
}

func runCases(args []string) {
	fs := flag.NewFlagSet("cases", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of operator case targets, one path per line or id,path")
	path := fs.String("path", ".", "repo or workspace path to inspect")
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
	path := fs.String("path", ".", "repo or workspace path to inspect")
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
	writer, closeFn, err := outputWriter(*outPath)
	if err != nil {
		fatal(err)
	}
	defer closeFn()
	if err := report.RenderProofs(writer, r, *format, *status, *caseID); err != nil {
		fatal(err)
	}
}

func runControls(args []string) {
	fs := flag.NewFlagSet("controls", flag.ExitOnError)
	targetsFile := fs.String("targets", "", "file of control catalog targets, one path per line or id,path")
	path := fs.String("path", ".", "repo or workspace path to inspect")
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
	path := fs.String("path", ".", "repo or workspace path to inspect")
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
	path := fs.String("path", ".", "repo or workspace path to inventory")
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
	path := fs.String("path", ".", "repo or workspace path to prove when --story is not set")
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
		if err := report.RenderScan(writer, r, "html"); err != nil {
			fatal(err)
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
	if err := report.Render(writer, r, "html"); err != nil {
		fatal(err)
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
  architecture   Show Zero Trust agent architecture flaws, filtered to breaking by default
  cases          Show the operator case board for architecture break paths
  proofs         Show focused proof patches for closing operator cases
  controls       Show missing hard-barrier controls and where to prove them
  compare        Compare two Ariadne JSON reports and show case state changes
  inventory      Collect deterministic AI surface facts without classifying exposure
  prove          Prove supported exposure paths for a real path or Story Lab scenario
  scan           Run exposure analysis across one or more local/mounted targets
  dashboard      Write a local HTML issue dashboard for one target or a target list
  stories list   List Story Lab scenarios

Examples:
  ariadne assess --path .
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
  ariadne proofs --path . --case case:input-trust-boundary --format json
  ariadne proofs --path . --case case:input-trust-boundary --format html --out proof-plan.html
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
