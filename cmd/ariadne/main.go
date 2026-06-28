package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hayahaya-ai/ariadne/internal/remediate"
	"github.com/hayahaya-ai/ariadne/internal/report"
	"github.com/hayahaya-ai/ariadne/internal/scan"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stdout)
		os.Exit(0)
	}
	switch os.Args[1] {
	case "doctor":
		doctor(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "remediate":
		runRemediate(os.Args[2:])
	case "explain":
		runExplain(os.Args[2:])
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func doctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	modeFlag := fs.String("mode", "repo", "scan mode: repo, endpoint, devbox")
	path := fs.String("path", ".", "path to scan")
	fs.Parse(args)
	mode, err := scan.ValidateMode(*modeFlag)
	if err != nil {
		fatal(err)
	}
	opts := scan.Options{Mode: mode, Path: *path}
	for _, line := range scan.Doctor(opts) {
		fmt.Println(line)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	modeFlag := fs.String("mode", "repo", "scan mode: repo, endpoint, devbox")
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "table", "output format: table, json, markdown, sarif")
	outPath := fs.String("out", "", "write output to file")
	failOn := fs.String("fail-on", "", "exit 1 when unsuppressed finding severity is at least this value")
	includeSensitive := fs.Bool("include-sensitive-paths", false, "include exact sensitive path names in local output")
	preview := fs.Bool("preview-collection", false, "show collection scope before scanning")
	fs.Parse(args)
	mode, err := scan.ValidateMode(*modeFlag)
	if err != nil {
		fatal(err)
	}
	opts := scan.Options{
		Mode:                  mode,
		Path:                  *path,
		Format:                *format,
		Out:                   *outPath,
		IncludeSensitivePaths: *includeSensitive,
		PreviewCollection:     *preview,
	}
	if *preview {
		for _, line := range scan.Doctor(opts) {
			fmt.Println(line)
		}
		return
	}
	if *failOn != "" {
		opts.FailOn = parseSeverity(*failOn)
	}
	r, err := scan.Run(opts)
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
	if opts.FailOn != "" && crossesThreshold(r, opts.FailOn) {
		os.Exit(1)
	}
}

func runRemediate(args []string) {
	fs := flag.NewFlagSet("remediate", flag.ExitOnError)
	input := fs.String("input", "", "JSON report to read")
	fs.Parse(args)
	if *input == "" {
		fatal(fmt.Errorf("--input is required"))
	}
	if err := remediate.RenderFromFile(os.Stdout, *input); err != nil {
		fatal(err)
	}
}

func runExplain(args []string) {
	if len(args) != 1 {
		fatal(fmt.Errorf("usage: ariadne explain FINDING_ID"))
	}
	id := args[0]
	explanations := map[string]string{
		"dangerous-agent-mode":              "Dangerous modes bypass approval and sandbox boundaries. The scanner detects declared indicators only; it does not verify runtime enforcement.",
		"network-enabled-agent":             "Network-enabled agent config raises data-egress risk from the developer environment. The scanner does not verify actual VPN/internal reachability.",
		"missing-secret-deny-policy":        "Missing deny-read policy coverage means common credential paths are not declared as protected. This is not proof that an agent can read secrets.",
		"unknown-or-unapproved-mcp":         "Unknown MCP servers expand tool blast radius and may expose local commands, SaaS APIs, or filesystem access.",
		"mcp-package-or-interpreter-launch": "Package-manager and interpreter-launched MCP servers can drift or execute local code under the developer user.",
	}
	for key, text := range explanations {
		if strings.Contains(id, key) || id == key {
			fmt.Println(text)
			return
		}
	}
	fmt.Println("No built-in explanation found for this finding ID. Inspect the report's why_it_matters and runtime_limitations fields.")
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `ariadne: local AI coding-agent posture scanner

Commands:
  doctor      Explain what Ariadne will inspect
  scan        Scan Claude Code, Codex, MCP, repo, and devcontainer posture
  remediate   Render remediation guidance from a JSON report
  explain     Explain a finding ID

Examples:
  ariadne doctor --mode endpoint
  ariadne scan --mode repo --path .
  ariadne scan --mode endpoint --format json --out report.json
  ariadne scan --mode repo --format sarif --out ariadne.sarif --fail-on high`)
}

func outputWriter(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { file.Close() }, nil
}

func parseSeverity(value string) scan.Severity {
	switch strings.ToLower(value) {
	case "critical":
		return scan.SeverityCritical
	case "high":
		return scan.SeverityHigh
	case "medium":
		return scan.SeverityMedium
	case "low":
		return scan.SeverityLow
	default:
		fatal(fmt.Errorf("--fail-on must be critical, high, medium, or low"))
		return ""
	}
}

func crossesThreshold(r scan.Report, threshold scan.Severity) bool {
	for _, f := range r.Findings {
		if !f.Suppressed && scan.SeverityRank(f.Severity) >= scan.SeverityRank(threshold) {
			return true
		}
	}
	for _, p := range r.AttackPaths {
		if scan.SeverityRank(p.Severity) >= scan.SeverityRank(threshold) {
			return true
		}
	}
	return false
}

func fatal(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "ariadne:", err)
	os.Exit(2)
}

func debugJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
