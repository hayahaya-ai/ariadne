package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/hayahaya-ai/ariadne/internal/scan"
)

func Render(w io.Writer, r scan.Report, format string) error {
	switch strings.ToLower(format) {
	case "", "table":
		return renderTable(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "markdown", "md":
		return renderMarkdown(w, r)
	case "sarif":
		return renderSARIF(w, r)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

func renderTable(w io.Writer, r scan.Report) error {
	fmt.Fprintf(w, "Ariadne Agent Posture Scan\n\n")
	fmt.Fprintf(w, "Repo: %s\n", empty(r.Repo.Remote, r.Repo.Root, "unknown"))
	fmt.Fprintf(w, "Mode: %s\n", r.ScanMode)
	fmt.Fprintf(w, "Platform: %s\n", r.Platform)
	fmt.Fprintf(w, "Risk: %s\n\n", highestSeverity(r))
	if len(r.AttackPaths) > 0 {
		fmt.Fprintf(w, "Attack Paths:\n")
		for _, path := range sortedAttackPaths(r.AttackPaths) {
			fmt.Fprintf(w, "[%s] %s\n", strings.ToUpper(string(path.Severity)), path.Title)
			fmt.Fprintf(w, "  %s\n", path.CredibleAbuseStory)
		}
		fmt.Fprintln(w)
	}
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return nil
	}
	fmt.Fprintf(w, "Findings:\n")
	for _, f := range sortedFindings(r.Findings) {
		if f.Suppressed {
			continue
		}
		fmt.Fprintf(w, "[%s] %s\n", strings.ToUpper(string(f.Severity)), f.Title)
		fmt.Fprintf(w, "  Evidence: %s (%s)\n", empty(f.EvidenceSource, "unknown"), f.EvidenceKind)
		fmt.Fprintf(w, "  Confidence: %s\n", f.Confidence)
		fmt.Fprintf(w, "  Limit: %s\n", f.RuntimeLimitations)
	}
	return nil
}

func renderMarkdown(w io.Writer, r scan.Report) error {
	fmt.Fprintf(w, "# Ariadne Agent Posture Scan\n\n")
	fmt.Fprintf(w, "- **Repo:** %s\n", empty(r.Repo.Remote, r.Repo.Root, "unknown"))
	fmt.Fprintf(w, "- **Mode:** %s\n", r.ScanMode)
	fmt.Fprintf(w, "- **Platform:** %s\n", r.Platform)
	fmt.Fprintf(w, "- **Highest risk:** %s\n\n", highestSeverity(r))
	if len(r.AttackPaths) > 0 {
		fmt.Fprintf(w, "## Attack Paths\n\n")
		for _, path := range sortedAttackPaths(r.AttackPaths) {
			fmt.Fprintf(w, "### [%s] %s\n\n", strings.ToUpper(string(path.Severity)), path.Title)
			fmt.Fprintf(w, "**Credible abuse story:** %s\n\n", path.CredibleAbuseStory)
			fmt.Fprintf(w, "**Why it matters:** %s\n\n", path.WhyItMatters)
			fmt.Fprintf(w, "**Reduce risk:**\n")
			for _, item := range path.WhatWouldReduceRisk {
				fmt.Fprintf(w, "- %s\n", item)
			}
			fmt.Fprintf(w, "\n**Limit:** %s\n\n", path.RuntimeLimitations)
		}
	}
	fmt.Fprintf(w, "## Findings\n\n")
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "No findings.\n\n")
	} else {
		for _, f := range sortedFindings(r.Findings) {
			if f.Suppressed {
				continue
			}
			fmt.Fprintf(w, "### [%s] %s\n\n", strings.ToUpper(string(f.Severity)), f.Title)
			fmt.Fprintf(w, "- **Confidence:** %s\n", f.Confidence)
			fmt.Fprintf(w, "- **Evidence:** %s (%s)\n", empty(f.EvidenceSource, "unknown"), f.EvidenceKind)
			fmt.Fprintf(w, "- **Affected asset:** %s\n", empty(f.AffectedAsset, "unknown"))
			fmt.Fprintf(w, "- **Why it matters:** %s\n", f.WhyItMatters)
			fmt.Fprintf(w, "- **Limit:** %s\n\n", f.RuntimeLimitations)
		}
	}
	if len(r.Remediations) > 0 {
		fmt.Fprintf(w, "## Remediation Snippets\n\n")
		for _, remediation := range r.Remediations {
			fmt.Fprintf(w, "### %s\n\n", remediation.Title)
			fmt.Fprintf(w, "**Applies to:** %s\n\n", remediation.AppliesTo)
			if remediation.Snippet != "" {
				fmt.Fprintf(w, "```text\n%s\n```\n\n", remediation.Snippet)
			}
			for _, step := range remediation.ManualSteps {
				fmt.Fprintf(w, "- %s\n", step)
			}
			fmt.Fprintf(w, "\n**Behavioral impact:** %s\n\n", remediation.BehavioralImpact)
		}
	}
	return nil
}

func renderSARIF(w io.Writer, r scan.Report) error {
	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string            `json:"ruleId"`
		Level     string            `json:"level"`
		Message   map[string]string `json:"message"`
		Locations []sarifLocation   `json:"locations,omitempty"`
	}
	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription map[string]string `json:"shortDescription"`
	}
	type sarifRun struct {
		Tool struct {
			Driver struct {
				Name  string      `json:"name"`
				Rules []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	root := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
	}
	var run sarifRun
	run.Tool.Driver.Name = "ariadne"
	seenRules := map[string]bool{}
	for _, f := range r.Findings {
		if f.Suppressed {
			continue
		}
		if !seenRules[f.RuleID] {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: map[string]string{"text": f.Title},
			})
			seenRules[f.RuleID] = true
		}
		result := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: map[string]string{"text": fmt.Sprintf("%s. %s", f.Title, f.RuntimeLimitations)},
		}
		if r.ScanMode == scan.ModeRepo && f.EvidenceSource != "" {
			var loc sarifLocation
			loc.PhysicalLocation.ArtifactLocation.URI = f.EvidenceSource
			result.Locations = []sarifLocation{loc}
		}
		run.Results = append(run.Results, result)
	}
	root["runs"] = []sarifRun{run}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(root)
}

func sortedFindings(findings []scan.Finding) []scan.Finding {
	out := append([]scan.Finding(nil), findings...)
	sort.SliceStable(out, func(i, j int) bool {
		ri := scan.SeverityRank(out[i].Severity)
		rj := scan.SeverityRank(out[j].Severity)
		if ri == rj {
			return out[i].Title < out[j].Title
		}
		return ri > rj
	})
	return out
}

func sortedAttackPaths(paths []scan.AttackPath) []scan.AttackPath {
	out := append([]scan.AttackPath(nil), paths...)
	sort.SliceStable(out, func(i, j int) bool {
		ri := scan.SeverityRank(out[i].Severity)
		rj := scan.SeverityRank(out[j].Severity)
		if ri == rj {
			return out[i].Title < out[j].Title
		}
		return ri > rj
	})
	return out
}

func highestSeverity(r scan.Report) scan.Severity {
	highest := scan.SeverityInfo
	for _, f := range r.Findings {
		if !f.Suppressed && scan.SeverityRank(f.Severity) > scan.SeverityRank(highest) {
			highest = f.Severity
		}
	}
	for _, p := range r.AttackPaths {
		if scan.SeverityRank(p.Severity) > scan.SeverityRank(highest) {
			highest = p.Severity
		}
	}
	return highest
}

func sarifLevel(s scan.Severity) string {
	switch s {
	case scan.SeverityCritical, scan.SeverityHigh:
		return "error"
	case scan.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func empty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
