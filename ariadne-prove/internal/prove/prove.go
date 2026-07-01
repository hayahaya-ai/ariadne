package prove

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/adapter"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/interpret"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/storylab"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/zerotrust"
)

type Options struct {
	StoryRoot             string
	StoryID               string
	Path                  string
	TargetsFile           string
	Targets               []model.ScanTarget
	Agent                 string
	Mode                  string
	RulesPath             string
	InterpretMode         string
	LLMReviewPath         string
	LLMCommand            string
	LLMRequestOut         string
	LLMTimeout            time.Duration
	IncludeSensitivePaths bool
}

func RunStory(opts Options) (model.Report, error) {
	if opts.StoryRoot == "" {
		opts.StoryRoot = filepath.Join("testdata", "storylab")
	}
	story, err := storylab.Load(opts.StoryRoot, opts.StoryID)
	if err != nil {
		return model.Report{}, err
	}
	manifest := story.Manifest
	repoPath := resolve(story.Dir, manifest.World.RepoPath)
	homePath := resolve(story.Dir, manifest.World.HomePath)
	collection := adapter.Collect(adapter.Options{RepoPath: repoPath, HomePath: homePath, Mode: manifest.Mode, Runtime: manifest.Runtime, StoryDir: story.Dir, IncludeSensitivePaths: opts.IncludeSensitivePaths})
	graph := BuildGraph(collection)
	exposure := Evaluate(collection, graph, manifest)
	zeroTrust := zerotrust.Assess(collection, graph, []model.ExposureResult{exposure})
	policy, err := loadPolicy(story.Dir, opts.RulesPath)
	if err != nil {
		return model.Report{}, err
	}
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		RunID:         randomID(),
		GeneratedAt:   time.Now().UTC(),
		RunKind:       "story",
		Story: model.StorySummary{
			ID:           manifest.ID,
			Title:        manifest.Title,
			Persona:      manifest.Persona,
			UserQuestion: manifest.UserQuestion,
			Runtime:      manifest.Runtime,
			Mode:         manifest.Mode,
		},
		Expected:  manifest.Expected,
		Exposure:  exposure,
		Exposures: []model.ExposureResult{exposure},
		ZeroTrust: zeroTrust,
		Graph:     graph,
		Evidence:  collection.Evidence,
		Redaction: model.RedactionInfo{
			Level:                  "default",
			SensitivePathsIncluded: opts.IncludeSensitivePaths,
			CanaryValuesIncluded:   false,
		},
		Warnings: collection.Warnings,
		Limitations: []string{
			"Story Lab uses synthetic worlds and fake canaries as the correctness oracle.",
			"No real secrets are read or reported.",
			"Phase 1 evaluates exposure paths, not governance or runtime blocking.",
		},
	}
	interp, err := interpret.EvaluateWithOptions(interpret.Input{
		Target:     manifest.ID,
		Mode:       manifest.Mode,
		Collection: collection,
		Graph:      graph,
		Exposures:  report.Exposures,
		Policy:     policy,
	}, interpret.Options{
		Mode:           opts.InterpretMode,
		ReviewPath:     opts.LLMReviewPath,
		Command:        opts.LLMCommand,
		RequestOut:     opts.LLMRequestOut,
		Timeout:        opts.LLMTimeout,
		Question:       report.Story.UserQuestion,
		Redaction:      report.Redaction,
		RunLimitations: report.Limitations,
	})
	if err != nil {
		return model.Report{}, err
	}
	report.Interpretation = interp
	report.Expected.RedactionMustNotContain = nil
	report.Matched, report.Mismatches = Compare(report, manifest.Expected)
	return report, nil
}

func RunPath(opts Options) (model.Report, error) {
	if opts.Path == "" {
		opts.Path = "."
	}
	if opts.Agent == "" {
		opts.Agent = "all"
	}
	if opts.Mode == "" {
		opts.Mode = "repo"
	}
	root, err := filepath.Abs(opts.Path)
	if err != nil {
		return model.Report{}, err
	}
	home := ""
	if opts.Mode == "endpoint" {
		home, _ = os.UserHomeDir()
	}
	collection := adapter.Collect(adapter.Options{
		RepoPath:              root,
		HomePath:              home,
		Mode:                  opts.Mode,
		Runtime:               opts.Agent,
		StoryDir:              root,
		IncludeSensitivePaths: opts.IncludeSensitivePaths,
	})
	graph := BuildGraph(collection)
	exposures := EvaluateAll(collection, graph, opts.Mode)
	normalizeRealPathExposures(exposures)
	zeroTrust := zerotrust.Assess(collection, graph, exposures)
	primary := model.ExposureResult{}
	if len(exposures) > 0 {
		primary = exposures[0]
	}
	policy, err := loadPolicy(root, opts.RulesPath)
	if err != nil {
		return model.Report{}, err
	}
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		RunID:         randomID(),
		GeneratedAt:   time.Now().UTC(),
		RunKind:       "path",
		TargetPath:    root,
		Story: model.StorySummary{
			ID:           "real-path",
			Title:        "Real path exposure proof",
			Persona:      "developer / IT / AppSec",
			UserQuestion: "What agent exposure paths exist in this repository or setup?",
			Runtime:      opts.Agent,
			Mode:         opts.Mode,
		},
		Matched:   true,
		Exposure:  primary,
		Exposures: exposures,
		ZeroTrust: zeroTrust,
		Graph:     graph,
		Evidence:  collection.Evidence,
		Redaction: model.RedactionInfo{
			Level:                  "default",
			SensitivePathsIncluded: opts.IncludeSensitivePaths,
			CanaryValuesIncluded:   false,
		},
		Warnings: collection.Warnings,
		Limitations: []string{
			"Real path mode is static and local; it does not execute Claude, Codex, MCP servers, or package managers.",
			"Exposure means Ariadne found a graph path from influence or tool authority to a sensitive boundary; runtime exploitability is not proven.",
			"Missing evidence is represented as inconclusive rather than safe.",
		},
	}
	interp, err := interpret.EvaluateWithOptions(interpret.Input{
		Target:     root,
		Mode:       opts.Mode,
		Collection: collection,
		Graph:      graph,
		Exposures:  exposures,
		Policy:     policy,
	}, interpret.Options{
		Mode:           opts.InterpretMode,
		ReviewPath:     opts.LLMReviewPath,
		Command:        opts.LLMCommand,
		RequestOut:     opts.LLMRequestOut,
		Timeout:        opts.LLMTimeout,
		Question:       report.Story.UserQuestion,
		Redaction:      report.Redaction,
		RunLimitations: report.Limitations,
	})
	if err != nil {
		return model.Report{}, err
	}
	report.Interpretation = interp
	return report, nil
}

func RunInventory(opts Options) (model.InventoryReport, error) {
	if opts.Path == "" {
		opts.Path = "."
	}
	if opts.Agent == "" {
		opts.Agent = "all"
	}
	if opts.Mode == "" {
		opts.Mode = "repo"
	}
	root, err := filepath.Abs(opts.Path)
	if err != nil {
		return model.InventoryReport{}, err
	}
	home := ""
	target := root
	if opts.Mode == "endpoint" {
		home, _ = os.UserHomeDir()
		target = home
	}
	collection := adapter.Collect(adapter.Options{
		RepoPath:              root,
		HomePath:              home,
		Mode:                  opts.Mode,
		Runtime:               opts.Agent,
		StoryDir:              root,
		IncludeSensitivePaths: opts.IncludeSensitivePaths,
	})
	graph := BuildGraph(collection)
	return model.InventoryReport{
		SchemaVersion: model.SchemaVersion,
		RunID:         randomID(),
		GeneratedAt:   time.Now().UTC(),
		RunKind:       "inventory",
		TargetPath:    target,
		Mode:          opts.Mode,
		Agent:         opts.Agent,
		Collection:    collection,
		Graph:         graph,
		Redaction: model.RedactionInfo{
			Level:                  "default",
			SensitivePathsIncluded: opts.IncludeSensitivePaths,
			CanaryValuesIncluded:   false,
		},
		Warnings: collection.Warnings,
		Limitations: []string{
			"Inventory mode collects deterministic local facts only; it does not classify exposure.",
			"Private histories, paste caches, transcripts, and file history are summarized by metadata only.",
			"Claude, Codex, MCP, and generic repo instruction surfaces are supported in this milestone.",
		},
	}, nil
}

func RunScan(opts Options) (model.ScanReport, error) {
	if opts.Agent == "" {
		opts.Agent = "all"
	}
	if opts.Mode == "" {
		opts.Mode = "repo"
	}
	targets := opts.Targets
	if opts.TargetsFile != "" {
		loaded, err := LoadTargets(opts.TargetsFile)
		if err != nil {
			return model.ScanReport{}, err
		}
		targets = append(targets, loaded...)
	}
	if len(targets) == 0 && opts.Path != "" {
		targets = append(targets, model.ScanTarget{ID: filepath.Base(opts.Path), Path: opts.Path})
	}
	if len(targets) == 0 {
		return model.ScanReport{}, fmt.Errorf("scan requires --targets or --path")
	}
	if len(targets) > 1 && opts.LLMReviewPath != "" {
		return model.ScanReport{}, fmt.Errorf("--llm-review can only be used with a single scan target; use --llm-command for multi-target LLM review")
	}
	if len(targets) > 1 && opts.LLMRequestOut != "" {
		return model.ScanReport{}, fmt.Errorf("--llm-request-out can only be used with a single scan target")
	}
	r := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		RunID:         randomID(),
		GeneratedAt:   time.Now().UTC(),
		RunKind:       "scan",
		Mode:          opts.Mode,
		Agent:         opts.Agent,
		Redaction: model.RedactionInfo{
			Level:                  "default",
			SensitivePathsIncluded: opts.IncludeSensitivePaths,
			CanaryValuesIncluded:   false,
		},
		Limitations: []string{
			"Scan mode runs deterministic local analysis across the provided paths.",
			"Fleet usage expects endpoint data to be available as local or mounted paths; Ariadne does not remotely collect files.",
			"Each target report is static and local; no agent, MCP server, package manager, or network call is executed.",
		},
	}
	r.Summary.Targets = len(targets)
	for _, target := range targets {
		target.Path = strings.TrimSpace(target.Path)
		if target.Path == "" {
			continue
		}
		if target.ID == "" {
			target.ID = filepath.Base(target.Path)
		}
		report, err := RunPath(Options{
			Path:                  target.Path,
			Agent:                 opts.Agent,
			Mode:                  opts.Mode,
			RulesPath:             opts.RulesPath,
			InterpretMode:         opts.InterpretMode,
			LLMReviewPath:         opts.LLMReviewPath,
			LLMCommand:            opts.LLMCommand,
			LLMRequestOut:         opts.LLMRequestOut,
			LLMTimeout:            opts.LLMTimeout,
			IncludeSensitivePaths: opts.IncludeSensitivePaths,
		})
		result := model.ScanTargetResult{Target: target}
		if err != nil {
			result.Error = err.Error()
			r.Summary.Errors++
			r.Targets = append(r.Targets, result)
			continue
		}
		result.Report = report
		r.Summary.Completed++
		for _, exposure := range report.Exposures {
			r.Summary.ExposurePaths++
			switch exposure.Status {
			case model.StatusExposed:
				r.Summary.Exposed++
			case model.StatusProtected:
				r.Summary.Protected++
			case model.StatusInconclusive:
				r.Summary.Inconclusive++
			}
		}
		r.Targets = append(r.Targets, result)
	}
	r.Interpretation = interpret.AggregateScan(r.Targets)
	r.Summary.Critical = r.Interpretation.Summary.Critical
	r.Summary.High = r.Interpretation.Summary.High
	r.Summary.Medium = r.Interpretation.Summary.Medium
	r.Summary.Low = r.Interpretation.Summary.Low
	r.Summary.Info = r.Interpretation.Summary.Info
	return r, nil
}

func loadPolicy(root, explicit string) (model.RulePolicy, error) {
	path := interpret.DefaultPolicyPath(root, explicit)
	if path == "" {
		return model.RulePolicy{Version: "ariadne.rules/v1"}, nil
	}
	return interpret.LoadPolicy(path)
}

func LoadTargets(path string) ([]model.ScanTarget, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	baseDir := filepath.Dir(path)
	var targets []model.ScanTarget
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		target := model.ScanTarget{}
		if before, after, ok := strings.Cut(line, ","); ok {
			target.ID = strings.TrimSpace(before)
			target.Path = strings.TrimSpace(after)
		} else if before, after, ok := strings.Cut(line, "="); ok {
			target.ID = strings.TrimSpace(before)
			target.Path = strings.TrimSpace(after)
		} else {
			target.Path = line
			target.ID = filepath.Base(line)
		}
		if target.Path == "" {
			return nil, fmt.Errorf("empty target path at %s:%d", path, lineNo)
		}
		if !filepath.IsAbs(target.Path) {
			target.Path = filepath.Join(baseDir, target.Path)
		}
		targets = append(targets, target)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

func normalizeRealPathExposures(exposures []model.ExposureResult) {
	for i := range exposures {
		if exposures[i].ProofMode == model.ProofSimulated {
			exposures[i].ProofMode = model.ProofInferred
		}
		if exposures[i].Observation.Status == model.ObservationSucceededInLab {
			exposures[i].Observation.Status = model.ObservationNotAttempted
		}
		switch exposures[i].Observation.Summary {
		case "The simulated story path reaches the fake secret boundary without a breaking control.":
			exposures[i].Observation.Summary = "The deterministic graph path reaches a secret-like boundary without a breaking control."
		case "The simulated path reaches a deny-read control before the fake secret boundary.":
			exposures[i].Observation.Summary = "The deterministic graph path reaches a deny-read control before the secret-like boundary."
		case "The simulated story path reaches local code execution through a mutable tool launcher.":
			exposures[i].Observation.Summary = "The deterministic graph path reaches local code execution through a mutable tool launcher."
		case "The simulated MCP path reaches a reviewed/pinned control before local code execution.":
			exposures[i].Observation.Summary = "The deterministic graph path reaches a reviewed/pinned control before local code execution."
		}
		if exposures[i].ID == "prompt-injection-to-secret-canary" {
			exposures[i].Title = "Prompt/repo instruction to secret-like file access"
			exposures[i].WhatWasTested = "Whether influence plus local agent authority creates a path to a secret-like boundary, and whether a deny-read control breaks that path."
			exposures[i].Limitations = []string{
				"Real path mode is static and local; it does not execute the agent or read secret values.",
				"Exposure means Ariadne found a graph path, not that a live exploit was observed.",
			}
		}
		if exposures[i].ID == "mutable-tool-launch-execution" {
			exposures[i].Limitations = []string{
				"Real path mode inspects declared MCP configuration only.",
				"The MCP server is not executed and package identity is not resolved from a registry.",
			}
		}
		if exposures[i].ID == "data-egress-chain" {
			exposures[i].Limitations = []string{
				"Real path mode is static and local; it does not execute the agent or observe live data movement.",
				"Exposure means Ariadne found deterministic graph evidence for untrusted influence, private-data reachability, and external communication reachability.",
			}
		}
	}
}

func BuildGraph(c model.Collection) model.Graph {
	g := model.Graph{
		Nodes: []model.Node{},
		Edges: []model.Edge{},
	}
	addNode := func(node model.Node) {
		for _, existing := range g.Nodes {
			if existing.ID == node.ID {
				return
			}
		}
		g.Nodes = append(g.Nodes, node)
	}
	addEdge := func(edge model.Edge) {
		for _, existing := range g.Edges {
			if existing.Key() == edge.Key() {
				return
			}
		}
		g.Edges = append(g.Edges, edge)
	}
	for _, runtime := range c.Runtimes {
		addNode(model.Node{ID: runtime.ID, Type: "runtime", Label: runtime.Kind, Runtime: runtime.Kind, Source: runtime.Source})
		if runtime.Scope != "" {
			configID := "config:" + runtime.Kind + "-" + runtime.Scope
			addNode(model.Node{ID: configID, Type: "config", Label: runtime.Kind + " " + runtime.Scope + " config", Runtime: runtime.Kind, Source: runtime.Source})
			addEdge(model.Edge{From: configID, Type: "configures", To: runtime.ID, EvidenceID: "evidence:" + configID})
		}
	}
	for _, surface := range c.Surfaces {
		nodeType := "surface"
		if surface.Category != "" {
			nodeType = surface.Category
		}
		addNode(model.Node{ID: surface.ID, Type: nodeType, Label: surface.Kind, Runtime: surface.Runtime, Source: surface.Source})
	}
	for _, input := range c.TrustInputs {
		addNode(model.Node{ID: input.ID, Type: "trust_input", Label: input.Kind, Source: input.Source})
		for _, runtime := range c.Runtimes {
			if input.Runtime != "" && input.Runtime != runtime.Kind {
				continue
			}
			addEdge(model.Edge{From: input.ID, Type: "influences", To: runtime.ID, EvidenceID: "evidence:" + input.ID})
		}
	}
	for _, tool := range c.Tools {
		addNode(model.Node{ID: tool.ID, Type: "tool", Label: tool.Kind, Source: tool.Source})
		for _, runtime := range c.Runtimes {
			if tool.Runtime != "" && tool.Runtime != runtime.Kind {
				continue
			}
			addEdge(model.Edge{From: runtime.ID, Type: "can_call", To: tool.ID, EvidenceID: "evidence:" + tool.ID})
		}
		if tool.ID == "tool:mcp-package-launch" {
			addEdge(model.Edge{From: tool.ID, Type: "grants", To: "authority:local-code-execution", EvidenceID: "evidence:" + tool.ID})
		}
		if tool.ID == "tool:agent-command-shell" {
			addEdge(model.Edge{From: tool.ID, Type: "grants", To: "authority:local-code-execution", EvidenceID: "evidence:" + tool.ID})
		}
		if tool.ID == "tool:agent-delegation" {
			addEdge(model.Edge{From: tool.ID, Type: "grants", To: "authority:delegated-agent-authority", EvidenceID: "evidence:" + tool.ID})
		}
	}
	for _, authority := range c.Authorities {
		addNode(model.Node{ID: authority.ID, Type: "authority", Label: authority.Kind})
		if authority.Runtime != "" {
			addEdge(model.Edge{From: "runtime:" + authority.Runtime, Type: "has_authority", To: authority.ID})
		}
	}
	for _, boundary := range c.Boundaries {
		addNode(model.Node{ID: boundary.ID, Type: "boundary", Label: boundary.Kind, Source: boundary.Source})
		for _, authority := range c.Authorities {
			if authorityReachesBoundary(authority.ID, boundary.ID) {
				addEdge(model.Edge{From: authority.ID, Type: "reaches", To: boundary.ID})
			}
		}
	}
	for _, control := range c.Controls {
		addNode(model.Node{ID: control.ID, Type: "control", Label: control.Kind, Runtime: control.Runtime, Source: control.Source})
		if control.ID == "control:mcp-reviewed-pinned" {
			addEdge(model.Edge{From: control.ID, Type: "restricts", To: "tool:mcp-package-launch"})
		}
		for _, tool := range c.Tools {
			if controlRestrictsTool(control.ID, tool.ID) {
				addEdge(model.Edge{From: control.ID, Type: "restricts", To: tool.ID})
			}
		}
		for _, authority := range c.Authorities {
			if controlRestrictsAuthority(control.ID, authority.ID) {
				addEdge(model.Edge{From: control.ID, Type: "restricts", To: authority.ID})
			}
		}
		if controlGovernsDeployment(control.ID) {
			for _, runtime := range c.Runtimes {
				addEdge(model.Edge{From: control.ID, Type: "governs", To: runtime.ID})
			}
			for _, tool := range c.Tools {
				addEdge(model.Edge{From: control.ID, Type: "governs", To: tool.ID})
			}
			for _, authority := range c.Authorities {
				addEdge(model.Edge{From: control.ID, Type: "governs", To: authority.ID})
			}
		}
		if controlVerifiesSupplyChain(control.ID) {
			for _, runtime := range c.Runtimes {
				addEdge(model.Edge{From: control.ID, Type: "verifies", To: runtime.ID})
			}
			for _, tool := range c.Tools {
				addEdge(model.Edge{From: control.ID, Type: "verifies", To: tool.ID})
			}
			for _, surface := range c.Surfaces {
				if supplyChainSurface(surface) {
					addEdge(model.Edge{From: control.ID, Type: "verifies", To: surface.ID})
				}
			}
		}
		if controlRestrictsConfig(control.ID) {
			for _, runtime := range c.Runtimes {
				if runtime.Scope == "" {
					continue
				}
				addEdge(model.Edge{From: control.ID, Type: "restricts", To: "config:" + runtime.Kind + "-" + runtime.Scope})
			}
			for _, surface := range c.Surfaces {
				if configIntegritySurface(surface) {
					addEdge(model.Edge{From: control.ID, Type: "restricts", To: surface.ID})
				}
			}
		}
		for _, boundary := range c.Boundaries {
			if controlRestrictsBoundary(control.ID, boundary.ID) {
				addEdge(model.Edge{From: control.ID, Type: "restricts", To: boundary.ID})
			}
		}
		for _, input := range c.TrustInputs {
			if controlRestrictsTrustInput(control.ID, input.ID) {
				addEdge(model.Edge{From: control.ID, Type: "restricts", To: input.ID})
			}
		}
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	sort.Slice(g.Edges, func(i, j int) bool { return g.Edges[i].Key() < g.Edges[j].Key() })
	return g
}

func controlRestrictsBoundary(controlID, boundaryID string) bool {
	switch controlID {
	case "control:deny-secret-read":
		return boundaryID == "boundary:secret-like-file" || boundaryID == "boundary:developer-secret-boundary" || boundaryID == "boundary:agent-private-context"
	case "control:memory-isolation":
		return boundaryID == "boundary:agent-private-context"
	case "control:network-restricted", "control:egress-destination-allowlist", "control:webhook-allowlist", "control:per-tool-network-scope":
		return boundaryID == "boundary:external-destination"
	case "control:mcp-reviewed-pinned":
		return boundaryID == "boundary:developer-execution-boundary"
	case "control:delegation-scope", "control:delegation-allowlist", "control:agent-to-agent-authorization", "control:origin-intent-verification", "control:delegated-credential-scope", "control:subagent-context-isolation":
		return boundaryID == "boundary:agent-delegation-boundary"
	case "control:containment-quarantine":
		return boundaryID == "boundary:external-destination" || boundaryID == "boundary:developer-execution-boundary"
	default:
		return false
	}
}

func controlRestrictsAuthority(controlID, authorityID string) bool {
	if authorityID == "" {
		return false
	}
	switch controlID {
	case "control:session-termination",
		"control:credential-revocation",
		"control:dynamic-access-reduction":
		return true
	case "control:containment-quarantine":
		return authorityID == "authority:external-communication" || authorityID == "authority:local-code-execution" || authorityID == "authority:broad-local"
	default:
		return false
	}
}

func controlGovernsDeployment(controlID string) bool {
	switch controlID {
	case "control:agent-inventory",
		"control:deployment-owner",
		"control:deployment-approval",
		"control:risk-assessment",
		"control:governance-audit",
		"control:shadow-ai-discovery":
		return true
	default:
		return false
	}
}

func controlVerifiesSupplyChain(controlID string) bool {
	switch controlID {
	case "control:ai-bom",
		"control:model-provenance",
		"control:training-data-lineage",
		"control:dependency-health-scan",
		"control:provider-risk-review",
		"control:signed-ai-artifacts",
		"control:runtime-component-validation",
		"control:dependency-reachability-analysis":
		return true
	default:
		return false
	}
}

func supplyChainSurface(surface model.Surface) bool {
	switch surface.Category {
	case "mcp-tool-config", "plugin-skill", "supply-chain-bom":
		return true
	default:
		return false
	}
}

func controlRestrictsTrustInput(controlID, inputID string) bool {
	if inputID == "" {
		return false
	}
	switch controlID {
	case "control:input-isolation", "control:trusted-source-policy":
		return true
	default:
		return false
	}
}

func controlRestrictsTool(controlID, toolID string) bool {
	if toolID == "" {
		return false
	}
	if controlID == "control:mcp-reviewed-pinned" {
		return toolID == "tool:mcp-package-launch"
	}
	switch controlID {
	case "control:tool-allowlist",
		"control:tool-descriptor-integrity",
		"control:tool-argument-validation",
		"control:tool-auth-required",
		"control:signed-tool-artifacts",
		"control:tool-deployment-verification",
		"control:tool-scope-policy":
		return true
	case "control:delegation-scope",
		"control:delegation-allowlist",
		"control:agent-to-agent-authorization",
		"control:origin-intent-verification",
		"control:delegated-credential-scope",
		"control:subagent-context-isolation":
		return toolID == "tool:agent-delegation"
	default:
		return false
	}
}

func controlRestrictsConfig(controlID string) bool {
	switch controlID {
	case "control:config-version-control",
		"control:config-review-required",
		"control:signed-config",
		"control:config-deployment-verification",
		"control:managed-settings-enforced",
		"control:immutable-agent-runtime":
		return true
	default:
		return false
	}
}

func configIntegritySurface(surface model.Surface) bool {
	switch surface.Category {
	case "runtime-config", "managed-remote-settings", "policy", "mcp-tool-config", "plugin-skill", "command-hook":
		return true
	default:
		return false
	}
}

func authorityReachesBoundary(authorityID, boundaryID string) bool {
	switch boundaryID {
	case "boundary:secret-like-file", "boundary:developer-secret-boundary":
		return authorityID == "authority:file-read" || authorityID == "authority:broad-local"
	case "boundary:agent-private-context":
		return authorityID == "authority:file-read" || authorityID == "authority:broad-local"
	case "boundary:developer-execution-boundary":
		return authorityID == "authority:local-code-execution" || authorityID == "authority:broad-local"
	case "boundary:external-destination":
		return authorityID == "authority:external-communication" || authorityID == "authority:broad-local"
	case "boundary:agent-delegation-boundary":
		return authorityID == "authority:delegated-agent-authority"
	default:
		return false
	}
}

func Evaluate(c model.Collection, g model.Graph, manifest model.Manifest) model.ExposureResult {
	if strings.HasPrefix(manifest.ID, "data-egress-chain-") {
		return evaluateDataEgressChain(c, g, manifest.Mode)
	}
	if strings.HasPrefix(manifest.ID, "mutable-tool-launch-") {
		return evaluateMCP(c, g)
	}
	return evaluateSecret(c, g, manifest.Mode)
}

func EvaluateAll(c model.Collection, g model.Graph, mode string) []model.ExposureResult {
	var out []model.ExposureResult
	secret := evaluateSecret(c, g, mode)
	if hasSecretEvidence(c) || len(secret.PathEdges) > 0 || secret.Status != model.StatusInconclusive {
		out = append(out, secret)
	}
	mcp := evaluateMCP(c, g)
	if len(mcp.PathEdges) > 0 || mcp.Status != model.StatusInconclusive {
		out = append(out, mcp)
	}
	dataEgress := evaluateDataEgressChain(c, g, mode)
	if hasDataEgressChainEvidence(c) || len(dataEgress.PathEdges) > 0 || dataEgress.Status != model.StatusInconclusive {
		out = append(out, dataEgress)
	}
	if len(out) == 0 {
		out = append(out, model.ExposureResult{
			ID:        "no-exposure-path-established",
			Title:     "No concrete exposure path established",
			Status:    model.StatusInconclusive,
			ProofMode: model.ProofInferred,
			PathNodes: []string{},
			PathEdges: []string{},
			Observation: model.Observation{
				Status:  model.ObservationInconclusive,
				Summary: "Ariadne did not collect enough evidence to establish a supported exposure path.",
			},
			WhyItMatters:  "Absence of evidence is not proof of safety; it means Ariadne could not connect influence, authority, boundary, and control evidence for supported exposure families.",
			WhatWasTested: "Whether the current path exposes secret-like file access or MCP package-launch local execution.",
			Limitations: []string{
				"Only Phase 1 exposure families are evaluated.",
				"Runtime behavior is not executed or observed.",
			},
		})
	}
	return out
}

func hasDataEgressChainEvidence(c model.Collection) bool {
	return hasAuthority(c, "authority:external-communication") ||
		hasBoundary(c, "boundary:external-destination") ||
		hasAnyControl(c, egressControlIDs()...)
}

func hasSecretEvidence(c model.Collection) bool {
	if len(c.TrustInputs) > 0 {
		return true
	}
	for _, boundary := range c.Boundaries {
		if boundary.ID == "boundary:secret-like-file" || boundary.ID == "boundary:developer-secret-boundary" {
			return true
		}
	}
	return hasAuthority(c, "authority:file-read") || hasAuthority(c, "authority:broad-local") || hasControl(c, "control:deny-secret-read")
}

func evaluateSecret(c model.Collection, g model.Graph, mode string) model.ExposureResult {
	runtimes := runtimeKinds(c)
	hasTrustInput := false
	for _, input := range c.TrustInputs {
		if input.Risky {
			hasTrustInput = true
			break
		}
	}
	hasFileRead := hasAuthority(c, "authority:file-read")
	hasBroadLocal := hasAuthority(c, "authority:broad-local")
	hasBoundary := len(c.Boundaries) > 0
	hasDeny := hasControl(c, "control:deny-secret-read")
	hasInputBreak := hasHardInputBreak(c)

	result := model.ExposureResult{
		ID:            "prompt-injection-to-secret-canary",
		Title:         "Prompt/repo instruction to secret-like file access",
		Runtimes:      runtimes,
		PathEdges:     secretPathEdges(g, mode),
		WhyItMatters:  "A local coding agent can convert untrusted instructions into file access near secret-like developer data.",
		WhatWasTested: "Whether influence plus local agent authority creates a path to a fake secret boundary, and whether a deny-read control breaks that path.",
		Limitations: []string{
			"The story uses controlled fixtures and fake canaries.",
			"This does not prove behavior against real secrets or unmanaged live sessions.",
		},
	}

	switch {
	case mode == "endpoint" && hasBroadLocal && hasBoundary:
		result.Status = model.StatusExposed
		result.ProofMode = model.ProofInferred
		result.Observation = model.Observation{Status: model.ObservationNotAttempted, Summary: "Endpoint config declares broad local authority; no live behavior was executed."}
	case hasTrustInput && hasFileRead && hasBoundary && hasInputBreak:
		result.Status = model.StatusProtected
		result.ProofMode = model.ProofSimulated
		result.Observation = model.Observation{Status: model.ObservationBlocked, Summary: "The deterministic path reaches an input-isolation or trusted-source control before runtime authority."}
		result.ControlsBreakPath = []string{"isolate or trust-gate untrusted instructions"}
		if hasDeny {
			result.ControlsBreakPath = append(result.ControlsBreakPath, "deny-read secret-like paths")
		}
	case hasTrustInput && hasFileRead && hasBoundary && hasDeny:
		result.Status = model.StatusProtected
		result.ProofMode = model.ProofSimulated
		result.Observation = model.Observation{Status: model.ObservationBlocked, Summary: "The simulated path reaches a deny-read control before the fake secret boundary."}
		result.ControlsBreakPath = []string{"deny-read secret-like paths"}
	case hasTrustInput && hasFileRead && hasBoundary:
		result.Status = model.StatusExposed
		result.ProofMode = model.ProofSimulated
		result.Observation = model.Observation{Status: model.ObservationSucceededInLab, Summary: "The simulated story path reaches the fake secret boundary without a breaking control."}
	case hasTrustInput && !hasFileRead:
		result.Status = model.StatusInconclusive
		result.ProofMode = model.ProofInferred
		result.Observation = model.Observation{Status: model.ObservationInconclusive, Summary: "Risky trust input exists, but runtime file-read authority was not established."}
	default:
		result.Status = model.StatusInconclusive
		result.ProofMode = model.ProofInferred
		result.Observation = model.Observation{Status: model.ObservationInconclusive, Summary: "A complete influence-to-boundary exposure path was not established."}
	}
	result.PathNodes = nodesFromEdges(result.PathEdges)
	return result
}

func evaluateMCP(c model.Collection, g model.Graph) model.ExposureResult {
	hasMCPPackageLaunch := hasTool(c, "tool:mcp-package-launch")
	hasRiskyMCPPackageLaunch := hasRiskyTool(c, "tool:mcp-package-launch")
	hasLocalCodeExecution := hasAuthority(c, "authority:local-code-execution")
	hasExecutionBoundary := hasBoundary(c, "boundary:developer-execution-boundary")
	hasReviewedPinnedControl := hasControl(c, "control:mcp-reviewed-pinned")
	result := model.ExposureResult{
		ID:            "mutable-tool-launch-execution",
		Title:         "MCP package launch to local code execution",
		Runtimes:      runtimeKinds(c),
		PathEdges:     mcpPathEdges(g),
		WhyItMatters:  "Agent tool servers bridge model-driven tool use to local code. Mutable package-manager or interpreter launchers can run unreviewed code under the developer user.",
		WhatWasTested: "Whether a local agent can call a tool launched through a mutable package/interpreter path, and whether review or pinning controls break that path.",
		Limitations: []string{
			"The story inspects declared MCP launch configuration only.",
			"The MCP server is not executed and package identity is not resolved from a registry.",
		},
	}
	switch {
	case hasMCPPackageLaunch && hasReviewedPinnedControl:
		result.Status = model.StatusProtected
		result.ProofMode = model.ProofSimulated
		result.Observation = model.Observation{Status: model.ObservationBlocked, Summary: "The simulated MCP path reaches a reviewed/pinned control before local code execution."}
		result.ControlsBreakPath = []string{"review and pin MCP servers"}
	case hasRiskyMCPPackageLaunch && hasLocalCodeExecution && hasExecutionBoundary:
		result.Status = model.StatusExposed
		result.ProofMode = model.ProofSimulated
		result.Observation = model.Observation{Status: model.ObservationSucceededInLab, Summary: "The simulated story path reaches local code execution through a mutable tool launcher."}
	default:
		result.Status = model.StatusInconclusive
		result.ProofMode = model.ProofInferred
		result.Observation = model.Observation{Status: model.ObservationInconclusive, Summary: "A complete MCP package-launch-to-execution path was not established."}
	}
	result.PathNodes = nodesFromEdges(result.PathEdges)
	return result
}

func evaluateDataEgressChain(c model.Collection, g model.Graph, mode string) model.ExposureResult {
	hasRiskyTrustInput := false
	for _, input := range c.TrustInputs {
		if input.Risky {
			hasRiskyTrustInput = true
			break
		}
	}
	hasPrivateAuthority := hasAuthority(c, "authority:file-read") || hasAuthority(c, "authority:broad-local")
	hasPrivateBoundary := hasBoundary(c, "boundary:secret-like-file") || hasBoundary(c, "boundary:developer-secret-boundary") || hasBoundary(c, "boundary:agent-private-context")
	hasExternalCommunication := hasAuthority(c, "authority:external-communication") || hasAuthority(c, "authority:broad-local")
	hasExternalDestination := hasBoundary(c, "boundary:external-destination")
	hasHardEgressControl := hasHardEgressBreak(c)
	hasDenyRead := hasControl(c, "control:deny-secret-read")
	hasInputBreak := hasHardInputBreak(c)

	result := model.ExposureResult{
		ID:            "data-egress-chain",
		Title:         "Data egress chain: untrusted influence to private data to external communication",
		Runtimes:      runtimeKinds(c),
		PathEdges:     dataEgressChainPathEdges(g, mode),
		WhyItMatters:  "When an agent can see untrusted instructions, reach private data, and communicate externally, prompt injection can become unauthorized data movement.",
		WhatWasTested: "Whether untrusted influence, private-data reachability, and external communication reachability all exist in the same agent graph, and whether controls break the path.",
		Limitations: []string{
			"The story uses deterministic graph evidence; it does not execute the agent or observe live data movement.",
			"External communication means a declared web, network, remote MCP, or command-mediated communication path.",
		},
	}

	switch {
	case hasRiskyTrustInput && hasPrivateAuthority && hasPrivateBoundary && hasExternalCommunication && hasExternalDestination && (hasInputBreak || hasHardEgressControl || hasDenyRead):
		result.Status = model.StatusProtected
		result.ProofMode = model.ProofSimulated
		result.Observation = model.Observation{Status: model.ObservationBlocked, Summary: "The graph contains data-egress ingredients, but a control breaks influence, private-data, or external-communication reachability."}
		if hasInputBreak {
			result.ControlsBreakPath = append(result.ControlsBreakPath, "isolate or trust-gate untrusted instructions")
		}
		result.ControlsBreakPath = append(result.ControlsBreakPath, egressBreakDescriptions(c)...)
		if hasDenyRead {
			result.ControlsBreakPath = append(result.ControlsBreakPath, "deny-read secret-like paths")
		}
	case hasRiskyTrustInput && hasPrivateAuthority && hasPrivateBoundary && hasExternalCommunication && hasExternalDestination:
		result.Status = model.StatusExposed
		result.ProofMode = model.ProofSimulated
		result.Observation = model.Observation{Status: model.ObservationSucceededInLab, Summary: "The graph contains all three data-egress ingredients: untrusted influence, private-data reachability, and external communication reachability."}
	case hasRiskyTrustInput && hasPrivateAuthority && hasPrivateBoundary && !hasExternalCommunication:
		result.Status = model.StatusInconclusive
		result.ProofMode = model.ProofInferred
		result.Observation = model.Observation{Status: model.ObservationInconclusive, Summary: "Untrusted influence and private-data reachability exist, but external communication authority was not established."}
	case hasRiskyTrustInput && hasExternalCommunication && !hasPrivateAuthority:
		result.Status = model.StatusInconclusive
		result.ProofMode = model.ProofInferred
		result.Observation = model.Observation{Status: model.ObservationInconclusive, Summary: "Untrusted influence and external communication exist, but private-data authority was not established."}
	default:
		result.Status = model.StatusInconclusive
		result.ProofMode = model.ProofInferred
		result.Observation = model.Observation{Status: model.ObservationInconclusive, Summary: "A complete data-egress chain was not established."}
	}
	result.PathNodes = nodesFromEdges(result.PathEdges)
	return result
}

func Compare(report model.Report, expected model.ExpectedResult) (bool, []string) {
	var mismatches []string
	if report.Exposure.Status != expected.Status {
		mismatches = append(mismatches, fmt.Sprintf("status: got %s, expected %s", report.Exposure.Status, expected.Status))
	}
	if report.Exposure.ProofMode != expected.ProofMode {
		mismatches = append(mismatches, fmt.Sprintf("proof_mode: got %s, expected %s", report.Exposure.ProofMode, expected.ProofMode))
	}
	for _, nodeID := range expected.RequiredNodes {
		if !report.Graph.HasNode(nodeID) {
			mismatches = append(mismatches, "missing graph node: "+nodeID)
		}
	}
	for _, edgeKey := range expected.RequiredEdges {
		if !report.Graph.HasEdge(edgeKey) {
			mismatches = append(mismatches, "missing graph edge: "+edgeKey)
		}
	}
	blob, _ := json.Marshal(report)
	for _, forbidden := range expected.RedactionMustNotContain {
		if forbidden != "" && strings.Contains(string(blob), forbidden) {
			mismatches = append(mismatches, "redaction leaked forbidden value")
		}
	}
	return len(mismatches) == 0, mismatches
}

func runtimeKinds(c model.Collection) []string {
	seen := map[string]bool{}
	var out []string
	for _, runtime := range c.Runtimes {
		if !seen[runtime.Kind] {
			seen[runtime.Kind] = true
			out = append(out, runtime.Kind)
		}
	}
	sort.Strings(out)
	return out
}

func hasAuthority(c model.Collection, id string) bool {
	for _, authority := range c.Authorities {
		if authority.ID == id {
			return true
		}
	}
	return false
}

func hasTool(c model.Collection, id string) bool {
	for _, tool := range c.Tools {
		if tool.ID == id {
			return true
		}
	}
	return false
}

func hasRiskyTool(c model.Collection, id string) bool {
	for _, tool := range c.Tools {
		if tool.ID == id && tool.Risky {
			return true
		}
	}
	return false
}

func hasControl(c model.Collection, id string) bool {
	for _, control := range c.Controls {
		if control.ID == id {
			return true
		}
	}
	return false
}

func hasBoundary(c model.Collection, id string) bool {
	for _, boundary := range c.Boundaries {
		if boundary.ID == id {
			return true
		}
	}
	return false
}

func hasAnyControl(c model.Collection, ids ...string) bool {
	for _, id := range ids {
		if hasControl(c, id) {
			return true
		}
	}
	return false
}

func hasHardInputBreak(c model.Collection) bool {
	return hasAnyControl(c, "control:input-isolation", "control:trusted-source-policy")
}

func secretPathEdges(g model.Graph, mode string) []string {
	var candidates []string
	if mode == "endpoint" {
		candidates = []string{
			"config:codex-endpoint|configures|runtime:codex",
			"config:claude-endpoint|configures|runtime:claude",
			"runtime:codex|has_authority|authority:broad-local",
			"runtime:claude|has_authority|authority:broad-local",
			"authority:broad-local|reaches|boundary:developer-secret-boundary",
			"control:deny-secret-read|restricts|boundary:developer-secret-boundary",
		}
	} else {
		candidates = []string{
			"trustinput:repo-instruction|influences|runtime:codex",
			"trustinput:repo-instruction|influences|runtime:claude",
			"runtime:codex|has_authority|authority:file-read",
			"runtime:claude|has_authority|authority:file-read",
			"authority:file-read|reaches|boundary:secret-like-file",
			"control:input-isolation|restricts|trustinput:repo-instruction",
			"control:trusted-source-policy|restricts|trustinput:repo-instruction",
			"control:deny-secret-read|restricts|boundary:secret-like-file",
		}
	}
	return existingEdges(g, candidates)
}

func mcpPathEdges(g model.Graph) []string {
	return existingEdges(g, []string{
		"runtime:codex|can_call|tool:mcp-package-launch",
		"runtime:claude|can_call|tool:mcp-package-launch",
		"tool:mcp-package-launch|grants|authority:local-code-execution",
		"authority:local-code-execution|reaches|boundary:developer-execution-boundary",
		"control:mcp-reviewed-pinned|restricts|tool:mcp-package-launch",
		"control:mcp-reviewed-pinned|restricts|boundary:developer-execution-boundary",
	})
}

func dataEgressChainPathEdges(g model.Graph, mode string) []string {
	candidates := []string{
		"trustinput:repo-instruction|influences|runtime:codex",
		"trustinput:repo-instruction|influences|runtime:claude",
		"runtime:codex|has_authority|authority:file-read",
		"runtime:claude|has_authority|authority:file-read",
		"runtime:codex|has_authority|authority:broad-local",
		"runtime:claude|has_authority|authority:broad-local",
		"authority:file-read|reaches|boundary:secret-like-file",
		"authority:file-read|reaches|boundary:developer-secret-boundary",
		"authority:file-read|reaches|boundary:agent-private-context",
		"authority:broad-local|reaches|boundary:secret-like-file",
		"authority:broad-local|reaches|boundary:developer-secret-boundary",
		"authority:broad-local|reaches|boundary:agent-private-context",
		"runtime:codex|has_authority|authority:external-communication",
		"runtime:claude|has_authority|authority:external-communication",
		"authority:external-communication|reaches|boundary:external-destination",
		"authority:broad-local|reaches|boundary:external-destination",
		"control:input-isolation|restricts|trustinput:repo-instruction",
		"control:trusted-source-policy|restricts|trustinput:repo-instruction",
		"control:network-restricted|restricts|boundary:external-destination",
		"control:egress-destination-allowlist|restricts|boundary:external-destination",
		"control:webhook-allowlist|restricts|boundary:external-destination",
		"control:per-tool-network-scope|restricts|boundary:external-destination",
		"control:deny-secret-read|restricts|boundary:secret-like-file",
		"control:deny-secret-read|restricts|boundary:developer-secret-boundary",
		"control:deny-secret-read|restricts|boundary:agent-private-context",
	}
	return existingEdges(g, candidates)
}

func egressControlIDs() []string {
	return []string{
		"control:network-restricted",
		"control:egress-destination-allowlist",
		"control:webhook-allowlist",
		"control:per-tool-network-scope",
		"control:egress-content-filter",
		"control:egress-audit",
	}
}

func hardEgressControlIDs() []string {
	return []string{
		"control:network-restricted",
		"control:egress-destination-allowlist",
		"control:webhook-allowlist",
		"control:per-tool-network-scope",
	}
}

func hasHardEgressBreak(c model.Collection) bool {
	return hasAnyControl(c, hardEgressControlIDs()...)
}

func egressBreakDescriptions(c model.Collection) []string {
	var out []string
	if hasControl(c, "control:network-restricted") {
		out = append(out, "restrict external network communication")
	}
	if hasControl(c, "control:egress-destination-allowlist") {
		out = append(out, "allowlist external destinations")
	}
	if hasControl(c, "control:webhook-allowlist") {
		out = append(out, "allowlist webhook destinations")
	}
	if hasControl(c, "control:per-tool-network-scope") {
		out = append(out, "scope per-tool network access")
	}
	return out
}

func existingEdges(g model.Graph, candidates []string) []string {
	out := []string{}
	for _, key := range candidates {
		if g.HasEdge(key) {
			out = append(out, key)
		}
	}
	return out
}

func nodesFromEdges(edges []string) []string {
	seen := map[string]bool{}
	nodes := []string{}
	for _, edge := range edges {
		parts := strings.Split(edge, "|")
		if len(parts) != 3 {
			continue
		}
		for _, id := range []string{parts[0], parts[2]} {
			if !seen[id] {
				seen[id] = true
				nodes = append(nodes, id)
			}
		}
	}
	sort.Strings(nodes)
	return nodes
}

func pathNodes(g model.Graph) []string {
	var ids []string
	for _, node := range g.Nodes {
		ids = append(ids, node.ID)
	}
	return ids
}

func pathEdges(g model.Graph) []string {
	var keys []string
	for _, edge := range g.Edges {
		keys = append(keys, edge.Key())
	}
	return keys
}

func resolve(root, child string) string {
	if child == "" {
		return ""
	}
	if filepath.IsAbs(child) {
		return child
	}
	return filepath.Join(root, child)
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	return "run-" + hex.EncodeToString(b[:])
}
