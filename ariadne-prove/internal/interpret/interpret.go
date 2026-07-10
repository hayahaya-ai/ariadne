package interpret

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

const (
	modeDeterministic = "deterministic"
	engineName        = "ariadne deterministic priority rules"
)

type Input struct {
	Target     string
	Mode       string
	Collection model.Collection
	Graph      model.Graph
	Exposures  []model.ExposureResult
	Policy     model.RulePolicy
}

func LoadPolicy(path string) (model.RulePolicy, error) {
	if path == "" {
		return model.RulePolicy{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return model.RulePolicy{}, err
	}
	var policy model.RulePolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return model.RulePolicy{}, err
	}
	if policy.Version == "" {
		policy.Version = "ariadne.rules/v1"
	}
	for i, rule := range policy.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return model.RulePolicy{}, fmt.Errorf("rule %d has empty id", i)
		}
	}
	return policy, nil
}

func DefaultPolicyPath(root, explicit string) string {
	if explicit != "" {
		return explicit
	}
	candidate := filepath.Join(root, ".ariadne", "rules.json")
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate
	}
	return ""
}

func Evaluate(in Input) model.Interpretation {
	issues := builtInIssues(in)
	issues = append(issues, customIssues(in)...)
	sortIssues(issues)
	return model.Interpretation{
		Mode:           modeDeterministic,
		Engine:         engineName,
		AvailableModes: availableModes(),
		Summary:        summarize(issues),
		Issues:         issues,
		Limitations: []string{
			"Deterministic interpretation prioritizes known graph patterns only.",
			"Priority is based on observed facts, declared config, modeled graph edges, and configured rules.",
			"LLM review was not used for this result.",
		},
		PolicySource: policySource(in.Policy),
	}
}

func AggregateScan(targets []model.ScanTargetResult) model.Interpretation {
	var issues []model.Issue
	mode := modeDeterministic
	engine := engineName
	for _, target := range targets {
		if target.Report.Interpretation.Mode == modeLLMReview {
			mode = modeLLMReview
			engine = llmEngineName
		}
		for _, issue := range target.Report.Interpretation.Issues {
			issue.AffectedTarget = target.Target.ID
			issues = append(issues, issue)
		}
	}
	sortIssues(issues)
	limitations := []string{
		"Scan interpretation aggregates per-target issues.",
		"Targets with collection errors do not contribute issues.",
	}
	if mode == modeDeterministic {
		limitations = append(limitations, "LLM review was not used for this result.")
	} else {
		limitations = append(limitations, "LLM review is an interpretation layer over deterministic Ariadne facts.")
	}
	return model.Interpretation{
		Mode:           mode,
		Engine:         engine,
		AvailableModes: availableModes(),
		Summary:        summarize(issues),
		Issues:         issues,
		Limitations:    limitations,
	}
}

func builtInIssues(in Input) []model.Issue {
	var issues []model.Issue
	for _, exposure := range in.Exposures {
		switch exposure.ID {
		case "prompt-injection-to-secret-canary":
			issues = append(issues, secretBoundaryIssue(in, exposure))
		case "mutable-tool-launch-execution":
			issues = append(issues, mutableToolIssue(in, exposure))
		case "data-egress-chain":
			issues = append(issues, dataEgressIssue(in, exposure))
		}
	}
	if countSurfaces(in.Collection, "history-cache") >= 100 {
		issues = append(issues, model.Issue{
			ID:                 "builtin:large-private-agent-context",
			Title:              "Large private agent context surface",
			Severity:           model.SeverityLow,
			Priority:           model.PriorityP3,
			Disposition:        model.DispositionMonitor,
			Category:           "private-context",
			RuleID:             "builtin-large-private-agent-context",
			RuleSource:         "built_in",
			InterpretationMode: modeDeterministic,
			AffectedTarget:     in.Target,
			Rationale:          "Many private history, memory, or cache surfaces increase blast radius if an agent path is compromised.",
			Signals:            []string{fmt.Sprintf("%d history/cache surfaces summarized", countSurfaces(in.Collection, "history-cache"))},
			Actions:            []string{"Review retention for agent histories, paste caches, and session state.", "Keep private context surfaces out of broad agent-readable scopes where possible."},
			Confidence:         "high",
		})
	}
	if countSurfaces(in.Collection, "mcp-tool-config") >= 10 {
		issues = append(issues, model.Issue{
			ID:                 "builtin:large-mcp-tool-surface",
			Title:              "Large MCP/tool configuration surface",
			Severity:           model.SeverityMedium,
			Priority:           model.PriorityP2,
			Disposition:        model.DispositionReview,
			Category:           "tool-surface",
			RuleID:             "builtin-large-mcp-tool-surface",
			RuleSource:         "built_in",
			InterpretationMode: modeDeterministic,
			AffectedTarget:     in.Target,
			Rationale:          "Many model-callable tools increase the number of places where authority, data access, and workflow influence can combine.",
			Signals:            []string{fmt.Sprintf("%d MCP/tool config surfaces discovered", countSurfaces(in.Collection, "mcp-tool-config"))},
			Actions:            []string{"Review installed MCP servers and plugins.", "Prefer allowlisted, pinned, and least-authority tool configurations."},
			Confidence:         "high",
		})
	}
	return compactIssues(issues)
}

func secretBoundaryIssue(in Input, exposure model.ExposureResult) model.Issue {
	issue := baseIssue(in, exposure, "builtin-secret-boundary-access", "secret-access")
	issue.Title = "Agent authority reaches developer secret boundary"
	issue.Signals = []string{"Agent runtime authority reaches a secret-like boundary.", "This is expected only when file access is tightly scoped and deny-read controls exist."}
	issue.Actions = []string{"Constrain agent filesystem authority to the active workspace.", "Add deny-read controls for secret-like paths such as .env, SSH keys, cloud credentials, and token caches.", "Keep untrusted repo instructions away from broad endpoint authority."}
	switch exposure.Status {
	case model.StatusExposed:
		issue.Severity = model.SeverityHigh
		issue.Priority = model.PriorityP1
		issue.Disposition = model.DispositionFixNow
		issue.Rationale = "A supported graph path reaches a developer secret boundary without a breaking control."
	case model.StatusProtected:
		issue.Severity = model.SeverityLow
		issue.Priority = model.PriorityP3
		issue.Disposition = model.DispositionControlled
		issue.Rationale = "A path attempt exists, but Ariadne found a control that breaks secret boundary reachability."
	default:
		issue.Severity = model.SeverityInfo
		issue.Priority = model.PriorityP4
		issue.Disposition = model.DispositionReview
		issue.Rationale = "Ariadne did not have enough evidence to prove or clear secret-boundary exposure."
	}
	return issue
}

func mutableToolIssue(in Input, exposure model.ExposureResult) model.Issue {
	issue := baseIssue(in, exposure, "builtin-mutable-tool-launch", "local-code-execution")
	issue.Title = "Mutable tool launch can reach local code execution"
	issue.Signals = []string{"An agent-callable tool is launched through a mutable package or interpreter path.", "The graph reaches local code execution authority."}
	issue.Actions = []string{"Review MCP/tool launchers.", "Pin tool packages and interpreter entrypoints.", "Require allowlisted MCP servers and remove unused tool configs."}
	switch exposure.Status {
	case model.StatusExposed:
		issue.Severity = model.SeverityCritical
		issue.Priority = model.PriorityP0
		issue.Disposition = model.DispositionFixNow
		issue.Rationale = "Model-callable tool configuration can bridge agent behavior into local code execution."
	case model.StatusProtected:
		issue.Severity = model.SeverityLow
		issue.Priority = model.PriorityP3
		issue.Disposition = model.DispositionControlled
		issue.Rationale = "A tool execution path exists, but reviewed/pinned controls break the mutable launch risk."
	default:
		issue.Severity = model.SeverityInfo
		issue.Priority = model.PriorityP4
		issue.Disposition = model.DispositionReview
		issue.Rationale = "Tool execution evidence was incomplete."
	}
	return issue
}

func dataEgressIssue(in Input, exposure model.ExposureResult) model.Issue {
	issue := baseIssue(in, exposure, "builtin-data-egress-chain", "data-egress")
	issue.Title = "Untrusted influence can combine with private data and external communication"
	issue.Signals = []string{"The graph joins trust input, private-data reachability, and external communication reachability.", "This is high priority when no control breaks either private-data or external-destination reachability."}
	issue.Actions = []string{"Restrict external network communication for agent runtimes.", "Add deny-read controls for sensitive local boundaries.", "Separate untrusted repo instructions from broad endpoint authority."}
	switch exposure.Status {
	case model.StatusExposed:
		issue.Severity = model.SeverityCritical
		issue.Priority = model.PriorityP0
		issue.Disposition = model.DispositionFixNow
		issue.Rationale = "All required graph ingredients for unauthorized data movement are present without a breaking control."
	case model.StatusProtected:
		issue.Severity = model.SeverityMedium
		issue.Priority = model.PriorityP2
		issue.Disposition = model.DispositionControlled
		issue.Rationale = "The graph contains the risky combination, but Ariadne found a control that breaks the path."
	default:
		issue.Severity = model.SeverityLow
		issue.Priority = model.PriorityP3
		issue.Disposition = model.DispositionReview
		issue.Rationale = "Some data-egress ingredients exist, but Ariadne did not prove a complete path."
	}
	return issue
}

func baseIssue(in Input, exposure model.ExposureResult, ruleID, category string) model.Issue {
	return model.Issue{
		ID:                 "builtin:" + ruleID + ":" + exposure.ID,
		Category:           category,
		ExposureID:         exposure.ID,
		ExposureStatus:     exposure.Status,
		RuleID:             ruleID,
		RuleSource:         "built_in",
		InterpretationMode: modeDeterministic,
		AffectedTarget:     in.Target,
		GraphEdges:         stringSlice(exposure.PathEdges),
		Controls:           stringSlice(exposure.ControlsBreakPath),
		Confidence:         "high",
	}
}

func customIssues(in Input) []model.Issue {
	var issues []model.Issue
	for _, rule := range in.Policy.Rules {
		for _, exposure := range in.Exposures {
			if !matchesRule(rule, exposure, in) {
				continue
			}
			issue := model.Issue{
				ID:                 "custom:" + rule.ID + ":" + exposure.ID,
				Title:              firstNonEmpty(rule.Title, rule.ID),
				Severity:           defaultSeverity(rule.Severity),
				Priority:           defaultPriority(rule.Priority),
				Disposition:        defaultDisposition(rule.Disposition),
				Category:           firstNonEmpty(rule.Category, "custom"),
				ExposureID:         exposure.ID,
				ExposureStatus:     exposure.Status,
				RuleID:             rule.ID,
				RuleSource:         "custom",
				InterpretationMode: modeDeterministic,
				AffectedTarget:     in.Target,
				Rationale:          firstNonEmpty(rule.Rationale, rule.Description, "Custom rule matched deterministic graph evidence."),
				Signals:            customSignals(rule, exposure, in),
				GraphEdges:         stringSlice(exposure.PathEdges),
				Controls:           stringSlice(exposure.ControlsBreakPath),
				Actions:            rule.Actions,
				Confidence:         "high",
			}
			if len(issue.Actions) == 0 {
				issue.Actions = []string{"Review the custom rule match and decide whether to constrain, accept, or suppress the path."}
			}
			issues = append(issues, issue)
		}
	}
	return compactIssues(issues)
}

func matchesRule(rule model.CustomRule, exposure model.ExposureResult, in Input) bool {
	when := rule.When
	if when.Mode != "" && when.Mode != in.Mode {
		return false
	}
	if when.ExposureID != "" && when.ExposureID != exposure.ID {
		return false
	}
	if when.ExposureStatus != "" && when.ExposureStatus != exposure.Status {
		return false
	}
	for _, nodeID := range when.HasNodes {
		if !in.Graph.HasNode(nodeID) {
			return false
		}
	}
	for _, edge := range when.HasEdges {
		if !in.Graph.HasEdge(edge) {
			return false
		}
	}
	for _, controlID := range when.HasControls {
		if !in.Graph.HasNode(controlID) {
			return false
		}
	}
	for _, controlID := range when.MissingControls {
		if in.Graph.HasNode(controlID) {
			return false
		}
	}
	for category, min := range when.MinSurfaceCountByCategory {
		if countSurfaces(in.Collection, category) < min {
			return false
		}
	}
	return true
}

func customSignals(rule model.CustomRule, exposure model.ExposureResult, in Input) []string {
	var signals []string
	if rule.When.ExposureID != "" {
		signals = append(signals, "Exposure matched: "+exposure.ID)
	}
	if rule.When.ExposureStatus != "" {
		signals = append(signals, "Exposure status matched: "+string(exposure.Status))
	}
	for _, edge := range rule.When.HasEdges {
		signals = append(signals, "Graph edge present: "+edge)
	}
	for _, node := range rule.When.HasNodes {
		signals = append(signals, "Graph node present: "+node)
	}
	for _, control := range rule.When.MissingControls {
		signals = append(signals, "Control missing: "+control)
	}
	for category, min := range rule.When.MinSurfaceCountByCategory {
		signals = append(signals, fmt.Sprintf("Surface category %s count %d >= %d", category, countSurfaces(in.Collection, category), min))
	}
	if len(signals) == 0 {
		signals = append(signals, "Custom rule matched exposure "+exposure.ID)
	}
	return signals
}

func countSurfaces(c model.Collection, category string) int {
	count := 0
	for _, surface := range c.Surfaces {
		if surface.Category == category {
			count++
		}
	}
	return count
}

func summarize(issues []model.Issue) model.IssueSummary {
	var summary model.IssueSummary
	summary.Total = len(issues)
	for _, issue := range issues {
		switch issue.Severity {
		case model.SeverityCritical:
			summary.Critical++
		case model.SeverityHigh:
			summary.High++
		case model.SeverityMedium:
			summary.Medium++
		case model.SeverityLow:
			summary.Low++
		default:
			summary.Info++
		}
		switch issue.Disposition {
		case model.DispositionFixNow:
			summary.FixNow++
		case model.DispositionReview:
			summary.Review++
		case model.DispositionMonitor:
			summary.Monitor++
		case model.DispositionControlled:
			summary.Controlled++
		case model.DispositionExpected:
			summary.Expected++
		}
	}
	return summary
}

func sortIssues(issues []model.Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if priorityRank(issues[i].Priority) != priorityRank(issues[j].Priority) {
			return priorityRank(issues[i].Priority) < priorityRank(issues[j].Priority)
		}
		if severityRank(issues[i].Severity) != severityRank(issues[j].Severity) {
			return severityRank(issues[i].Severity) < severityRank(issues[j].Severity)
		}
		return issues[i].ID < issues[j].ID
	})
}

func compactIssues(issues []model.Issue) []model.Issue {
	seen := map[string]bool{}
	var out []model.Issue
	for _, issue := range issues {
		if issue.ID == "" || seen[issue.ID] {
			continue
		}
		seen[issue.ID] = true
		out = append(out, issue)
	}
	return out
}

func priorityRank(priority model.Priority) int {
	switch priority {
	case model.PriorityP0:
		return 0
	case model.PriorityP1:
		return 1
	case model.PriorityP2:
		return 2
	case model.PriorityP3:
		return 3
	default:
		return 4
	}
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 0
	case model.SeverityHigh:
		return 1
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 3
	default:
		return 4
	}
}

func defaultSeverity(value model.Severity) model.Severity {
	if value == "" {
		return model.SeverityMedium
	}
	return value
}

func defaultPriority(value model.Priority) model.Priority {
	if value == "" {
		return model.PriorityP2
	}
	return value
}

func defaultDisposition(value model.Disposition) model.Disposition {
	if value == "" {
		return model.DispositionReview
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func policySource(policy model.RulePolicy) string {
	if len(policy.Rules) == 0 {
		return "built_in"
	}
	return "built_in+custom"
}

func stringSlice(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func availableModes() []string {
	return []string{modeDeterministic, modeLLMReview}
}
