package interpret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

const (
	modeLLMReview      = "llm_review"
	llmEngineName      = "ariadne fact-bound llm review"
	llmRequestVersion  = "ariadne.llm_review_request/v1"
	llmResponseVersion = "ariadne.llm_review/v1"

	llmReviewProfileFollowUp       = "follow_up"
	llmReviewProfileInventoryBlind = "inventory_blind"
)

type Options struct {
	Mode           string
	ReviewPath     string
	Command        string
	RequestOut     string
	Timeout        time.Duration
	Question       string
	ReviewProfile  string
	Redaction      model.RedactionInfo
	RunLimitations []string
}

func EvaluateWithOptions(in Input, opts Options) (model.Interpretation, error) {
	deterministic := Evaluate(in)
	mode := strings.TrimSpace(opts.Mode)
	if mode == "" {
		mode = modeDeterministic
	}
	request, payload, digest, err := BuildLLMReviewRequest(in, deterministic, opts)
	if err != nil {
		return model.Interpretation{}, err
	}
	if opts.RequestOut != "" {
		if err := os.WriteFile(opts.RequestOut, append(payload, '\n'), 0o644); err != nil {
			return model.Interpretation{}, err
		}
	}
	switch mode {
	case modeDeterministic:
		return deterministic, nil
	case modeLLMReview, "llm":
		if request.ReviewProfile != llmReviewProfileFollowUp {
			return model.Interpretation{}, fmt.Errorf("llm interpretation requires --llm-review-profile follow-up; %s packets are request-only until mapped back to Ariadne exposure evidence", request.ReviewProfile)
		}
		resp, source, err := loadLLMReview(payload, opts)
		if err != nil {
			return model.Interpretation{}, err
		}
		return reviewToInterpretation(in, request, resp, source, digest)
	default:
		return model.Interpretation{}, fmt.Errorf("unknown interpretation mode %q; use deterministic or llm", opts.Mode)
	}
}

func BuildLLMReviewRequest(in Input, deterministic model.Interpretation, opts Options) (model.LLMReviewRequest, []byte, string, error) {
	profile, err := normalizeLLMReviewProfile(opts.ReviewProfile)
	if err != nil {
		return model.LLMReviewRequest{}, nil, "", err
	}
	exposures := exposureSlice(in.Exposures)
	deterministicAnchor := deterministic
	if profile == llmReviewProfileInventoryBlind {
		exposures = []model.ExposureResult{}
		deterministicAnchor = inventoryBlindDeterministicAnchor()
	}
	request := model.LLMReviewRequest{
		SchemaVersion: llmRequestVersion,
		Target:        in.Target,
		Mode:          in.Mode,
		ReviewProfile: profile,
		Question:      llmReviewQuestion(profile, opts.Question),
		Instructions:  llmReviewInstructions(profile),
		ReviewContract: model.LLMReviewContract{
			Summary:           llmReviewContractSummary(profile),
			RequiredCitations: llmRequiredCitations(profile),
			AllowedClaims:     llmAllowedClaims(profile),
			ForbiddenClaims:   llmForbiddenClaims(profile),
			ResponseRules:     llmResponseRules(profile),
		},
		ReviewerTasks:   llmReviewerTasks(profile),
		CitationCatalog: llmCitationCatalog(in, exposures, profile),
		Collection:      in.Collection,
		Graph:           in.Graph,
		Exposures:       exposures,
		Deterministic:   deterministicAnchor,
		Redaction:       opts.Redaction,
		Limitations:     stringSlice(opts.RunLimitations),
		AllowedStatuses: []model.Status{
			model.StatusExposed,
			model.StatusProtected,
			model.StatusInconclusive,
		},
		AllowedPriorities: []model.Priority{
			model.PriorityP0,
			model.PriorityP1,
			model.PriorityP2,
			model.PriorityP3,
			model.PriorityP4,
		},
		AllowedSeverities: []model.Severity{
			model.SeverityCritical,
			model.SeverityHigh,
			model.SeverityMedium,
			model.SeverityLow,
			model.SeverityInfo,
		},
		AllowedDisposition: []model.Disposition{
			model.DispositionFixNow,
			model.DispositionReview,
			model.DispositionMonitor,
			model.DispositionControlled,
			model.DispositionExpected,
		},
	}
	payload, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return model.LLMReviewRequest{}, nil, "", err
	}
	digest := sha256.Sum256(payload)
	return request, payload, hex.EncodeToString(digest[:]), nil
}

func normalizeLLMReviewProfile(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	if normalized == "" {
		return llmReviewProfileFollowUp, nil
	}
	switch normalized {
	case "follow_up", "followup", "deterministic_follow_up", "deterministic":
		return llmReviewProfileFollowUp, nil
	case "inventory_blind", "blind_inventory", "blind", "inventory":
		return llmReviewProfileInventoryBlind, nil
	default:
		return "", fmt.Errorf("unknown LLM review profile %q; use follow-up or inventory-blind", value)
	}
}

func inventoryBlindDeterministicAnchor() model.Interpretation {
	return model.Interpretation{
		Mode:           "not_included",
		Engine:         engineName,
		AvailableModes: availableModes(),
		Summary:        model.IssueSummary{},
		Issues:         []model.Issue{},
		Limitations: []string{
			"Deterministic exposure interpretation is intentionally omitted for this inventory-blind review profile.",
			"Reviewer output from this profile is exploratory and must be mapped back to Ariadne graph evidence before becoming interpretation.",
		},
	}
}

func llmReviewQuestion(profile, question string) string {
	if strings.TrimSpace(question) != "" {
		return question
	}
	if profile == llmReviewProfileInventoryBlind {
		return "From redacted inventory and graph facts only, what exposure hypotheses or collector gaps should a reviewer investigate?"
	}
	return "Which graph-backed agent exposure paths should be treated as risky?"
}

func llmReviewInstructions(profile string) []string {
	common := []string{
		"Use only the facts, source references, graph edges, controls, boundaries, and limitations in this packet.",
		"Do not infer secret values or private file contents.",
		"Do not invent graph edges, exposure IDs, controls, files, users, runtimes, authorities, or boundaries.",
		"If the evidence is insufficient, describe the missing evidence instead of overstating risk.",
	}
	if profile == llmReviewProfileInventoryBlind {
		return append(common,
			"This inventory-blind packet intentionally omits Ariadne's deterministic exposure list and priority interpretation.",
			"Return exploratory review notes or hypotheses for a human reviewer; do not present them as Ariadne findings.",
			"Cite fact_ids, graph_edges, and source_refs exactly from the citation_catalog.",
		)
	}
	return append(common,
		"Return JSON using schema_version ariadne.llm_review/v1 with an issues array.",
		"Every issue must cite an exposure_id from citation_catalog.exposure_ids.",
		"Every graph_edges entry must be copied exactly from citation_catalog.graph_edges.",
	)
}

func llmReviewContractSummary(profile string) string {
	if profile == llmReviewProfileInventoryBlind {
		return "Inventory-blind review reduces anchoring on Ariadne priority rules. It is request-only: reviewer hypotheses are not accepted as Ariadne interpretation until mapped back to deterministic exposures and graph edges."
	}
	return "Follow-up review lets a model reprioritize or explain Ariadne exposure paths, but accepted issues remain bound to deterministic exposure IDs, graph edges, allowed severities, priorities, dispositions, and redacted source refs."
}

func llmRequiredCitations(profile string) []string {
	if profile == llmReviewProfileInventoryBlind {
		return []string{"fact_ids", "graph_edges", "source_refs"}
	}
	return []string{"exposure_id", "exposure_status", "graph_edges"}
}

func llmAllowedClaims(profile string) []string {
	claims := []string{
		"The packet contains a specific redacted fact, source reference, graph node, graph edge, authority, boundary, or control.",
		"Additional evidence should be collected before treating an ambiguous path as exposed, protected, or accepted risk.",
	}
	if profile == llmReviewProfileInventoryBlind {
		return append(claims,
			"A packet fact or graph edge suggests an exposure hypothesis that should be mapped back to Ariadne evidence.",
			"A collector gap may require deterministic parser or fixture expansion.",
		)
	}
	return append(claims,
		"A graph-backed path may be higher or lower priority than Ariadne's deterministic ordering when the rationale cites packet evidence.",
		"An existing Ariadne exposure should be fixed, reviewed, monitored, treated as controlled, or treated as expected capability.",
	)
}

func llmForbiddenClaims(profile string) []string {
	claims := []string{
		"Secret values, private file contents, exact sensitive paths, or unredacted cache/history contents.",
		"Live exploitability, runtime enforcement, package provenance, network reachability, or user intent unless present as packet evidence.",
		"New files, controls, graph edges, exposure IDs, users, runtimes, tools, authorities, or boundaries that are not in the packet.",
	}
	if profile == llmReviewProfileInventoryBlind {
		return append(claims, "Final Ariadne findings, accepted issue priorities, or exposure classifications.")
	}
	return claims
}

func llmResponseRules(profile string) []string {
	if profile == llmReviewProfileInventoryBlind {
		return []string{
			"Prefer short hypotheses with cited fact_ids, graph_edges, and source_refs.",
			"Label unsupported items as missing evidence or collector gaps.",
			"Do not emit ariadne.llm_review/v1 issues for direct ingestion from this profile.",
		}
	}
	return []string{
		"Use only schema_version ariadne.llm_review/v1.",
		"Every issue must cite one exposure_id from the packet.",
		"exposure_status must exactly match the cited exposure.",
		"severity, priority, and disposition must use the allowed enum values.",
		"graph_edges must be copied exactly from the packet.",
	}
}

func llmReviewerTasks(profile string) []model.LLMReviewerTask {
	if profile == llmReviewProfileInventoryBlind {
		return []model.LLMReviewerTask{
			{
				ID:                "identify_exposure_hypotheses",
				Title:             "Identify exposure hypotheses from facts",
				Prompt:            "Look for combinations of influence, authority, boundary reachability, missing controls, or private context surfaces that deserve deterministic follow-up.",
				RequiredCitations: []string{"fact_ids", "graph_edges", "source_refs"},
			},
			{
				ID:                "find_collector_gaps",
				Title:             "Find deterministic collector gaps",
				Prompt:            "Name missing facts or parser coverage that would be required before Ariadne could classify a path.",
				RequiredCitations: []string{"fact_ids", "source_refs"},
			},
			{
				ID:                "separate_capability_from_exposure",
				Title:             "Separate capability from exposure",
				Prompt:            "Call out ordinary agent capability separately from paths where influence, authority, and boundary reachability appear connected.",
				RequiredCitations: []string{"graph_edges", "source_refs"},
			},
		}
	}
	return []model.LLMReviewerTask{
		{
			ID:                "review_top_exposures",
			Title:             "Review Ariadne exposure priority",
			Prompt:            "Assess whether Ariadne's exposed paths are correctly prioritized for security action using only cited graph evidence.",
			RequiredCitations: []string{"exposure_id", "graph_edges"},
		},
		{
			ID:                "identify_missing_or_overstated_signal",
			Title:             "Identify missing or overstated signal",
			Prompt:            "Point out where deterministic findings appear over-prioritized, under-prioritized, or missing required evidence.",
			RequiredCitations: []string{"exposure_id", "graph_edges"},
		},
		{
			ID:                "recommend_evidence_next_steps",
			Title:             "Recommend evidence next steps",
			Prompt:            "Suggest deterministic evidence to collect next when the packet is inconclusive or a control claim is weak.",
			RequiredCitations: []string{"exposure_id", "source_refs"},
		},
	}
}

func llmCitationCatalog(in Input, exposures []model.ExposureResult, profile string) model.LLMCitationCatalog {
	catalog := model.LLMCitationCatalog{
		ExposureIDs:  exposureIDs(exposures),
		FactIDs:      factIDs(in.Collection.Facts),
		GraphEdges:   graphEdgeKeys(in.Graph),
		ControlIDs:   controlIDs(in.Collection, exposures),
		AuthorityIDs: authorityIDs(in.Collection),
		BoundaryIDs:  boundaryIDs(in.Collection),
		SourceRefs:   llmSourceRefs(in, exposures, profile),
	}
	return catalog
}

func loadLLMReview(payload []byte, opts Options) (model.LLMReviewResponse, string, error) {
	switch {
	case opts.ReviewPath != "":
		data, err := os.ReadFile(opts.ReviewPath)
		if err != nil {
			return model.LLMReviewResponse{}, "", err
		}
		resp, err := parseLLMReview(data)
		return resp, "file:" + opts.ReviewPath, err
	case opts.Command != "":
		resp, err := runLLMCommand(payload, opts)
		return resp, "command:" + opts.Command, err
	default:
		return model.LLMReviewResponse{}, "", fmt.Errorf("llm interpretation requires --llm-review or --llm-command")
	}
}

func parseLLMReview(data []byte) (model.LLMReviewResponse, error) {
	var resp model.LLMReviewResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return model.LLMReviewResponse{}, err
	}
	if resp.SchemaVersion == "" {
		resp.SchemaVersion = llmResponseVersion
	}
	if resp.SchemaVersion != llmResponseVersion {
		return model.LLMReviewResponse{}, fmt.Errorf("unsupported LLM review schema %q", resp.SchemaVersion)
	}
	if resp.Issues == nil {
		resp.Issues = []model.Issue{}
	}
	return resp, nil
}

func runLLMCommand(payload []byte, opts Options) (model.LLMReviewResponse, error) {
	parts := strings.Fields(opts.Command)
	if len(parts) == 0 {
		return model.LLMReviewResponse{}, fmt.Errorf("empty LLM command")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 800 {
			msg = msg[:800]
		}
		if msg != "" {
			return model.LLMReviewResponse{}, fmt.Errorf("LLM command failed: %w: %s", err, msg)
		}
		return model.LLMReviewResponse{}, fmt.Errorf("LLM command failed: %w", err)
	}
	return parseLLMReview(stdout.Bytes())
}

func reviewToInterpretation(in Input, request model.LLMReviewRequest, resp model.LLMReviewResponse, source, digest string) (model.Interpretation, error) {
	issues := make([]model.Issue, 0, len(resp.Issues))
	for i, raw := range resp.Issues {
		issue, err := normalizeLLMIssue(in, request, raw, i)
		if err != nil {
			return model.Interpretation{}, err
		}
		issues = append(issues, issue)
	}
	sortIssues(issues)
	limitations := []string{
		"LLM review is an interpretation layer over Ariadne facts; it is not raw evidence.",
		"Ariadne rejected any LLM issue that cited unsupported exposure IDs, statuses, or graph edges.",
		"No agent runtime, MCP server, package manager, or network probe was executed by Ariadne.",
	}
	limitations = append(limitations, resp.Limitations...)
	if resp.Summary != "" {
		limitations = append(limitations, "LLM summary: "+resp.Summary)
	}
	engine := llmEngineName
	if resp.Model != "" {
		engine += " (" + resp.Model + ")"
	}
	return model.Interpretation{
		Mode:           modeLLMReview,
		Engine:         engine,
		AvailableModes: availableModes(),
		Summary:        summarize(issues),
		Issues:         issues,
		Limitations:    limitations,
		ReviewSource:   source,
		RequestDigest:  digest,
	}, nil
}

func normalizeLLMIssue(in Input, request model.LLMReviewRequest, issue model.Issue, idx int) (model.Issue, error) {
	exposure, ok := exposureByID(request.Exposures, issue.ExposureID)
	if !ok {
		return model.Issue{}, fmt.Errorf("LLM issue %d cites unsupported exposure_id %q", idx, issue.ExposureID)
	}
	if issue.ExposureStatus == "" {
		issue.ExposureStatus = exposure.Status
	}
	if issue.ExposureStatus != exposure.Status {
		return model.Issue{}, fmt.Errorf("LLM issue %d status %q does not match exposure %q status %q", idx, issue.ExposureStatus, exposure.ID, exposure.Status)
	}
	if !validSeverity(issue.Severity) {
		return model.Issue{}, fmt.Errorf("LLM issue %d has unsupported severity %q", idx, issue.Severity)
	}
	if !validPriority(issue.Priority) {
		return model.Issue{}, fmt.Errorf("LLM issue %d has unsupported priority %q", idx, issue.Priority)
	}
	if !validDisposition(issue.Disposition) {
		return model.Issue{}, fmt.Errorf("LLM issue %d has unsupported disposition %q", idx, issue.Disposition)
	}
	for _, edge := range issue.GraphEdges {
		if !request.Graph.HasEdge(edge) {
			return model.Issue{}, fmt.Errorf("LLM issue %d cites unsupported graph edge %q", idx, edge)
		}
	}
	if len(issue.GraphEdges) == 0 {
		issue.GraphEdges = stringSlice(exposure.PathEdges)
	}
	if issue.ID == "" {
		issue.ID = "llm:" + safeID(issue.ExposureID)
	} else if !strings.HasPrefix(issue.ID, "llm:") {
		issue.ID = "llm:" + issue.ID
	}
	issue.Title = firstNonEmpty(issue.Title, exposure.Title)
	issue.Category = firstNonEmpty(issue.Category, "llm-review")
	issue.RuleID = firstNonEmpty(issue.RuleID, "llm-review")
	issue.RuleSource = "llm"
	issue.InterpretationMode = modeLLMReview
	issue.AffectedTarget = in.Target
	issue.Rationale = firstNonEmpty(issue.Rationale, "LLM review matched graph-backed exposure evidence.")
	issue.Signals = stringSlice(issue.Signals)
	issue.Controls = stringSlice(issue.Controls)
	issue.Actions = stringSlice(issue.Actions)
	issue.Confidence = firstNonEmpty(issue.Confidence, "medium")
	return issue, nil
}

func exposureByID(exposures []model.ExposureResult, id string) (model.ExposureResult, bool) {
	for _, exposure := range exposures {
		if exposure.ID == id {
			return exposure, true
		}
	}
	return model.ExposureResult{}, false
}

func validSeverity(value model.Severity) bool {
	switch value {
	case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo:
		return true
	default:
		return false
	}
}

func validPriority(value model.Priority) bool {
	switch value {
	case model.PriorityP0, model.PriorityP1, model.PriorityP2, model.PriorityP3, model.PriorityP4:
		return true
	default:
		return false
	}
}

func validDisposition(value model.Disposition) bool {
	switch value {
	case model.DispositionFixNow, model.DispositionReview, model.DispositionMonitor, model.DispositionControlled, model.DispositionExpected:
		return true
	default:
		return false
	}
}

func safeID(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return strings.Trim(b.String(), "-")
}

func exposureSlice(values []model.ExposureResult) []model.ExposureResult {
	if values == nil {
		return []model.ExposureResult{}
	}
	return values
}

func exposureIDs(exposures []model.ExposureResult) []string {
	var out []string
	for _, exposure := range exposures {
		if exposure.ID != "" {
			out = append(out, exposure.ID)
		}
	}
	return uniqueSorted(out)
}

func factIDs(facts []model.Fact) []string {
	var out []string
	for _, fact := range facts {
		if fact.ID != "" {
			out = append(out, fact.ID)
		}
	}
	return uniqueSorted(out)
}

func graphEdgeKeys(graph model.Graph) []string {
	var out []string
	for _, edge := range graph.Edges {
		if edge.From != "" && edge.To != "" && edge.Type != "" {
			out = append(out, edge.Key())
		}
	}
	return uniqueSorted(out)
}

func controlIDs(collection model.Collection, exposures []model.ExposureResult) []string {
	var out []string
	for _, control := range collection.Controls {
		if control.ID != "" {
			out = append(out, control.ID)
		}
	}
	for _, exposure := range exposures {
		out = append(out, exposure.ControlsBreakPath...)
	}
	for _, fact := range collection.Facts {
		if fact.Type == "control" && fact.ID != "" {
			out = append(out, fact.ID)
		}
	}
	return uniqueSorted(out)
}

func authorityIDs(collection model.Collection) []string {
	var out []string
	for _, authority := range collection.Authorities {
		if authority.ID != "" {
			out = append(out, authority.ID)
		}
	}
	return uniqueSorted(out)
}

func boundaryIDs(collection model.Collection) []string {
	var out []string
	for _, boundary := range collection.Boundaries {
		if boundary.ID != "" {
			out = append(out, boundary.ID)
		}
	}
	return uniqueSorted(out)
}

func llmSourceRefs(in Input, exposures []model.ExposureResult, profile string) []model.EvidenceReference {
	var refs []model.EvidenceReference
	for _, evidence := range in.Collection.Evidence {
		refs = append(refs, model.EvidenceReference{
			ID:      evidence.ID,
			Kind:    evidence.Kind,
			Source:  evidence.Source,
			Summary: evidence.Summary,
		})
	}
	for _, fact := range in.Collection.Facts {
		refs = append(refs, model.EvidenceReference{
			ID:      fact.ID,
			Kind:    firstNonEmpty(fact.Type, "fact"),
			Source:  fact.Source,
			Summary: fact.Summary,
		})
	}
	for _, surface := range in.Collection.Surfaces {
		refs = append(refs, model.EvidenceReference{
			ID:      surface.ID,
			Kind:    firstNonEmpty(surface.Kind, surface.Category, "surface"),
			Source:  surface.Source,
			Summary: surface.Summary,
		})
	}
	if profile == llmReviewProfileFollowUp {
		for _, exposure := range exposures {
			refs = append(refs, exposure.EvidenceReferences...)
		}
	}
	return dedupeLLMSourceRefs(refs)
}

func dedupeLLMSourceRefs(refs []model.EvidenceReference) []model.EvidenceReference {
	seen := map[string]bool{}
	out := []model.EvidenceReference{}
	for _, ref := range refs {
		if ref.ID == "" && ref.Source == "" && ref.Summary == "" {
			continue
		}
		key := strings.Join([]string{
			ref.Target,
			ref.ID,
			ref.Kind,
			ref.Source,
			fmt.Sprintf("%d", ref.LineStart),
			fmt.Sprintf("%d", ref.LineEnd),
			ref.Summary,
		}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].LineStart != out[j].LineStart {
			return out[i].LineStart < out[j].LineStart
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
