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
	Verdict        *model.LLMVerdictContext
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
		return reviewToInterpretation(deterministic, request, resp, source, digest)
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
	verdictContext := opts.Verdict
	if profile == llmReviewProfileInventoryBlind {
		verdictContext = nil
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
		CitationCatalog: llmCitationCatalog(in, exposures, profile, verdictContext),
		Verdict:         verdictContext,
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
		"Return JSON using schema_version ariadne.llm_review/v1 with finding_explanations, finding_ranking, and optional default_judgment_overrides.",
		"Every finding explanation and ranking entry must cite a finding_id from citation_catalog.finding_ids.",
		"Every fact_id, evidence_ref_id, and graph_edges entry must be copied exactly from citation_catalog.",
		"Do not return issues; follow-up reviews explain and rank existing verdict findings only.",
	)
}

func llmReviewContractSummary(profile string) string {
	if profile == llmReviewProfileInventoryBlind {
		return "Inventory-blind review reduces anchoring on Ariadne priority rules. It is request-only: reviewer hypotheses are not accepted as Ariadne interpretation until mapped back to deterministic exposures and graph edges."
	}
	return "Follow-up review lets a model explain, rank, and propose default-judgment overrides for the deterministic verdict, but accepted analyst content remains bound to existing reckless finding IDs, default judgments, fact IDs, graph edges, and redacted source refs."
}

func llmRequiredCitations(profile string) []string {
	if profile == llmReviewProfileInventoryBlind {
		return []string{"fact_ids", "graph_edges", "source_refs"}
	}
	return []string{"finding_id", "fact_ids", "graph_edges"}
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
		"An existing reckless finding can be explained in operator context when the explanation cites packet evidence.",
		"Existing reckless findings can be ranked when each one-line rationale cites packet evidence.",
		"An existing default_judgment can be proposed for override when the reviewer cites that judgment's basis facts.",
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
	return append(claims,
		"New findings, new exposure classifications, or issue lists not backed by the packet's existing reckless findings.",
		"Closing, removing, suppressing, or resolving a finding.",
		"Changing the deterministic verdict word.",
	)
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
		"Do not emit issues; analyst output must use finding_explanations, finding_ranking, and optional default_judgment_overrides.",
		"Every finding_explanations entry must cite an existing finding_id and matching exposure_id.",
		"finding_ranking must include each reckless finding exactly once when rankings are present.",
		"default_judgment_overrides may only name an existing default_judgments rule and exposure_id, and must cite that judgment's basis fact IDs.",
		"graph_edges, fact_ids, and evidence_ref_ids must be copied exactly from the packet citation catalog.",
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
			ID:                "explain_reckless_findings",
			Title:             "Explain each reckless finding",
			Prompt:            "Explain every verdict.reckless finding in operator context without adding findings or changing the verdict.",
			RequiredCitations: []string{"finding_id", "fact_ids", "graph_edges"},
		},
		{
			ID:                "rank_reckless_findings",
			Title:             "Rank reckless findings",
			Prompt:            "Rank existing reckless findings with one one-line rationale per finding.",
			RequiredCitations: []string{"finding_id", "fact_ids", "graph_edges"},
		},
		{
			ID:                "propose_default_judgment_overrides",
			Title:             "Optionally propose default-judgment overrides",
			Prompt:            "If a default_judgment should be overridden, name its rule and exposure_id, cite its basis fact IDs, and give the reason. Do not change the verdict word.",
			RequiredCitations: []string{"default_judgment", "basis_fact_ids"},
		},
	}
}

func llmCitationCatalog(in Input, exposures []model.ExposureResult, profile string, verdictContext *model.LLMVerdictContext) model.LLMCitationCatalog {
	sourceRefs := llmSourceRefs(in, exposures, profile)
	catalog := model.LLMCitationCatalog{
		ExposureIDs:          exposureIDs(exposures),
		FactIDs:              factIDs(in.Collection.Facts),
		GraphEdges:           graphEdgeKeys(in.Graph),
		ControlIDs:           controlIDs(in.Collection, exposures),
		AuthorityIDs:         authorityIDs(in.Collection),
		BoundaryIDs:          boundaryIDs(in.Collection),
		FindingIDs:           verdictFindingIDs(verdictContext),
		DefaultJudgmentIDs:   verdictDefaultJudgmentIDs(verdictContext),
		DefaultJudgmentRules: verdictDefaultJudgmentRules(verdictContext),
		TradeoffIDs:          verdictTradeoffIDs(verdictContext),
		EvidenceRefIDs:       evidenceRefIDs(sourceRefs, verdictContext),
		SourceRefs:           sourceRefs,
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

func ValidateLLMReview(request model.LLMReviewRequest, reviewData []byte, source, digest string) (model.Interpretation, error) {
	if request.ReviewProfile != llmReviewProfileFollowUp {
		return model.Interpretation{}, fmt.Errorf("llm review validation requires a follow-up packet; %s packets are request-only until mapped back to Ariadne exposure evidence", request.ReviewProfile)
	}
	resp, err := parseLLMReview(reviewData)
	if err != nil {
		return model.Interpretation{}, err
	}
	return reviewToInterpretation(request.Deterministic, request, resp, source, digest)
}

func parseLLMReview(data []byte) (model.LLMReviewResponse, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return model.LLMReviewResponse{}, err
	}
	forbiddenVerdictFields := []string{"verdict", "verdict_word"}
	for _, field := range forbiddenVerdictFields {
		if _, ok := raw[field]; ok {
			return model.LLMReviewResponse{}, fmt.Errorf("LLM review attempts to change the verdict word via field %q", field)
		}
	}
	forbiddenClosureFields := []string{"close_findings", "closed_findings", "remove_findings", "removed_findings", "resolved_findings", "suppressed_findings"}
	for _, field := range forbiddenClosureFields {
		if _, ok := raw[field]; ok {
			return model.LLMReviewResponse{}, fmt.Errorf("LLM review attempts to close or remove findings via field %q", field)
		}
	}
	if _, ok := raw["issues"]; ok {
		return model.LLMReviewResponse{}, fmt.Errorf("LLM review issues are not accepted by verdict-aware follow-up; explain existing reckless findings instead")
	}
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
	resp.FindingExplanations = nonNilFindingExplanations(resp.FindingExplanations)
	resp.FindingRanking = nonNilFindingRanking(resp.FindingRanking)
	resp.DefaultJudgmentOverrides = nonNilDefaultJudgmentOverrides(resp.DefaultJudgmentOverrides)
	resp.Issues = stringIssueSlice(resp.Issues)
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

func reviewToInterpretation(deterministic model.Interpretation, request model.LLMReviewRequest, resp model.LLMReviewResponse, source, digest string) (model.Interpretation, error) {
	analyst, err := validateAnalystReview(request, resp, source, digest)
	if err != nil {
		return model.Interpretation{}, err
	}
	out := deterministic
	out.Analyst = &analyst
	return out, nil
}

func validateAnalystReview(request model.LLMReviewRequest, resp model.LLMReviewResponse, source, digest string) (model.LLMAnalyst, error) {
	if request.Verdict == nil {
		return model.LLMAnalyst{}, fmt.Errorf("follow-up packet is missing verdict context")
	}
	if len(resp.Issues) > 0 {
		return model.LLMAnalyst{}, fmt.Errorf("LLM review issues are not accepted by verdict-aware follow-up; explain existing reckless findings instead")
	}
	findingByID := verdictFindingsByID(request.Verdict)
	if err := validateFindingExplanations(request, resp.FindingExplanations, findingByID); err != nil {
		return model.LLMAnalyst{}, err
	}
	if err := validateFindingRanking(request, resp.FindingRanking, findingByID); err != nil {
		return model.LLMAnalyst{}, err
	}
	if err := validateDefaultJudgmentOverrides(request, resp.DefaultJudgmentOverrides); err != nil {
		return model.LLMAnalyst{}, err
	}
	return model.LLMAnalyst{
		SourceType:               modeLLMReview,
		DerivedBy:                "llm",
		ReviewSource:             source,
		RequestDigest:            digest,
		Reviewer:                 resp.Reviewer,
		Model:                    resp.Model,
		Summary:                  resp.Summary,
		FindingExplanations:      nonNilFindingExplanations(resp.FindingExplanations),
		FindingRanking:           nonNilFindingRanking(resp.FindingRanking),
		DefaultJudgmentOverrides: nonNilDefaultJudgmentOverrides(resp.DefaultJudgmentOverrides),
		Limitations:              stringSlice(resp.Limitations),
	}, nil
}

func validateFindingExplanations(request model.LLMReviewRequest, explanations []model.LLMFindingExplanation, findingByID map[string]model.LLMVerdictFinding) error {
	if len(findingByID) == 0 && len(explanations) == 0 {
		return nil
	}
	if len(explanations) != len(findingByID) {
		return fmt.Errorf("LLM finding_explanations must explain each reckless finding exactly once; got %d, want %d", len(explanations), len(findingByID))
	}
	seen := map[string]bool{}
	for i, explanation := range explanations {
		label := fmt.Sprintf("LLM finding_explanations[%d]", i)
		finding, ok := findingByID[explanation.FindingID]
		if !ok || !containsString(request.CitationCatalog.FindingIDs, explanation.FindingID) {
			return fmt.Errorf("%s cites unsupported finding_id %q", label, explanation.FindingID)
		}
		if seen[explanation.FindingID] {
			return fmt.Errorf("%s duplicates finding_id %q", label, explanation.FindingID)
		}
		seen[explanation.FindingID] = true
		if explanation.ExposureID != finding.ExposureID {
			return fmt.Errorf("%s exposure_id %q does not match finding %q exposure_id %q", label, explanation.ExposureID, explanation.FindingID, finding.ExposureID)
		}
		if strings.TrimSpace(explanation.OperatorContext) == "" {
			return fmt.Errorf("%s has empty operator_context", label)
		}
		if err := validateAnalystCitations(label, request, explanation.FactIDs, explanation.EvidenceRefIDs, explanation.GraphEdges); err != nil {
			return err
		}
	}
	return nil
}

func validateFindingRanking(request model.LLMReviewRequest, ranking []model.LLMFindingRanking, findingByID map[string]model.LLMVerdictFinding) error {
	if len(ranking) == 0 && len(findingByID) == 0 {
		return nil
	}
	if len(ranking) != len(findingByID) {
		return fmt.Errorf("LLM finding_ranking must rank each reckless finding exactly once; got %d, want %d", len(ranking), len(findingByID))
	}
	seenFindings := map[string]bool{}
	seenRanks := map[int]bool{}
	for i, ranked := range ranking {
		label := fmt.Sprintf("LLM finding_ranking[%d]", i)
		finding, ok := findingByID[ranked.FindingID]
		if !ok || !containsString(request.CitationCatalog.FindingIDs, ranked.FindingID) {
			return fmt.Errorf("%s cites unsupported finding_id %q", label, ranked.FindingID)
		}
		if seenFindings[ranked.FindingID] {
			return fmt.Errorf("%s duplicates finding_id %q", label, ranked.FindingID)
		}
		seenFindings[ranked.FindingID] = true
		if ranked.ExposureID != finding.ExposureID {
			return fmt.Errorf("%s exposure_id %q does not match finding %q exposure_id %q", label, ranked.ExposureID, ranked.FindingID, finding.ExposureID)
		}
		if ranked.Rank < 1 || ranked.Rank > len(findingByID) {
			return fmt.Errorf("%s has unsupported rank %d", label, ranked.Rank)
		}
		if seenRanks[ranked.Rank] {
			return fmt.Errorf("%s duplicates rank %d", label, ranked.Rank)
		}
		seenRanks[ranked.Rank] = true
		if strings.TrimSpace(ranked.Rationale) == "" {
			return fmt.Errorf("%s has empty rationale", label)
		}
		if err := validateAnalystCitations(label, request, ranked.FactIDs, ranked.EvidenceRefIDs, ranked.GraphEdges); err != nil {
			return err
		}
	}
	return nil
}

func validateDefaultJudgmentOverrides(request model.LLMReviewRequest, overrides []model.LLMDefaultJudgmentOverride) error {
	judgmentByKey := defaultJudgmentsByKey(request.Verdict)
	for i, override := range overrides {
		label := fmt.Sprintf("LLM default_judgment_overrides[%d]", i)
		judgment, ok := judgmentByKey[defaultJudgmentKey(override.Rule, override.ExposureID)]
		if !ok {
			return fmt.Errorf("%s references unsupported default_judgment rule %q exposure_id %q", label, override.Rule, override.ExposureID)
		}
		if !containsString(request.CitationCatalog.DefaultJudgmentRules, override.Rule) {
			return fmt.Errorf("%s cites unsupported default_judgment rule %q", label, override.Rule)
		}
		if strings.TrimSpace(override.ProposedJudgment) == "" {
			return fmt.Errorf("%s has empty proposed_judgment", label)
		}
		if strings.TrimSpace(override.Reason) == "" {
			return fmt.Errorf("%s has empty reason", label)
		}
		if len(override.BasisFactIDs) == 0 {
			return fmt.Errorf("%s must cite at least one basis_fact_id", label)
		}
		validBasisFacts := judgmentBasisFactSet(judgment)
		for _, factID := range override.BasisFactIDs {
			if !containsString(request.CitationCatalog.FactIDs, factID) {
				return fmt.Errorf("%s cites unsupported fact_id %q", label, factID)
			}
			if !validBasisFacts[factID] {
				return fmt.Errorf("%s cites fact_id %q outside default_judgment basis", label, factID)
			}
		}
	}
	return nil
}

func validateAnalystCitations(label string, request model.LLMReviewRequest, factIDs, evidenceRefIDs, graphEdges []string) error {
	if len(factIDs)+len(evidenceRefIDs)+len(graphEdges) == 0 {
		return fmt.Errorf("%s must cite at least one fact_id, evidence_ref_id, or graph_edge", label)
	}
	for _, factID := range factIDs {
		if !containsString(request.CitationCatalog.FactIDs, factID) {
			return fmt.Errorf("%s cites unsupported fact_id %q", label, factID)
		}
	}
	for _, refID := range evidenceRefIDs {
		if !containsString(request.CitationCatalog.EvidenceRefIDs, refID) {
			return fmt.Errorf("%s cites unsupported evidence_ref_id %q", label, refID)
		}
	}
	for _, edge := range graphEdges {
		if !containsString(request.CitationCatalog.GraphEdges, edge) {
			return fmt.Errorf("%s cites unsupported graph edge %q", label, edge)
		}
	}
	return nil
}

func verdictFindingsByID(verdictContext *model.LLMVerdictContext) map[string]model.LLMVerdictFinding {
	out := map[string]model.LLMVerdictFinding{}
	if verdictContext == nil {
		return out
	}
	for _, finding := range verdictContext.Reckless {
		if finding.ID != "" {
			out[finding.ID] = finding
		}
	}
	return out
}

func defaultJudgmentsByKey(verdictContext *model.LLMVerdictContext) map[string]model.LLMDefaultJudgment {
	out := map[string]model.LLMDefaultJudgment{}
	if verdictContext == nil {
		return out
	}
	for _, judgment := range verdictContext.DefaultJudgments {
		out[defaultJudgmentKey(judgment.Rule, judgment.ExposureID)] = judgment
	}
	return out
}

func defaultJudgmentKey(rule, exposureID string) string {
	return strings.TrimSpace(rule) + "\x00" + strings.TrimSpace(exposureID)
}

func judgmentBasisFactSet(judgment model.LLMDefaultJudgment) map[string]bool {
	out := map[string]bool{}
	for _, basis := range judgment.Basis {
		if basis.Kind == "fact" && basis.ID != "" {
			out[basis.ID] = true
		}
	}
	return out
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

func verdictFindingIDs(verdictContext *model.LLMVerdictContext) []string {
	if verdictContext == nil {
		return []string{}
	}
	var out []string
	for _, finding := range verdictContext.Reckless {
		out = append(out, finding.ID)
	}
	return uniqueSorted(out)
}

func verdictDefaultJudgmentIDs(verdictContext *model.LLMVerdictContext) []string {
	if verdictContext == nil {
		return []string{}
	}
	var out []string
	for _, judgment := range verdictContext.DefaultJudgments {
		out = append(out, judgment.ID)
	}
	return uniqueSorted(out)
}

func verdictDefaultJudgmentRules(verdictContext *model.LLMVerdictContext) []string {
	if verdictContext == nil {
		return []string{}
	}
	var out []string
	for _, judgment := range verdictContext.DefaultJudgments {
		out = append(out, judgment.Rule)
	}
	return uniqueSorted(out)
}

func verdictTradeoffIDs(verdictContext *model.LLMVerdictContext) []string {
	if verdictContext == nil {
		return []string{}
	}
	var out []string
	for _, tradeoff := range verdictContext.Tradeoffs {
		out = append(out, tradeoff.ID)
	}
	return uniqueSorted(out)
}

func evidenceRefIDs(refs []model.EvidenceReference, verdictContext *model.LLMVerdictContext) []string {
	var out []string
	for _, ref := range refs {
		out = append(out, ref.ID)
	}
	if verdictContext != nil {
		for _, finding := range verdictContext.Reckless {
			out = append(out, finding.EvidenceRefs...)
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
	for _, runtime := range in.Collection.Runtimes {
		refs = append(refs, model.EvidenceReference{ID: runtime.ID, Kind: "runtime", Source: runtime.Source, Summary: runtime.Summary})
		refs = append(refs, model.EvidenceReference{ID: runtime.OccurrenceID, Kind: "runtime_occurrence", Source: runtime.Source, Summary: runtime.Summary})
	}
	for _, input := range in.Collection.TrustInputs {
		refs = append(refs, model.EvidenceReference{ID: input.ID, Kind: "trust-input", Source: input.Source, Summary: input.Summary})
		refs = append(refs, model.EvidenceReference{ID: input.OccurrenceID, Kind: "trust_input_occurrence", Source: input.Source, Summary: input.Summary})
	}
	for _, tool := range in.Collection.Tools {
		refs = append(refs, model.EvidenceReference{ID: tool.ID, Kind: "tool", Source: tool.Source, Summary: tool.Summary})
		refs = append(refs, model.EvidenceReference{ID: tool.OccurrenceID, Kind: "tool_occurrence", Source: tool.Source, Summary: tool.Summary})
	}
	for _, authority := range in.Collection.Authorities {
		refs = append(refs, model.EvidenceReference{ID: authority.ID, Kind: "authority", Source: authority.Source, Summary: authority.Summary})
		refs = append(refs, model.EvidenceReference{ID: authority.OccurrenceID, Kind: "authority_occurrence", Source: authority.Source, Summary: authority.Summary})
	}
	for _, boundary := range in.Collection.Boundaries {
		refs = append(refs, model.EvidenceReference{ID: boundary.ID, Kind: "boundary", Source: boundary.Source, Summary: boundary.Summary})
		refs = append(refs, model.EvidenceReference{ID: boundary.OccurrenceID, Kind: "boundary_occurrence", Source: boundary.Source, Summary: boundary.Summary})
	}
	for _, control := range in.Collection.Controls {
		refs = append(refs, model.EvidenceReference{ID: control.ID, Kind: "control", Source: control.Source, Summary: control.Summary})
		refs = append(refs, model.EvidenceReference{ID: control.OccurrenceID, Kind: "control_occurrence", Source: control.Source, Summary: control.Summary})
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func nonNilFindingExplanations(values []model.LLMFindingExplanation) []model.LLMFindingExplanation {
	if values == nil {
		return []model.LLMFindingExplanation{}
	}
	return values
}

func nonNilFindingRanking(values []model.LLMFindingRanking) []model.LLMFindingRanking {
	if values == nil {
		return []model.LLMFindingRanking{}
	}
	return values
}

func nonNilDefaultJudgmentOverrides(values []model.LLMDefaultJudgmentOverride) []model.LLMDefaultJudgmentOverride {
	if values == nil {
		return []model.LLMDefaultJudgmentOverride{}
	}
	return values
}

func stringIssueSlice(values []model.Issue) []model.Issue {
	if values == nil {
		return []model.Issue{}
	}
	return values
}
