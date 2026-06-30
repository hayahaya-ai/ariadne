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
	"strings"
	"time"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

const (
	modeLLMReview      = "llm_review"
	llmEngineName      = "ariadne fact-bound llm review"
	llmRequestVersion  = "ariadne.llm_review_request/v1"
	llmResponseVersion = "ariadne.llm_review/v1"
)

type Options struct {
	Mode           string
	ReviewPath     string
	Command        string
	RequestOut     string
	Timeout        time.Duration
	Question       string
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
	request := model.LLMReviewRequest{
		SchemaVersion: llmRequestVersion,
		Target:        in.Target,
		Mode:          in.Mode,
		Question:      firstNonEmpty(opts.Question, "Which graph-backed agent exposure paths should be treated as risky?"),
		Instructions: []string{
			"Use only the facts, graph edges, exposures, controls, and limitations in this packet.",
			"Do not infer secret values or private file contents.",
			"Do not invent graph edges, exposure IDs, controls, files, users, runtimes, or boundaries.",
			"Return JSON using schema_version ariadne.llm_review/v1 with an issues array.",
			"Every issue must cite an exposure_id. Graph edges must be copied exactly from the packet.",
			"If the evidence is insufficient, return an inconclusive or review-oriented issue rather than overstating risk.",
		},
		Collection:    in.Collection,
		Graph:         in.Graph,
		Exposures:     exposureSlice(in.Exposures),
		Deterministic: deterministic,
		Redaction:     opts.Redaction,
		Limitations:   stringSlice(opts.RunLimitations),
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
