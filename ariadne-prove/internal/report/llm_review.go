package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

func RenderLLMReviewRequestSummary(w io.Writer, request model.LLMReviewRequest, digest string, packetPath string) error {
	fmt.Fprintln(w, "Ariadne Review Packet")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Target: %s\n", request.Target)
	fmt.Fprintf(w, "Mode: %s\n", request.Mode)
	fmt.Fprintf(w, "Profile: %s\n", request.ReviewProfile)
	if digest != "" {
		fmt.Fprintf(w, "Digest: %s\n", shortDigest(digest))
	}
	if packetPath != "" {
		fmt.Fprintf(w, "Packet JSON: %s\n", packetPath)
	} else {
		fmt.Fprintln(w, "Packet JSON: not written; use --packet-out <file> or --format json")
	}
	fmt.Fprintf(w, "Ingestible as analyst output: %s\n", reviewPacketIngestibility(request.ReviewProfile))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Evidence available:")
	fmt.Fprintf(w, "  Facts: %d\n", len(request.CitationCatalog.FactIDs))
	fmt.Fprintf(w, "  Source refs: %d\n", len(request.CitationCatalog.SourceRefs))
	fmt.Fprintf(w, "  Graph edges: %d\n", len(request.CitationCatalog.GraphEdges))
	fmt.Fprintf(w, "  Exposures: %d\n", len(request.CitationCatalog.ExposureIDs))
	fmt.Fprintf(w, "  Reckless findings: %d\n", len(request.CitationCatalog.FindingIDs))
	fmt.Fprintf(w, "  Default judgments: %d\n", len(request.CitationCatalog.DefaultJudgmentIDs))
	fmt.Fprintf(w, "  Authorities: %d\n", len(request.CitationCatalog.AuthorityIDs))
	fmt.Fprintf(w, "  Boundaries: %d\n", len(request.CitationCatalog.BoundaryIDs))
	fmt.Fprintln(w)

	if request.ReviewContract.Summary != "" {
		fmt.Fprintln(w, "Review contract:")
		fmt.Fprintf(w, "  %s\n", request.ReviewContract.Summary)
	}
	if len(request.ReviewContract.RequiredCitations) > 0 {
		fmt.Fprintf(w, "  Required citations: %s\n", strings.Join(request.ReviewContract.RequiredCitations, ", "))
	}
	if len(request.ReviewContract.ResponseRules) > 0 {
		fmt.Fprintln(w, "  Response rules:")
		for _, rule := range request.ReviewContract.ResponseRules {
			fmt.Fprintf(w, "    - %s\n", rule)
		}
	}
	fmt.Fprintln(w)

	if len(request.ReviewerTasks) > 0 {
		fmt.Fprintln(w, "Reviewer tasks:")
		for _, task := range request.ReviewerTasks {
			fmt.Fprintf(w, "  - %s: %s\n", task.ID, task.Title)
			if len(task.RequiredCitations) > 0 {
				fmt.Fprintf(w, "    Cite: %s\n", strings.Join(task.RequiredCitations, ", "))
			}
		}
		fmt.Fprintln(w)
	}

	if len(request.ReviewContract.ForbiddenClaims) > 0 {
		fmt.Fprintln(w, "Forbidden claims:")
		for _, claim := range request.ReviewContract.ForbiddenClaims {
			fmt.Fprintf(w, "  - %s\n", claim)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Next:")
	if request.ReviewProfile == "inventory_blind" {
		fmt.Fprintln(w, "  - Give the packet JSON to a reviewer for hypothesis and collector-gap review.")
		fmt.Fprintln(w, "  - Map any hypothesis back to Ariadne fact IDs, source refs, and graph edges before treating it as a finding.")
		fmt.Fprintln(w, "  - Rerun deterministic Ariadne commands after adding parser coverage or evidence.")
	} else {
		fmt.Fprintln(w, "  - Give the packet JSON to a reviewer that returns ariadne.llm_review/v1.")
		fmt.Fprintln(w, "  - Ingest the review with ariadne prove --interpret llm --llm-review <file>.")
		fmt.Fprintln(w, "  - Ariadne will reject unsupported finding IDs, fact IDs, graph edges, default judgments, verdict changes, and finding closure attempts.")
	}
	return nil
}

func RenderLLMReviewCheck(w io.Writer, check model.LLMReviewCheckReport, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "summary", "table":
		return RenderLLMReviewCheckSummary(w, check)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(check)
	default:
		return fmt.Errorf("unknown review-check format: %s", format)
	}
}

func RenderLLMReviewCheckSummary(w io.Writer, check model.LLMReviewCheckReport) error {
	fmt.Fprintln(w, "Ariadne Review Check")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Target: %s\n", check.Target)
	fmt.Fprintf(w, "Mode: %s\n", check.Mode)
	fmt.Fprintf(w, "Profile: %s\n", check.ReviewProfile)
	fmt.Fprintf(w, "Packet: %s\n", check.PacketSource)
	fmt.Fprintf(w, "Review: %s\n", check.ReviewSource)
	if check.RequestDigest != "" {
		fmt.Fprintf(w, "Packet digest: %s\n", shortDigest(check.RequestDigest))
	}
	fmt.Fprintf(w, "Accepted: %t\n", check.Accepted)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Validated analyst output:")
	analyst := check.Interpretation.Analyst
	if analyst == nil {
		fmt.Fprintln(w, "  Analyst: not attached")
	} else {
		fmt.Fprintf(w, "  Finding explanations: %d\n", len(analyst.FindingExplanations))
		for _, explanation := range analyst.FindingExplanations {
			fmt.Fprintf(w, "  - %s/%s %s\n", explanation.FindingID, explanation.ExposureID, explanation.OperatorContext)
		}
		fmt.Fprintf(w, "  Rankings: %d\n", len(analyst.FindingRanking))
		for _, ranked := range analyst.FindingRanking {
			fmt.Fprintf(w, "  - #%d %s/%s %s\n", ranked.Rank, ranked.FindingID, ranked.ExposureID, ranked.Rationale)
		}
		fmt.Fprintf(w, "  Default-judgment overrides: %d\n", len(analyst.DefaultJudgmentOverrides))
		for _, override := range analyst.DefaultJudgmentOverrides {
			fmt.Fprintf(w, "  - %s/%s %s\n", override.Rule, override.ExposureID, override.Reason)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "What Ariadne verified:")
	fmt.Fprintln(w, "  - every explanation and ranking cited packet finding IDs")
	fmt.Fprintln(w, "  - cited fact IDs, evidence refs, and graph edges existed in the packet catalog")
	fmt.Fprintln(w, "  - default-judgment overrides referenced an existing rule, exposure, and basis facts")
	fmt.Fprintln(w, "  - verdict-word changes and finding closure attempts were rejected before this report was produced")
	return nil
}

func RenderLLMReviewRun(w io.Writer, run model.LLMReviewRunReport, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "summary", "table":
		return RenderLLMReviewRunSummary(w, run)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(run)
	default:
		return fmt.Errorf("unknown review-run format: %s", format)
	}
}

func RenderLLMReviewRunSummary(w io.Writer, run model.LLMReviewRunReport) error {
	fmt.Fprintln(w, "Ariadne Review Run")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Target: %s\n", run.Target)
	fmt.Fprintf(w, "Mode: %s\n", run.Mode)
	fmt.Fprintf(w, "Profile: %s\n", run.ReviewProfile)
	fmt.Fprintf(w, "Command: %s\n", run.Command)
	fmt.Fprintf(w, "Accepted: %t\n", run.Accepted)
	if run.RequestDigest != "" {
		fmt.Fprintf(w, "Packet digest: %s\n", shortDigest(run.RequestDigest))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Artifacts:")
	fmt.Fprintf(w, "  - Packet JSON: %s\n", run.PacketPath)
	fmt.Fprintf(w, "  - Reviewer JSON: %s\n", run.ReviewPath)
	fmt.Fprintf(w, "  - Review check JSON: %s\n", run.CheckJSONPath)
	fmt.Fprintf(w, "  - Review check summary: %s\n", run.CheckSummaryPath)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Validated analyst output:")
	analyst := run.Check.Interpretation.Analyst
	if analyst == nil {
		fmt.Fprintln(w, "  Analyst: not attached")
	} else {
		fmt.Fprintf(w, "  Finding explanations: %d\n", len(analyst.FindingExplanations))
		for _, explanation := range analyst.FindingExplanations {
			fmt.Fprintf(w, "  - %s/%s %s\n", explanation.FindingID, explanation.ExposureID, explanation.OperatorContext)
		}
		fmt.Fprintf(w, "  Rankings: %d\n", len(analyst.FindingRanking))
		for _, ranked := range analyst.FindingRanking {
			fmt.Fprintf(w, "  - #%d %s/%s %s\n", ranked.Rank, ranked.FindingID, ranked.ExposureID, ranked.Rationale)
		}
		fmt.Fprintf(w, "  Default-judgment overrides: %d\n", len(analyst.DefaultJudgmentOverrides))
		for _, override := range analyst.DefaultJudgmentOverrides {
			fmt.Fprintf(w, "  - %s/%s %s\n", override.Rule, override.ExposureID, override.Reason)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "What Ariadne did:")
	fmt.Fprintln(w, "  - generated a redacted follow-up review packet")
	fmt.Fprintln(w, "  - sent only that packet to the reviewer command on stdin")
	fmt.Fprintln(w, "  - saved the raw reviewer JSON")
	fmt.Fprintln(w, "  - validated analyst claims against packet evidence before accepting them")
	return nil
}

func reviewPacketIngestibility(profile string) string {
	if profile == "inventory_blind" {
		return "no; request-only until mapped back to deterministic evidence"
	}
	return "yes; only ariadne.llm_review/v1 analyst content bound to packet findings, facts, graph edges, and default judgments"
}

func shortDigest(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}
