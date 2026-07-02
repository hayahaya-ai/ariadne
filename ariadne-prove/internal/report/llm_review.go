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
	fmt.Fprintf(w, "Ingestible as findings: %s\n", reviewPacketIngestibility(request.ReviewProfile))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Evidence available:")
	fmt.Fprintf(w, "  Facts: %d\n", len(request.CitationCatalog.FactIDs))
	fmt.Fprintf(w, "  Source refs: %d\n", len(request.CitationCatalog.SourceRefs))
	fmt.Fprintf(w, "  Graph edges: %d\n", len(request.CitationCatalog.GraphEdges))
	fmt.Fprintf(w, "  Exposures: %d\n", len(request.CitationCatalog.ExposureIDs))
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
		fmt.Fprintln(w, "  - Ariadne will reject unsupported exposure IDs, statuses, graph edges, severities, priorities, and dispositions.")
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

	fmt.Fprintln(w, "Validated interpretation:")
	fmt.Fprintf(w, "  Issues: %d total, %d critical, %d high, %d medium, %d low, %d info\n",
		check.Interpretation.Summary.Total,
		check.Interpretation.Summary.Critical,
		check.Interpretation.Summary.High,
		check.Interpretation.Summary.Medium,
		check.Interpretation.Summary.Low,
		check.Interpretation.Summary.Info,
	)
	for _, issue := range check.Interpretation.Issues {
		fmt.Fprintf(w, "  - %s/%s %s [%s] Exposure: %s\n",
			strings.ToUpper(string(issue.Priority)),
			strings.ToUpper(string(issue.Severity)),
			issue.Title,
			issue.Disposition,
			issue.ExposureID,
		)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "What Ariadne verified:")
	fmt.Fprintln(w, "  - every issue cited a packet exposure_id")
	fmt.Fprintln(w, "  - exposure_status matched the packet")
	fmt.Fprintln(w, "  - graph_edges were copied from the packet graph")
	fmt.Fprintln(w, "  - severity, priority, and disposition used allowed values")
	fmt.Fprintln(w, "  - unsupported reviewer claims were rejected before this report was produced")
	return nil
}

func reviewPacketIngestibility(profile string) string {
	if profile == "inventory_blind" {
		return "no; request-only until mapped back to deterministic evidence"
	}
	return "yes; only ariadne.llm_review/v1 issues bound to packet exposure IDs and graph edges"
}

func shortDigest(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}
