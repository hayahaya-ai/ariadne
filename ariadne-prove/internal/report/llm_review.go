package report

import (
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
