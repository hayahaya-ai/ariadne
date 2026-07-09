package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/report"
)

func TestResolveDefaultStoryRootFindsRepoSubdir(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("ARIADNE_STORY_ROOT", "")
	if err := os.MkdirAll(filepath.Join(root, "ariadne-prove", "testdata", "storylab"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveDefaultStoryRoot(filepath.Join("testdata", "storylab"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("ariadne-prove", "testdata", "storylab")
	if got != want {
		t.Fatalf("story root = %q, want %q", got, want)
	}
}

func TestRunAssessFormatSummary(t *testing.T) {
	root := t.TempDir()
	summaryPath := filepath.Join(root, "assess-summary.txt")
	operatorPath := filepath.Join(root, "assess-operator.txt")
	operatorJSONPath := filepath.Join(root, "assess-operator.json")
	sourcePath := filepath.Join(root, "assess-source-inspection.txt")
	sourceJSONPath := filepath.Join(root, "assess-source-inspection.json")
	runbookPath := filepath.Join(root, "assess-runbook.txt")
	runbookJSONPath := filepath.Join(root, "assess-runbook.json")
	tablePath := filepath.Join(root, "assess-table.txt")
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")

	// --format summary is where the previous (pre-readout) default behavior
	// now lives; see docs/cli-contract.md.
	runAssess([]string{
		"--path", target,
		"--format", "summary",
		"--out", summaryPath,
	})
	runAssess([]string{
		"--path", target,
		"--format", "operator",
		"--out", operatorPath,
	})
	runAssess([]string{
		"--path", target,
		"--format", "operator-json",
		"--out", operatorJSONPath,
	})
	runAssess([]string{
		"--path", target,
		"--format", "source-inspection",
		"--out", sourcePath,
	})
	runAssess([]string{
		"--path", target,
		"--format", "source-inspection-json",
		"--out", sourceJSONPath,
	})
	runAssess([]string{
		"--path", target,
		"--format", "runbook",
		"--out", runbookPath,
	})
	runAssess([]string{
		"--path", target,
		"--format", "runbook-json",
		"--out", runbookJSONPath,
	})
	runAssess([]string{
		"--path", target,
		"--format", "table",
		"--out", tablePath,
	})

	summary := readTestFile(t, summaryPath)
	for _, want := range []string{
		"Ariadne Summary",
		"Decision:",
		"Evidence files:",
		"Source references:",
		"file:",
		"line:",
		"inspect:",
		"Next action:",
		"Create closure workspace:",
		"ariadne closure --path",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("default assess summary missing %q:\n%s", want, summary)
		}
	}
	if strings.Contains(summary, "Ariadne Assess") || strings.Contains(summary, "Architecture break paths:") {
		t.Fatalf("default assess should be compact summary, not full table:\n%s", summary)
	}

	operator := readTestFile(t, operatorPath)
	for _, want := range []string{
		"Ariadne Operator Packet",
		"Start here:",
		"Signal contract:",
		"Normal capability",
		"Signal trigger",
		"Control proof profile:",
		"Open first source references:",
		"file:",
		"line:",
		"inspect:",
		"Evidence to inspect:",
		"Metadata-only context:",
		"Proof checkpoint:",
		"Commands:",
		"Compare before and after:",
	} {
		if !strings.Contains(operator, want) {
			t.Fatalf("operator assess output missing %q:\n%s", want, operator)
		}
	}
	if strings.Contains(operator, "Architecture break paths:") {
		t.Fatalf("operator assess output should stay compact:\n%s", operator)
	}

	sourceInspection := readTestFile(t, sourcePath)
	for _, want := range []string{
		"Ariadne Source Inspection",
		"Source action checklist:",
		"Evidence reference rows:",
		"file:",
		"line:",
		"inspect:",
		"control:",
		"metadata-only",
	} {
		if !strings.Contains(sourceInspection, want) {
			t.Fatalf("source inspection output missing %q:\n%s", want, sourceInspection)
		}
	}

	sourceInspectionJSON := readTestFile(t, sourceJSONPath)
	for _, want := range []string{
		`"run_kind": "source_inspection"`,
		`"source_run_kind": "assess"`,
		`"source_reference_workbench"`,
		`"source_action_board"`,
		`"inspect_commands"`,
		`"metadata_only"`,
		`"local_path"`,
	} {
		if !strings.Contains(sourceInspectionJSON, want) {
			t.Fatalf("source inspection JSON missing %q:\n%s", want, sourceInspectionJSON)
		}
	}

	operatorJSON := readTestFile(t, operatorJSONPath)
	for _, want := range []string{
		`"run_kind": "operator_packet"`,
		`"source_run_kind": "assess"`,
		`"operator_packet"`,
		`"source_reference_workbench"`,
		`"source_action_board"`,
		`"inspect_command"`,
		`"case_id": "case:egress-output-boundary"`,
		`"compare_state"`,
	} {
		if !strings.Contains(operatorJSON, want) {
			t.Fatalf("operator-json assess output missing %q:\n%s", want, operatorJSON)
		}
	}

	runbook := readTestFile(t, runbookPath)
	for _, want := range []string{
		"Ariadne Operator Runbook",
		"case:egress-output-boundary",
		"Open first:",
		"Do next:",
		"Save Baseline Proof",
		"Add Or Verify Proof",
		"Commands:",
		"ariadne closure --path",
		"Closure workflow:",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("runbook assess output missing %q:\n%s", want, runbook)
		}
	}

	runbookJSON := readTestFile(t, runbookJSONPath)
	for _, want := range []string{
		`"run_kind": "operator_runbook"`,
		`"source_run_kind": "assess"`,
		`"operator_runbook"`,
		`"source_reference_workbench"`,
		`"source_action_board"`,
		`"inspect_command"`,
		`"case:egress-output-boundary"`,
		`"current_step"`,
		`"next_step"`,
		`"open_first"`,
		`"ariadne closure --path`,
		`"closure_workflow"`,
		`"save_baseline_proof"`,
		`"add_or_verify_proof"`,
	} {
		if !strings.Contains(runbookJSON, want) {
			t.Fatalf("runbook-json assess output missing %q:\n%s", want, runbookJSON)
		}
	}

	table := readTestFile(t, tablePath)
	for _, want := range []string{
		"Ariadne Assess",
		"Signal triage:",
		"Architecture break paths:",
	} {
		if !strings.Contains(table, want) {
			t.Fatalf("explicit table assess output missing %q:\n%s", want, table)
		}
	}
	if len(strings.Split(strings.TrimSpace(summary), "\n")) >= len(strings.Split(strings.TrimSpace(table), "\n")) {
		t.Fatalf("default summary should be shorter than table output")
	}
}

func TestRunCasesActionFormat(t *testing.T) {
	root := t.TempDir()
	actionPath := filepath.Join(root, "case-action.txt")
	actionJSONPath := filepath.Join(root, "case-action.json")
	runCases([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "combined-risk"),
		"--case", "case:input-trust-boundary",
		"--format", "action",
		"--out", actionPath,
	})
	runCases([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "combined-risk"),
		"--case", "case:input-trust-boundary",
		"--format", "action-json",
		"--out", actionJSONPath,
	})
	action := readTestFile(t, actionPath)
	for _, want := range []string{
		"Ariadne Case Action",
		"Focus: case:input-trust-boundary",
		"Case: Input Trust Boundary (case:input-trust-boundary)",
		"Current proof target:",
		"Open first:",
		"CLAUDE.md",
		"Action commands:",
		"Export proof files",
		"--patch-dir proof-patches",
		"Create closure receipt",
		"closure-receipt.txt",
		"Done when:",
	} {
		if !strings.Contains(action, want) {
			t.Fatalf("cases action output missing %q:\n%s", want, action)
		}
	}
	actionJSON := readTestFile(t, actionJSONPath)
	for _, want := range []string{
		`"run_kind": "case_action"`,
		`"source_run_kind": "case_board"`,
		`"case_filter": "case:input-trust-boundary"`,
		`"case":`,
		`"id": "case:input-trust-boundary"`,
		`"action_packet"`,
		`"current_control": "control:input-isolation"`,
		`"proof_surface": ".ariadne/input-policy.json"`,
		`"open_first"`,
		`"commands"`,
	} {
		if !strings.Contains(actionJSON, want) {
			t.Fatalf("cases action JSON missing %q:\n%s", want, actionJSON)
		}
	}
}

func TestRunInventoryCoverageFormat(t *testing.T) {
	root := t.TempDir()
	coveragePath := filepath.Join(root, "inventory-coverage.txt")
	runInventory([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "messy-ai-surfaces"),
		"--format", "coverage",
		"--out", coveragePath,
	})
	coverage := readTestFile(t, coveragePath)
	for _, want := range []string{
		"Ariadne AI Surface Coverage",
		"Coverage matrix:",
		"Runtime",
		"Surfaces",
		"Parsed",
		"Summarized",
		"Boundary",
		"claude",
		"codex",
		"cursor",
		"continue",
		"copilot",
		"github-actions",
		"gitlab-ci",
		"mcp",
		"opencode",
		"roo",
		"Fact boundary:",
		"coverage is inventory only; it does not classify exposure",
		"parsed means known security-relevant artifacts were structurally inspected",
		"summarized means private or high-volume context was counted without emitting content",
	} {
		if !strings.Contains(coverage, want) {
			t.Fatalf("inventory coverage output missing %q:\n%s", want, coverage)
		}
	}
}

func TestRunDashboardDefaultsToAssessmentView(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")
	assessmentPath := filepath.Join(root, "ariadne-dashboard.html")
	exposurePath := filepath.Join(root, "exposure-dashboard.html")

	runDashboard([]string{
		"--path", target,
		"--out", assessmentPath,
	})
	runDashboard([]string{
		"--path", target,
		"--view", "exposure",
		"--out", exposurePath,
	})

	assessment := readTestFile(t, assessmentPath)
	for _, want := range []string{
		"Ariadne Assessment",
		"Operator Console",
		"The current case, source tasks, and proof loop in one place.",
		"Case Action Board",
		"Inspect Source Evidence",
		"Confirm Sensitive Boundary",
		"Add Or Verify Control Proof",
		"Control Proof Profile",
		"Control family: Egress And Output Boundary",
		"egress_destination_allowlist",
		"Rerun And Save After Proof",
		"Compare Before And After",
		"Compare artifact: closure-receipt.txt",
		"Signal Contract",
		"Normal Capability Is Noise Until Correlated",
		"Signal Trigger",
		"Control State Test",
		"Downgrade Or Close Evidence",
		"Capability alone is not exposure",
		"Open / Verify",
		"Create Workspace",
		"Operator Runbook",
		"Current Action",
		"Source Action Board",
		"add_or_verify_control",
		"Create closure workspace",
		"Open these first",
		"Current proof command",
		"Closure Workflow",
		"Files / Artifacts",
		"save_baseline_proof",
		"compare_state",
		"Operator Packet",
		"Operator Cases",
		"Action Packet",
		"Open first evidence",
		"Action commands",
		"Suggested destination",
		"Destination path",
		"Done criteria",
		"Closure Loop",
		"Artifact: before-proof.json",
		"Export proof files",
		"--patch-dir proof-patches",
	} {
		if !strings.Contains(assessment, want) {
			t.Fatalf("default dashboard missing %q:\n%s", want, assessment)
		}
	}
	if strings.Contains(assessment, "Ariadne Exposure Dashboard") {
		t.Fatalf("default dashboard should use the assessment view, not exposure view:\n%s", assessment)
	}

	exposure := readTestFile(t, exposurePath)
	for _, want := range []string{
		"Ariadne Exposure Dashboard",
		"Exposure Paths",
		"Facts Dive",
	} {
		if !strings.Contains(exposure, want) {
			t.Fatalf("exposure dashboard missing %q:\n%s", want, exposure)
		}
	}
}

func TestRunReviewPacketWritesSummaryAndPacket(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")
	summaryPath := filepath.Join(root, "review-summary.txt")
	packetPath := filepath.Join(root, "llm-request.json")
	blindPath := filepath.Join(root, "llm-request-blind.json")

	runReviewPacket([]string{
		"--path", target,
		"--profile", "follow-up",
		"--packet-out", packetPath,
		"--out", summaryPath,
	})
	runReviewPacket([]string{
		"--path", target,
		"--profile", "inventory-blind",
		"--format", "json",
		"--out", blindPath,
	})

	summary := readTestFile(t, summaryPath)
	for _, want := range []string{
		"Ariadne Review Packet",
		"Profile: follow_up",
		"Packet JSON:",
		"Ingestible as findings: yes",
		"Evidence available:",
		"Reviewer tasks:",
		"review_top_exposures",
		"Forbidden claims:",
		"ariadne prove --interpret llm --llm-review <file>",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("review packet summary missing %q:\n%s", want, summary)
		}
	}

	packet := readTestFile(t, packetPath)
	for _, want := range []string{
		`"schema_version": "ariadne.llm_review_request/v1"`,
		`"review_profile": "follow_up"`,
		`"review_contract"`,
		`"citation_catalog"`,
		`"data-egress-chain"`,
		`"source_refs"`,
	} {
		if !strings.Contains(packet, want) {
			t.Fatalf("follow-up packet missing %q:\n%s", want, packet)
		}
	}
	if strings.Contains(packet, "REALPATH_FAKE_SECRET_DO_NOT_LEAK") {
		t.Fatalf("follow-up packet leaked fake secret value")
	}

	blind := readTestFile(t, blindPath)
	for _, want := range []string{
		`"review_profile": "inventory_blind"`,
		`"exposures": []`,
		`"mode": "not_included"`,
		`"issues": []`,
		`"exposure_ids": []`,
		`"fact_ids"`,
		`"Final Ariadne findings, accepted issue priorities, or exposure classifications."`,
	} {
		if !strings.Contains(blind, want) {
			t.Fatalf("inventory-blind packet missing %q:\n%s", want, blind)
		}
	}
}

func TestRunReviewCheckWritesSummaryAndJSON(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")
	packetPath := filepath.Join(root, "llm-request.json")
	checkSummaryPath := filepath.Join(root, "review-check.txt")
	checkJSONPath := filepath.Join(root, "review-check.json")
	reviewPath := filepath.Join("..", "..", "testdata", "llm-review", "combined-risk-review.json")

	runReviewPacket([]string{
		"--path", target,
		"--profile", "follow-up",
		"--format", "json",
		"--out", packetPath,
	})
	runReviewCheck([]string{
		"--packet", packetPath,
		"--review", reviewPath,
		"--out", checkSummaryPath,
	})
	runReviewCheck([]string{
		"--packet", packetPath,
		"--review", reviewPath,
		"--format", "json",
		"--out", checkJSONPath,
	})

	summary := readTestFile(t, checkSummaryPath)
	for _, want := range []string{
		"Ariadne Review Check",
		"Accepted: true",
		"Packet:",
		"Review:",
		"LLM-reviewed data egress path",
		"data-egress-chain",
		"What Ariadne verified:",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("review-check summary missing %q:\n%s", want, summary)
		}
	}

	blob := readTestFile(t, checkJSONPath)
	for _, want := range []string{
		`"run_kind": "llm_review_check"`,
		`"accepted": true`,
		`"review_profile": "follow_up"`,
		`"request_digest"`,
		`"interpretation"`,
	} {
		if !strings.Contains(blob, want) {
			t.Fatalf("review-check JSON missing %q:\n%s", want, blob)
		}
	}
}

func TestRunReviewRunWritesArtifactsSummaryAndJSON(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")
	reviewer := writeCLIReviewer(t, root)
	artifactDir := filepath.Join(root, "ariadne-review")
	summaryPath := filepath.Join(root, "review-run.txt")
	jsonPath := filepath.Join(root, "review-run.json")

	runReviewRun([]string{
		"--path", target,
		"--command", reviewer,
		"--dir", artifactDir,
		"--out", summaryPath,
	})
	runReviewRun([]string{
		"--path", target,
		"--command", reviewer,
		"--dir", filepath.Join(root, "ariadne-review-json"),
		"--format", "json",
		"--out", jsonPath,
	})

	summary := readTestFile(t, summaryPath)
	for _, want := range []string{
		"Ariadne Review Run",
		"Accepted: true",
		"Packet JSON:",
		"Reviewer JSON:",
		"Review check summary:",
		"LLM-reviewed data egress path",
		"What Ariadne did:",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("review-run summary missing %q:\n%s", want, summary)
		}
	}
	for _, name := range []string{"llm-request.json", "llm-review.json", "review-check.json", "review-check.txt"} {
		if _, err := os.Stat(filepath.Join(artifactDir, name)); err != nil {
			t.Fatalf("review-run missing artifact %s: %v", name, err)
		}
	}
	checkSummary := readTestFile(t, filepath.Join(artifactDir, "review-check.txt"))
	if !strings.Contains(checkSummary, "Ariadne Review Check") || !strings.Contains(checkSummary, "Accepted: true") {
		t.Fatalf("review-run check summary artifact mismatch:\n%s", checkSummary)
	}

	blob := readTestFile(t, jsonPath)
	for _, want := range []string{
		`"run_kind": "llm_review_run"`,
		`"accepted": true`,
		`"review_profile": "follow_up"`,
		`"check"`,
		`"packet_path"`,
	} {
		if !strings.Contains(blob, want) {
			t.Fatalf("review-run JSON missing %q:\n%s", want, blob)
		}
	}
}

func TestRunSelfFormatSummaryIsEndpointAssessment(t *testing.T) {
	root := t.TempDir()
	target, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", "messy-ai-surfaces"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", target)
	summaryPath := filepath.Join(root, "self-summary.txt")
	htmlPath := filepath.Join(root, "self-dashboard.html")

	// --format summary is where the previous (pre-readout) default behavior
	// now lives; see docs/cli-contract.md and TestSelfDefaultIsReadout.
	runSelf([]string{
		"--format", "summary",
		"--out", summaryPath,
	})
	runSelf([]string{
		"--format", "html",
		"--out", htmlPath,
	})

	summary := readTestFile(t, summaryPath)
	for _, want := range []string{
		"Ariadne Summary",
		"Mode: endpoint",
		"Decision:",
		"Next action:",
		"Identity And Credentials",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("self summary missing %q:\n%s", want, summary)
		}
	}

	rendered := readTestFile(t, htmlPath)
	for _, want := range []string{
		"Ariadne Assessment",
		"--mode endpoint",
		"Operator Cases",
		"Export proof files",
		"Action commands",
		"Open first evidence",
		"Suggested destination",
		"Done criteria",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("self dashboard missing %q:\n%s", want, rendered)
		}
	}
}

func TestRunSelfBundleExportsFirstRunArtifacts(t *testing.T) {
	root := t.TempDir()
	target, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", "messy-ai-surfaces"))
	if err != nil {
		t.Fatal(err)
	}
	summaryPath := filepath.Join(root, "self-summary.txt")
	bundleDir := filepath.Join(root, "ariadne-self")

	runSelf([]string{
		"--path", target,
		"--bundle-dir", bundleDir,
		"--format", "summary",
		"--out", summaryPath,
	})

	for _, name := range []string{
		"assessment.txt",
		"assessment.json",
		"runbook.txt",
		"runbook.json",
		"operator-packet.txt",
		"operator-packet.json",
		"source-inspection.txt",
		"source-inspection.json",
		"dashboard.html",
		"inventory-coverage.txt",
		"inventory.json",
		"llm-follow-up-request.txt",
		"llm-follow-up-request.json",
		"llm-inventory-blind-request.txt",
		"llm-inventory-blind-request.json",
		"cases.txt",
		"cases.json",
		"case-action.txt",
		"case-action.json",
		"proof-action.txt",
		"proof-plan.json",
		"README.md",
		"manifest.json",
	} {
		if _, err := os.Stat(filepath.Join(bundleDir, name)); err != nil {
			t.Fatalf("self bundle missing %s: %v", name, err)
		}
	}

	summary := readTestFile(t, summaryPath)
	for _, want := range []string{
		"Ariadne Summary",
		"Mode: endpoint",
		"Identity And Credentials",
		"Signal quality:",
		"Lethal trifecta:",
		"Source references:",
		"inspect:",
		"file:",
		"line:",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("self summary missing %q:\n%s", want, summary)
		}
	}

	readme := readTestFile(t, filepath.Join(bundleDir, "README.md"))
	for _, want := range []string{
		"Ariadne Self-Assessment Bundle",
		"assessment.txt",
		"runbook.txt",
		"runbook.json",
		"operator-packet.txt",
		"operator-packet.json",
		"source-inspection.txt",
		"source-inspection.json",
		"case-action.txt",
		"case-action.json",
		"Bundle Integrity",
		"ariadne bundle verify --dir",
		"exact files, line labels, inspect commands",
		"inventory-coverage.txt",
		"llm-follow-up-request.txt",
		"llm-follow-up-request.json",
		"llm-inventory-blind-request.txt",
		"llm-inventory-blind-request.json",
		"dashboard.html",
		"proof-action.txt",
		"What This Bundle Answers",
		"Proof Loop Commands",
		"ariadne closure --path",
		"before-proof.json",
		"--patch-dir proof-patches",
		"ariadne compare --before before-proof.json --after after-proof.json --format receipt --out closure-receipt.txt",
		"ariadne compare --before before-proof.json --after after-proof.json --format html --out case-compare.html",
		"Limits And Privacy",
		"does not execute agents",
		"closure-receipt.txt",
		"case-compare.html",
		"optional reviewer follow-up",
		"lower-bias hypothesis",
		"manifest.json",
		"SHA-256",
		"case:identity-credentials",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("self bundle README missing %q:\n%s", want, readme)
		}
	}

	assessmentJSON := readTestFile(t, filepath.Join(bundleDir, "assessment.json"))
	for _, want := range []string{
		`"run_kind": "assess"`,
		`"mode": "endpoint"`,
		`"signal_quality"`,
		`"lethal_trifecta"`,
		`"noise_filters"`,
		`"top_case_id": "case:identity-credentials"`,
		`"first_action"`,
		`"operator_packet"`,
		`"operator_workbench"`,
		`"review_packets"`,
		`"id": "llm-follow-up"`,
		`"id": "llm-inventory-blind"`,
		`llm-follow-up-request.json`,
		`llm-inventory-blind-request.json`,
		`"ariadne review-check --packet`,
		`"ariadne prove --path`,
		`inventory-gap-check.json`,
		`"ingestibility": "no; request-only`,
		`"closure_loop"`,
		`"runbook"`,
		`"open_first"`,
		`"closure_workflow"`,
		`"save_baseline_proof"`,
		`"closure_decision"`,
		`"source_reference_workbench"`,
		`"rows"`,
		`"inspect_command"`,
		`"metadata_only"`,
		`"content_inspectable"`,
	} {
		if !strings.Contains(assessmentJSON, want) {
			t.Fatalf("self bundle assessment JSON missing %q:\n%s", want, assessmentJSON)
		}
	}

	runbook := readTestFile(t, filepath.Join(bundleDir, "runbook.txt"))
	for _, want := range []string{
		"Ariadne Operator Runbook",
		"case:identity-credentials",
		"Open first:",
		"file:",
		"inspect:",
		"Do next:",
		"Save Baseline Proof",
		"Add Or Verify Proof",
		"Commands:",
		"Closure workflow:",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("self bundle runbook missing %q:\n%s", want, runbook)
		}
	}

	runbookJSON := readTestFile(t, filepath.Join(bundleDir, "runbook.json"))
	for _, want := range []string{
		`"run_kind": "operator_runbook"`,
		`"operator_runbook"`,
		`"source_reference_workbench"`,
		`"source_action_board"`,
		`"inspect_command"`,
		`"available": true`,
		`"case:identity-credentials"`,
		`"current_step"`,
		`"next_step"`,
		`"open_first"`,
		`"closure_workflow"`,
		`"save_baseline_proof"`,
		`"add_or_verify_proof"`,
	} {
		if !strings.Contains(runbookJSON, want) {
			t.Fatalf("self bundle runbook JSON missing %q:\n%s", want, runbookJSON)
		}
	}

	sourceInspection := readTestFile(t, filepath.Join(bundleDir, "source-inspection.txt"))
	for _, want := range []string{
		"Ariadne Source Inspection",
		"Source action checklist:",
		"Evidence reference rows:",
		"file:",
		"inspect:",
		"metadata-only",
		"control:",
	} {
		if !strings.Contains(sourceInspection, want) {
			t.Fatalf("self bundle source inspection missing %q:\n%s", want, sourceInspection)
		}
	}

	sourceInspectionJSON := readTestFile(t, filepath.Join(bundleDir, "source-inspection.json"))
	for _, want := range []string{
		`"run_kind": "source_inspection"`,
		`"source_run_kind": "assess"`,
		`"source_reference_workbench"`,
		`"source_action_board"`,
		`"inspect_commands"`,
		`"metadata_only"`,
		`"control:`,
	} {
		if !strings.Contains(sourceInspectionJSON, want) {
			t.Fatalf("self bundle source inspection JSON missing %q:\n%s", want, sourceInspectionJSON)
		}
	}

	operatorPacket := readTestFile(t, filepath.Join(bundleDir, "operator-packet.txt"))
	for _, want := range []string{
		"Ariadne Operator Packet",
		"Start here:",
		"case:identity-credentials",
		"Open first source references:",
		"file:",
		"line:",
		"inspect:",
		"Evidence to inspect:",
		"Metadata-only context:",
		"Controls:",
		"Proof checkpoint:",
		"Commands:",
		"Compare before and after:",
		"Done when:",
	} {
		if !strings.Contains(operatorPacket, want) {
			t.Fatalf("self bundle operator packet missing %q:\n%s", want, operatorPacket)
		}
	}
	if strings.Contains(operatorPacket, "Architecture break paths:") || strings.Contains(operatorPacket, "additional items in JSON") || strings.Contains(operatorPacket, "more evidence source(s) in JSON") {
		t.Fatalf("self bundle operator packet should stay compact:\n%s", operatorPacket)
	}

	operatorPacketJSON := readTestFile(t, filepath.Join(bundleDir, "operator-packet.json"))
	for _, want := range []string{
		`"run_kind": "operator_packet"`,
		`"source_run_kind": "assess"`,
		`"mode": "endpoint"`,
		`"operator_packet"`,
		`"source_reference_workbench"`,
		`"source_action_board"`,
		`"inspect_command"`,
		`"case_id": "case:identity-credentials"`,
		`"current_control": "control:credential-isolation"`,
		`"commands"`,
		`"compare_state"`,
	} {
		if !strings.Contains(operatorPacketJSON, want) {
			t.Fatalf("self bundle operator packet JSON missing %q:\n%s", want, operatorPacketJSON)
		}
	}

	caseAction := readTestFile(t, filepath.Join(bundleDir, "case-action.txt"))
	for _, want := range []string{
		"Ariadne Case Action",
		"case:identity-credentials",
		"Current proof target:",
		"Open first:",
		"Action commands:",
		"Done when:",
	} {
		if !strings.Contains(caseAction, want) {
			t.Fatalf("self bundle case action missing %q:\n%s", want, caseAction)
		}
	}

	caseActionJSON := readTestFile(t, filepath.Join(bundleDir, "case-action.json"))
	for _, want := range []string{
		`"run_kind": "case_action"`,
		`"source_run_kind": "case_board"`,
		`"case_filter": "case:identity-credentials"`,
		`"case"`,
		`"id": "case:identity-credentials"`,
		`"action_packet"`,
		`"current_control": "control:credential-isolation"`,
		`"open_first"`,
		`"commands"`,
	} {
		if !strings.Contains(caseActionJSON, want) {
			t.Fatalf("self bundle case action JSON missing %q:\n%s", want, caseActionJSON)
		}
	}

	inventoryJSON := readTestFile(t, filepath.Join(bundleDir, "inventory.json"))
	for _, want := range []string{
		`"run_kind": "inventory"`,
		`"mode": "endpoint"`,
		`".claude/settings.local.json"`,
		`".codex/config.toml"`,
	} {
		if !strings.Contains(inventoryJSON, want) {
			t.Fatalf("self bundle inventory JSON missing %q:\n%s", want, inventoryJSON)
		}
	}

	inventoryCoverage := readTestFile(t, filepath.Join(bundleDir, "inventory-coverage.txt"))
	for _, want := range []string{
		"Ariadne AI Surface Coverage",
		"Coverage matrix:",
		"Runtime",
		"claude",
		"codex",
		"copilot",
		"gemini",
		"roo",
		"Fact boundary:",
		"coverage is inventory only; it does not classify exposure",
	} {
		if !strings.Contains(inventoryCoverage, want) {
			t.Fatalf("self bundle inventory coverage missing %q:\n%s", want, inventoryCoverage)
		}
	}

	llmFollowUpSummary := readTestFile(t, filepath.Join(bundleDir, "llm-follow-up-request.txt"))
	for _, want := range []string{
		"Ariadne Review Packet",
		"Profile: follow_up",
		"Packet JSON:",
		"llm-follow-up-request.json",
		"Ingestible as findings: yes",
		"Evidence available:",
		"Reviewer tasks:",
		"review_top_exposures",
		"Forbidden claims:",
		"ariadne prove --interpret llm --llm-review <file>",
	} {
		if !strings.Contains(llmFollowUpSummary, want) {
			t.Fatalf("self bundle follow-up LLM summary missing %q:\n%s", want, llmFollowUpSummary)
		}
	}

	llmFollowUpJSON := readTestFile(t, filepath.Join(bundleDir, "llm-follow-up-request.json"))
	for _, want := range []string{
		`"schema_version": "ariadne.llm_review_request/v1"`,
		`"review_profile": "follow_up"`,
		`"review_contract"`,
		`"reviewer_tasks"`,
		`"citation_catalog"`,
		`"required_citations"`,
		`"exposure_ids"`,
		`"source_refs"`,
		`"graph_edges"`,
		`"canary_values_included": false`,
	} {
		if !strings.Contains(llmFollowUpJSON, want) {
			t.Fatalf("self bundle follow-up LLM JSON missing %q:\n%s", want, llmFollowUpJSON)
		}
	}
	if strings.Contains(llmFollowUpJSON, "DO_NOT_LEAK") || strings.Contains(llmFollowUpJSON, "FAKE_SECRET") {
		t.Fatalf("self bundle follow-up LLM JSON leaked fake sensitive value:\n%s", llmFollowUpJSON)
	}

	llmBlindSummary := readTestFile(t, filepath.Join(bundleDir, "llm-inventory-blind-request.txt"))
	for _, want := range []string{
		"Ariadne Review Packet",
		"Profile: inventory_blind",
		"Packet JSON:",
		"llm-inventory-blind-request.json",
		"Ingestible as findings: no; request-only",
		"Map any hypothesis back",
		"Rerun deterministic Ariadne commands",
	} {
		if !strings.Contains(llmBlindSummary, want) {
			t.Fatalf("self bundle inventory-blind LLM summary missing %q:\n%s", want, llmBlindSummary)
		}
	}

	llmBlindJSON := readTestFile(t, filepath.Join(bundleDir, "llm-inventory-blind-request.json"))
	for _, want := range []string{
		`"schema_version": "ariadne.llm_review_request/v1"`,
		`"review_profile": "inventory_blind"`,
		`"exposures": []`,
		`"mode": "not_included"`,
		`"issues": []`,
		`"exposure_ids": []`,
		`"fact_ids"`,
		`"Final Ariadne findings, accepted issue priorities, or exposure classifications."`,
		`"canary_values_included": false`,
	} {
		if !strings.Contains(llmBlindJSON, want) {
			t.Fatalf("self bundle inventory-blind LLM JSON missing %q:\n%s", want, llmBlindJSON)
		}
	}
	if strings.Contains(llmBlindJSON, "DO_NOT_LEAK") || strings.Contains(llmBlindJSON, "FAKE_SECRET") {
		t.Fatalf("self bundle inventory-blind LLM JSON leaked fake sensitive value:\n%s", llmBlindJSON)
	}

	dashboard := readTestFile(t, filepath.Join(bundleDir, "dashboard.html"))
	for _, want := range []string{
		"Ariadne Assessment",
		"Operator Console",
		"The current case, source tasks, and proof loop in one place.",
		"Optional Reviewer Handoff",
		"Deterministic facts stay primary",
		"Review Ariadne Exposure IDs",
		"llm-follow-up-request.json",
		"Validate reviewer output",
		"ariadne review-check --packet",
		"Ingest validated review",
		"Blind Inventory Gap Review",
		"llm-inventory-blind-request.json",
		"request-only",
		"inventory-gap-check.json",
		"Case Action Board",
		"Inspect Source Evidence",
		"Confirm Sensitive Boundary",
		"Add Or Verify Control Proof",
		"Control Proof Profile",
		"Control family: Identity And Credentials",
		"credential_isolation",
		"Rerun And Save After Proof",
		"Compare Before And After",
		"Compare artifact: closure-receipt.txt",
		"Signal Contract",
		"Normal Capability Is Noise Until Correlated",
		"Signal Trigger",
		"Control State Test",
		"Downgrade Or Close Evidence",
		"Capability alone is not exposure",
		"Open / Verify",
		"Create Workspace",
		"Source Reference Workbench",
		"Source Action Board",
		"add_or_verify_control",
		"Operator Runbook",
		"Current Action",
		"Create closure workspace",
		"Open these first",
		"Current proof command",
		"Files and artifacts",
		"Open First",
		"Do Next",
		"Closure Workflow",
		"Files / Artifacts",
		"save_baseline_proof",
		"compare_state",
		"Artifact: before-proof.json",
		"Exact files and lines to open first",
		"Inspect command",
		"sed -n",
		"ls -ld",
		".claude/settings.local.json",
		"Signal Quality",
		"Lethal Trifecta",
		"Closure Loop",
		"Save Baseline Proof",
		"Closure Decision",
		"Operator Cases",
		"Export proof files",
	} {
		if !strings.Contains(dashboard, want) {
			t.Fatalf("self bundle dashboard missing %q:\n%s", want, dashboard)
		}
	}

	proofAction := readTestFile(t, filepath.Join(bundleDir, "proof-action.txt"))
	for _, want := range []string{
		"Ariadne Proof Action",
		"case:identity-credentials",
		"Control proof profile:",
		"Family: Identity And Credentials (identity-credentials)",
		"Recognized indicators: credential_isolation; per_agent_credentials",
		"Proof to add or verify:",
		"Export suggested files:",
	} {
		if !strings.Contains(proofAction, want) {
			t.Fatalf("self bundle proof action missing %q:\n%s", want, proofAction)
		}
	}

	proofPlan := readTestFile(t, filepath.Join(bundleDir, "proof-plan.json"))
	for _, want := range []string{
		`"run_kind": "proof_plan"`,
		`"case_filter": "case:identity-credentials"`,
		`"proof_patches"`,
	} {
		if !strings.Contains(proofPlan, want) {
			t.Fatalf("self bundle proof plan missing %q:\n%s", want, proofPlan)
		}
	}

	manifest := readTestFile(t, filepath.Join(bundleDir, "manifest.json"))
	for _, want := range []string{
		`"top_case_id": "case:identity-credentials"`,
		`"integrity_command": "ariadne bundle verify --dir`,
		`"review_order"`,
		`ariadne bundle verify --dir BUNDLE_DIR`,
		`before attaching`,
		`"proof_loop"`,
		`--patch-dir proof-patches`,
		`"ariadne compare --before before-proof.json --after after-proof.json --format receipt --out closure-receipt.txt"`,
		`"ariadne compare --before before-proof.json --after after-proof.json --format html --out case-compare.html"`,
		`"limitations"`,
		`"name": "README.md"`,
		`"name": "manifest.json"`,
		`"name": "runbook.txt"`,
		`"name": "runbook.json"`,
		`"name": "operator-packet.txt"`,
		`"name": "operator-packet.json"`,
		`"name": "source-inspection.txt"`,
		`"name": "source-inspection.json"`,
		`"name": "inventory-coverage.txt"`,
		`"name": "llm-follow-up-request.txt"`,
		`"name": "llm-follow-up-request.json"`,
		`"name": "llm-inventory-blind-request.txt"`,
		`"name": "llm-inventory-blind-request.json"`,
		`"name": "case-action.txt"`,
		`"name": "case-action.json"`,
		`"name": "proof-action.txt"`,
		`"size_bytes"`,
		`"sha256"`,
		`intentionally not self-hashed`,
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("self bundle manifest missing %q:\n%s", want, manifest)
		}
	}
	operatorPacketJSONBytes, err := os.ReadFile(filepath.Join(bundleDir, "operator-packet.json"))
	if err != nil {
		t.Fatal(err)
	}
	operatorPacketJSONSum := sha256.Sum256(operatorPacketJSONBytes)
	operatorPacketJSONHash := fmt.Sprintf("%x", operatorPacketJSONSum[:])
	if !strings.Contains(manifest, operatorPacketJSONHash) {
		t.Fatalf("self bundle manifest missing operator-packet.json hash %q:\n%s", operatorPacketJSONHash, manifest)
	}
	llmFollowUpJSONBytes, err := os.ReadFile(filepath.Join(bundleDir, "llm-follow-up-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	llmFollowUpJSONSum := sha256.Sum256(llmFollowUpJSONBytes)
	llmFollowUpJSONHash := fmt.Sprintf("%x", llmFollowUpJSONSum[:])
	if !strings.Contains(manifest, llmFollowUpJSONHash) {
		t.Fatalf("self bundle manifest missing llm-follow-up-request.json hash %q:\n%s", llmFollowUpJSONHash, manifest)
	}

	verifySummaryPath := filepath.Join(root, "bundle-verify.txt")
	verifyJSONPath := filepath.Join(root, "bundle-verify.json")
	runBundle([]string{"verify", "--dir", bundleDir, "--out", verifySummaryPath})
	runBundle([]string{"verify", "--dir", bundleDir, "--format", "json", "--out", verifyJSONPath})
	verifySummary := readTestFile(t, verifySummaryPath)
	for _, want := range []string{
		"Ariadne Bundle Verify",
		"Status: ok",
		"Files checked:",
		"Failed: 0",
		"SKIPPED manifest.json: no sha256 recorded in manifest",
		"Limitations:",
	} {
		if !strings.Contains(verifySummary, want) {
			t.Fatalf("bundle verify summary missing %q:\n%s", want, verifySummary)
		}
	}
	verifyJSON := readTestFile(t, verifyJSONPath)
	for _, want := range []string{
		`"run_kind": "bundle_verify"`,
		`"status": "ok"`,
		`"failed": 0`,
		`"name": "assessment.txt"`,
		`"status": "ok"`,
		`"name": "manifest.json"`,
		`"status": "skipped"`,
	} {
		if !strings.Contains(verifyJSON, want) {
			t.Fatalf("bundle verify JSON missing %q:\n%s", want, verifyJSON)
		}
	}

	if err := os.WriteFile(filepath.Join(bundleDir, "assessment.txt"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tampered, err := buildBundleVerifyReport(filepath.Join(bundleDir, "manifest.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	if tampered.Status != "failed" || tampered.Failed == 0 {
		t.Fatalf("tampered bundle status = %s failed=%d, want failed with at least one failed file", tampered.Status, tampered.Failed)
	}
	foundTamperedAssessment := false
	for _, result := range tampered.Results {
		if result.Name == "assessment.txt" {
			foundTamperedAssessment = true
			if result.Status != "failed" || !strings.Contains(result.Reason, "sha256 mismatch") {
				t.Fatalf("tampered assessment result = %+v, want sha256 mismatch", result)
			}
		}
	}
	if !foundTamperedAssessment {
		t.Fatalf("tampered bundle verify did not include assessment.txt result: %+v", tampered.Results)
	}
}

func TestRunProofsPatchDirExportsSuggestedFiles(t *testing.T) {
	root := t.TempDir()
	outPath := filepath.Join(root, "proof-plan.json")
	actionPath := filepath.Join(root, "proof-action.txt")
	patchDir := filepath.Join(root, "proof-patches")
	runProofs([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "combined-risk"),
		"--case", "case:input-trust-boundary",
		"--format", "json",
		"--out", outPath,
		"--patch-dir", patchDir,
	})
	runProofs([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "combined-risk"),
		"--case", "case:input-trust-boundary",
		"--format", "action",
		"--out", actionPath,
	})
	for _, path := range []string{
		outPath,
		actionPath,
		filepath.Join(patchDir, "README.md"),
		filepath.Join(patchDir, "manifest.json"),
		filepath.Join(patchDir, "surfaces", ".ariadne", "input-policy.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("runProofs missing %s: %v", path, err)
		}
	}
	blob, err := os.ReadFile(filepath.Join(patchDir, "surfaces", ".ariadne", "input-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"input_isolation": true`) {
		t.Fatalf("exported patch file missing input isolation evidence:\n%s", blob)
	}
	action := readTestFile(t, actionPath)
	for _, want := range []string{
		"Ariadne Proof Action",
		"Proof to add or verify:",
		"Control: control:input-isolation",
		"Proof surface: .ariadne/input-policy.json",
		"Control proof profile:",
		"Family: Input Trust Boundary (input-trust-boundary)",
		"Recognized indicators: input_isolation; instruction_isolation",
		"Compare loop:",
	} {
		if !strings.Contains(action, want) {
			t.Fatalf("proof action output missing %q:\n%s", want, action)
		}
	}
}

func TestRunClosureExportsProofLoopWorkspace(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, "ariadne-closure")
	runClosure([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "combined-risk"),
		"--case", "case:egress-output-boundary",
		"--dir", workspaceDir,
	})
	for _, path := range []string{
		filepath.Join(workspaceDir, "runbook.txt"),
		filepath.Join(workspaceDir, "runbook.json"),
		filepath.Join(workspaceDir, "source-inspection.txt"),
		filepath.Join(workspaceDir, "source-inspection.json"),
		filepath.Join(workspaceDir, "before-proof.json"),
		filepath.Join(workspaceDir, "proof-action.txt"),
		filepath.Join(workspaceDir, "proof-plan.html"),
		filepath.Join(workspaceDir, "proof-patches", "README.md"),
		filepath.Join(workspaceDir, "proof-patches", "manifest.json"),
		filepath.Join(workspaceDir, "proof-patches", "surfaces", ".ariadne", "egress-policy.json"),
		filepath.Join(workspaceDir, "proof-patches", "surfaces", ".ariadne", "output-policy.json"),
		filepath.Join(workspaceDir, "README.md"),
		filepath.Join(workspaceDir, "manifest.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("runClosure missing %s: %v", path, err)
		}
	}

	readme := readTestFile(t, filepath.Join(workspaceDir, "README.md"))
	for _, want := range []string{
		"Ariadne Closure Workspace",
		"before/change/after/compare loop",
		"case:egress-output-boundary",
		"Workspace Integrity",
		"ariadne bundle verify --dir",
		"Run the workspace integrity command",
		"source-inspection.txt",
		"exact source files, line labels, inspect commands",
		"Save after proof",
		"Create closure receipt",
		"Create HTML compare",
		"after-proof.json",
		"closure-receipt.txt",
		"case-compare.html",
		"proof-patches/manifest.json",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("closure README missing %q:\n%s", want, readme)
		}
	}

	manifest := readTestFile(t, filepath.Join(workspaceDir, "manifest.json"))
	for _, want := range []string{
		`"run_kind": "closure_workspace"`,
		`"case_id": "case:egress-output-boundary"`,
		`"integrity_command": "ariadne bundle verify --dir`,
		`"name": "source-inspection.txt"`,
		`"name": "source-inspection.json"`,
		`"proof_loop"`,
		`"save_after_proof"`,
		`"closure_receipt"`,
		`"compare_state"`,
		`"proof-patches/surfaces/.ariadne/egress-policy.json"`,
		`"proof-patches/surfaces/.ariadne/output-policy.json"`,
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("closure manifest missing %q:\n%s", want, manifest)
		}
	}

	runbook := readTestFile(t, filepath.Join(workspaceDir, "runbook.txt"))
	for _, want := range []string{
		"Ariadne Operator Runbook",
		"case:egress-output-boundary",
		"Open first:",
		"Closure workflow:",
	} {
		if !strings.Contains(runbook, want) {
			t.Fatalf("closure runbook missing %q:\n%s", want, runbook)
		}
	}

	sourceInspection := readTestFile(t, filepath.Join(workspaceDir, "source-inspection.txt"))
	for _, want := range []string{
		"Ariadne Source Inspection",
		"case:egress-output-boundary",
		"Source action checklist:",
		"Evidence reference rows:",
		"file:",
		"inspect:",
		"control:",
	} {
		if !strings.Contains(sourceInspection, want) {
			t.Fatalf("closure source inspection missing %q:\n%s", want, sourceInspection)
		}
	}

	sourceInspectionJSON := readTestFile(t, filepath.Join(workspaceDir, "source-inspection.json"))
	for _, want := range []string{
		`"run_kind": "source_inspection"`,
		`"case_filter": "case:egress-output-boundary"`,
		`"source_action_board"`,
		`"inspect_commands"`,
		`"source_reference_workbench"`,
	} {
		if !strings.Contains(sourceInspectionJSON, want) {
			t.Fatalf("closure source inspection JSON missing %q:\n%s", want, sourceInspectionJSON)
		}
	}

	beforeProof := readTestFile(t, filepath.Join(workspaceDir, "before-proof.json"))
	for _, want := range []string{
		`"run_kind": "proof_plan"`,
		`"case_filter": "case:egress-output-boundary"`,
		`"compare_commands"`,
	} {
		if !strings.Contains(beforeProof, want) {
			t.Fatalf("closure before proof missing %q:\n%s", want, beforeProof)
		}
	}
}

func TestRenderProofPatchExportSummaryShowsApplyStep(t *testing.T) {
	var out bytes.Buffer
	renderProofPatchExportSummary(&out, report.ProofPatchExportResult{
		Directory:       "/tmp/proof-patches",
		ManifestPath:    "/tmp/proof-patches/manifest.json",
		ReadmePath:      "/tmp/proof-patches/README.md",
		PatchCount:      2,
		ClosureControls: []string{"control:input-isolation", "control:trusted-source-policy"},
		ClosureFiles:    []string{filepath.Join("surfaces", ".ariadne", "input-policy.json")},
		ClosureRule:     "Rerun must show every bundle control is no longer a missing hard barrier for this case.",
		FileDetails: []report.ProofPatchExportFileResult{
			{
				Path:            filepath.Join("surfaces", ".ariadne", "input-policy.json"),
				GeneratedPath:   "/tmp/proof-patches/surfaces/.ariadne/input-policy.json",
				Surface:         ".ariadne/input-policy.json",
				DestinationPath: "/repo/.ariadne/input-policy.json",
				ApplyCommand:    "cd /tmp/proof-patches && mkdir -p /repo/.ariadne && cp surfaces/.ariadne/input-policy.json /repo/.ariadne/input-policy.json",
				Format:          "json_merge_object",
				Controls:        []string{"control:input-isolation", "control:trusted-source-policy"},
				PatchCount:      2,
			},
		},
	})
	rendered := out.String()
	for _, want := range []string{
		"Exported 2 proof patch(es) to /tmp/proof-patches",
		"Manifest: /tmp/proof-patches/manifest.json",
		"README: /tmp/proof-patches/README.md",
		"Closure bundle:",
		"Controls: control:input-isolation, control:trusted-source-policy",
		"Generated files: surfaces/.ariadne/input-policy.json",
		"Rule: Rerun must show every bundle control is no longer a missing hard barrier for this case.",
		"Generated proof files:",
		"/tmp/proof-patches/surfaces/.ariadne/input-policy.json -> /repo/.ariadne/input-policy.json",
		"Surface: .ariadne/input-policy.json (json_merge_object)",
		"Controls: control:input-isolation, control:trusted-source-policy",
		"Review/apply: cd /tmp/proof-patches",
		"Review generated proof evidence before applying it",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("proof export summary missing %q:\n%s", want, rendered)
		}
	}
}

func TestRunCompareShowsOpenToClosedProofLoop(t *testing.T) {
	root := t.TempDir()
	beforePath := filepath.Join(root, "before-proof.json")
	afterPath := filepath.Join(root, "after-proof.json")
	tablePath := filepath.Join(root, "case-compare.txt")
	receiptPath := filepath.Join(root, "closure-receipt.txt")
	jsonPath := filepath.Join(root, "case-compare.json")
	htmlPath := filepath.Join(root, "case-compare.html")
	runProofs([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "combined-risk"),
		"--case", "case:least-agency-authority",
		"--format", "json",
		"--out", beforePath,
	})
	runProofs([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "safe-controls"),
		"--case", "case:least-agency-authority",
		"--format", "json",
		"--out", afterPath,
	})
	runCompare([]string{
		"--before", beforePath,
		"--after", afterPath,
		"--out", tablePath,
	})
	runCompare([]string{
		"--before", beforePath,
		"--after", afterPath,
		"--format", "receipt",
		"--out", receiptPath,
	})
	runCompare([]string{
		"--before", beforePath,
		"--after", afterPath,
		"--format", "json",
		"--out", jsonPath,
	})
	runCompare([]string{
		"--before", beforePath,
		"--after", afterPath,
		"--format", "html",
		"--out", htmlPath,
	})
	table := readTestFile(t, tablePath)
	for _, want := range []string{
		"Ariadne case compare:",
		"1 case(s) compared: 0 open after rerun, 1 closed after rerun",
		"Next action: No open case remains",
		"CLOSED Least Agency And Authority Scope",
		"Closure receipts:",
		"Least Agency And Authority Scope (case:least-agency-authority): open -> closed / proof closed",
		"open -> closed",
		"Missing controls before: control:deny-by-default; control:deny-secret-read; control:scoped-permissions",
		"Observed controls after: control:deny-by-default-permissions; control:scoped-permissions",
		"Proof verdict: proof closed",
		"control evidence: control:deny-by-default-permissions",
		"Remaining action: No remaining action for this case",
		"Proof patches: 3 -> 0",
		"Added evidence:",
		".ariadne/agent-policy.json",
		"After compare loop:",
		"closure-receipt.txt",
	} {
		if !strings.Contains(table, want) {
			t.Fatalf("compare table missing %q:\n%s", want, table)
		}
	}
	receipt := readTestFile(t, receiptPath)
	for _, want := range []string{
		"Ariadne closure receipts",
		"Verdict: proof succeeded",
		"Outcome: 1 case(s) compared: 0 open after rerun, 1 closed after rerun",
		"Closure receipts:",
		"Least Agency And Authority Scope (case:least-agency-authority): open -> closed / proof closed",
		"control evidence: control:deny-by-default-permissions",
		"evidence source: .ariadne/agent-policy.json",
		"evidence ref: target: .ariadne/agent-policy.json",
		"artifact hash: before",
		"artifact hash: after",
		"sha256:",
		"verification command:",
		"--format receipt --out closure-receipt.txt",
		"remaining action: No remaining action for this case",
		"Limits:",
	} {
		if !strings.Contains(receipt, want) {
			t.Fatalf("compare receipt missing %q:\n%s", want, receipt)
		}
	}
	blob := readTestFile(t, jsonPath)
	for _, want := range []string{
		`"disposition": "closed"`,
		`"before_state": "open"`,
		`"after_state": "closed"`,
		`"closure_receipts"`,
		`"receipt_id": "closure-receipt:case:least-agency-authority"`,
		`"proof_status": "proof_closed"`,
		`"evidence_refs"`,
		`"line_start"`,
		`"artifact_hashes"`,
		`"sha256"`,
		`"size_bytes"`,
		`"verification_commands"`,
		`"proof_verdict"`,
		`"status": "proof_closed"`,
		`"remaining_action": "No remaining action for this case`,
		`"control:deny-by-default-permissions"`,
		`".ariadne/agent-policy.json"`,
		`"added_evidence_refs"`,
	} {
		if !strings.Contains(blob, want) {
			t.Fatalf("compare JSON missing %q:\n%s", want, blob)
		}
	}
	html := readTestFile(t, htmlPath)
	for _, want := range []string{
		"Ariadne Case Compare",
		"CLOSED",
		"Least Agency And Authority Scope",
		"Closure Receipts",
		"Ticket-ready proof summaries",
		"Proof verdict",
		"Status: proof closed",
		"Remaining action: No remaining action for this case",
		"open",
		"closed",
		".ariadne/agent-policy.json",
		"closure-receipt.txt",
		"Evidence refs",
		"Artifact hashes",
		"Verification commands",
		"sha256:",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("compare HTML missing %q:\n%s", want, html)
		}
	}
	if strings.Contains(html, "STAYED OPEN Least Agency And Authority Scope") {
		t.Fatalf("compare HTML should show input trust as closed, not stayed open:\n%s", html)
	}
}

func TestRunVerdictJSONOnCombinedRisk(t *testing.T) {
	root := t.TempDir()
	outPath := filepath.Join(root, "verdict.json")
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")

	runVerdict([]string{
		"--path", target,
		"--mode", "repo",
		"--json",
		"--out", outPath,
	})

	blob := readTestFile(t, outPath)
	if !strings.Contains(blob, `"verdict": "reckless"`) {
		t.Fatalf("verdict json missing reckless verdict word:\n%s", blob)
	}
	var decoded struct {
		Reckless []json.RawMessage `json:"reckless"`
	}
	if err := json.Unmarshal([]byte(blob), &decoded); err != nil {
		t.Fatalf("verdict json did not decode: %v\n%s", err, blob)
	}
	if len(decoded.Reckless) == 0 {
		t.Fatalf("expected non-empty reckless array:\n%s", blob)
	}
	if strings.Contains(blob, ".ariadne") {
		t.Fatalf("verdict json must never mention .ariadne:\n%s", blob)
	}
}

func TestCLIExitCode0SuccessfulVerdictNoGate(t *testing.T) {
	recklessTarget, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", "combined-risk"))
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	got := runCLI([]string{"verdict", "--path", recklessTarget, "--mode", "repo"}, &stdout, &stderr)
	if got != exitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", got, exitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VERDICT: RECKLESS") {
		t.Fatalf("successful verdict output missing reckless word:\n%s", stdout.String())
	}
}

func TestCLIExitCode1RuntimeError(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	missingPath := filepath.Join(t.TempDir(), "missing-endpoint")
	got := runCLI([]string{"verdict", "--path", missingPath, "--mode", "endpoint"}, &stdout, &stderr)
	if got != exitRuntimeError {
		t.Fatalf("exit code = %d, want %d; stdout:\n%s\nstderr:\n%s", got, exitRuntimeError, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "ariadne:") {
		t.Fatalf("runtime error should print ariadne-prefixed stderr, got:\n%s", stderr.String())
	}
}

func TestCLIExitCode2UsageError(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	got := runCLI([]string{"verdict", "--definitely-not-a-flag"}, &stdout, &stderr)
	if got != exitUsageError {
		t.Fatalf("exit code = %d, want %d; stdout:\n%s\nstderr:\n%s", got, exitUsageError, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("usage error should explain the unknown flag, got:\n%s", stderr.String())
	}
}

func TestCLIExitCode3RecklessGate(t *testing.T) {
	recklessTarget, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", "combined-risk"))
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	got := runCLI([]string{"verdict", "--path", recklessTarget, "--mode", "repo", "--gate"}, &stdout, &stderr)
	if got != exitReckless {
		t.Fatalf("exit code = %d, want %d; stdout:\n%s\nstderr:\n%s", got, exitReckless, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "VERDICT: RECKLESS") {
		t.Fatalf("gate verdict output missing reckless word:\n%s", stdout.String())
	}
}

func TestRunLsFindings(t *testing.T) {
	root := t.TempDir()
	outPath := filepath.Join(root, "ls-findings.txt")
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")

	runLs([]string{
		"findings",
		"--path", target,
		"--mode", "repo",
		"--out", outPath,
	})

	out := readTestFile(t, outPath)
	if !strings.Contains(out, "reckless:1") {
		t.Fatalf("ls findings missing reckless:1:\n%s", out)
	}
}

func TestRunShowReckless(t *testing.T) {
	root := t.TempDir()
	outPath := filepath.Join(root, "show-reckless.txt")
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")

	runShow([]string{
		"reckless:1",
		"--path", target,
		"--mode", "repo",
		"--out", outPath,
	})

	out := readTestFile(t, outPath)
	if !strings.Contains(out, "CLAUDE.md") && !strings.Contains(out, "mcp.json") {
		t.Fatalf("show reckless:1 missing a file source:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "fix") {
		t.Fatalf("show reckless:1 missing fix content:\n%s", out)
	}
}

func TestSelfDefaultIsReadout(t *testing.T) {
	root := t.TempDir()
	selfOutPath := filepath.Join(root, "self-readout.txt")
	assessOutPath := filepath.Join(root, "assess-readout.txt")
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")

	runSelf([]string{
		"--path", target,
		"--mode", "repo",
		"--out", selfOutPath,
	})
	runAssess([]string{
		"--path", target,
		"--out", assessOutPath,
	})

	selfOut := readTestFile(t, selfOutPath)
	if !strings.Contains(selfOut, "VERDICT:") {
		t.Fatalf("self default output missing VERDICT: (expected readout):\n%s", selfOut)
	}
	assessOut := readTestFile(t, assessOutPath)
	if !strings.Contains(assessOut, "VERDICT:") {
		t.Fatalf("assess default output missing VERDICT: (expected readout):\n%s", assessOut)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}

func writeCLIReviewer(t *testing.T, dir string) string {
	t.Helper()
	reviewPath, err := filepath.Abs(filepath.Join("..", "..", "testdata", "llm-review", "combined-risk-review.json"))
	if err != nil {
		t.Fatal(err)
	}
	reviewer := filepath.Join(dir, "fixture-reviewer.sh")
	script := "#!/bin/sh\ncat >/dev/null\ncat \"" + reviewPath + "\"\n"
	if err := os.WriteFile(reviewer, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return reviewer
}
