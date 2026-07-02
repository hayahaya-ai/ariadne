package main

import (
	"bytes"
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

func TestRunAssessDefaultsToSummary(t *testing.T) {
	root := t.TempDir()
	summaryPath := filepath.Join(root, "assess-summary.txt")
	operatorPath := filepath.Join(root, "assess-operator.txt")
	tablePath := filepath.Join(root, "assess-table.txt")
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")

	runAssess([]string{
		"--path", target,
		"--out", summaryPath,
	})
	runAssess([]string{
		"--path", target,
		"--format", "operator",
		"--out", operatorPath,
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
		"Next action:",
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
		"Evidence to open:",
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
		"Operator Packet",
		"Operator Cases",
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

func TestRunSelfDefaultsToEndpointAssessment(t *testing.T) {
	root := t.TempDir()
	target, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", "messy-ai-surfaces"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", target)
	summaryPath := filepath.Join(root, "self-summary.txt")
	htmlPath := filepath.Join(root, "self-dashboard.html")

	runSelf([]string{
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
		"--out", summaryPath,
	})

	for _, name := range []string{
		"assessment.txt",
		"assessment.json",
		"dashboard.html",
		"inventory.json",
		"cases.txt",
		"cases.json",
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
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("self summary missing %q:\n%s", want, summary)
		}
	}

	readme := readTestFile(t, filepath.Join(bundleDir, "README.md"))
	for _, want := range []string{
		"Ariadne Self-Assessment Bundle",
		"assessment.txt",
		"dashboard.html",
		"proof-action.txt",
		"What This Bundle Answers",
		"Proof Loop Commands",
		"before-proof.json",
		"--patch-dir proof-patches",
		"ariadne compare --before before-proof.json --after after-proof.json --format html --out case-compare.html",
		"Limits And Privacy",
		"does not execute agents",
		"case-compare.html",
		"manifest.json",
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
	} {
		if !strings.Contains(assessmentJSON, want) {
			t.Fatalf("self bundle assessment JSON missing %q:\n%s", want, assessmentJSON)
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

	dashboard := readTestFile(t, filepath.Join(bundleDir, "dashboard.html"))
	for _, want := range []string{
		"Ariadne Assessment",
		"Signal Quality",
		"Lethal Trifecta",
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
		`"review_order"`,
		`"proof_loop"`,
		`--patch-dir proof-patches`,
		`"ariadne compare --before before-proof.json --after after-proof.json --format html --out case-compare.html"`,
		`"limitations"`,
		`"name": "README.md"`,
		`"name": "manifest.json"`,
		`"name": "proof-action.txt"`,
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("self bundle manifest missing %q:\n%s", want, manifest)
		}
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
		"Compare loop:",
	} {
		if !strings.Contains(action, want) {
			t.Fatalf("proof action output missing %q:\n%s", want, action)
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
	jsonPath := filepath.Join(root, "case-compare.json")
	htmlPath := filepath.Join(root, "case-compare.html")
	runProofs([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "combined-risk"),
		"--case", "case:input-trust-boundary",
		"--format", "json",
		"--out", beforePath,
	})
	runProofs([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "input-controls"),
		"--case", "case:input-trust-boundary",
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
		"CLOSED Input Trust Boundary",
		"open -> closed",
		"Missing controls before: control:input-isolation; control:trusted-source-policy",
		"Observed controls after: control:input-isolation; control:trusted-source-policy",
		"Proof patches: 2 -> 0",
		"Added evidence:",
		".ariadne/input-policy.json",
		"After compare loop:",
		"case-compare.html",
	} {
		if !strings.Contains(table, want) {
			t.Fatalf("compare table missing %q:\n%s", want, table)
		}
	}
	blob := readTestFile(t, jsonPath)
	for _, want := range []string{
		`"disposition": "closed"`,
		`"before_state": "open"`,
		`"after_state": "closed"`,
		`"control:input-isolation"`,
		`".ariadne/input-policy.json"`,
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
		"Input Trust Boundary",
		"open",
		"closed",
		".ariadne/input-policy.json",
		"case-compare.html",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("compare HTML missing %q:\n%s", want, html)
		}
	}
	if strings.Contains(html, "STAYED OPEN Input Trust Boundary") {
		t.Fatalf("compare HTML should show input trust as closed, not stayed open:\n%s", html)
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
