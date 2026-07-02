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
	tablePath := filepath.Join(root, "assess-table.txt")
	target := filepath.Join("..", "..", "testdata", "realpath", "combined-risk")

	runAssess([]string{
		"--path", target,
		"--out", summaryPath,
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
		Directory:    "/tmp/proof-patches",
		ManifestPath: "/tmp/proof-patches/manifest.json",
		ReadmePath:   "/tmp/proof-patches/README.md",
		PatchCount:   2,
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
