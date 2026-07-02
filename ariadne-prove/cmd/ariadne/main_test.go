package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		"After controls: control:input-isolation; control:trusted-source-policy",
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
