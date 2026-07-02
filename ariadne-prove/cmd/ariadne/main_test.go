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
	patchDir := filepath.Join(root, "proof-patches")
	runProofs([]string{
		"--path", filepath.Join("..", "..", "testdata", "realpath", "combined-risk"),
		"--case", "case:input-trust-boundary",
		"--format", "json",
		"--out", outPath,
		"--patch-dir", patchDir,
	})
	for _, path := range []string{
		outPath,
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
}
