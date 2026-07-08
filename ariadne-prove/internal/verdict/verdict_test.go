package verdict_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/prove"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/verdict"
)

func realPathFixture(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "realpath", name))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func buildVerdict(t *testing.T, name string) verdict.Verdict {
	t.Helper()
	fixture := realPathFixture(t, name)
	inv, err := prove.RunInventory(prove.Options{Path: fixture, Mode: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := prove.RunPath(prove.Options{Path: fixture, Mode: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	return verdict.Build(inv, r, fixture, "repo")
}

func TestBuildCombinedRiskIsReckless(t *testing.T) {
	v := buildVerdict(t, "combined-risk")

	if v.VerdictWord != verdict.WordReckless {
		t.Fatalf("verdict = %s, want %s", v.VerdictWord, verdict.WordReckless)
	}
	if len(v.Reckless) == 0 {
		t.Fatalf("expected at least one reckless finding")
	}
	if v.Reckless[0].ExposureID != verdict.FamilyEgress {
		t.Fatalf("first reckless finding = %s, want %s (egress-first ordering)", v.Reckless[0].ExposureID, verdict.FamilyEgress)
	}
	for _, finding := range v.Reckless {
		if finding.Where.Source == "" {
			t.Fatalf("finding %s has empty where.source: %+v", finding.ID, finding)
		}
		if finding.Why == "" {
			t.Fatalf("finding %s has empty why: %+v", finding.ID, finding)
		}
		if finding.Fix == "" {
			t.Fatalf("finding %s has empty fix: %+v", finding.ID, finding)
		}
		if strings.Contains(finding.Fix, ".ariadne") {
			t.Fatalf("finding %s fix must never mention .ariadne: %q", finding.ID, finding.Fix)
		}
	}
}

func TestBuildSafeControlsIsNotReckless(t *testing.T) {
	v := buildVerdict(t, "safe-controls")

	if v.VerdictWord == verdict.WordReckless {
		t.Fatalf("verdict = %s, want not reckless", v.VerdictWord)
	}
	if len(v.Hardened) == 0 {
		t.Fatalf("expected non-empty hardened list")
	}
	for _, h := range v.Hardened {
		if h.Control == "control:ai-bom" {
			t.Fatalf("attested-only control:ai-bom must not appear in hardened: %+v", h)
		}
	}
}

func TestBuildTradeoffsOnlyFixtureIsNotReckless(t *testing.T) {
	v := buildVerdict(t, "tradeoffs-only")

	if v.VerdictWord == verdict.WordReckless {
		t.Fatalf("verdict = %s, want not reckless", v.VerdictWord)
	}
	if len(v.Tradeoffs) == 0 {
		t.Fatalf("expected at least one trade-off line")
	}
}

func TestRenderReadoutCombinedRisk(t *testing.T) {
	v := buildVerdict(t, "combined-risk")

	var buf bytes.Buffer
	if err := verdict.RenderReadout(&buf, v); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) > 40 {
		t.Fatalf("readout has %d lines, want <=40:\n%s", len(lines), out)
	}
	if !strings.Contains(out, "VERDICT: RECKLESS") {
		t.Fatalf("readout missing VERDICT: RECKLESS:\n%s", out)
	}
	if !strings.Contains(out, "RECKLESS ──") {
		t.Fatalf("readout missing RECKLESS section header:\n%s", out)
	}
	if !strings.Contains(out, "fix") {
		t.Fatalf("readout missing fix line:\n%s", out)
	}
	for _, line := range lines {
		if strings.Contains(line, "fix") && strings.Contains(line, ".ariadne") {
			t.Fatalf("fix line must never mention .ariadne: %q", line)
		}
	}
	if !strings.Contains(out, "Next:") {
		t.Fatalf("readout missing Next: line:\n%s", out)
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	v := buildVerdict(t, "combined-risk")

	var buf bytes.Buffer
	if err := verdict.RenderJSON(&buf, v); err != nil {
		t.Fatal(err)
	}
	var decoded verdict.Verdict
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.VerdictWord != v.VerdictWord {
		t.Fatalf("round-tripped verdict = %s, want %s", decoded.VerdictWord, v.VerdictWord)
	}
}

func TestRenderJSONArraysAreEmptyNotNull(t *testing.T) {
	v := buildVerdict(t, "tradeoffs-only")

	var buf bytes.Buffer
	if err := verdict.RenderJSON(&buf, v); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"reckless": []`) {
		t.Fatalf("expected empty reckless array (not null) in JSON:\n%s", out)
	}
	if strings.Contains(out, "null") {
		t.Fatalf("verdict JSON must never contain null arrays:\n%s", out)
	}
}

func TestBuildInconclusiveExposuresAreCounted(t *testing.T) {
	v := buildVerdict(t, "repo-only-risk")
	if v.Inconclusive == 0 {
		t.Fatalf("expected at least one inconclusive exposure for repo-only-risk fixture")
	}
}
