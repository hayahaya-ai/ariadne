package storylab

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/verdict"
)

func TestLoadParsesVerdictExpectation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "fixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{
  "id": "fixture",
  "title": "Fixture",
  "persona": "tester",
  "user_question": "What happens?",
  "runtime": "all",
  "mode": "repo",
  "world": { "repo_path": "." },
  "expected": {
    "verdict": {
      "word": "reckless",
      "min_tradeoffs": 1,
      "max_tradeoffs": 2,
      "default_judgment_rules": ["nested_instructions_scoped_by_default"],
      "require_evidence_line_anchors": true,
      "findings": [
        {
          "family": "data-egress-chain",
          "source": ".gemini/settings.json",
          "line": 3,
          "fix_surface": ".gemini/settings.json"
        }
      ]
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, ManifestName), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	story, err := Load(root, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if story.Manifest.Expected.Verdict == nil {
		t.Fatalf("expected verdict expectation to parse")
	}
	got := story.Manifest.Expected.Verdict
	if got.Word != verdict.WordReckless || got.MinTradeoffs != 1 || got.MaxTradeoffs != 2 || !got.RequireEvidenceLineAnchors {
		t.Fatalf("parsed verdict expectation = %+v", got)
	}
	if len(got.Findings) != 1 || got.Findings[0].FixSurface != ".gemini/settings.json" {
		t.Fatalf("parsed findings = %+v", got.Findings)
	}
	if len(got.DefaultJudgmentRules) != 1 || got.DefaultJudgmentRules[0] != "nested_instructions_scoped_by_default" {
		t.Fatalf("parsed default judgment rules = %+v", got.DefaultJudgmentRules)
	}
}

func TestScoreVerdictsClean(t *testing.T) {
	score := ScoreVerdicts([]EvalCaseResult{{
		FixturePath: "testdata/storylab/clean",
		Expected: model.ExpectedVerdict{
			Word:                 verdict.WordReckless,
			MinTradeoffs:         1,
			MaxTradeoffs:         1,
			DefaultJudgmentRules: []string{"nested_instructions_scoped_by_default"},
			Findings: []model.ExpectedVerdictFinding{{
				Family:     verdict.FamilyEgress,
				Source:     ".claude/settings.json",
				Line:       4,
				FixSurface: ".claude/settings.json",
			}},
		},
		Actual: verdict.Verdict{
			VerdictWord: verdict.WordReckless,
			DefaultJudgments: []verdict.DefaultJudgment{{
				Rule: "nested_instructions_scoped_by_default",
			}},
			Reckless: []verdict.RecklessFinding{{
				ExposureID: verdict.FamilyEgress,
				Where:      verdict.EvidenceLocation{Source: ".claude/settings.json", Line: 4},
				Fix:        "deny WebFetch/WebSearch in .claude/settings.json",
			}},
			Tradeoffs: []verdict.TradeoffLine{{ID: "tradeoff:1"}},
		},
	}})

	if !score.Clean {
		t.Fatalf("expected clean scorecard, got %+v", score.Mismatches)
	}
	if score.VerdictCorrect != 1 || score.VerdictTotal != 1 {
		t.Fatalf("verdict accuracy = %d/%d", score.VerdictCorrect, score.VerdictTotal)
	}
	if len(score.Families) != 1 || score.Families[0].TruePos != 1 || score.Families[0].FalsePos != 0 || score.Families[0].FalseNeg != 0 {
		t.Fatalf("family score = %+v", score.Families)
	}
}

func TestScoreVerdictsReportsMismatches(t *testing.T) {
	score := ScoreVerdicts([]EvalCaseResult{{
		FixturePath: "testdata/storylab/mismatch",
		Expected: model.ExpectedVerdict{
			Word:                       verdict.WordTradeoffsOnly,
			MinTradeoffs:               1,
			MaxTradeoffs:               1,
			DefaultJudgmentRules:       []string{"nested_instructions_scoped_by_default"},
			RequireEvidenceLineAnchors: true,
			Findings: []model.ExpectedVerdictFinding{{
				Family:     verdict.FamilyEgress,
				Source:     ".gemini/settings.json",
				Line:       2,
				FixSurface: ".gemini/settings.json",
			}},
		},
		Actual: verdict.Verdict{
			VerdictWord: verdict.WordReckless,
			Reckless: []verdict.RecklessFinding{
				{
					ExposureID: verdict.FamilyEgress,
					Where:      verdict.EvidenceLocation{Source: ".claude/settings.json", Line: 0},
					Fix:        "deny WebFetch/WebSearch in .claude/settings.json",
					EvidenceRefs: []model.EvidenceReference{{
						Source: ".env",
					}},
				},
				{
					ExposureID: verdict.FamilySecret,
					Where:      verdict.EvidenceLocation{Source: "CLAUDE.md", Line: 1},
				},
			},
			Tradeoffs: []verdict.TradeoffLine{
				{ID: "tradeoff:1"},
				{ID: "tradeoff:2"},
			},
		},
	}})

	if score.Clean {
		t.Fatalf("expected mismatches")
	}
	rendered := renderScorecardForTest(t, score)
	for _, want := range []string{
		"testdata/storylab/mismatch [verdict_word]",
		"testdata/storylab/mismatch [evidence_source]",
		"testdata/storylab/mismatch [evidence_line]",
		"testdata/storylab/mismatch [fix_surface]",
		"testdata/storylab/mismatch [false_positive]",
		"testdata/storylab/mismatch [tradeoffs]",
		"testdata/storylab/mismatch [default_judgment] missing default judgment rule nested_instructions_scoped_by_default",
		"expected at most 1",
		"testdata/storylab/mismatch [line_anchor]",
		"data-egress-chain precision 1/1 (100.0%) recall 1/1 (100.0%)",
		"prompt-injection-to-secret-canary precision 0/1 (0.0%) recall n/a",
		"result: FAIL",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("scorecard missing %q:\n%s", want, rendered)
		}
	}
}

func TestLineAnchorExpectationAllowsExplicitMetadataFileAnchors(t *testing.T) {
	score := ScoreVerdicts([]EvalCaseResult{{
		FixturePath: "testdata/storylab/file-anchor",
		Expected: model.ExpectedVerdict{
			Word:                       verdict.WordReckless,
			RequireEvidenceLineAnchors: true,
			Findings: []model.ExpectedVerdictFinding{{
				Family: verdict.FamilySecret,
				Source: "CLAUDE.md",
				Line:   3,
			}},
		},
		Surfaces: []model.Surface{
			{Source: "CLAUDE.md", HandlingMode: "parse"},
			{Source: ".env", HandlingMode: "boundary_indicator"},
		},
		Actual: verdict.Verdict{
			VerdictWord: verdict.WordReckless,
			Reckless: []verdict.RecklessFinding{{
				ExposureID: verdict.FamilySecret,
				Where:      verdict.EvidenceLocation{Source: "CLAUDE.md", Line: 3},
				EvidenceRefs: []model.EvidenceReference{
					{ID: "trustinput:repo-instruction", Kind: "trust_input", Source: "CLAUDE.md", LineStart: 3, LineEnd: 3, Summary: "parsed"},
					{ID: "boundary:secret-like-file", Kind: "boundary", Source: ".env", Anchor: "file", Summary: "metadata"},
				},
			}},
		},
	}})

	if !score.Clean {
		t.Fatalf("explicit file-level metadata anchor should pass: %+v", score.Mismatches)
	}
}

func TestLineAnchorExpectationRejectsLazyFileAnchorsOnParsedSurfaces(t *testing.T) {
	score := ScoreVerdicts([]EvalCaseResult{{
		FixturePath: "testdata/storylab/lazy-file-anchor",
		Expected: model.ExpectedVerdict{
			Word:                       verdict.WordReckless,
			RequireEvidenceLineAnchors: true,
			Findings: []model.ExpectedVerdictFinding{{
				Family: verdict.FamilyEgress,
				Source: ".claude/settings.json",
				Line:   4,
			}},
		},
		Surfaces: []model.Surface{
			{Source: ".claude/settings.json", HandlingMode: "parse"},
			{Source: ".env", HandlingMode: "boundary_indicator"},
		},
		Actual: verdict.Verdict{
			VerdictWord: verdict.WordReckless,
			Reckless: []verdict.RecklessFinding{{
				ExposureID: verdict.FamilyEgress,
				Where:      verdict.EvidenceLocation{Source: ".env", Anchor: "file"},
				EvidenceRefs: []model.EvidenceReference{
					{ID: "authority:external-communication", Kind: "authority", Source: ".claude/settings.json", LineStart: 4, LineEnd: 4, Summary: "parsed"},
					{ID: "authority:file-read", Kind: "authority", Source: ".claude/settings.json", Anchor: "file", Summary: "lazy"},
					{ID: "boundary:secret-like-file", Kind: "boundary", Source: ".env", Anchor: "file", Summary: "metadata"},
				},
			}},
		},
	}})

	if score.Clean {
		t.Fatalf("expected lazy parsed file anchors to fail")
	}
	rendered := renderScorecardForTest(t, score)
	for _, want := range []string{
		"where .env is file-level despite parsed line evidence",
		"evidence ref .claude/settings.json marks parsed evidence as file-level",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("scorecard missing %q:\n%s", want, rendered)
		}
	}
}

func renderScorecardForTest(t *testing.T, score EvalScorecard) string {
	t.Helper()
	var out bytes.Buffer
	if err := RenderScorecard(&out, score); err != nil {
		t.Fatal(err)
	}
	return out.String()
}
