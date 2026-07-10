package storylab

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/verdict"
)

type EvalCaseResult struct {
	FixturePath string
	Expected    model.ExpectedVerdict
	Actual      verdict.Verdict
	Surfaces    []model.Surface
}

type EvalScorecard struct {
	Cases          int
	VerdictCorrect int
	VerdictTotal   int
	Families       []EvalFamilyScore
	Mismatches     []EvalMismatch
	Clean          bool
}

type EvalFamilyScore struct {
	Family    string
	TruePos   int
	FalsePos  int
	FalseNeg  int
	Precision float64
	Recall    float64
}

type EvalMismatch struct {
	FixturePath string
	Kind        string
	Message     string
}

func ScoreVerdicts(cases []EvalCaseResult) EvalScorecard {
	score := EvalScorecard{Cases: len(cases)}
	families := map[string]*EvalFamilyScore{}
	for _, c := range cases {
		if c.Expected.Word != "" {
			score.VerdictTotal++
			if c.Actual.VerdictWord == c.Expected.Word {
				score.VerdictCorrect++
			} else {
				score.Mismatches = append(score.Mismatches, EvalMismatch{
					FixturePath: c.FixturePath,
					Kind:        "verdict_word",
					Message:     fmt.Sprintf("got %s, expected %s", c.Actual.VerdictWord, c.Expected.Word),
				})
			}
		}

		expectedByFamily := map[string]model.ExpectedVerdictFinding{}
		for _, finding := range c.Expected.Findings {
			expectedByFamily[finding.Family] = finding
		}
		actualByFamily := map[string]verdict.RecklessFinding{}
		for _, finding := range c.Actual.Reckless {
			actualByFamily[finding.ExposureID] = finding
		}

		for family, expected := range expectedByFamily {
			familyScore := evalFamily(families, family)
			actual, ok := actualByFamily[family]
			if !ok {
				familyScore.FalseNeg++
				score.Mismatches = append(score.Mismatches, EvalMismatch{
					FixturePath: c.FixturePath,
					Kind:        "missing_finding",
					Message:     "missing reckless finding for " + family,
				})
				continue
			}
			familyScore.TruePos++
			score.Mismatches = append(score.Mismatches, findingMismatches(c.FixturePath, expected, actual)...)
		}

		for family := range actualByFamily {
			if _, ok := expectedByFamily[family]; ok {
				continue
			}
			familyScore := evalFamily(families, family)
			familyScore.FalsePos++
			score.Mismatches = append(score.Mismatches, EvalMismatch{
				FixturePath: c.FixturePath,
				Kind:        "false_positive",
				Message:     "unexpected reckless finding for " + family,
			})
		}

		if c.Expected.MinTradeoffs > 0 && len(c.Actual.Tradeoffs) < c.Expected.MinTradeoffs {
			score.Mismatches = append(score.Mismatches, EvalMismatch{
				FixturePath: c.FixturePath,
				Kind:        "tradeoffs",
				Message:     fmt.Sprintf("got %d trade-off(s), expected at least %d", len(c.Actual.Tradeoffs), c.Expected.MinTradeoffs),
			})
		}
		if c.Expected.MaxTradeoffs > 0 && len(c.Actual.Tradeoffs) > c.Expected.MaxTradeoffs {
			score.Mismatches = append(score.Mismatches, EvalMismatch{
				FixturePath: c.FixturePath,
				Kind:        "tradeoffs",
				Message:     fmt.Sprintf("got %d trade-off(s), expected at most %d", len(c.Actual.Tradeoffs), c.Expected.MaxTradeoffs),
			})
		}
		if c.Expected.MinHardened > 0 && len(c.Actual.Hardened) < c.Expected.MinHardened {
			score.Mismatches = append(score.Mismatches, EvalMismatch{
				FixturePath: c.FixturePath,
				Kind:        "hardened",
				Message:     fmt.Sprintf("got %d hardened control(s), expected at least %d", len(c.Actual.Hardened), c.Expected.MinHardened),
			})
		}
		for _, rule := range c.Expected.DefaultJudgmentRules {
			if !hasDefaultJudgmentRule(c.Actual.DefaultJudgments, rule) {
				score.Mismatches = append(score.Mismatches, EvalMismatch{
					FixturePath: c.FixturePath,
					Kind:        "default_judgment",
					Message:     "missing default judgment rule " + rule,
				})
			}
		}
		if c.Expected.RequireEvidenceLineAnchors {
			score.Mismatches = append(score.Mismatches, lineAnchorMismatches(c.FixturePath, c.Actual, c.Surfaces)...)
		}
	}

	for _, family := range sortedFamilyKeys(families) {
		value := *families[family]
		if denom := value.TruePos + value.FalsePos; denom > 0 {
			value.Precision = float64(value.TruePos) / float64(denom)
		}
		if denom := value.TruePos + value.FalseNeg; denom > 0 {
			value.Recall = float64(value.TruePos) / float64(denom)
		}
		score.Families = append(score.Families, value)
	}
	score.Clean = len(score.Mismatches) == 0
	return score
}

func findingMismatches(path string, expected model.ExpectedVerdictFinding, actual verdict.RecklessFinding) []EvalMismatch {
	var out []EvalMismatch
	if expected.Source != "" && actual.Where.Source != expected.Source {
		out = append(out, EvalMismatch{
			FixturePath: path,
			Kind:        "evidence_source",
			Message:     fmt.Sprintf("%s got source %s, expected %s", expected.Family, actual.Where.Source, expected.Source),
		})
	}
	if expected.Line > 0 && actual.Where.Line != expected.Line {
		out = append(out, EvalMismatch{
			FixturePath: path,
			Kind:        "evidence_line",
			Message:     fmt.Sprintf("%s got line %d, expected %d", expected.Family, actual.Where.Line, expected.Line),
		})
	}
	if expected.FixSurface != "" && !strings.Contains(actual.Fix, expected.FixSurface) {
		out = append(out, EvalMismatch{
			FixturePath: path,
			Kind:        "fix_surface",
			Message:     fmt.Sprintf("%s fix %q does not target %s", expected.Family, actual.Fix, expected.FixSurface),
		})
	}
	return out
}

func hasDefaultJudgmentRule(judgments []verdict.DefaultJudgment, rule string) bool {
	for _, judgment := range judgments {
		if judgment.Rule == rule {
			return true
		}
	}
	return false
}

func lineAnchorMismatches(path string, actual verdict.Verdict, surfaces []model.Surface) []EvalMismatch {
	var out []EvalMismatch
	surfaceHandling := surfaceHandlingBySource(surfaces)
	for _, finding := range actual.Reckless {
		parsedRefs := findingHasParsedLineRef(finding, surfaceHandling)
		if finding.Where.Source != "" && finding.Where.Line <= 0 && finding.Where.Anchor != "file" {
			out = append(out, EvalMismatch{
				FixturePath: path,
				Kind:        "line_anchor",
				Message:     fmt.Sprintf("%s where %s has line %d", finding.ExposureID, finding.Where.Source, finding.Where.Line),
			})
		}
		if finding.Where.Anchor == "file" && parsedRefs {
			out = append(out, EvalMismatch{
				FixturePath: path,
				Kind:        "line_anchor",
				Message:     fmt.Sprintf("%s where %s is file-level despite parsed line evidence", finding.ExposureID, finding.Where.Source),
			})
		}
		if finding.Where.Anchor == "file" && surfaceHandling[finding.Where.Source] == "parse" {
			out = append(out, EvalMismatch{
				FixturePath: path,
				Kind:        "line_anchor",
				Message:     fmt.Sprintf("%s where %s marks parsed evidence as file-level", finding.ExposureID, finding.Where.Source),
			})
		}
		for _, ref := range finding.EvidenceRefs {
			if ref.Source == "" {
				continue
			}
			handling := surfaceHandling[ref.Source]
			if ref.LineStart > 0 {
				continue
			}
			if ref.Anchor == "file" {
				if handling == "parse" {
					out = append(out, EvalMismatch{
						FixturePath: path,
						Kind:        "line_anchor",
						Message:     fmt.Sprintf("%s evidence ref %s marks parsed evidence as file-level", finding.ExposureID, ref.Source),
					})
				}
				continue
			}
			out = append(out, EvalMismatch{
				FixturePath: path,
				Kind:        "line_anchor",
				Message:     fmt.Sprintf("%s evidence ref %s has line %d", finding.ExposureID, ref.Source, ref.LineStart),
			})
		}
	}
	return out
}

func surfaceHandlingBySource(surfaces []model.Surface) map[string]string {
	out := map[string]string{}
	for _, surface := range surfaces {
		if surface.Source == "" {
			continue
		}
		if _, ok := out[surface.Source]; !ok {
			out[surface.Source] = surface.HandlingMode
		}
	}
	return out
}

func findingHasParsedLineRef(finding verdict.RecklessFinding, surfaceHandling map[string]string) bool {
	for _, ref := range finding.EvidenceRefs {
		if ref.Source != "" && ref.LineStart > 0 && surfaceHandling[ref.Source] == "parse" {
			return true
		}
	}
	return false
}

func evalFamily(families map[string]*EvalFamilyScore, family string) *EvalFamilyScore {
	if families[family] == nil {
		families[family] = &EvalFamilyScore{Family: family}
	}
	return families[family]
}

func sortedFamilyKeys(families map[string]*EvalFamilyScore) []string {
	keys := make([]string, 0, len(families))
	for family := range families {
		keys = append(keys, family)
	}
	sort.Strings(keys)
	return keys
}

func RenderScorecard(w io.Writer, score EvalScorecard) error {
	if _, err := fmt.Fprintf(w, "Ariadne Story Lab verdict eval scorecard\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "fixtures: %d\n", score.Cases); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "verdict-word accuracy: %s\n", formatEvalRatio(score.VerdictCorrect, score.VerdictTotal)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "families:\n"); err != nil {
		return err
	}
	if len(score.Families) == 0 {
		if _, err := fmt.Fprintf(w, "  (none)\n"); err != nil {
			return err
		}
	}
	for _, family := range score.Families {
		if _, err := fmt.Fprintf(w, "  %s precision %s recall %s\n",
			family.Family,
			formatEvalRatio(family.TruePos, family.TruePos+family.FalsePos),
			formatEvalRatio(family.TruePos, family.TruePos+family.FalseNeg),
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "mismatches:\n"); err != nil {
		return err
	}
	if len(score.Mismatches) == 0 {
		if _, err := fmt.Fprintf(w, "  (none)\n"); err != nil {
			return err
		}
	} else {
		for _, mismatch := range score.Mismatches {
			if _, err := fmt.Fprintf(w, "  - %s [%s] %s\n", mismatch.FixturePath, mismatch.Kind, mismatch.Message); err != nil {
				return err
			}
		}
	}
	result := "PASS"
	if !score.Clean {
		result = "FAIL"
	}
	_, err := fmt.Fprintf(w, "result: %s\n", result)
	return err
}

func formatEvalRatio(numerator, denominator int) string {
	if denominator == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d/%d (%.1f%%)", numerator, denominator, 100*float64(numerator)/float64(denominator))
}
