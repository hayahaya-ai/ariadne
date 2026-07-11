package verdict

import (
	"strings"
	"testing"
)

func TestComputeVerdictWordPrecedence(t *testing.T) {
	tests := []struct {
		name           string
		reckless       int
		tradeoffs      int
		hardened       int
		inconclusive   int
		conclusive     int
		runtimes       int
		parserFailures int
		wantVerdict    string
	}{
		{name: "reckless outranks every other bucket", reckless: 1, tradeoffs: 1, hardened: 1, inconclusive: 1, runtimes: 1, wantVerdict: WordReckless},
		{name: "parser failure is inconclusive", tradeoffs: 1, hardened: 1, conclusive: 1, runtimes: 1, parserFailures: 1, wantVerdict: WordInconclusive},
		{name: "inconclusive paths alone do not erase deterministic capability grading", tradeoffs: 1, hardened: 1, inconclusive: 2, runtimes: 1, wantVerdict: WordTradeoffsOnly},
		{name: "tradeoffs outrank partial inconclusive evidence when another path is conclusive", tradeoffs: 1, hardened: 1, inconclusive: 1, conclusive: 1, runtimes: 1, wantVerdict: WordTradeoffsOnly},
		{name: "runtime with controls is hardened", hardened: 1, runtimes: 1, wantVerdict: WordHardened},
		{name: "runtime without controls is hardened", runtimes: 1, wantVerdict: WordHardened},
		{name: "controls cannot harden an absent runtime", hardened: 1, wantVerdict: WordNoAgentsFound},
		{name: "nothing observed has no agents", wantVerdict: WordNoAgentsFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeVerdictWord(tt.reckless, tt.tradeoffs, tt.hardened, tt.inconclusive, tt.conclusive, tt.runtimes, tt.parserFailures); got != tt.wantVerdict {
				t.Fatalf("computeVerdictWord() = %s, want %s", got, tt.wantVerdict)
			}
		})
	}
}

func TestCountsSentenceForRuntimeWithoutBuckets(t *testing.T) {
	v := Verdict{
		VerdictWord: WordHardened,
		Scanned:     ScannedSummary{Runtimes: []string{"claude"}},
	}

	got := countsSentence(v)
	if got != "1 agent runtime(s) found" {
		t.Fatalf("countsSentence() = %q, want runtime observation", got)
	}
	if strings.Contains(got, "no agent runtimes") {
		t.Fatalf("hardened headline must not claim no runtime: %q", got)
	}
}
