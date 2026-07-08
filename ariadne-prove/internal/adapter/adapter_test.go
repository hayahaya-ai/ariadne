package adapter

import (
	"testing"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/agentconfig"
)

// TestClaudeHasUndeniedAllowTool_BroadDenyCancelsNarrowerAllow guards the
// bidirectional-aware cancellation rule from docs/parser-spec.md: a broad
// deny (scope "*"/empty) cancels a narrower allow of the same tool, even
// though the scopes are not identical. Before this fix, allow:["Bash(git)"]
// + deny:["Bash(*)"] still granted local-code-execution authority, which
// contradicts the plain meaning of "deny everything Bash".
func TestClaudeHasUndeniedAllowTool_BroadDenyCancelsNarrowerAllow(t *testing.T) {
	cfg, ok := agentconfig.ParseClaudeSettings([]byte(`{"permissions":{"allow":["Bash(git)"],"deny":["Bash(*)"]}}`))
	if !ok {
		t.Fatal("ParseClaudeSettings: ok=false, want true")
	}
	if claudeHasUndeniedAllowTool(cfg, "Bash") {
		t.Fatal("broad deny Bash(*) should cancel narrower allow Bash(git); got undenied allow")
	}
}

// TestClaudeHasUndeniedAllowTool_NarrowDenyDoesNotCancelBroadAllow pins the
// non-symmetric half of the rule: a narrow deny must never cancel a
// broader allow of the same tool.
func TestClaudeHasUndeniedAllowTool_NarrowDenyDoesNotCancelBroadAllow(t *testing.T) {
	cfg, ok := agentconfig.ParseClaudeSettings([]byte(`{"permissions":{"allow":["Bash(*)"],"deny":["Bash(git)"]}}`))
	if !ok {
		t.Fatal("ParseClaudeSettings: ok=false, want true")
	}
	if !claudeHasUndeniedAllowTool(cfg, "Bash") {
		t.Fatal("narrow deny Bash(git) must not cancel broader allow Bash(*)")
	}
}

// TestClaudeNetworkRestricted_DoesNotLaunderBroadBashAllow is the house
// rule #1 regression test: a defaultMode=="default" config that grants
// allow:["Bash(*)"] (shell -> curl/wget network egress) must never also be
// credited with control:network-restricted merely because WebFetch/
// WebSearch are absent from allow. Before the fix, this single config
// produced BOTH authority:external-communication and
// control:network-restricted, which would launder a real data-egress
// exposure to "protected".
func TestClaudeNetworkRestricted_DoesNotLaunderBroadBashAllow(t *testing.T) {
	cfg, ok := agentconfig.ParseClaudeSettings([]byte(`{"permissions":{"defaultMode":"default","allow":["Read(*)","Bash(*)"]}}`))
	if !ok {
		t.Fatal("ParseClaudeSettings: ok=false, want true")
	}
	if !claudeAllowsExternalCommunication(cfg) {
		t.Fatal("expected external-communication authority from broad Bash allow")
	}
	if claudeNetworkRestricted(cfg) {
		t.Fatal("config granting external-communication authority must not also get control:network-restricted")
	}
}

// TestClaudeNetworkRestricted_GenuinelyScopedConfigStillCredited proves the
// fix does not over-correct: a config with defaultMode=="default" and no
// Bash/WebFetch/WebSearch allow at all is genuinely network-restricted and
// must still receive the control.
func TestClaudeNetworkRestricted_GenuinelyScopedConfigStillCredited(t *testing.T) {
	cfg, ok := agentconfig.ParseClaudeSettings([]byte(`{"permissions":{"defaultMode":"default","allow":["Read(src/**)"]}}`))
	if !ok {
		t.Fatal("ParseClaudeSettings: ok=false, want true")
	}
	if claudeAllowsExternalCommunication(cfg) {
		t.Fatal("scoped Read-only allow should not grant external-communication authority")
	}
	if !claudeNetworkRestricted(cfg) {
		t.Fatal("scoped config with no network/broad-shell allow should still be credited control:network-restricted")
	}
}
