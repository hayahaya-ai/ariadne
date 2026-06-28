package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeSecret = "FAKE_SECRET_DO_NOT_LEAK_123456789"

func TestUnsafeCodexProducesAttackPathsAndRedactsSecrets(t *testing.T) {
	root := fixture(t, "unsafe-codex")
	report, err := Run(Options{Mode: ModeRepo, Path: root, Format: "json"})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, report, "dangerous-agent-mode")
	assertFinding(t, report, "network-enabled-agent")
	assertFinding(t, report, "missing-secret-deny-policy")
	assertAttackPath(t, report, "agent-network-data-egress")
	out, _ := json.Marshal(report)
	if strings.Contains(string(out), fakeSecret) {
		t.Fatalf("report leaked fixture secret: %s", out)
	}
}

func TestEndpointModeSynthesizesFullAccessLocalAgent(t *testing.T) {
	root := fixture(t, "unsafe-codex")
	report, err := Run(Options{Mode: ModeEndpoint, Path: root, Format: "json"})
	if err != nil {
		t.Fatal(err)
	}
	assertAttackPath(t, report, "full-access-local-agent")
}

func TestMCPPackageAndBroadFilesystemDetection(t *testing.T) {
	root := fixture(t, "malicious-mcp")
	report, err := Run(Options{Mode: ModeRepo, Path: root})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, report, "unknown-or-unapproved-mcp")
	assertFinding(t, report, "mcp-package-or-interpreter-launch")
	assertFinding(t, report, "mcp-broad-filesystem")
	assertAttackPath(t, report, "mutable-tool-launch-execution")
}

func TestUnsafeClaudeBypassAndMCPDetection(t *testing.T) {
	root := fixture(t, "unsafe-claude")
	report, err := Run(Options{Mode: ModeRepo, Path: root})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, report, "dangerous-agent-mode")
	assertFinding(t, report, "unknown-or-unapproved-mcp")
	assertFinding(t, report, "mcp-package-or-interpreter-launch")
	assertFinding(t, report, "mcp-broad-filesystem")
	assertAttackPath(t, report, "mutable-tool-launch-execution")
}

func TestDevcontainerRisks(t *testing.T) {
	root := fixture(t, "devcontainer-risk")
	report, err := Run(Options{Mode: ModeDevbox, Path: root})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, report, "devcontainer-risk-docker-socket")
	assertFinding(t, report, "devcontainer-risk-privileged-mode")
	assertAttackPath(t, report, "false-devcontainer-isolation")
}

func TestSymlinkEscapeIsNotFollowedInRepoMode(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "mcp.json"), []byte(`{"mcpServers":{"evil":{"command":"npx attacker"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "mcp.json"), filepath.Join(repo, "mcp.json")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	report, err := Run(Options{Mode: ModeRepo, Path: repo})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		if finding.RuleID == "mcp-package-or-interpreter-launch" {
			t.Fatalf("scanner followed symlink escape and parsed outside MCP config")
		}
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("expected symlink warning")
	}
}

func TestSafeCodexHasNoHighFindings(t *testing.T) {
	root := fixture(t, "safe-codex")
	report, err := Run(Options{Mode: ModeRepo, Path: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		if !finding.Suppressed && SeverityRank(finding.Severity) >= SeverityRank(SeverityHigh) {
			t.Fatalf("unexpected high finding: %s", finding.RuleID)
		}
	}
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "fixtures", name)
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func assertFinding(t *testing.T, report Report, rule string) {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.RuleID == rule && !finding.Suppressed {
			return
		}
	}
	t.Fatalf("missing finding %s; got %+v", rule, report.Findings)
}

func assertAttackPath(t *testing.T, report Report, id string) {
	t.Helper()
	for _, path := range report.AttackPaths {
		if path.ID == id {
			return
		}
	}
	t.Fatalf("missing attack path %s; got %+v", id, report.AttackPaths)
}
