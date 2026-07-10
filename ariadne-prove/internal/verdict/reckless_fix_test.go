package verdict

import (
	"strings"
	"testing"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

func TestRecklessFixUsesGeminiEvidenceSurface(t *testing.T) {
	fix := recklessFix(FamilyEgress, []model.EvidenceReference{{
		ID:     "authority:external-communication",
		Kind:   "authority",
		Source: ".gemini/settings.json",
	}}, model.Collection{Surfaces: []model.Surface{{
		Runtime:  "gemini",
		Kind:     "gemini-settings",
		Category: "runtime-config",
		Source:   ".gemini/settings.json",
	}}})

	assertContains(t, fix, ".gemini/settings.json")
	assertNotContainsAny(t, fix, ".claude/settings.json", ".codex/config.toml", ".codex/requirements.toml")
}

func TestRecklessFixUsesCodexEvidenceSurface(t *testing.T) {
	fix := recklessFix(FamilySecret, []model.EvidenceReference{{
		ID:     "authority:file-read",
		Kind:   "authority",
		Source: ".codex/config.toml",
	}}, model.Collection{Surfaces: []model.Surface{{
		Runtime:  "codex",
		Kind:     "codex-config",
		Category: "runtime-config",
		Source:   ".codex/config.toml",
	}}})

	assertContains(t, fix, ".codex/config.toml")
	assertNotContainsAny(t, fix, ".claude/settings.json", ".gemini/settings.json")
}

func TestRecklessFixUsesActualMCPSource(t *testing.T) {
	fix := recklessFix(FamilyMCP, []model.EvidenceReference{{
		ID:     "tool:mcp-package-launch",
		Kind:   "tool",
		Source: "tools/mcp.json",
	}}, model.Collection{Surfaces: []model.Surface{{
		Runtime:  "mcp",
		Kind:     "mcp-config",
		Category: "mcp-tool-config",
		Source:   "tools/mcp.json",
	}}})

	assertContains(t, fix, "tools/mcp.json")
	assertNotContainsAny(t, fix, ".claude/settings.json", ".codex/config.toml", ".gemini/settings.json")
}

func TestRecklessFixUnknownRuntimeFallsBackToEvidenceSource(t *testing.T) {
	fix := recklessFix(FamilyEgress, []model.EvidenceReference{{
		ID:     "authority:external-communication",
		Kind:   "authority",
		Source: ".cursor/settings.json",
	}}, model.Collection{Surfaces: []model.Surface{{
		Runtime:  "cursor",
		Kind:     "cursor-settings",
		Category: "runtime-config",
		Source:   ".cursor/settings.json",
	}}})

	assertContains(t, fix, ".cursor/settings.json")
	assertNotContainsAny(t, fix, ".claude/settings.json", ".codex/config.toml", ".codex/requirements.toml", ".gemini/settings.json")
}

func assertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("fix %q does not contain %q", haystack, needle)
	}
}

func assertNotContainsAny(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			t.Fatalf("fix %q must not contain %q", haystack, needle)
		}
	}
}
