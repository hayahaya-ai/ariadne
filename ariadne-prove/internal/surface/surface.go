package surface

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

const RegistryVersion = "ariadne.ai-surface/v1"

type Options struct {
	RepoPath              string
	HomePath              string
	Mode                  string
	Runtime               string
	BasePath              string
	IncludeSensitivePaths bool
}

type Rule struct {
	Runtime      string
	Scope        string
	Category     string
	Kind         string
	HandlingMode string
	Summary      string
	Matches      func(string) bool
}

func Discover(opts Options) ([]model.Surface, []string) {
	var surfaces []model.Surface
	var warnings []string
	for _, root := range roots(opts) {
		found, rootWarnings := discoverRoot(root.path, root.scope, root.prefix, opts)
		surfaces = append(surfaces, found...)
		warnings = append(warnings, rootWarnings...)
	}
	sort.Slice(surfaces, func(i, j int) bool {
		if surfaces[i].Source == surfaces[j].Source {
			return surfaces[i].Kind < surfaces[j].Kind
		}
		return surfaces[i].Source < surfaces[j].Source
	})
	return dedupe(surfaces), warnings
}

func Registry() []Rule {
	return []Rule{
		{Runtime: "claude", Scope: "repo", Category: "runtime-config", Kind: "claude-settings", HandlingMode: "parse", Summary: "Claude Code settings configure permissions, tools, and runtime posture.", Matches: exact(".claude/settings.json")},
		{Runtime: "claude", Scope: "repo", Category: "runtime-config", Kind: "claude-local-settings", HandlingMode: "parse", Summary: "Claude Code local settings can override project posture.", Matches: exact(".claude/settings.local.json")},
		{Runtime: "claude", Scope: "repo", Category: "mcp-tool-config", Kind: "claude-mcp-config", HandlingMode: "parse", Summary: "Claude MCP config declares model-callable tools.", Matches: exact(".claude/.mcp.json")},
		{Runtime: "claude", Scope: "repo", Category: "command-hook", Kind: "claude-command", HandlingMode: "parse", Summary: "Claude command files can influence repeatable agent workflows.", Matches: prefixSuffix(".claude/commands/", ".md")},
		{Runtime: "claude", Scope: "repo", Category: "agent-delegation", Kind: "claude-subagent", HandlingMode: "parse", Summary: "Claude subagent definition can delegate work across agent contexts.", Matches: prefixSuffix(".claude/agents/", ".md")},
		{Runtime: "claude", Scope: "repo", Category: "plugin-skill", Kind: "claude-plugin-config", HandlingMode: "parse", Summary: "Claude plugin config declares installed extension surfaces.", Matches: exact(".claude/plugins/config.json")},
		{Runtime: "claude", Scope: "repo", Category: "plugin-skill", Kind: "claude-installed-plugins", HandlingMode: "parse", Summary: "Claude installed plugin inventory declares extension surfaces.", Matches: exact(".claude/plugins/installed_plugins.json")},
		{Runtime: "claude", Scope: "repo", Category: "managed-remote-settings", Kind: "claude-remote-settings", HandlingMode: "parse", Summary: "Claude remote settings can affect managed runtime posture.", Matches: exact(".claude/remote-settings.json")},
		{Runtime: "claude", Scope: "repo", Category: "policy", Kind: "claude-policy-limits", HandlingMode: "parse", Summary: "Claude policy limits can constrain runtime behavior.", Matches: exact(".claude/policy-limits.json")},
		{Runtime: "claude", Scope: "repo", Category: "memory", Kind: "claude-project-memory", HandlingMode: "parse", Summary: "Claude project memory can influence future agent behavior.", Matches: containsSegmentAndSuffix("/memory/", ".md")},
		{Runtime: "claude", Scope: "repo", Category: "history-cache", Kind: "claude-history", HandlingMode: "summarize", Summary: "Claude history/session state may contain prompts or context; contents are not emitted.", Matches: anyOf(exact(".claude/history.jsonl"), prefix(".claude/tasks/"), prefix(".claude/file-history/"), prefix(".claude/paste-cache/"), prefixSuffix(".claude/", ".jsonl"))},

		{Runtime: "codex", Scope: "repo", Category: "runtime-config", Kind: "codex-config", HandlingMode: "parse", Summary: "Codex config declares sandbox, approval, MCP, and profile posture.", Matches: exact(".codex/config.toml")},
		{Runtime: "codex", Scope: "repo", Category: "policy", Kind: "codex-requirements", HandlingMode: "parse", Summary: "Codex requirements can constrain filesystem and runtime behavior.", Matches: exact(".codex/requirements.toml")},
		{Runtime: "codex", Scope: "repo", Category: "trust-input", Kind: "codex-agents-md", HandlingMode: "parse", Summary: "Codex AGENTS.md can influence agent behavior.", Matches: exact(".codex/AGENTS.md")},
		{Runtime: "codex", Scope: "repo", Category: "history-cache", Kind: "codex-browser-session", HandlingMode: "summarize", Summary: "Codex browser/session state may contain local context; contents are not emitted.", Matches: anyOf(prefix(".codex/browser/sessions/"), prefix(".codex/sessions/"))},

		{Runtime: "generic", Scope: "repo", Category: "trust-input", Kind: "claude-md", HandlingMode: "parse", Summary: "CLAUDE.md can influence local coding-agent behavior.", Matches: exact("CLAUDE.md")},
		{Runtime: "generic", Scope: "repo", Category: "trust-input", Kind: "agents-md", HandlingMode: "parse", Summary: "AGENTS.md can influence local coding-agent behavior.", Matches: exact("AGENTS.md")},
		{Runtime: "generic", Scope: "repo", Category: "trust-input", Kind: "nested-agents-md", HandlingMode: "parse", Summary: "Nested AGENTS.md can influence agent behavior in a subtree.", Matches: suffix("/AGENTS.md")},
		{Runtime: "generic", Scope: "repo", Category: "trust-input", Kind: "cursor-rules", HandlingMode: "parse", Summary: "Cursor rules can influence AI coding behavior.", Matches: anyOf(exact(".cursorrules"), prefix(".cursor/rules/"))},
		{Runtime: "generic", Scope: "repo", Category: "trust-input", Kind: "windsurf-rules", HandlingMode: "parse", Summary: "Windsurf rules can influence AI coding behavior.", Matches: anyOf(exact(".windsurfrules"), prefix(".windsurf/"))},
		{Runtime: "mcp", Scope: "repo", Category: "mcp-tool-config", Kind: "mcp-config", HandlingMode: "parse", Summary: "MCP config declares model-callable tools.", Matches: anyOf(exact("mcp.json"), exact(".mcp.json"), suffix("/mcp.json"), suffix("/.mcp.json"))},
		{Runtime: "mcp", Scope: "repo", Category: "policy", Kind: "mcp-policy", HandlingMode: "parse", Summary: "Ariadne MCP policy declares MCP review, allowlist, or package pinning controls.", Matches: exact(".ariadne/mcp-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "network-policy", HandlingMode: "parse", Summary: "Ariadne network policy declares external communication controls.", Matches: exact(".ariadne/network-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "egress-policy", HandlingMode: "parse", Summary: "Ariadne egress policy declares external destination, webhook, per-tool network, output-filter, or egress-audit controls.", Matches: exact(".ariadne/egress-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "agent-policy", HandlingMode: "parse", Summary: "Ariadne agent policy declares identity, approval, sandbox, audit, or retention controls.", Matches: exact(".ariadne/agent-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "tool-policy", HandlingMode: "parse", Summary: "Ariadne tool policy declares model-callable tool allowlists, provenance, descriptor integrity, authentication, or validation controls.", Matches: exact(".ariadne/tool-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "delegation-policy", HandlingMode: "parse", Summary: "Ariadne delegation policy declares agent-to-agent authorization, scoped delegation, intent verification, and delegated credential controls.", Matches: exact(".ariadne/delegation-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "input-policy", HandlingMode: "parse", Summary: "Ariadne input policy declares trusted-source, provenance, isolation, or prompt-injection controls.", Matches: exact(".ariadne/input-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "identity-policy", HandlingMode: "parse", Summary: "Ariadne identity policy declares per-agent identity, credential issuance, and lifecycle controls.", Matches: exact(".ariadne/identity-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "authorization-policy", HandlingMode: "parse", Summary: "Ariadne authorization policy declares per-action authorization, continuous policy evaluation, JIT elevation, and automatic revocation controls.", Matches: exact(".ariadne/authorization-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "workload-policy", HandlingMode: "parse", Summary: "Ariadne workload policy declares ABAC, named-caller, segmentation, or tool-scope controls.", Matches: exact(".ariadne/workload-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "resource-policy", HandlingMode: "parse", Summary: "Ariadne resource policy declares rate, spend, loop, timeout, concurrency, and usage-audit controls for agent operations.", Matches: exact(".ariadne/resource-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "memory-policy", HandlingMode: "parse", Summary: "Ariadne memory policy declares context retention, isolation, integrity, or provenance controls.", Matches: exact(".ariadne/memory-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "integrity-policy", HandlingMode: "parse", Summary: "Ariadne integrity policy declares config review, signing, deployment verification, managed enforcement, immutable runtime, or rollback controls.", Matches: exact(".ariadne/integrity-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "observability-policy", HandlingMode: "parse", Summary: "Ariadne observability policy declares audit, trace, telemetry, or log-integrity controls.", Matches: exact(".ariadne/observability-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "response-policy", HandlingMode: "parse", Summary: "Ariadne response policy declares automated triage, containment, session termination, credential revocation, or quarantine controls.", Matches: exact(".ariadne/response-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "governance-policy", HandlingMode: "parse", Summary: "Ariadne governance policy declares agent inventory, ownership, approval, risk assessment, and review controls.", Matches: exact(".ariadne/governance-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "output-policy", HandlingMode: "parse", Summary: "Ariadne output policy declares sensitive-output filtering, redaction, logging, semantic review, or high-risk output approval controls.", Matches: exact(".ariadne/output-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "policy", Kind: "supply-chain-policy", HandlingMode: "parse", Summary: "Ariadne supply-chain policy declares AI-BOM, model provenance, dependency health, vendor review, signing, or runtime validation controls.", Matches: exact(".ariadne/supply-chain-policy.json")},
		{Runtime: "generic", Scope: "repo", Category: "supply-chain-bom", Kind: "ai-bom", HandlingMode: "parse", Summary: "AI bill of materials can declare model, dataset, fine-tuning, dependency, and component provenance.", Matches: anyOf(exact(".ariadne/ai-bom.json"), exact(".ariadne/aibom.json"), exact(".ariadne/ml-bom.json"), exact(".ariadne/mlbom.json"), exact("ai-bom.json"), exact("aibom.json"), exact("ml-bom.json"), exact("mlbom.json"), exact("cyclonedx.json"), exact("bom.json"), suffix("/ai-bom.json"), suffix("/ml-bom.json"), suffix("/cyclonedx.json"))},
		{Runtime: "generic", Scope: "repo", Category: "telemetry-config", Kind: "opentelemetry-config", HandlingMode: "parse", Summary: "OpenTelemetry collector config can export agent traces or logs for audit correlation.", Matches: anyOf(exact(".ariadne/otel-collector.yaml"), exact(".ariadne/otel-collector.yml"), exact(".ariadne/otel-collector.json"), exact("otelcol.yaml"), exact("otelcol.yml"), exact("otel-collector.yaml"), exact("otel-collector.yml"))},

		{Runtime: "generic", Scope: "repo", Category: "sensitive-boundary", Kind: "secret-like-file", HandlingMode: "boundary_indicator", Summary: "Secret-like file path exists; contents are not read or emitted.", Matches: secretLike},
	}
}

func discoverRoot(root, scope, pathPrefix string, opts Options) ([]model.Surface, []string) {
	if root == "" {
		return nil, nil
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}
	rules := Registry()
	var surfaces []model.Surface
	var warnings []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			warnings = append(warnings, "could not inspect "+safeRel(opts, path)+": "+walkErr.Error())
			return nil
		}
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		relPath = filepath.ToSlash(relPath)
		if relPath == "." {
			return nil
		}
		matchPath := relPath
		if pathPrefix != "" {
			matchPath = pathPrefix + "/" + relPath
		}
		if d.IsDir() {
			if shouldSkipDir(matchPath) {
				surfaces = append(surfaces, skippedSurface(path, matchPath, scope, opts))
				return filepath.SkipDir
			}
			if shouldSummarizeDir(matchPath) {
				surfaces = append(surfaces, summarizeDir(path, matchPath, scope, opts))
				return filepath.SkipDir
			}
			return nil
		}
		for _, rule := range rules {
			if !runtimeAllowed(opts.Runtime, rule.Runtime) || !scopeAllowed(scope, rule.Scope) {
				continue
			}
			if !rule.Matches(matchPath) {
				continue
			}
			info, _ := d.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			sensitiveNameCount := 0
			if rule.HandlingMode == "summarize" && credentialLikeName(matchPath) {
				sensitiveNameCount = 1
			}
			surfaces = append(surfaces, model.Surface{
				ID:                 surfaceID(rule.Runtime, rule.Kind, safeRel(opts, path)),
				Path:               path,
				Runtime:            rule.Runtime,
				Scope:              scope,
				Category:           rule.Category,
				Kind:               rule.Kind,
				HandlingMode:       rule.HandlingMode,
				Source:             safeRel(opts, path),
				Summary:            rule.Summary,
				ApproxBytes:        size,
				SensitiveNameCount: sensitiveNameCount,
			})
		}
		return nil
	})
	if err != nil {
		warnings = append(warnings, "surface discovery failed for "+safeRel(opts, root)+": "+err.Error())
	}
	return surfaces, warnings
}

func roots(opts Options) []struct {
	path   string
	scope  string
	prefix string
} {
	if opts.Mode == "endpoint" {
		return []struct {
			path   string
			scope  string
			prefix string
		}{
			{filepath.Join(opts.HomePath, ".claude"), "endpoint", ".claude"},
			{filepath.Join(opts.HomePath, ".codex"), "endpoint", ".codex"},
		}
	}
	return []struct {
		path   string
		scope  string
		prefix string
	}{{opts.RepoPath, "repo", ""}}
}

func shouldSkipDir(relPath string) bool {
	first := strings.Split(relPath, "/")[0]
	switch first {
	case ".git", "node_modules", "dist", "build", "target", "vendor", ".cache", ".venv", "venv", "__pycache__":
		return true
	default:
		return false
	}
}

func shouldSummarizeDir(relPath string) bool {
	return relPath == ".claude/tasks" ||
		strings.HasPrefix(relPath, ".claude/tasks/") ||
		relPath == ".claude/file-history" ||
		strings.HasPrefix(relPath, ".claude/file-history/") ||
		relPath == ".claude/paste-cache" ||
		strings.HasPrefix(relPath, ".claude/paste-cache/") ||
		relPath == ".codex/browser/sessions" ||
		strings.HasPrefix(relPath, ".codex/browser/sessions/")
}

func skippedSurface(path, relPath, scope string, opts Options) model.Surface {
	return model.Surface{
		ID:           surfaceID("generic", "skipped-directory", safeRel(opts, path)),
		Path:         path,
		Runtime:      "generic",
		Scope:        scope,
		Category:     "skipped",
		Kind:         "skipped-directory",
		HandlingMode: "skip",
		Source:       safeRel(opts, path),
		Summary:      "Directory skipped during AI surface discovery: " + relPath,
	}
}

func summarizeDir(path, relPath, scope string, opts Options) model.Surface {
	files, bytes, sensitiveNames := summarizePath(path)
	runtime := "claude"
	kind := "claude-private-context"
	if strings.HasPrefix(relPath, ".codex/") {
		runtime = "codex"
		kind = "codex-private-context"
	}
	return model.Surface{
		ID:                 surfaceID(runtime, kind, safeRel(opts, path)),
		Path:               path,
		Runtime:            runtime,
		Scope:              scope,
		Category:           "history-cache",
		Kind:               kind,
		HandlingMode:       "summarize",
		Source:             safeRel(opts, path),
		Summary:            "Private context surface summarized; contents were not inspected or emitted.",
		ApproxBytes:        bytes,
		FileCount:          files,
		SensitiveNameCount: sensitiveNames,
	}
}

func summarizePath(path string) (int, int64, int) {
	files := 0
	var bytes int64
	sensitiveNames := 0
	_ = filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files++
		if credentialLikeName(path) {
			sensitiveNames++
		}
		if info, statErr := d.Info(); statErr == nil {
			bytes += info.Size()
		}
		return nil
	})
	return files, bytes, sensitiveNames
}

func runtimeAllowed(selected, runtime string) bool {
	if selected == "" || selected == "all" || runtime == "generic" || runtime == "mcp" {
		return true
	}
	return selected == runtime
}

func scopeAllowed(actual, rule string) bool {
	return rule == "" || rule == "repo" || actual == rule
}

func dedupe(in []model.Surface) []model.Surface {
	seen := map[string]bool{}
	var out []model.Surface
	for _, surface := range in {
		key := surface.ID + "|" + surface.Source + "|" + surface.Kind
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, surface)
	}
	return out
}

func surfaceID(runtime, kind, source string) string {
	h := sha256.Sum256([]byte(runtime + "|" + kind + "|" + source))
	return "surface:" + runtime + ":" + kind + ":" + hex.EncodeToString(h[:])[:12]
}

func safeRel(opts Options, path string) string {
	if opts.IncludeSensitivePaths {
		return filepath.Clean(path)
	}
	if opts.BasePath != "" {
		if r, err := filepath.Rel(opts.BasePath, path); err == nil && !strings.HasPrefix(r, "..") {
			return filepath.ToSlash(r)
		}
	}
	clean := filepath.Clean(path)
	h := sha256.Sum256([]byte(clean))
	return "redacted-path-" + hex.EncodeToString(h[:])[:12]
}

func exact(want string) func(string) bool {
	return func(path string) bool { return path == want }
}

func prefix(want string) func(string) bool {
	return func(path string) bool { return strings.HasPrefix(path, want) }
}

func suffix(want string) func(string) bool {
	return func(path string) bool { return strings.HasSuffix(path, want) }
}

func prefixSuffix(pre, suf string) func(string) bool {
	return func(path string) bool { return strings.HasPrefix(path, pre) && strings.HasSuffix(path, suf) }
}

func containsSegmentAndSuffix(segment, suf string) func(string) bool {
	return func(path string) bool { return strings.Contains(path, segment) && strings.HasSuffix(path, suf) }
}

func anyOf(matchers ...func(string) bool) func(string) bool {
	return func(path string) bool {
		for _, matcher := range matchers {
			if matcher(path) {
				return true
			}
		}
		return false
	}
}

func secretLike(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == ".env" ||
		strings.HasPrefix(base, ".env.") ||
		base == "secrets.env" ||
		strings.HasSuffix(base, ".pem") ||
		strings.HasSuffix(base, ".key") ||
		base == ".npmrc" ||
		base == ".netrc" ||
		base == "id_rsa" ||
		base == "id_ed25519"
}

func credentialLikeName(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == ".env" ||
		strings.HasPrefix(base, ".env.") ||
		base == "secrets.env" ||
		strings.HasSuffix(base, ".pem") ||
		strings.HasSuffix(base, ".key") ||
		base == ".npmrc" ||
		base == ".netrc" ||
		base == "id_rsa" ||
		base == "id_ed25519" ||
		strings.Contains(base, "credential") ||
		strings.Contains(base, "api_key") ||
		strings.Contains(base, "api-key") ||
		strings.Contains(base, "secret") ||
		strings.Contains(base, "token")
}
