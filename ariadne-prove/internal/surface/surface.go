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
	if opts.Mode == "endpoint" {
		found, fileWarnings := discoverEndpointFiles(opts)
		surfaces = append(surfaces, found...)
		warnings = append(warnings, fileWarnings...)
		found, boundaryWarnings := discoverEndpointBoundaryIndicators(opts)
		surfaces = append(surfaces, found...)
		warnings = append(warnings, boundaryWarnings...)
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

		{Runtime: "cursor", Scope: "repo", Category: "runtime-config", Kind: "cursor-settings", HandlingMode: "parse", Summary: "Cursor settings can configure AI coding behavior, permissions, and tool posture.", Matches: anyOf(exact(".cursor/settings.json"), exact(".cursor/config.json"))},
		{Runtime: "cursor", Scope: "repo", Category: "trust-input", Kind: "cursor-rules", HandlingMode: "parse", Summary: "Cursor rules can influence AI coding behavior.", Matches: anyOf(exact(".cursorrules"), prefix(".cursor/rules/"))},
		{Runtime: "cursor", Scope: "repo", Category: "mcp-tool-config", Kind: "cursor-mcp-config", HandlingMode: "parse", Summary: "Cursor MCP config declares model-callable tools.", Matches: exact(".cursor/mcp.json")},
		{Runtime: "cursor", Scope: "repo", Category: "history-cache", Kind: "cursor-private-context", HandlingMode: "summarize", Summary: "Cursor private context or cache may contain prompts, indexed code, or local context; contents are not emitted.", Matches: anyOf(prefix(".cursor/chats/"), prefix(".cursor/history/"), prefix(".cursor/cache/"), prefix(".cursor/index/"))},

		{Runtime: "windsurf", Scope: "repo", Category: "runtime-config", Kind: "windsurf-settings", HandlingMode: "parse", Summary: "Windsurf settings can configure AI coding behavior, permissions, and tool posture.", Matches: anyOf(exact(".windsurf/settings.json"), exact(".windsurf/config.json"))},
		{Runtime: "windsurf", Scope: "repo", Category: "trust-input", Kind: "windsurf-rules", HandlingMode: "parse", Summary: "Windsurf rules can influence AI coding behavior.", Matches: anyOf(exact(".windsurfrules"), prefix(".windsurf/rules/"))},
		{Runtime: "windsurf", Scope: "repo", Category: "mcp-tool-config", Kind: "windsurf-mcp-config", HandlingMode: "parse", Summary: "Windsurf MCP config declares model-callable tools.", Matches: exact(".windsurf/mcp.json")},
		{Runtime: "windsurf", Scope: "repo", Category: "history-cache", Kind: "windsurf-private-context", HandlingMode: "summarize", Summary: "Windsurf private context or cache may contain prompts, indexed code, or local context; contents are not emitted.", Matches: anyOf(prefix(".windsurf/chats/"), prefix(".windsurf/conversations/"), prefix(".windsurf/history/"), prefix(".windsurf/cache/"), prefix(".windsurf/index/"))},

		{Runtime: "continue", Scope: "repo", Category: "runtime-config", Kind: "continue-config", HandlingMode: "parse", Summary: "Continue config can declare models, context providers, MCP servers, tools, and runtime posture.", Matches: anyOf(exact(".continue/config.json"), exact(".continue/config.yaml"), exact(".continue/config.yml"), exact(".continue/config.ts"), prefixSuffix(".continue/assistants/", ".yaml"), prefixSuffix(".continue/assistants/", ".yml"))},
		{Runtime: "continue", Scope: "repo", Category: "trust-input", Kind: "continue-rules", HandlingMode: "parse", Summary: "Continue rule or instruction files can influence AI coding behavior.", Matches: anyOf(exact(".continuerules"), prefixSuffix(".continue/rules/", ".md"), prefixSuffix(".continue/rules/", ".mdc"))},
		{Runtime: "continue", Scope: "repo", Category: "mcp-tool-config", Kind: "continue-mcp-config", HandlingMode: "parse", Summary: "Continue MCP config declares model-callable tools.", Matches: anyOf(exact(".continue/mcp.json"), exact(".continue/mcpServers.json"), prefixSuffix(".continue/mcpServers/", ".json"))},
		{Runtime: "continue", Scope: "repo", Category: "history-cache", Kind: "continue-private-context", HandlingMode: "summarize", Summary: "Continue private context, sessions, or indexes may contain prompts, code context, or pasted material; contents are not emitted.", Matches: anyOf(prefix(".continue/sessions/"), prefix(".continue/dev_data/"), prefix(".continue/cache/"), prefix(".continue/index/"))},

		{Runtime: "aider", Scope: "repo", Category: "runtime-config", Kind: "aider-config", HandlingMode: "parse", Summary: "Aider config can declare model, edit, auto-approval, and command posture.", Matches: anyOf(exact(".aider.conf.yml"), exact(".aider.conf.yaml"), exact(".aider.conf"), exact(".aider.model.settings.yml"), exact(".aider.model.metadata.json"))},
		{Runtime: "aider", Scope: "repo", Category: "policy", Kind: "aider-ignore", HandlingMode: "parse", Summary: "Aider ignore policy can constrain files available to the agent.", Matches: exact(".aiderignore")},
		{Runtime: "aider", Scope: "repo", Category: "history-cache", Kind: "aider-private-context", HandlingMode: "summarize", Summary: "Aider chat, input, or repository-map cache may contain prompts or code context; contents are not emitted.", Matches: anyOf(exact(".aider.chat.history.md"), exact(".aider.input.history"), prefix(".aider.tags.cache"), prefix(".aider/cache/"))},

		{Runtime: "gemini", Scope: "repo", Category: "runtime-config", Kind: "gemini-settings", HandlingMode: "parse", Summary: "Gemini CLI settings can configure AI coding behavior, tools, and runtime posture.", Matches: anyOf(exact(".gemini/settings.json"), exact(".gemini/settings.local.json"))},
		{Runtime: "gemini", Scope: "repo", Category: "trust-input", Kind: "gemini-md", HandlingMode: "parse", Summary: "GEMINI.md can influence Gemini CLI behavior.", Matches: anyOf(exact("GEMINI.md"), exact(".gemini/GEMINI.md"))},
		{Runtime: "gemini", Scope: "repo", Category: "command-hook", Kind: "gemini-command", HandlingMode: "parse", Summary: "Gemini CLI command files can influence repeatable agent workflows.", Matches: anyOf(prefixSuffix(".gemini/commands/", ".toml"), prefixSuffix(".gemini/commands/", ".md"))},
		{Runtime: "gemini", Scope: "repo", Category: "plugin-skill", Kind: "gemini-extension", HandlingMode: "parse", Summary: "Gemini CLI extension manifests declare extension surfaces.", Matches: anyOf(prefixSuffix(".gemini/extensions/", "gemini-extension.json"), prefixSuffix(".gemini/extensions/", "extension.json"))},
		{Runtime: "gemini", Scope: "repo", Category: "history-cache", Kind: "gemini-private-context", HandlingMode: "summarize", Summary: "Gemini CLI history, temp, or session context may contain prompts, code context, or pasted material; contents are not emitted.", Matches: anyOf(prefix(".gemini/history/"), prefix(".gemini/tmp/"), prefix(".gemini/sessions/"))},

		{Runtime: "opencode", Scope: "repo", Category: "runtime-config", Kind: "opencode-config", HandlingMode: "parse", Summary: "OpenCode config can declare model, provider, tool, and runtime posture.", Matches: anyOf(exact("opencode.json"), exact("opencode.jsonc"), exact("opencode.yml"), exact("opencode.yaml"), exact(".opencode.json"), exact(".opencode/config.json"), exact(".opencode/config.jsonc"), exact(".opencode/config.yml"), exact(".opencode/config.yaml"))},
		{Runtime: "opencode", Scope: "repo", Category: "history-cache", Kind: "opencode-private-context", HandlingMode: "summarize", Summary: "OpenCode session or cache context may contain prompts, code context, or pasted material; contents are not emitted.", Matches: anyOf(prefix(".opencode/sessions/"), prefix(".opencode/cache/"))},

		{Runtime: "generic", Scope: "repo", Category: "trust-input", Kind: "claude-md", HandlingMode: "parse", Summary: "CLAUDE.md can influence local coding-agent behavior.", Matches: exact("CLAUDE.md")},
		{Runtime: "generic", Scope: "repo", Category: "trust-input", Kind: "agents-md", HandlingMode: "parse", Summary: "AGENTS.md can influence local coding-agent behavior.", Matches: exact("AGENTS.md")},
		{Runtime: "generic", Scope: "repo", Category: "trust-input", Kind: "nested-agents-md", HandlingMode: "parse", Summary: "Nested AGENTS.md can influence agent behavior in a subtree.", Matches: suffix("/AGENTS.md")},
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

func discoverEndpointFiles(opts Options) ([]model.Surface, []string) {
	if opts.HomePath == "" {
		return nil, nil
	}
	var surfaces []model.Surface
	var warnings []string
	for _, candidate := range endpointFileCandidates() {
		path := filepath.Join(opts.HomePath, filepath.FromSlash(candidate))
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		found, fileWarnings := discoverFile(path, candidate, "endpoint", info.Size(), opts)
		surfaces = append(surfaces, found...)
		warnings = append(warnings, fileWarnings...)
	}
	return surfaces, warnings
}

func discoverEndpointBoundaryIndicators(opts Options) ([]model.Surface, []string) {
	if opts.HomePath == "" {
		return nil, nil
	}
	var surfaces []model.Surface
	var warnings []string
	entries, err := os.ReadDir(opts.HomePath)
	if err != nil {
		return nil, []string{"could not inspect endpoint boundary indicators in " + safeRel(opts, opts.HomePath) + ": " + err.Error()}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !secretLike(name) {
			continue
		}
		path := filepath.Join(opts.HomePath, name)
		found, fileWarnings := discoverEndpointBoundaryFile(path, name, opts)
		surfaces = append(surfaces, found...)
		warnings = append(warnings, fileWarnings...)
	}
	for _, dir := range []string{".ssh"} {
		root := filepath.Join(opts.HomePath, filepath.FromSlash(dir))
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			matchPath := dir + "/" + entry.Name()
			if !secretLike(matchPath) {
				continue
			}
			path := filepath.Join(root, entry.Name())
			found, fileWarnings := discoverEndpointBoundaryFile(path, matchPath, opts)
			surfaces = append(surfaces, found...)
			warnings = append(warnings, fileWarnings...)
		}
	}
	for _, candidate := range endpointNestedBoundaryCandidates() {
		path := filepath.Join(opts.HomePath, filepath.FromSlash(candidate))
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		found, fileWarnings := discoverFile(path, candidate, "endpoint", info.Size(), opts)
		surfaces = append(surfaces, found...)
		warnings = append(warnings, fileWarnings...)
	}
	return surfaces, warnings
}

func discoverEndpointBoundaryFile(path string, matchPath string, opts Options) ([]model.Surface, []string) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil, nil
	}
	return discoverFile(path, matchPath, "endpoint", info.Size(), opts)
}

func endpointNestedBoundaryCandidates() []string {
	return []string{
		".aws/credentials",
		".config/gcloud/application_default_credentials.json",
		".docker/config.json",
		".kube/config",
	}
}

func endpointFileCandidates() []string {
	return []string{
		".aider.conf.yml",
		".aider.conf.yaml",
		".aider.conf",
		".aider.chat.history.md",
		".aider.input.history",
		".aider.model.settings.yml",
		".aider.model.metadata.json",
		".cursorrules",
		".windsurfrules",
		"GEMINI.md",
		"opencode.json",
		"opencode.jsonc",
		"opencode.yml",
		"opencode.yaml",
		".opencode.json",
	}
}

func discoverFile(path, matchPath, scope string, size int64, opts Options) ([]model.Surface, []string) {
	var surfaces []model.Surface
	var warnings []string
	for _, rule := range Registry() {
		if !runtimeAllowed(opts.Runtime, rule.Runtime) || !scopeAllowed(scope, rule.Scope) {
			continue
		}
		if !rule.Matches(matchPath) {
			continue
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
			{filepath.Join(opts.HomePath, ".cursor"), "endpoint", ".cursor"},
			{filepath.Join(opts.HomePath, ".windsurf"), "endpoint", ".windsurf"},
			{filepath.Join(opts.HomePath, ".continue"), "endpoint", ".continue"},
			{filepath.Join(opts.HomePath, ".aider"), "endpoint", ".aider"},
			{filepath.Join(opts.HomePath, ".gemini"), "endpoint", ".gemini"},
			{filepath.Join(opts.HomePath, ".opencode"), "endpoint", ".opencode"},
			{filepath.Join(opts.HomePath, ".ariadne"), "endpoint", ".ariadne"},
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
		strings.HasPrefix(relPath, ".codex/browser/sessions/") ||
		relPath == ".codex/sessions" ||
		strings.HasPrefix(relPath, ".codex/sessions/") ||
		relPath == ".cursor/chats" ||
		strings.HasPrefix(relPath, ".cursor/chats/") ||
		relPath == ".cursor/history" ||
		strings.HasPrefix(relPath, ".cursor/history/") ||
		relPath == ".cursor/cache" ||
		strings.HasPrefix(relPath, ".cursor/cache/") ||
		relPath == ".cursor/index" ||
		strings.HasPrefix(relPath, ".cursor/index/") ||
		relPath == ".windsurf/chats" ||
		strings.HasPrefix(relPath, ".windsurf/chats/") ||
		relPath == ".windsurf/conversations" ||
		strings.HasPrefix(relPath, ".windsurf/conversations/") ||
		relPath == ".windsurf/history" ||
		strings.HasPrefix(relPath, ".windsurf/history/") ||
		relPath == ".windsurf/cache" ||
		strings.HasPrefix(relPath, ".windsurf/cache/") ||
		relPath == ".windsurf/index" ||
		strings.HasPrefix(relPath, ".windsurf/index/") ||
		relPath == ".continue/sessions" ||
		strings.HasPrefix(relPath, ".continue/sessions/") ||
		relPath == ".continue/dev_data" ||
		strings.HasPrefix(relPath, ".continue/dev_data/") ||
		relPath == ".continue/cache" ||
		strings.HasPrefix(relPath, ".continue/cache/") ||
		relPath == ".continue/index" ||
		strings.HasPrefix(relPath, ".continue/index/") ||
		relPath == ".aider/cache" ||
		strings.HasPrefix(relPath, ".aider/cache/") ||
		relPath == ".gemini/history" ||
		strings.HasPrefix(relPath, ".gemini/history/") ||
		relPath == ".gemini/tmp" ||
		strings.HasPrefix(relPath, ".gemini/tmp/") ||
		relPath == ".gemini/sessions" ||
		strings.HasPrefix(relPath, ".gemini/sessions/") ||
		relPath == ".opencode/sessions" ||
		strings.HasPrefix(relPath, ".opencode/sessions/") ||
		relPath == ".opencode/cache" ||
		strings.HasPrefix(relPath, ".opencode/cache/")
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
	} else if strings.HasPrefix(relPath, ".cursor/") {
		runtime = "cursor"
		kind = "cursor-private-context"
	} else if strings.HasPrefix(relPath, ".windsurf/") {
		runtime = "windsurf"
		kind = "windsurf-private-context"
	} else if strings.HasPrefix(relPath, ".continue/") {
		runtime = "continue"
		kind = "continue-private-context"
	} else if strings.HasPrefix(relPath, ".aider/") {
		runtime = "aider"
		kind = "aider-private-context"
	} else if strings.HasPrefix(relPath, ".gemini/") {
		runtime = "gemini"
		kind = "gemini-private-context"
	} else if strings.HasPrefix(relPath, ".opencode/") {
		runtime = "opencode"
		kind = "opencode-private-context"
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
	normalized := strings.ToLower(filepath.ToSlash(path))
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
		normalized == ".aws/credentials" ||
		normalized == ".config/gcloud/application_default_credentials.json" ||
		normalized == ".docker/config.json" ||
		normalized == ".kube/config"
}

func credentialLikeName(path string) bool {
	if secretLike(path) {
		return true
	}
	base := strings.ToLower(filepath.Base(path))
	return strings.Contains(base, "credential") ||
		strings.Contains(base, "api_key") ||
		strings.Contains(base, "api-key") ||
		strings.Contains(base, "secret") ||
		strings.Contains(base, "token")
}
