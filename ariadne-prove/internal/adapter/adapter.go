package adapter

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/agentconfig"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/surface"
)

type Options struct {
	RepoPath              string
	HomePath              string
	Mode                  string
	Runtime               string
	StoryDir              string
	IncludeSensitivePaths bool
}

var (
	riskyInstructionPattern      = regexp.MustCompile(`(?i)(read\s+\.env|read\s+.*secret|secret|token|always approve|ignore security|bypass|send\s+.*secret|send\s+.*token|private key|\.ssh|\.aws)`)
	delegationInstructionPattern = regexp.MustCompile(`(?i)(sub[- ]?agent|delegate\s+to|handoff\s+to|worker\s+agent|manager\s+agent|spawn\s+agent|parallel\s+agents|task\s+tool|agent\s+team)`)
	inlineCredentialPattern      = regexp.MustCompile(`(?i)(api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|password)\s*[:=]`)
)

func Collect(opts Options) model.Collection {
	var c model.Collection
	base := opts.StoryDir
	if base == "" {
		base = opts.RepoPath
	}
	surfaces, warnings := surface.Discover(surface.Options{
		RepoPath:              opts.RepoPath,
		HomePath:              opts.HomePath,
		Mode:                  opts.Mode,
		Runtime:               opts.Runtime,
		BasePath:              base,
		IncludeSensitivePaths: opts.IncludeSensitivePaths,
	})
	c.Surfaces = surfaces
	c.Warnings = append(c.Warnings, warnings...)
	for _, s := range surfaces {
		collectSurface(&c, opts, s)
	}
	if opts.Mode == "endpoint" && !hasBoundary(&c, "boundary:developer-secret-boundary") && len(c.Authorities) > 0 {
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:developer-secret-boundary",
			Kind:     "secret-like-files",
			Abstract: true,
			Summary:  "Developer machines commonly hold secret-like files and credential caches near local agents.",
		})
	}
	return c
}

func hasBoundary(c *model.Collection, id string) bool {
	for _, boundary := range c.Boundaries {
		if boundary.ID == id {
			return true
		}
	}
	return false
}

func collectSurface(c *model.Collection, opts Options, s model.Surface) {
	c.Facts = appendUniqueFact(c.Facts, model.Fact{
		ID:            "fact:" + trimPrefix(s.ID, "surface:"),
		Type:          s.Category,
		Runtime:       s.Runtime,
		Scope:         s.Scope,
		Source:        s.Source,
		HandlingMode:  s.HandlingMode,
		EvidenceGrade: gradeForSurface(s),
		Redaction:     redactionForSurface(s),
		Summary:       s.Summary,
		Limitations:   limitationsForSurface(s),
	})
	collectRuntimeSurfaceEvidence(c, s)

	switch s.HandlingMode {
	case "skip", "ignore":
		return
	case "summarize":
		collectSummarySurface(c, s)
		return
	case "boundary_indicator":
		collectBoundaryIndicator(c, s)
		return
	}

	switch s.Kind {
	case "claude-md", "agents-md", "nested-agents-md", "cursor-rules", "windsurf-rules", "continue-rules", "gemini-md", "codex-agents-md", "copilot-instructions", "copilot-path-instructions", "cline-rules", "roo-rules", "claude-command", "gemini-command", "claude-project-memory":
		collectInstruction(c, s)
	case "claude-subagent":
		collectDelegationSurface(c, s)
	case "codex-config", "codex-requirements":
		collectCodexConfig(c, s)
	case "claude-settings", "claude-local-settings":
		collectClaudeSettings(c, s)
	case "cursor-settings", "windsurf-settings", "continue-config", "aider-config", "gemini-settings", "opencode-config", "vscode-settings":
		collectGenericAgentConfig(c, s)
	case "aider-ignore", "cline-ignore":
		collectIgnorePolicy(c, s)
	case "mcp-config", "claude-mcp-config", "cursor-mcp-config", "windsurf-mcp-config", "continue-mcp-config", "vscode-mcp-config", "cline-mcp-config", "roo-mcp-config":
		collectMCPConfig(c, s)
	case "mcp-policy":
		collectMCPPolicy(c, s)
	case "network-policy":
		collectNetworkPolicy(c, s)
	case "egress-policy":
		collectEgressPolicy(c, s)
	case "agent-policy":
		collectAgentPolicy(c, s)
	case "tool-policy":
		collectToolPolicy(c, s)
	case "delegation-policy":
		collectDelegationPolicy(c, s)
	case "input-policy":
		collectInputPolicy(c, s)
	case "identity-policy":
		collectIdentityPolicy(c, s)
	case "authorization-policy":
		collectAuthorizationPolicy(c, s)
	case "workload-policy":
		collectWorkloadPolicy(c, s)
	case "resource-policy":
		collectResourcePolicy(c, s)
	case "memory-policy":
		collectMemoryPolicy(c, s)
	case "integrity-policy":
		collectIntegrityPolicy(c, s)
	case "observability-policy":
		collectObservabilityPolicy(c, s)
	case "response-policy":
		collectResponsePolicy(c, s)
	case "governance-policy":
		collectGovernancePolicy(c, s)
	case "output-policy":
		collectOutputPolicy(c, s)
	case "supply-chain-policy":
		collectSupplyChainPolicy(c, s)
	case "ai-bom":
		collectAIBOM(c, s)
	case "opentelemetry-config":
		collectTelemetryConfig(c, s)
	case "claude-plugin-config", "claude-installed-plugins", "gemini-extension":
		collectPluginSurface(c, s)
	case "claude-remote-settings", "claude-policy-limits":
		collectManagedControlSurface(c, s)
	case "github-actions-workflow":
		collectGitHubActionsWorkflow(c, s)
	case "gitlab-ci-pipeline":
		collectGitLabCIWorkflow(c, s)
	}
	_ = opts
}

func collectRuntimeSurfaceEvidence(c *model.Collection, s model.Surface) {
	if s.HandlingMode != "parse" {
		return
	}
	runtime := runtimeForSurface(s)
	if runtime == "" {
		return
	}
	summary := displayRuntime(runtime) + " surface evidence was found."
	if s.Category == "trust-input" {
		summary = displayRuntime(runtime) + " instruction or rule surface evidence was found; authority is not inferred from this surface alone."
	}
	c.Runtimes = appendUniqueRuntime(c.Runtimes, model.RuntimeEvidence{
		ID:      "runtime:" + runtime,
		Kind:    runtime,
		Source:  s.Source,
		Scope:   s.Scope,
		Summary: summary,
	})
}

func collectInstruction(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	risky := riskyInstructionPattern.Match(data)
	id := "trustinput:repo-instruction"
	kind := "repo-instruction"
	summary := "Agent instruction surface can influence local coding-agent behavior."
	if s.Kind == "claude-project-memory" {
		id = "trustinput:agent-memory"
		kind = "agent-memory"
		summary = "Agent memory surface can influence future coding-agent behavior."
	}
	if s.Category == "command-hook" {
		id = "trustinput:agent-command"
		kind = "agent-command"
		summary = "Agent command surface can influence repeatable coding-agent workflows."
	}
	if risky {
		summary = "Agent instruction surface contains secret-seeking or permission-bypass guidance."
	}
	c.TrustInputs = appendUniqueTrustInput(c.TrustInputs, model.TrustInput{
		ID:      id,
		Kind:    kind,
		Runtime: runtimeForTrustInput(s),
		Source:  s.Source,
		Risky:   risky,
		Summary: summary,
	})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:"+id, "trust-input", s.Source, "declared", "Agent instruction surface was parsed without emitting raw content."))
	lower := strings.ToLower(string(data))
	if s.Category == "command-hook" && containsAny(lower, []string{"bash", "shell", "exec", "npm ", "npx ", "python "}) {
		runtime := runtimeForTrustInput(s)
		c.Tools = appendUniqueTool(c.Tools, model.Tool{ID: "tool:agent-command-shell", Kind: "agent-command-shell", Runtime: runtime, Source: s.Source, Risky: true, Summary: displayRuntime(runtime) + " command surface appears able to steer shell or command execution."})
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:local-code-execution", Kind: "local-code-execution", Runtime: runtime, Source: s.Source, Summary: "Command surface can steer local command execution when invoked by the agent."})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:developer-execution-boundary", Kind: "developer-execution-boundary", Abstract: true, Summary: "Developer user execution context and local machine privileges."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:agent-command-shell", "tool", s.Source, "declared", "Agent command content was inspected for command-execution indicators."))
	}
	if s.Category == "command-hook" && containsExternalCommunication(lower) {
		runtime := runtimeForTrustInput(s)
		addExternalCommunication(c, runtime, s.Source, displayRuntime(runtime)+" command surface contains external communication indicators.")
	}
	if delegationInstructionPattern.MatchString(lower) {
		addDelegationSurface(c, runtimeForTrustInput(s), s.Source, "Agent instruction surface includes delegation, subagent, handoff, or worker-agent language.")
	}
}

func collectDelegationSurface(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	summary := "Claude subagent definition can receive delegated work from the parent agent context."
	if riskyInstructionPattern.Match(data) {
		summary = "Claude subagent definition contains secret-seeking or permission-bypass guidance."
	}
	addDelegationSurface(c, "claude", s.Source, summary)
	c.TrustInputs = appendUniqueTrustInput(c.TrustInputs, model.TrustInput{
		ID:      "trustinput:agent-delegation",
		Kind:    "agent-delegation",
		Runtime: "claude",
		Source:  s.Source,
		Risky:   riskyInstructionPattern.Match(data),
		Summary: "Subagent definition can influence delegated agent behavior.",
	})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:trustinput:agent-delegation", "trust-input", s.Source, "declared", "Subagent definition was parsed without emitting raw content."))
}

func addDelegationSurface(c *model.Collection, runtime, source, summary string) {
	c.Tools = appendUniqueTool(c.Tools, model.Tool{
		ID:      "tool:agent-delegation",
		Kind:    "agent-delegation",
		Runtime: runtime,
		Source:  source,
		Risky:   true,
		Summary: summary,
	})
	c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
		ID:      "authority:delegated-agent-authority",
		Kind:    "delegated-agent-authority",
		Runtime: runtime,
		Source:  source,
		Summary: "Delegated or sub-agent work can inherit parent agent authority unless scoped.",
	})
	c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
		ID:       "boundary:agent-delegation-boundary",
		Kind:     "agent-delegation-boundary",
		Source:   source,
		Abstract: true,
		Summary:  "Trust boundary between initiating agent, delegated agent, and original user intent.",
	})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:agent-delegation", "tool", source, "declared", "Agent delegation surface was collected without invoking delegated agents."))
}

func runtimeForTrustInput(s model.Surface) string {
	if s.Kind == "claude-command" || s.Kind == "claude-project-memory" {
		return "claude"
	}
	if s.Runtime != "" && s.Runtime != "generic" && s.Runtime != "mcp" {
		return s.Runtime
	}
	return ""
}

// collectCodexConfig parses .codex/config.toml (or requirements.toml) with
// agentconfig.ParseCodexConfig and grades authorities/controls/tools
// strictly off the parsed struct fields — no keyword scanning of raw text.
// See docs/parser-spec.md "Codex -> authorities / controls / tool".
func collectCodexConfig(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	source := s.Source
	c.Runtimes = appendUniqueRuntime(c.Runtimes, model.RuntimeEvidence{
		ID:      "runtime:codex",
		Kind:    "codex",
		Source:  source,
		Scope:   s.Scope,
		Summary: "Codex configuration evidence was found.",
	})
	configID := "config:codex-" + s.Scope
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:"+configID, "config", source, "declared", "Codex config source was collected."))

	cfg, ok := agentconfig.ParseCodexConfig(data)
	if !ok {
		return
	}
	cfg.IsRequirements = s.Kind == "codex-requirements"

	broadLocal := cfg.SandboxMode == "danger-full-access" || cfg.ApprovalPolicy == "never"
	if broadLocal {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:broad-local", Kind: "broad-local", Runtime: "codex", Source: source, Summary: "Codex config declares broad local authority or bypass posture."})
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: "codex", Source: source, Summary: "Codex can read files in the configured workspace."})
	} else if cfg.SandboxMode == "read-only" || cfg.SandboxMode == "workspace-write" || cfg.IsRequirements {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: "codex", Source: source, Summary: "Codex has normal file-read authority in the configured workspace."})
	}

	if cfg.NetworkAccess != nil && *cfg.NetworkAccess {
		addExternalCommunication(c, "codex", source, "Codex config declares external network access.")
	}
	if cfg.NetworkAccess != nil && !*cfg.NetworkAccess {
		addControl(c, "control:network-restricted", "network-restricted", "codex", source, "Codex config restricts external network communication.")
	}
	if codexDeniesSecretPath(cfg) {
		addControl(c, "control:deny-secret-read", "deny-secret-read", "codex", source, "Codex deny-read policy covers secret-like paths.")
	}
	scopedSandbox := cfg.SandboxMode == "read-only" || cfg.SandboxMode == "workspace-write"
	scopedApproval := cfg.ApprovalPolicy == "on-request" || cfg.ApprovalPolicy == "on-failure" || cfg.ApprovalPolicy == "untrusted"
	if scopedSandbox || scopedApproval {
		addControl(c, "control:scoped-permissions", "scoped-permissions", "codex", source, "Codex config declares scoped sandbox or approval permissions.")
	}
	if cfg.HasMCPServers {
		c.Tools = appendUniqueTool(c.Tools, model.Tool{ID: "tool:mcp-configured", Kind: "mcp-configured", Runtime: "codex", Source: source, Summary: "Codex config includes MCP/tool configuration."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:mcp-configured", "tool", source, "declared", "Codex MCP configuration surface was collected."))
	}
	if cfg.HasInlineCredential {
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:credential-material",
			Kind:     "credential-material",
			Source:   source,
			Abstract: false,
			Summary:  "Codex config contains an inline credential-named field; values are not emitted.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:credential-material", "boundary", source, "observed", "Inline credential field indicators were detected without emitting values."))
	}
}

func codexDeniesSecretPath(cfg agentconfig.CodexConfig) bool {
	for _, path := range cfg.DenyRead {
		if agentconfig.IsSecretLikePath(path) {
			return true
		}
	}
	return false
}

// collectClaudeSettings parses .claude/settings.json (or settings.local.json)
// with agentconfig.ParseClaudeSettings and grades authorities/boundaries/
// controls/external-communication strictly off the parsed struct fields —
// no keyword scanning of raw text. See docs/parser-spec.md "Claude ->
// authorities / boundaries / controls / external-communication".
func collectClaudeSettings(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	source := s.Source
	c.Runtimes = appendUniqueRuntime(c.Runtimes, model.RuntimeEvidence{
		ID:      "runtime:claude",
		Kind:    "claude",
		Source:  source,
		Scope:   s.Scope,
		Summary: "Claude Code settings evidence was found.",
	})
	configID := "config:claude-" + s.Scope
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:"+configID, "config", source, "declared", "Claude Code config source was collected."))

	cfg, ok := agentconfig.ParseClaudeSettings(data)
	if !ok {
		return
	}

	broadLocal := cfg.DefaultMode == "bypassPermissions" || (cfg.HasBroadBashAllow() && !cfg.HasBroadBashDeny())
	if broadLocal {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:broad-local", Kind: "broad-local", Runtime: "claude", Source: source, Summary: "Claude Code settings declare broad local authority or bypass posture."})
	}

	if broadLocal || cfg.DefaultMode == "acceptEdits" || claudeHasUndeniedAllowTool(cfg, "Read") {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: "claude", Source: source, Summary: "Claude Code can read files in the configured workspace."})
	}

	if broadLocal || claudeHasUndeniedAllowTool(cfg, "Bash") {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:local-code-execution", Kind: "local-code-execution", Runtime: "claude", Source: source, Summary: "Claude Code settings allow broad shell or local execution posture."})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:developer-execution-boundary", Kind: "developer-execution-boundary", Abstract: true, Summary: "Developer user execution context and local machine privileges."})
	}

	if claudeAllowsExternalCommunication(cfg) {
		addExternalCommunication(c, "claude", source, "Claude Code settings allow web, shell, or external communication posture.")
	}

	if claudeNetworkRestricted(cfg) {
		addControl(c, "control:network-restricted", "network-restricted", "claude", source, "Claude Code settings restrict web or external network communication.")
	}
	if cfg.HasSecretReadDeny() {
		addControl(c, "control:deny-secret-read", "deny-secret-read", "claude", source, "Claude Code deny/disallow policy covers secret-like paths.")
	}
	if (cfg.DefaultMode == "default" && len(cfg.Allow) > 0) || len(cfg.Deny) > 0 {
		addControl(c, "control:scoped-permissions", "scoped-permissions", "claude", source, "Claude Code settings declare scoped default-mode permissions.")
	}
	if cfg.DefaultMode == "default" && !cfg.HasBroadBashAllow() {
		addControl(c, "control:deny-by-default-permissions", "deny-by-default-permissions", "claude", source, "Claude Code settings run nothing without a prompt under default-mode permissions.")
	}
	if cfg.HasInlineCredential {
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:credential-material",
			Kind:     "credential-material",
			Source:   source,
			Abstract: false,
			Summary:  "Claude Code settings contain an inline credential-named field; values are not emitted.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:credential-material", "boundary", source, "observed", "Inline credential field indicators were detected without emitting values."))
	}
}

// claudeHasUndeniedAllowTool reports whether allow contains a rule for tool
// that is not cancelled by a deny rule for the same tool (see
// claudeAllowRuleDenied for the cancellation semantics).
func claudeHasUndeniedAllowTool(cfg agentconfig.ClaudeSettings, tool string) bool {
	if !cfg.HasAllowTool(tool) {
		return false
	}
	for _, allow := range cfg.Allow {
		if !strings.EqualFold(allow.Tool, tool) {
			continue
		}
		if !claudeAllowRuleDenied(cfg, allow) {
			return true
		}
	}
	return false
}

// claudeAllowRuleDenied reports whether allow is cancelled by some deny rule
// for the same tool. Cancellation is bidirectional-aware but not symmetric:
// a deny rule cancels an allow rule for the same tool when the deny's scope
// is equal to the allow's scope, OR when the deny's scope is broad (*/empty)
// — a broad deny cancels any narrower allow of that tool. A narrow deny
// (e.g. Bash(git)) must NEVER cancel a broader allow (e.g. Bash(*)).
func claudeAllowRuleDenied(cfg agentconfig.ClaudeSettings, allow agentconfig.PermRule) bool {
	for _, deny := range cfg.Deny {
		if !strings.EqualFold(deny.Tool, allow.Tool) {
			continue
		}
		if deny.Scope == allow.Scope || agentconfig.IsBroadScope(deny.Scope) {
			return true
		}
	}
	return false
}

// claudeAllowsExternalCommunication reports whether Allow grants a
// WebFetch/WebSearch rule, or a broad Bash rule (shell -> curl/wget), that
// is not contradicted by a deny of the same tool/scope. Tools present only
// in Deny must never trigger external-communication authority.
func claudeAllowsExternalCommunication(cfg agentconfig.ClaudeSettings) bool {
	if claudeHasUndeniedAllowTool(cfg, "WebFetch") || claudeHasUndeniedAllowTool(cfg, "WebSearch") {
		return true
	}
	return cfg.HasBroadBashAllow() && !cfg.HasBroadBashDeny()
}

// claudeNetworkRestricted reports the control:network-restricted signal:
// an explicit deny of a network tool (with no offsetting allow of the same
// tool) is the strong signal. The conservative fallback signal is
// DefaultMode=="default" AND the config grants no external-communication
// authority at all.
//
// House rule #1 (no gameable verdicts): the fallback is defined as the
// literal negation of claudeAllowsExternalCommunication, not as "no
// WebFetch/WebSearch in allow" — a config with allow:["Bash(*)"] grants
// shell-mediated network egress (curl/wget) even though it names no web
// tool, and must not be credited with network-restricted merely because
// WebFetch/WebSearch are unlisted. This makes it structurally impossible
// for a single config to produce both authority:external-communication and
// control:network-restricted.
func claudeNetworkRestricted(cfg agentconfig.ClaudeSettings) bool {
	deniedWebFetch := cfg.HasDenyTool("WebFetch") && !cfg.HasAllowTool("WebFetch")
	deniedWebSearch := cfg.HasDenyTool("WebSearch") && !cfg.HasAllowTool("WebSearch")
	if deniedWebFetch || deniedWebSearch {
		return true
	}
	if cfg.DefaultMode == "default" && !claudeAllowsExternalCommunication(cfg) {
		return true
	}
	return false
}

func collectGenericAgentConfig(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	runtime := runtimeForSurface(s)
	if runtime == "" {
		return
	}
	source := s.Source
	display := displayRuntime(runtime)
	c.Runtimes = appendUniqueRuntime(c.Runtimes, model.RuntimeEvidence{
		ID:      "runtime:" + runtime,
		Kind:    runtime,
		Source:  source,
		Scope:   s.Scope,
		Summary: display + " configuration evidence was found.",
	})
	configID := "config:" + runtime + "-" + s.Scope
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:"+configID, "config", source, "declared", display+" config source was collected."))
	text := strings.ToLower(string(data))
	if broadLocalAgentConfig(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:broad-local", Kind: "broad-local", Runtime: runtime, Source: source, Summary: display + " config declares broad local authority, auto-approval, or bypass posture."})
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: runtime, Source: source, Summary: display + " can read files in the configured workspace or local context."})
	}
	if fileReadAgentConfig(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: runtime, Source: source, Summary: display + " config declares filesystem, workspace, or context-read posture."})
	}
	if localExecutionAgentConfig(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:local-code-execution", Kind: "local-code-execution", Runtime: runtime, Source: source, Summary: display + " config declares shell, terminal, interpreter, or local command posture."})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:developer-execution-boundary", Kind: "developer-execution-boundary", Abstract: true, Summary: "Developer user execution context and local machine privileges."})
	}
	if mcpConfigured(text) {
		c.Tools = appendUniqueTool(c.Tools, model.Tool{ID: "tool:mcp-configured", Kind: "mcp-configured", Runtime: runtime, Source: source, Summary: display + " config includes MCP/tool configuration."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:mcp-configured", "tool", source, "declared", display+" MCP/tool configuration surface was collected."))
	}
	collectRuntimeSecurityControls(c, runtime, source, text)
	collectToolIntegrityControls(c, runtime, source, text)
	collectResourceControls(c, runtime, source, text)
	collectConfigIntegrityControls(c, runtime, source, text)
	if networkEnabled(text) || containsExternalCommunication(text) {
		addExternalCommunication(c, runtime, source, display+" config declares external communication posture.")
	}
	if networkRestricted(text) {
		c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:network-restricted", Kind: "network-restricted", Runtime: runtime, Source: source, Summary: display + " config restricts external network communication."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:control:network-restricted", "control", source, "declared", "Network restriction control was collected."))
	}
	if declaresSecretDeny(text) {
		c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:deny-secret-read", Kind: "deny-secret-read", Runtime: runtime, Source: source, Summary: display + " deny/disallow policy covers secret-like paths."})
	}
}

func collectIgnorePolicy(c *model.Collection, s model.Surface) {
	if _, err := os.Stat(s.Path); err != nil {
		return
	}
	runtime := runtimeForSurface(s)
	if runtime == "" {
		runtime = "aider"
	}
	addControl(c, "control:scoped-permissions", "scoped-permissions", runtime, s.Source, displayRuntime(runtime)+" ignore policy exists and can constrain files available to the agent.")
}

func collectMCPConfig(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	type mcpServer struct {
		Type           string   `json:"type"`
		Command        string   `json:"command"`
		Args           []string `json:"args"`
		URL            string   `json:"url"`
		Disabled       bool     `json:"disabled"`
		SandboxEnabled bool     `json:"sandboxEnabled"`
		AlwaysAllow    []string `json:"alwaysAllow"`
	}
	var root struct {
		MCPServers map[string]mcpServer `json:"mcpServers"`
		Servers    map[string]mcpServer `json:"servers"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return
	}
	if runtime := runtimeForSurface(s); runtime != "" {
		c.Runtimes = appendUniqueRuntime(c.Runtimes, model.RuntimeEvidence{ID: "runtime:" + runtime, Kind: runtime, Source: s.Source, Scope: s.Scope, Summary: displayRuntime(runtime) + " MCP configuration evidence was found."})
	}
	servers := root.MCPServers
	if servers == nil {
		servers = map[string]mcpServer{}
	}
	for name, server := range root.Servers {
		servers[name] = server
	}
	for serverName, server := range servers {
		if server.Disabled {
			addControl(c, "control:tool-allowlist", "tool-allowlist", runtimeForSurface(s), s.Source, "MCP server "+serverName+" is disabled in configuration.")
			continue
		}
		commandLine := strings.TrimSpace(server.Command + " " + strings.Join(server.Args, " "))
		lower := strings.ToLower(commandLine)
		if commandLine == "" && server.URL != "" {
			commandLine = server.URL
			lower = strings.ToLower(server.URL)
		}
		packageLaunch := containsAny(lower, []string{"npx ", "uvx ", "npm ", "pnpm ", "yarn ", "node ", "python ", "python3 ", "docker "})
		riskyPackageLaunch := packageLaunch && !looksPinned(lower)
		toolID := "tool:mcp-package-launch"
		toolKind := "mcp-package-launch"
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			toolID = "tool:mcp-remote-server"
			toolKind = "mcp-remote-server"
		}
		c.Tools = appendUniqueTool(c.Tools, model.Tool{
			ID:      toolID,
			Kind:    toolKind,
			Runtime: runtimeForSurface(s),
			Source:  s.Source,
			Risky:   riskyPackageLaunch || strings.HasPrefix(lower, "http://"),
			Summary: "MCP server " + serverName + " is declared for local agent use.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:"+toolID, "tool", s.Source, "declared", "MCP launch mechanism was collected without executing the MCP server."))
		if packageLaunch {
			c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:local-code-execution", Kind: "local-code-execution", Runtime: runtimeForSurface(s), Source: s.Source, Summary: "Package-manager or interpreter-launched MCP can execute local code under the developer user."})
			c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:developer-execution-boundary", Kind: "developer-execution-boundary", Abstract: true, Summary: "Developer user execution context and local machine privileges."})
		}
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || containsExternalCommunication(lower) {
			addExternalCommunication(c, runtimeForSurface(s), s.Source, "MCP config declares a remote server or external communication path.")
		}
		if strings.Contains(lower, "~") || strings.Contains(lower, "$home") || strings.Contains(lower, "/users/") {
			c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: runtimeForSurface(s), Source: s.Source, Summary: "MCP filesystem arguments appear to include broad home or filesystem reachability."})
			c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:developer-secret-boundary", Kind: "secret-like-files", Abstract: true, Summary: "Developer machines commonly hold secret-like files and credential caches near local agents."})
		}
		if looksPinned(lower) {
			c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:mcp-reviewed-pinned", Kind: "mcp-reviewed-pinned", Source: s.Source, Summary: "MCP command pinning constrains package-manager drift."})
		}
		if server.SandboxEnabled || strings.Contains(lower, "sandboxenabled") {
			addControl(c, "control:tool-sandbox-execution", "tool-sandbox-execution", runtimeForSurface(s), s.Source, "MCP server "+serverName+" declares sandboxed tool execution.")
		}
		if len(server.AlwaysAllow) > 0 {
			c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:broad-local", Kind: "broad-local", Runtime: runtimeForSurface(s), Source: s.Source, Summary: "MCP server " + serverName + " declares always-allowed tool calls."})
		}
	}
}

func collectMCPPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if strings.Contains(text, "require_pinned_packages") || strings.Contains(text, "approved_mcp_servers") {
		c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:mcp-reviewed-pinned", Kind: "mcp-reviewed-pinned", Source: s.Source, Summary: "Repo declares reviewed MCP allowlist or package pinning policy."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:control:mcp-reviewed-pinned", "control", s.Source, "declared", "MCP review or pinning policy was collected."))
	}
	collectToolIntegrityControls(c, "", s.Source, text)
	collectResourceControls(c, "", s.Source, text)
}

func collectGitHubActionsWorkflow(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	source := s.Source
	runtime := "github-actions"
	c.Runtimes = appendUniqueRuntime(c.Runtimes, model.RuntimeEvidence{
		ID:      "runtime:" + runtime,
		Kind:    runtime,
		Source:  source,
		Scope:   s.Scope,
		Summary: "GitHub Actions workflow evidence was found.",
	})
	configID := "config:" + runtime + "-" + s.Scope
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:"+configID, "config", source, "declared", "GitHub Actions workflow source was collected."))
	text := strings.ToLower(string(data))
	if workflowHasUntrustedTrigger(text) {
		c.TrustInputs = appendUniqueTrustInput(c.TrustInputs, model.TrustInput{
			ID:      "trustinput:managed-workflow-trigger",
			Kind:    "managed-workflow-trigger",
			Runtime: runtime,
			Source:  source,
			Risky:   true,
			Summary: "Workflow can be triggered by pull request, issue, or other repository event input.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:trustinput:managed-workflow-trigger", "trust-input", source, "declared", "Managed workflow trigger surface was parsed without executing the workflow."))
	}
	if workflowAgentLike(text) {
		c.Tools = appendUniqueTool(c.Tools, model.Tool{
			ID:      "tool:managed-agent-workflow",
			Kind:    "managed-agent-workflow",
			Runtime: runtime,
			Source:  source,
			Risky:   workflowHasWritePermission(text) || containsExternalCommunication(text),
			Summary: "Workflow appears to invoke AI or agent-like automation from CI-managed configuration.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:managed-agent-workflow", "tool", source, "declared", "Managed workflow agent invocation indicators were collected without running the workflow."))
	}
	if workflowExecutesCode(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:local-code-execution",
			Kind:    "local-code-execution",
			Runtime: runtime,
			Source:  source,
			Summary: "GitHub Actions workflow can execute commands or actions on a workflow runner.",
		})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:developer-execution-boundary",
			Kind:     "developer-execution-boundary",
			Abstract: true,
			Summary:  "Local or CI runner execution context reachable from agent/tool automation.",
		})
	}
	if workflowReadsRepo(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:file-read",
			Kind:    "file-read",
			Runtime: runtime,
			Source:  source,
			Summary: "GitHub Actions workflow can read checked-out repository files or workflow workspace context.",
		})
	}
	if workflowHasWritePermission(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:broad-local",
			Kind:    "broad-local",
			Runtime: runtime,
			Source:  source,
			Summary: "GitHub Actions workflow declares write-capable permissions or broad workflow token posture.",
		})
	}
	if workflowHasRepositoryWritePermission(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:repository-write",
			Kind:    "repository-write",
			Runtime: runtime,
			Source:  source,
			Summary: "GitHub Actions workflow token can write repository, pull request, issue, or package state.",
		})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:repository-integrity-boundary",
			Kind:     "repository-integrity-boundary",
			Source:   source,
			Abstract: false,
			Summary:  "Repository state, pull requests, issues, packages, or code review outputs controlled by workflow token permissions.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:authority:repository-write", "authority", source, "declared", "Repository write-capable workflow token permission was collected."))
	}
	if workflowHasOIDCTokenPermission(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:cloud-identity-token",
			Kind:    "cloud-identity-token",
			Runtime: runtime,
			Source:  source,
			Summary: "GitHub Actions workflow can request an OIDC identity token for cloud or external identity federation.",
		})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:cloud-identity-boundary",
			Kind:     "cloud-identity-boundary",
			Source:   source,
			Abstract: false,
			Summary:  "Cloud or external identity provider trust boundary reachable through workflow OIDC token issuance.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:authority:cloud-identity-token", "authority", source, "declared", "OIDC id-token workflow permission was collected."))
	}
	if workflowReferencesSecrets(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:credential-access",
			Kind:    "credential-access",
			Runtime: runtime,
			Source:  source,
			Summary: "GitHub Actions workflow references CI secret context or secret-backed environment variables.",
		})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:ci-secret-boundary",
			Kind:     "ci-secret-boundary",
			Source:   source,
			Abstract: false,
			Summary:  "CI secret or secret-backed environment boundary; secret values are not emitted.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:authority:credential-access", "authority", source, "declared", "CI secret context reference was collected without emitting secret values."))
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:ci-secret-boundary", "boundary", source, "observed", "Workflow references CI secret context; values were not read or emitted."))
	}
	if containsExternalCommunication(text) || strings.Contains(text, "uses:") {
		addExternalCommunication(c, runtime, source, "GitHub Actions workflow can call external actions, package registries, APIs, or web endpoints.")
	}
	if workflowScopedPermissions(text) {
		addControl(c, "control:scoped-permissions", "scoped-permissions", runtime, source, "GitHub Actions workflow declares scoped or read-only permissions.")
	}
	if workflowPinnedActions(text) {
		addControl(c, "control:signed-tool-artifacts", "signed-tool-artifacts", runtime, source, "GitHub Actions workflow pins at least one action by version, digest, or immutable-looking reference.")
	}
	if strings.Contains(text, "environment:") {
		addControl(c, "control:approval-required", "approval-required", runtime, source, "GitHub Actions workflow declares an environment gate that can require deployment approval.")
	}
	collectResourceControls(c, runtime, source, text)
	collectGovernanceControls(c, runtime, source, text)
	collectObservabilityControls(c, runtime, source, text)
	if inlineCredentialConfigured(text) {
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:credential-material",
			Kind:     "credential-material",
			Source:   source,
			Abstract: false,
			Summary:  "Workflow contains inline credential field indicators; values are not emitted.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:credential-material", "boundary", source, "observed", "Inline credential field indicators were detected without emitting values."))
	}
}

func collectGitLabCIWorkflow(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	source := s.Source
	runtime := "gitlab-ci"
	c.Runtimes = appendUniqueRuntime(c.Runtimes, model.RuntimeEvidence{
		ID:      "runtime:" + runtime,
		Kind:    runtime,
		Source:  source,
		Scope:   s.Scope,
		Summary: "GitLab CI pipeline evidence was found.",
	})
	configID := "config:" + runtime + "-" + s.Scope
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:"+configID, "config", source, "declared", "GitLab CI pipeline source was collected."))
	text := strings.ToLower(string(data))
	if gitlabWorkflowHasUntrustedTrigger(text) {
		c.TrustInputs = appendUniqueTrustInput(c.TrustInputs, model.TrustInput{
			ID:      "trustinput:managed-workflow-trigger",
			Kind:    "managed-workflow-trigger",
			Runtime: runtime,
			Source:  source,
			Risky:   true,
			Summary: "Pipeline can be triggered by merge request, trigger, web, schedule, or other repository event input.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:trustinput:managed-workflow-trigger", "trust-input", source, "declared", "Managed workflow trigger surface was parsed without executing the pipeline."))
	}
	if workflowAgentLike(text) {
		c.Tools = appendUniqueTool(c.Tools, model.Tool{
			ID:      "tool:managed-agent-workflow",
			Kind:    "managed-agent-workflow",
			Runtime: runtime,
			Source:  source,
			Risky:   gitlabWorkflowHasWritePermission(text) || containsExternalCommunication(text),
			Summary: "Pipeline appears to invoke AI or agent-like automation from CI-managed configuration.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:managed-agent-workflow", "tool", source, "declared", "Managed workflow agent invocation indicators were collected without running the pipeline."))
	}
	if gitlabWorkflowExecutesCode(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:local-code-execution",
			Kind:    "local-code-execution",
			Runtime: runtime,
			Source:  source,
			Summary: "GitLab CI pipeline can execute script commands on a CI runner.",
		})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:developer-execution-boundary",
			Kind:     "developer-execution-boundary",
			Abstract: true,
			Summary:  "Local or CI runner execution context reachable from agent/tool automation.",
		})
	}
	if gitlabWorkflowReadsRepo(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:file-read",
			Kind:    "file-read",
			Runtime: runtime,
			Source:  source,
			Summary: "GitLab CI pipeline can read checked-out repository files or CI project workspace context.",
		})
	}
	if gitlabWorkflowHasWritePermission(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:broad-local",
			Kind:    "broad-local",
			Runtime: runtime,
			Source:  source,
			Summary: "GitLab CI pipeline declares write-capable repository, package, or API token posture.",
		})
	}
	if gitlabWorkflowHasRepositoryWritePermission(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:repository-write",
			Kind:    "repository-write",
			Runtime: runtime,
			Source:  source,
			Summary: "GitLab CI job token or token-backed script can write repository, merge request, package, or project state.",
		})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:repository-integrity-boundary",
			Kind:     "repository-integrity-boundary",
			Source:   source,
			Abstract: false,
			Summary:  "Repository state, merge requests, packages, or code review outputs controlled by CI token permissions.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:authority:repository-write", "authority", source, "declared", "Repository write-capable CI token or API use was collected."))
	}
	if gitlabWorkflowHasOIDCTokenPermission(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:cloud-identity-token",
			Kind:    "cloud-identity-token",
			Runtime: runtime,
			Source:  source,
			Summary: "GitLab CI pipeline can request an ID token for cloud or external identity federation.",
		})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:cloud-identity-boundary",
			Kind:     "cloud-identity-boundary",
			Source:   source,
			Abstract: false,
			Summary:  "Cloud or external identity provider trust boundary reachable through CI identity token issuance.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:authority:cloud-identity-token", "authority", source, "declared", "GitLab CI ID token configuration was collected."))
	}
	if gitlabWorkflowReferencesSecrets(text) {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{
			ID:      "authority:credential-access",
			Kind:    "credential-access",
			Runtime: runtime,
			Source:  source,
			Summary: "GitLab CI pipeline references CI variables, job tokens, deploy tokens, or secret-like environment variables.",
		})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:ci-secret-boundary",
			Kind:     "ci-secret-boundary",
			Source:   source,
			Abstract: false,
			Summary:  "CI variable or secret-backed environment boundary; secret values are not emitted.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:authority:credential-access", "authority", source, "declared", "CI variable or token reference was collected without emitting values."))
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:ci-secret-boundary", "boundary", source, "observed", "Pipeline references CI variables or token context; values were not read or emitted."))
	}
	if containsExternalCommunication(text) || strings.Contains(text, "image:") {
		addExternalCommunication(c, runtime, source, "GitLab CI pipeline can call external images, package registries, APIs, or web endpoints.")
	}
	if gitlabWorkflowHasScopedRules(text) {
		addControl(c, "control:scoped-permissions", "scoped-permissions", runtime, source, "GitLab CI pipeline declares scoped rules or protected execution conditions.")
	}
	if gitlabWorkflowPinnedImage(text) {
		addControl(c, "control:signed-tool-artifacts", "signed-tool-artifacts", runtime, source, "GitLab CI pipeline pins at least one image or artifact by digest or immutable-looking reference.")
	}
	if gitlabWorkflowRequiresApproval(text) {
		addControl(c, "control:approval-required", "approval-required", runtime, source, "GitLab CI pipeline declares a manual job or protected environment gate.")
	}
	collectResourceControls(c, runtime, source, text)
	collectGovernanceControls(c, runtime, source, text)
	collectObservabilityControls(c, runtime, source, text)
	if inlineCredentialConfigured(text) {
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:credential-material",
			Kind:     "credential-material",
			Source:   source,
			Abstract: false,
			Summary:  "Pipeline contains inline credential field indicators; values are not emitted.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:credential-material", "boundary", source, "observed", "Inline credential field indicators were detected without emitting values."))
	}
}

func collectNetworkPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if networkRestricted(text) || strings.Contains(text, "block_external") || strings.Contains(text, "deny_external") {
		c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:network-restricted", Kind: "network-restricted", Source: s.Source, Summary: "Policy declares external network communication restrictions."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:control:network-restricted", "control", s.Source, "declared", "External communication restriction policy was collected."))
	}
	if networkSegmentationConfigured(text) {
		addControl(c, "control:network-segmentation", "network-segmentation", "", s.Source, "Network policy declares workload network segmentation or microsegmentation.")
	}
	collectEgressControls(c, s.Source, text)
}

func collectEgressPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if networkRestricted(text) || strings.Contains(text, "block_external") || strings.Contains(text, "deny_external") {
		addControl(c, "control:network-restricted", "network-restricted", "", s.Source, "Egress policy declares external network communication restrictions.")
	}
	collectEgressControls(c, s.Source, text)
}

func collectEgressControls(c *model.Collection, source, text string) {
	if egressDestinationAllowlistConfigured(text) {
		addControl(c, "control:egress-destination-allowlist", "egress-destination-allowlist", "", source, "Egress policy declares approved external destinations or domains.")
	}
	if webhookAllowlistConfigured(text) {
		addControl(c, "control:webhook-allowlist", "webhook-allowlist", "", source, "Egress policy declares approved webhook destinations.")
	}
	if perToolNetworkScopeConfigured(text) {
		addControl(c, "control:per-tool-network-scope", "per-tool-network-scope", "", source, "Egress policy declares per-tool network destination scope.")
	}
	if egressContentFilterConfigured(text) {
		addControl(c, "control:egress-content-filter", "egress-content-filter", "", source, "Egress policy declares output or sensitive-content filtering for external communication.")
	}
	if egressAuditConfigured(text) {
		addControl(c, "control:egress-audit", "egress-audit", "", source, "Egress policy declares audit logging for outbound or external communication.")
	}
	collectOutputControls(c, "", source, text)
}

func collectConfigIntegrityControls(c *model.Collection, runtime, source, text string) {
	prefix := "Agent policy"
	if runtime != "" {
		prefix = runtime + " config"
	}
	if configVersionControlled(text) {
		addControl(c, "control:config-version-control", "config-version-control", runtime, source, prefix+" declares version-controlled agent configuration.")
	}
	if configReviewRequired(text) {
		addControl(c, "control:config-review-required", "config-review-required", runtime, source, prefix+" requires review or approval for agent configuration changes.")
	}
	if signedConfigConfigured(text) {
		addControl(c, "control:signed-config", "signed-config", runtime, source, prefix+" declares signed agent configuration or policy artifacts.")
	}
	if configDeploymentVerificationConfigured(text) {
		addControl(c, "control:config-deployment-verification", "config-deployment-verification", runtime, source, prefix+" declares verification before agent configuration deployment.")
	}
	if managedSettingsEnforced(text) {
		addControl(c, "control:managed-settings-enforced", "managed-settings-enforced", runtime, source, prefix+" declares centrally enforced managed settings that users cannot override.")
	}
	if immutableRuntimeConfigured(text) {
		addControl(c, "control:immutable-agent-runtime", "immutable-agent-runtime", runtime, source, prefix+" declares immutable agent runtime or replace-not-modify deployment.")
	}
	if rollbackProcedureConfigured(text) {
		addControl(c, "control:config-rollback-procedure", "config-rollback-procedure", runtime, source, prefix+" declares rollback or recovery procedures for agent configuration.")
	}
	if automatedRollbackConfigured(text) {
		addControl(c, "control:automated-config-rollback", "automated-config-rollback", runtime, source, prefix+" declares automated rollback or health-check-based recovery for agent configuration.")
	}
}

func collectToolIntegrityControls(c *model.Collection, runtime, source, text string) {
	prefix := "Tool policy"
	if runtime != "" {
		prefix = runtime + " tool policy"
	}
	if toolAllowlistConfigured(text) {
		addControl(c, "control:tool-allowlist", "tool-allowlist", runtime, source, prefix+" declares approved model-callable tools or MCP servers.")
	}
	if mcpReviewOrPinningConfigured(text) {
		addControl(c, "control:mcp-reviewed-pinned", "mcp-reviewed-pinned", runtime, source, prefix+" declares reviewed or pinned MCP/tool package launchers.")
	}
	if toolDescriptorIntegrityConfigured(text) {
		addControl(c, "control:tool-descriptor-integrity", "tool-descriptor-integrity", runtime, source, prefix+" declares descriptor, schema, or metadata integrity validation for tools.")
	}
	if toolArgumentValidationConfigured(text) {
		addControl(c, "control:tool-argument-validation", "tool-argument-validation", runtime, source, prefix+" declares validation for tool call arguments before execution.")
	}
	if toolAuthRequiredConfigured(text) {
		addControl(c, "control:tool-auth-required", "tool-auth-required", runtime, source, prefix+" declares authenticated tool access instead of unauthenticated local tool reachability.")
	}
	if signedToolArtifactsConfigured(text) {
		addControl(c, "control:signed-tool-artifacts", "signed-tool-artifacts", runtime, source, prefix+" declares signed tool, MCP, plugin, or server artifacts.")
	}
	if toolDeploymentVerificationConfigured(text) {
		addControl(c, "control:tool-deployment-verification", "tool-deployment-verification", runtime, source, prefix+" declares verification before tool or MCP deployment.")
	}
	if toolSandboxExecutionConfigured(text) {
		addControl(c, "control:tool-sandbox-execution", "tool-sandbox-execution", runtime, source, prefix+" declares sandboxed execution for model-callable tools.")
	}
	if toolCircuitBreakerConfigured(text) {
		addControl(c, "control:tool-circuit-breaker", "tool-circuit-breaker", runtime, source, prefix+" declares rate limits, spend limits, or circuit breakers for tool execution.")
	}
}

func collectResourceControls(c *model.Collection, runtime, source, text string) {
	prefix := "Resource policy"
	if runtime != "" {
		prefix = runtime + " resource policy"
	}
	if toolRateLimitConfigured(text) {
		addControl(c, "control:tool-rate-limit", "tool-rate-limit", runtime, source, prefix+" declares per-tool, API, or request rate limits for agent operations.")
	}
	if spendLimitConfigured(text) {
		addControl(c, "control:spend-limit", "spend-limit", runtime, source, prefix+" declares spend, budget, token, or cost ceilings for agent operations.")
	}
	if loopGuardConfigured(text) {
		addControl(c, "control:loop-guard", "loop-guard", runtime, source, prefix+" declares loop, recursion, iteration, or runaway-operation guards.")
	}
	if toolTimeoutConfigured(text) {
		addControl(c, "control:tool-timeout", "tool-timeout", runtime, source, prefix+" declares wall-clock or per-tool execution timeouts.")
	}
	if concurrencyLimitConfigured(text) {
		addControl(c, "control:concurrency-limit", "concurrency-limit", runtime, source, prefix+" declares concurrency, parallelism, or worker limits for agent operations.")
	}
	if resourceUsageAuditConfigured(text) {
		addControl(c, "control:resource-usage-audit", "resource-usage-audit", runtime, source, prefix+" declares usage, budget, quota, token, or cost event logging.")
	}
	if toolCircuitBreakerConfigured(text) {
		addControl(c, "control:tool-circuit-breaker", "tool-circuit-breaker", runtime, source, prefix+" declares circuit breakers for runaway or excessive tool execution.")
	}
}

func collectDelegationControls(c *model.Collection, runtime, source, text string) {
	prefix := "Delegation policy"
	if runtime != "" {
		prefix = runtime + " delegation policy"
	}
	if delegationScopeConfigured(text) {
		addControl(c, "control:delegation-scope", "delegation-scope", runtime, source, prefix+" declares scoped authority for delegated or sub-agent work.")
	}
	if delegationAllowlistConfigured(text) {
		addControl(c, "control:delegation-allowlist", "delegation-allowlist", runtime, source, prefix+" declares approved delegate agents or permitted handoff targets.")
	}
	if agentToAgentAuthorizationConfigured(text) {
		addControl(c, "control:agent-to-agent-authorization", "agent-to-agent-authorization", runtime, source, prefix+" declares authorization checks for agent-to-agent delegation.")
	}
	if originIntentVerificationConfigured(text) {
		addControl(c, "control:origin-intent-verification", "origin-intent-verification", runtime, source, prefix+" requires delegated work to verify original user intent and request provenance.")
	}
	if delegatedCredentialScopeConfigured(text) {
		addControl(c, "control:delegated-credential-scope", "delegated-credential-scope", runtime, source, prefix+" declares reduced or separately scoped credentials for delegated agents.")
	}
	if subagentContextIsolationConfigured(text) {
		addControl(c, "control:subagent-context-isolation", "subagent-context-isolation", runtime, source, prefix+" declares isolated context windows or memory boundaries for delegated agents.")
	}
	if delegationAuditConfigured(text) {
		addControl(c, "control:delegation-audit", "delegation-audit", runtime, source, prefix+" declares logging for delegation, handoff, and agent-to-agent communication.")
	}
}

func collectResponseControls(c *model.Collection, runtime, source, text string) {
	prefix := "Response policy"
	if runtime != "" {
		prefix = runtime + " response policy"
	}
	if automatedTriageConfigured(text) {
		addControl(c, "control:automated-triage", "automated-triage", runtime, source, prefix+" declares automated first-pass investigation or alert triage.")
	}
	if behavioralMonitoringConfigured(text) {
		addControl(c, "control:behavioral-monitoring", "behavioral-monitoring", runtime, source, prefix+" declares behavioral monitoring, anomaly detection, or baseline drift detection for agent activity.")
	}
	if sessionTerminationConfigured(text) {
		addControl(c, "control:session-termination", "session-termination", runtime, source, prefix+" declares automatic termination of suspicious or compromised agent sessions.")
	}
	if credentialRevocationConfigured(text) {
		addControl(c, "control:credential-revocation", "credential-revocation", runtime, source, prefix+" declares credential revocation or token invalidation for compromised agent activity.")
	}
	if containmentQuarantineConfigured(text) {
		addControl(c, "control:containment-quarantine", "containment-quarantine", runtime, source, prefix+" declares quarantine, isolation, or network containment for suspicious agent behavior.")
	}
	if dynamicAccessReductionConfigured(text) {
		addControl(c, "control:dynamic-access-reduction", "dynamic-access-reduction", runtime, source, prefix+" declares dynamic access reduction or privilege downscoping during risky agent activity.")
	}
	if responseEscalationConfigured(text) {
		addControl(c, "control:response-escalation", "response-escalation", runtime, source, prefix+" declares escalation paths or human review for high-impact automated response.")
	}
}

func collectGovernanceControls(c *model.Collection, runtime, source, text string) {
	prefix := "Governance policy"
	if runtime != "" {
		prefix = runtime + " governance policy"
	}
	if agentInventoryConfigured(text) {
		addControl(c, "control:agent-inventory", "agent-inventory", runtime, source, prefix+" declares registered or cataloged agent deployments.")
	}
	if deploymentOwnerConfigured(text) {
		addControl(c, "control:deployment-owner", "deployment-owner", runtime, source, prefix+" declares accountable owner, service owner, or responsible team for agent deployment.")
	}
	if deploymentApprovalConfigured(text) {
		addControl(c, "control:deployment-approval", "deployment-approval", runtime, source, prefix+" declares an approval process for new or changed agent deployments.")
	}
	if riskAssessmentConfigured(text) {
		addControl(c, "control:risk-assessment", "risk-assessment", runtime, source, prefix+" declares risk tier, impact assessment, or data classification for agent deployment.")
	}
	if governanceAuditConfigured(text) {
		addControl(c, "control:governance-audit", "governance-audit", runtime, source, prefix+" declares governance review, audit trail, or compliance review evidence.")
	}
	if shadowAIDiscoveryConfigured(text) {
		addControl(c, "control:shadow-ai-discovery", "shadow-ai-discovery", runtime, source, prefix+" declares discovery or detection for unmanaged AI or unauthorized agent usage.")
	}
}

func collectAuthorizationControls(c *model.Collection, runtime, source, text string) {
	prefix := "Authorization policy"
	if runtime != "" {
		prefix = runtime + " authorization policy"
	}
	if perActionAuthorizationConfigured(text) {
		addControl(c, "control:per-action-authorization", "per-action-authorization", runtime, source, prefix+" declares authorization checks for each agent action or tool invocation.")
	}
	if continuousAuthorizationConfigured(text) {
		addControl(c, "control:continuous-authorization", "continuous-authorization", runtime, source, prefix+" declares continuous or real-time policy evaluation for agent actions.")
	}
	if dynamicPrivilegeScopingConfigured(text) {
		addControl(c, "control:dynamic-privilege-scoping", "dynamic-privilege-scoping", runtime, source, prefix+" declares dynamic privilege scoping or just-enough-access boundaries.")
	}
	if jitElevationConfigured(text) {
		addControl(c, "control:jit-elevation", "jit-elevation", runtime, source, prefix+" declares just-in-time privilege elevation for specific operations.")
	}
	if standingAccessDeniedConfigured(text) {
		addControl(c, "control:standing-access-denied", "standing-access-denied", runtime, source, prefix+" declares no standing elevated access for agent authority.")
	}
	if automaticAccessRevocationConfigured(text) {
		addControl(c, "control:automatic-access-revocation", "automatic-access-revocation", runtime, source, prefix+" declares automatic access revocation or reauthorization when risk changes.")
	}
}

func collectOutputControls(c *model.Collection, runtime, source, text string) {
	prefix := "Output policy"
	if runtime != "" {
		prefix = runtime + " output policy"
	}
	if outputSensitiveDataFilterConfigured(text) {
		addControl(c, "control:output-sensitive-data-filter", "output-sensitive-data-filter", runtime, source, prefix+" declares sensitive-data, credential, PII, or DLP filtering for agent outputs.")
	}
	if outputRedactionConfigured(text) {
		addControl(c, "control:output-redaction", "output-redaction", runtime, source, prefix+" declares blocking or redaction for sensitive agent output before delivery.")
	}
	if outputFilterLoggingConfigured(text) {
		addControl(c, "control:output-filter-logging", "output-filter-logging", runtime, source, prefix+" declares logging for output filtering, redaction, or DLP events.")
	}
	if semanticOutputAnalysisConfigured(text) {
		addControl(c, "control:semantic-output-analysis", "semantic-output-analysis", runtime, source, prefix+" declares semantic analysis for sensitive, encoded, or harmful output before delivery.")
	}
	if highRiskOutputReviewConfigured(text) {
		addControl(c, "control:high-risk-output-review", "high-risk-output-review", runtime, source, prefix+" declares human review or approval before high-risk agent outputs are delivered.")
	}
}

func collectSupplyChainControls(c *model.Collection, runtime, source, text string) {
	prefix := "Supply-chain policy"
	if runtime != "" {
		prefix = runtime + " supply-chain policy"
	}
	if aiBOMConfigured(text) {
		addControl(c, "control:ai-bom", "ai-bom", runtime, source, prefix+" declares an AI bill of materials or ML bill of materials.")
	}
	if modelProvenanceConfigured(text) {
		addControl(c, "control:model-provenance", "model-provenance", runtime, source, prefix+" declares model origin, model provider, model version, or model artifact provenance.")
	}
	if trainingDataLineageConfigured(text) {
		addControl(c, "control:training-data-lineage", "training-data-lineage", runtime, source, prefix+" declares training data, fine-tuning data, dataset lineage, or source attribution.")
	}
	if dependencyHealthConfigured(text) {
		addControl(c, "control:dependency-health-scan", "dependency-health-scan", runtime, source, prefix+" declares dependency health, OpenSSF Scorecard, maintainer activity, vulnerability, or redundancy review.")
	}
	if providerRiskReviewConfigured(text) {
		addControl(c, "control:provider-risk-review", "provider-risk-review", runtime, source, prefix+" declares tool, model, framework, vendor, or provider security review.")
	}
	if signedAIArtifactsConfigured(text) {
		addControl(c, "control:signed-ai-artifacts", "signed-ai-artifacts", runtime, source, prefix+" declares signed model, dataset, framework, or agent component artifacts.")
	}
	if runtimeComponentValidationConfigured(text) {
		addControl(c, "control:runtime-component-validation", "runtime-component-validation", runtime, source, prefix+" declares runtime validation for model, tool, framework, or component integrity.")
	}
	if reachabilityAnalysisConfigured(text) {
		addControl(c, "control:dependency-reachability-analysis", "dependency-reachability-analysis", runtime, source, prefix+" declares vulnerable dependency reachability or dependency redundancy analysis.")
	}
}

func collectAgentPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if cryptographicIdentityConfigured(text) {
		addControl(c, "control:cryptographic-identity", "cryptographic-identity", "", s.Source, "Agent policy declares cryptographic or workload identity for agent instances.")
	}
	if leastAgencyConfigured(text) {
		addControl(c, "control:least-agency-policy", "least-agency-policy", "", s.Source, "Agent policy declares deny-by-default or least-agency permission scoping.")
	}
	if denyByDefaultConfigured(text) {
		addControl(c, "control:deny-by-default-permissions", "deny-by-default-permissions", "", s.Source, "Agent policy declares deny-by-default permission posture.")
	}
	if scopedPermissionConfigured(text) {
		addControl(c, "control:scoped-permissions", "scoped-permissions", "", s.Source, "Agent policy declares scoped filesystem, shell, network, or tool permissions.")
	}
	if denySecretReadConfigured(text) {
		addControl(c, "control:deny-secret-read", "deny-secret-read", "", s.Source, "Agent policy declares deny-read protection for secret-like paths.")
	}
	if identityBasedIsolationConfigured(text) {
		addControl(c, "control:identity-based-isolation", "identity-based-isolation", "", s.Source, "Agent policy declares identity-based isolation or named-caller network boundaries.")
	}
	if namedCallerConfigured(text) {
		addControl(c, "control:named-caller-allowlist", "named-caller-allowlist", "", s.Source, "Agent policy declares named caller, principal, or workload allowlist controls.")
	}
	if abacPolicyConfigured(text) {
		addControl(c, "control:abac-policy", "abac-policy", "", s.Source, "Agent policy declares attribute-based access control for agent workloads.")
	}
	if networkSegmentationConfigured(text) {
		addControl(c, "control:network-segmentation", "network-segmentation", "", s.Source, "Agent policy declares workload network segmentation or microsegmentation.")
	}
	if toolScopePolicyConfigured(text) {
		addControl(c, "control:tool-scope-policy", "tool-scope-policy", "", s.Source, "Agent policy declares per-tool scope, allowlist, or permission scope controls.")
	}
	if approvalRequired(text) {
		addControl(c, "control:approval-required", "approval-required", "", s.Source, "Agent policy requires approval for high-risk agent actions.")
	}
	if sandboxIsolated(text) {
		addControl(c, "control:sandbox-isolation", "sandbox-isolation", "", s.Source, "Agent policy requires sandbox or filesystem isolation.")
	}
	if credentialHelperConfigured(text) {
		addControl(c, "control:credential-helper", "credential-helper", "", s.Source, "Agent policy requires credentials to be retrieved through a helper or vault instead of inline config.")
	}
	if shortLivedCredentialConfigured(text) {
		addControl(c, "control:short-lived-credential", "short-lived-credential", "", s.Source, "Agent policy requires short-lived or federated credentials.")
	}
	if credentialIsolationConfigured(text) {
		addControl(c, "control:credential-isolation", "credential-isolation", "", s.Source, "Agent policy declares per-agent or non-shared credential isolation.")
	}
	if jitAccessConfigured(text) {
		addControl(c, "control:jit-access", "jit-access", "", s.Source, "Agent policy declares just-in-time access for agent tool credentials.")
	}
	if tokenLifetimePolicyConfigured(text) {
		addControl(c, "control:token-lifetime-policy", "token-lifetime-policy", "", s.Source, "Agent policy declares token lifetime limits for agent credentials.")
	}
	if hardwareBoundCredentialConfigured(text) {
		addControl(c, "control:hardware-bound-credential", "hardware-bound-credential", "", s.Source, "Agent policy declares hardware-bound credential posture.")
	}
	if identityLifecycleConfigured(text) {
		addControl(c, "control:identity-lifecycle", "identity-lifecycle", "", s.Source, "Agent policy declares credential rotation, revocation, or identity lifecycle controls.")
	}
	if auditLoggingConfigured(text) {
		addControl(c, "control:audit-logging", "audit-logging", "", s.Source, "Agent policy requires tool-call, approval, or telemetry logging.")
	}
	if traceabilityConfigured(text) {
		addControl(c, "control:request-traceability", "request-traceability", "", s.Source, "Agent policy requires request IDs, trace IDs, or provenance through agent actions.")
	}
	if telemetryExportConfigured(text) {
		addControl(c, "control:telemetry-export", "telemetry-export", "", s.Source, "Agent policy declares telemetry export for audit correlation.")
	}
	if immutableAuditConfigured(text) {
		addControl(c, "control:immutable-audit-log", "immutable-audit-log", "", s.Source, "Agent policy declares append-only or immutable audit log storage.")
	}
	if inputValidationConfigured(text) {
		addControl(c, "control:input-validation", "input-validation", "", s.Source, "Agent policy requires schema, length, or prompt-injection validation for untrusted inputs.")
	}
	if inputIsolationConfigured(text) {
		addControl(c, "control:input-isolation", "input-isolation", "", s.Source, "Agent policy declares isolation between untrusted instructions and authority-bearing runtime behavior.")
	}
	if trustedSourcePolicyConfigured(text) {
		addControl(c, "control:trusted-source-policy", "trusted-source-policy", "", s.Source, "Agent policy declares trusted source or allowlist controls for instruction inputs.")
	}
	if instructionProvenanceConfigured(text) {
		addControl(c, "control:instruction-provenance", "instruction-provenance", "", s.Source, "Agent policy declares instruction provenance, signature, or source attribution controls.")
	}
	if untrustedInputDelimitingConfigured(text) {
		addControl(c, "control:untrusted-input-delimiting", "untrusted-input-delimiting", "", s.Source, "Agent policy declares explicit delimiting or spotlighting for untrusted content.")
	}
	if promptInjectionFilterConfigured(text) {
		addControl(c, "control:prompt-injection-filter", "prompt-injection-filter", "", s.Source, "Agent policy declares prompt-injection filtering controls.")
	}
	if automatedTriageConfigured(text) {
		addControl(c, "control:automated-triage", "automated-triage", "", s.Source, "Agent policy declares automated first-pass investigation or alert triage.")
	}
	if contextRetentionConfigured(text) {
		addControl(c, "control:context-retention", "context-retention", "", s.Source, "Agent policy constrains memory, transcript, or private-context retention.")
	}
	if memoryIsolationConfigured(text) {
		addControl(c, "control:memory-isolation", "memory-isolation", "", s.Source, "Agent policy declares memory or private-context isolation controls.")
	}
	if contextIntegrityConfigured(text) {
		addControl(c, "control:context-integrity", "context-integrity", "", s.Source, "Agent policy declares context integrity validation controls.")
	}
	if contextProvenanceConfigured(text) {
		addControl(c, "control:context-provenance", "context-provenance", "", s.Source, "Agent policy declares source attribution or provenance metadata for context.")
	}
	collectToolIntegrityControls(c, "", s.Source, text)
	collectDelegationControls(c, "", s.Source, text)
	collectConfigIntegrityControls(c, "", s.Source, text)
	collectEgressControls(c, s.Source, text)
	collectResponseControls(c, "", s.Source, text)
	collectGovernanceControls(c, "", s.Source, text)
	collectOutputControls(c, "", s.Source, text)
	collectAuthorizationControls(c, "", s.Source, text)
	collectResourceControls(c, "", s.Source, text)
	collectSupplyChainControls(c, "", s.Source, text)
}

func collectToolPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectToolIntegrityControls(c, "", s.Source, text)
	collectResourceControls(c, "", s.Source, text)
}

func collectDelegationPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectDelegationControls(c, "", s.Source, text)
}

func collectResponsePolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if auditLoggingConfigured(text) {
		addControl(c, "control:audit-logging", "audit-logging", "", s.Source, "Response policy declares audit logging for containment actions.")
	}
	if traceabilityConfigured(text) {
		addControl(c, "control:request-traceability", "request-traceability", "", s.Source, "Response policy declares request, trace, correlation, or provenance IDs for containment actions.")
	}
	if telemetryExportConfigured(text) {
		addControl(c, "control:telemetry-export", "telemetry-export", "", s.Source, "Response policy declares telemetry export for response correlation.")
	}
	if immutableAuditConfigured(text) {
		addControl(c, "control:immutable-audit-log", "immutable-audit-log", "", s.Source, "Response policy declares append-only or immutable response logs.")
	}
	collectResponseControls(c, "", s.Source, text)
	collectAuthorizationControls(c, "", s.Source, text)
	collectResourceControls(c, "", s.Source, text)
}

func collectGovernancePolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectGovernanceControls(c, "", s.Source, text)
}

func collectOutputPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectOutputControls(c, "", s.Source, text)
}

func collectSupplyChainPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectSupplyChainControls(c, "", s.Source, text)
}

func collectAIBOM(c *model.Collection, s model.Surface) {
	addObservedControl(c, "control:ai-bom", "ai-bom", "", s.Source, "AI bill of materials surface was observed.")
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	collectSupplyChainControls(c, "", s.Source, strings.ToLower(string(data)))
}

func collectInputPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if inputValidationConfigured(text) {
		addControl(c, "control:input-validation", "input-validation", "", s.Source, "Input policy declares schema, length, or prompt-injection validation for untrusted inputs.")
	}
	if inputIsolationConfigured(text) {
		addControl(c, "control:input-isolation", "input-isolation", "", s.Source, "Input policy declares isolation between untrusted instructions and authority-bearing runtime behavior.")
	}
	if trustedSourcePolicyConfigured(text) {
		addControl(c, "control:trusted-source-policy", "trusted-source-policy", "", s.Source, "Input policy declares trusted source or allowlist controls for instruction inputs.")
	}
	if instructionProvenanceConfigured(text) {
		addControl(c, "control:instruction-provenance", "instruction-provenance", "", s.Source, "Input policy declares instruction provenance, signature, or source attribution controls.")
	}
	if untrustedInputDelimitingConfigured(text) {
		addControl(c, "control:untrusted-input-delimiting", "untrusted-input-delimiting", "", s.Source, "Input policy declares explicit delimiting or spotlighting for untrusted content.")
	}
	if promptInjectionFilterConfigured(text) {
		addControl(c, "control:prompt-injection-filter", "prompt-injection-filter", "", s.Source, "Input policy declares prompt-injection filtering controls.")
	}
}

func collectIdentityPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if cryptographicIdentityConfigured(text) {
		addControl(c, "control:cryptographic-identity", "cryptographic-identity", "", s.Source, "Identity policy declares cryptographic or workload identity for agent instances.")
	}
	if credentialIsolationConfigured(text) {
		addControl(c, "control:credential-isolation", "credential-isolation", "", s.Source, "Identity policy declares per-agent or non-shared credential isolation.")
	}
	if credentialHelperConfigured(text) {
		addControl(c, "control:credential-helper", "credential-helper", "", s.Source, "Identity policy requires credentials to be retrieved through a helper or vault instead of inline config.")
	}
	if shortLivedCredentialConfigured(text) {
		addControl(c, "control:short-lived-credential", "short-lived-credential", "", s.Source, "Identity policy requires short-lived, OAuth/OIDC, or federated credentials.")
	}
	if jitAccessConfigured(text) {
		addControl(c, "control:jit-access", "jit-access", "", s.Source, "Identity policy declares just-in-time access for agent tool credentials.")
	}
	if tokenLifetimePolicyConfigured(text) {
		addControl(c, "control:token-lifetime-policy", "token-lifetime-policy", "", s.Source, "Identity policy declares token lifetime limits for agent credentials.")
	}
	if hardwareBoundCredentialConfigured(text) {
		addControl(c, "control:hardware-bound-credential", "hardware-bound-credential", "", s.Source, "Identity policy declares hardware-bound credential posture.")
	}
	if identityLifecycleConfigured(text) {
		addControl(c, "control:identity-lifecycle", "identity-lifecycle", "", s.Source, "Identity policy declares credential rotation, revocation, or identity lifecycle controls.")
	}
	collectAuthorizationControls(c, "", s.Source, text)
}

func collectAuthorizationPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectAuthorizationControls(c, "", s.Source, text)
}

func collectWorkloadPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if identityBasedIsolationConfigured(text) {
		addControl(c, "control:identity-based-isolation", "identity-based-isolation", "", s.Source, "Workload policy declares identity-based workload isolation.")
	}
	if namedCallerConfigured(text) {
		addControl(c, "control:named-caller-allowlist", "named-caller-allowlist", "", s.Source, "Workload policy declares named caller, principal, or workload allowlist controls.")
	}
	if abacPolicyConfigured(text) {
		addControl(c, "control:abac-policy", "abac-policy", "", s.Source, "Workload policy declares attribute-based access control for agent workloads.")
	}
	if networkSegmentationConfigured(text) {
		addControl(c, "control:network-segmentation", "network-segmentation", "", s.Source, "Workload policy declares network segmentation or microsegmentation.")
	}
	if toolScopePolicyConfigured(text) {
		addControl(c, "control:tool-scope-policy", "tool-scope-policy", "", s.Source, "Workload policy declares per-tool scope, allowlist, or permission scope controls.")
	}
	collectAuthorizationControls(c, "", s.Source, text)
	collectResourceControls(c, "", s.Source, text)
	collectDelegationControls(c, "", s.Source, text)
}

func collectResourcePolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectResourceControls(c, "", s.Source, text)
}

func collectMemoryPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if contextRetentionConfigured(text) {
		addControl(c, "control:context-retention", "context-retention", "", s.Source, "Memory policy declares retention windows for memory, transcripts, or private context.")
	}
	if memoryIsolationConfigured(text) {
		addControl(c, "control:memory-isolation", "memory-isolation", "", s.Source, "Memory policy declares session, user, workspace, or tenant isolation for persisted context.")
	}
	if contextIntegrityConfigured(text) {
		addControl(c, "control:context-integrity", "context-integrity", "", s.Source, "Memory policy declares hashes, signatures, or integrity validation for persisted context.")
	}
	if contextProvenanceConfigured(text) {
		addControl(c, "control:context-provenance", "context-provenance", "", s.Source, "Memory policy declares source attribution or provenance metadata for persisted context.")
	}
	if credentialIsolationConfigured(text) {
		addControl(c, "control:credential-isolation", "credential-isolation", "", s.Source, "Memory policy declares that credentials are isolated from shared or persisted agent context.")
	}
}

func collectIntegrityPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectConfigIntegrityControls(c, "", s.Source, text)
}

func collectObservabilityPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectObservabilityControls(c, "", s.Source, text)
	collectResponseControls(c, "", s.Source, text)
}

func collectObservabilityControls(c *model.Collection, runtime, source, text string) {
	prefix := "Observability policy"
	if runtime != "" {
		prefix = runtime + " observability evidence"
	}
	if auditLoggingConfigured(text) {
		addControl(c, "control:audit-logging", "audit-logging", runtime, source, prefix+" declares tool-call, approval, telemetry, or audit logging.")
	}
	if traceabilityConfigured(text) {
		addControl(c, "control:request-traceability", "request-traceability", runtime, source, prefix+" declares request, trace, correlation, or provenance IDs.")
	}
	if telemetryExportConfigured(text) {
		addControl(c, "control:telemetry-export", "telemetry-export", runtime, source, prefix+" declares telemetry export for agent audit correlation.")
	}
	if immutableAuditConfigured(text) {
		addControl(c, "control:immutable-audit-log", "immutable-audit-log", runtime, source, prefix+" declares append-only or immutable audit log storage.")
	}
}

func collectTelemetryConfig(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	if telemetryExportConfigured(text) {
		addControl(c, "control:telemetry-export", "telemetry-export", "", s.Source, "OpenTelemetry collector config exports traces, logs, or metrics for audit correlation.")
	}
	if strings.Contains(text, "traces") || strings.Contains(text, "trace") {
		addControl(c, "control:request-traceability", "request-traceability", "", s.Source, "OpenTelemetry collector config includes trace pipeline evidence.")
	}
	if strings.Contains(text, "logs") || strings.Contains(text, "logging") {
		addControl(c, "control:audit-logging", "audit-logging", "", s.Source, "OpenTelemetry collector config includes log pipeline evidence.")
	}
}

func collectPluginSurface(c *model.Collection, s model.Surface) {
	runtime := runtimeForSurface(s)
	c.Tools = appendUniqueTool(c.Tools, model.Tool{ID: "tool:agent-plugin-surface", Kind: "agent-plugin-surface", Runtime: runtime, Source: s.Source, Summary: displayRuntime(runtime) + " plugin, skill, or extension configuration surface exists."})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:agent-plugin-surface", "tool", s.Source, "observed", "Plugin surface was observed; plugin code was not executed."))
}

func collectManagedControlSurface(c *model.Collection, s model.Surface) {
	c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:managed-runtime-settings", Kind: "managed-runtime-settings", Runtime: "claude", Source: s.Source, Summary: "Managed or policy settings surface exists for Claude Code."})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:control:managed-runtime-settings", "control", s.Source, "observed", "Managed settings surface was observed."))
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	collectConfigIntegrityControls(c, "claude", s.Source, strings.ToLower(string(data)))
}

func addExternalCommunication(c *model.Collection, runtime, source, summary string) {
	c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:external-communication", Kind: "external-communication", Runtime: runtime, Source: source, Summary: summary})
	c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:external-destination", Kind: "external-destination", Abstract: true, Summary: "External network, web, or remote service destination outside the local trust boundary."})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:authority:external-communication", "authority", source, "declared", "External communication authority was collected."))
}

func collectRuntimeSecurityControls(c *model.Collection, runtime, source, text string) {
	if cryptographicIdentityConfigured(text) {
		addControl(c, "control:cryptographic-identity", "cryptographic-identity", runtime, source, runtime+" config declares cryptographic, certificate, or workload identity posture.")
	}
	if leastAgencyConfigured(text) {
		addControl(c, "control:least-agency-policy", "least-agency-policy", runtime, source, runtime+" config declares deny-by-default or least-agency permission scoping.")
	}
	if denyByDefaultConfigured(text) {
		addControl(c, "control:deny-by-default-permissions", "deny-by-default-permissions", runtime, source, runtime+" config declares deny-by-default permission posture.")
	}
	if scopedPermissionConfigured(text) {
		addControl(c, "control:scoped-permissions", "scoped-permissions", runtime, source, runtime+" config declares scoped filesystem, shell, network, or tool permissions.")
	}
	if identityBasedIsolationConfigured(text) {
		addControl(c, "control:identity-based-isolation", "identity-based-isolation", runtime, source, runtime+" config declares identity-based isolation or named-caller boundaries.")
	}
	if namedCallerConfigured(text) {
		addControl(c, "control:named-caller-allowlist", "named-caller-allowlist", runtime, source, runtime+" config declares named caller, principal, or workload allowlist controls.")
	}
	if abacPolicyConfigured(text) {
		addControl(c, "control:abac-policy", "abac-policy", runtime, source, runtime+" config declares attribute-based access control for agent workloads.")
	}
	if networkSegmentationConfigured(text) {
		addControl(c, "control:network-segmentation", "network-segmentation", runtime, source, runtime+" config declares workload network segmentation or microsegmentation.")
	}
	if toolScopePolicyConfigured(text) {
		addControl(c, "control:tool-scope-policy", "tool-scope-policy", runtime, source, runtime+" config declares per-tool scope, allowlist, or permission scope controls.")
	}
	if approvalRequired(text) {
		addControl(c, "control:approval-required", "approval-required", runtime, source, runtime+" config requires approval for high-risk or non-read-only agent actions.")
	}
	if sandboxIsolated(text) {
		addControl(c, "control:sandbox-isolation", "sandbox-isolation", runtime, source, runtime+" config declares sandbox or filesystem isolation.")
	}
	if credentialHelperConfigured(text) {
		addControl(c, "control:credential-helper", "credential-helper", runtime, source, runtime+" config retrieves credentials through a helper or vault instead of inline config.")
	}
	if shortLivedCredentialConfigured(text) {
		addControl(c, "control:short-lived-credential", "short-lived-credential", runtime, source, runtime+" config declares OAuth, OIDC, or short-lived credential posture.")
	}
	if credentialIsolationConfigured(text) {
		addControl(c, "control:credential-isolation", "credential-isolation", runtime, source, runtime+" config declares per-agent or non-shared credential isolation.")
	}
	if jitAccessConfigured(text) {
		addControl(c, "control:jit-access", "jit-access", runtime, source, runtime+" config declares just-in-time access for agent tool credentials.")
	}
	if tokenLifetimePolicyConfigured(text) {
		addControl(c, "control:token-lifetime-policy", "token-lifetime-policy", runtime, source, runtime+" config declares token lifetime limits for agent credentials.")
	}
	if hardwareBoundCredentialConfigured(text) {
		addControl(c, "control:hardware-bound-credential", "hardware-bound-credential", runtime, source, runtime+" config declares hardware-bound credential posture.")
	}
	if identityLifecycleConfigured(text) {
		addControl(c, "control:identity-lifecycle", "identity-lifecycle", runtime, source, runtime+" config declares credential rotation, revocation, or identity lifecycle controls.")
	}
	if auditLoggingConfigured(text) {
		addControl(c, "control:audit-logging", "audit-logging", runtime, source, runtime+" config declares tool-call, approval, or telemetry logging.")
	}
	if traceabilityConfigured(text) {
		addControl(c, "control:request-traceability", "request-traceability", runtime, source, runtime+" config declares request, trace, correlation, or provenance IDs.")
	}
	if telemetryExportConfigured(text) {
		addControl(c, "control:telemetry-export", "telemetry-export", runtime, source, runtime+" config declares telemetry export for audit correlation.")
	}
	if immutableAuditConfigured(text) {
		addControl(c, "control:immutable-audit-log", "immutable-audit-log", runtime, source, runtime+" config declares append-only or immutable audit log storage.")
	}
	if inputValidationConfigured(text) {
		addControl(c, "control:input-validation", "input-validation", runtime, source, runtime+" config declares schema, length, or prompt-injection validation.")
	}
	if inputIsolationConfigured(text) {
		addControl(c, "control:input-isolation", "input-isolation", runtime, source, runtime+" config declares isolation between untrusted instructions and authority-bearing runtime behavior.")
	}
	if trustedSourcePolicyConfigured(text) {
		addControl(c, "control:trusted-source-policy", "trusted-source-policy", runtime, source, runtime+" config declares trusted source or allowlist controls for instruction inputs.")
	}
	if instructionProvenanceConfigured(text) {
		addControl(c, "control:instruction-provenance", "instruction-provenance", runtime, source, runtime+" config declares instruction provenance, signature, or source attribution controls.")
	}
	if untrustedInputDelimitingConfigured(text) {
		addControl(c, "control:untrusted-input-delimiting", "untrusted-input-delimiting", runtime, source, runtime+" config declares explicit delimiting or spotlighting for untrusted content.")
	}
	if promptInjectionFilterConfigured(text) {
		addControl(c, "control:prompt-injection-filter", "prompt-injection-filter", runtime, source, runtime+" config declares prompt-injection filtering controls.")
	}
	if automatedTriageConfigured(text) {
		addControl(c, "control:automated-triage", "automated-triage", runtime, source, runtime+" config declares automated first-pass investigation or alert triage.")
	}
	if contextRetentionConfigured(text) {
		addControl(c, "control:context-retention", "context-retention", runtime, source, runtime+" config constrains transcript, memory, or private-context retention.")
	}
	if memoryIsolationConfigured(text) {
		addControl(c, "control:memory-isolation", "memory-isolation", runtime, source, runtime+" config declares memory or private-context isolation controls.")
	}
	if contextIntegrityConfigured(text) {
		addControl(c, "control:context-integrity", "context-integrity", runtime, source, runtime+" config declares context integrity validation controls.")
	}
	if contextProvenanceConfigured(text) {
		addControl(c, "control:context-provenance", "context-provenance", runtime, source, runtime+" config declares context source attribution or provenance metadata.")
	}
	collectToolIntegrityControls(c, runtime, source, text)
	collectDelegationControls(c, runtime, source, text)
	collectConfigIntegrityControls(c, runtime, source, text)
	collectResponseControls(c, runtime, source, text)
	collectOutputControls(c, runtime, source, text)
	collectAuthorizationControls(c, runtime, source, text)
	collectResourceControls(c, runtime, source, text)
	if inlineCredentialConfigured(text) {
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:credential-material",
			Kind:     "credential-material",
			Source:   source,
			Abstract: false,
			Summary:  "Config contains inline credential field indicators; values are not emitted.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:credential-material", "boundary", source, "observed", "Inline credential field indicators were detected without emitting values."))
	}
}

func addControl(c *model.Collection, id, kind, runtime, source, summary string) {
	c.Controls = appendUniqueControl(c.Controls, model.Control{ID: id, Kind: kind, Runtime: runtime, Source: source, Summary: summary})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:"+id, "control", source, "declared", summary))
}

func addObservedControl(c *model.Collection, id, kind, runtime, source, summary string) {
	c.Controls = appendUniqueControl(c.Controls, model.Control{ID: id, Kind: kind, Runtime: runtime, Source: source, Summary: summary})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:"+id, "control", source, "observed", summary))
}

func collectSummarySurface(c *model.Collection, s model.Surface) {
	c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:agent-private-context", Kind: "agent-private-context", Source: s.Source, Abstract: false, Summary: "Agent private context cache/history exists; contents are not inspected or emitted by default."})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:agent-private-context", "boundary", s.Source, "observed", "Private agent context surface was summarized without reading contents."))
	if s.SensitiveNameCount > 0 {
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
			ID:       "boundary:memory-credential-retention",
			Kind:     "memory-credential-retention",
			Source:   s.Source,
			Abstract: false,
			Summary:  "Agent private context includes credential-like filename indicators; contents are not inspected or emitted.",
		})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence(
			"evidence:boundary:memory-credential-retention",
			"boundary",
			s.Source,
			"observed",
			fmt.Sprintf("Private context metadata includes %d credential-like filename indicator(s); values and content were not inspected.", s.SensitiveNameCount),
		))
	}
	collectObservabilityMetadata(c, s)
}

func collectBoundaryIndicator(c *model.Collection, s model.Surface) {
	c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{
		ID:      "boundary:secret-like-file",
		Kind:    "secret-like-file",
		Source:  s.Source,
		Summary: "Secret-like file path exists; contents are not read or reported.",
	})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:secret-like-file", "boundary", s.Source, "observed", "Secret-like boundary exists; values are not included in reports."))
}

func runtimeForSurface(s model.Surface) string {
	if s.Runtime == "mcp" || s.Runtime == "generic" {
		return ""
	}
	return s.Runtime
}

func displayRuntime(runtime string) string {
	switch runtime {
	case "claude":
		return "Claude Code"
	case "codex":
		return "Codex"
	case "cursor":
		return "Cursor"
	case "windsurf":
		return "Windsurf"
	case "continue":
		return "Continue"
	case "aider":
		return "Aider"
	case "gemini":
		return "Gemini CLI"
	case "opencode":
		return "OpenCode"
	case "copilot":
		return "GitHub Copilot"
	case "github-actions":
		return "GitHub Actions"
	case "gitlab-ci":
		return "GitLab CI"
	case "cline":
		return "Cline"
	case "roo":
		return "Roo Code"
	case "":
		return "Agent"
	default:
		return runtime
	}
}

func gradeForSurface(s model.Surface) string {
	switch s.HandlingMode {
	case "parse":
		return "observed"
	case "boundary_indicator":
		return "observed"
	case "summarize":
		return "observed"
	case "skip":
		return "skipped"
	default:
		return "observed"
	}
}

func redactionForSurface(s model.Surface) string {
	switch s.HandlingMode {
	case "summarize":
		return "content-not-inspected"
	case "boundary_indicator":
		return "path-only-no-content"
	case "parse":
		return "summary-only"
	default:
		return "default"
	}
}

func limitationsForSurface(s model.Surface) []string {
	switch s.HandlingMode {
	case "summarize":
		return []string{"Private or high-volume content was summarized by metadata only."}
	case "boundary_indicator":
		return []string{"Boundary detection uses the path/name only; file contents were not read."}
	case "skip":
		return []string{"Surface was intentionally skipped by bounded discovery rules."}
	default:
		return nil
	}
}

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) || strings.HasPrefix(text, strings.TrimSpace(needle)+" ") {
			return true
		}
	}
	return false
}

func broadLocalAgentConfig(text string) bool {
	return containsAny(text, []string{
		"danger-full-access",
		"full_access",
		"full access",
		"bypasspermissions",
		"bypass permissions",
		"dangerously-bypass",
		"auto-approve",
		"auto_approve",
		"yes_always",
		"approval_policy = \"never\"",
		"approval_policy: never",
		"approval: never",
		"yolo",
	})
}

func fileReadAgentConfig(text string) bool {
	return containsAny(text, []string{
		"read_file",
		"read files",
		"filesystem",
		"file_system",
		"workspace",
		"allowed_directories",
		"allowed-directories",
		"context provider",
		"context_provider",
	})
}

func localExecutionAgentConfig(text string) bool {
	return containsAny(text, []string{
		"bash(",
		"shell",
		"terminal",
		"run_command",
		"run-command",
		"exec",
		"subprocess",
		"allow_commands",
		"allow-commands",
	})
}

func mcpConfigured(text string) bool {
	return containsAny(text, []string{
		"mcpservers",
		"mcp_servers",
		"mcp server",
		"mcp_server",
		"\"mcp\"",
		"[mcp",
	})
}

func containsExternalCommunication(text string) bool {
	return containsAny(text, []string{"curl ", "wget ", "http://", "https://", "webhook", "webfetch", "websearch", "post ", "upload", "send to"})
}

func workflowAgentLike(text string) bool {
	return containsAny(text, []string{
		"claude",
		"anthropic",
		"codex",
		"openai",
		"copilot",
		"gemini",
		"aider",
		"cursor-agent",
		"continue",
		"llm",
		"ai review",
		"ai-review",
		"agent",
	})
}

func workflowExecutesCode(text string) bool {
	return strings.Contains(text, "\nrun:") ||
		strings.Contains(text, "\n  run:") ||
		strings.Contains(text, "\n    run:") ||
		strings.Contains(text, "uses:")
}

func workflowReadsRepo(text string) bool {
	return strings.Contains(text, "actions/checkout") ||
		strings.Contains(text, "checkout@") ||
		strings.Contains(text, "github.workspace") ||
		strings.Contains(text, "${{ github.workspace }}")
}

func workflowHasUntrustedTrigger(text string) bool {
	return strings.Contains(text, "pull_request") ||
		strings.Contains(text, "pull_request_target") ||
		strings.Contains(text, "issue_comment") ||
		strings.Contains(text, "workflow_run") ||
		strings.Contains(text, "repository_dispatch")
}

func workflowHasWritePermission(text string) bool {
	return strings.Contains(text, "write-all") ||
		strings.Contains(text, "contents: write") ||
		strings.Contains(text, "pull-requests: write") ||
		strings.Contains(text, "issues: write") ||
		strings.Contains(text, "id-token: write") ||
		strings.Contains(text, "packages: write")
}

func workflowHasRepositoryWritePermission(text string) bool {
	return strings.Contains(text, "write-all") ||
		strings.Contains(text, "contents: write") ||
		strings.Contains(text, "pull-requests: write") ||
		strings.Contains(text, "issues: write") ||
		strings.Contains(text, "packages: write") ||
		strings.Contains(text, "actions: write") ||
		strings.Contains(text, "checks: write") ||
		strings.Contains(text, "statuses: write")
}

func workflowHasOIDCTokenPermission(text string) bool {
	return strings.Contains(text, "id-token: write")
}

func workflowReferencesSecrets(text string) bool {
	return strings.Contains(text, "${{ secrets.") ||
		strings.Contains(text, "secrets.") ||
		strings.Contains(text, " secrets:") ||
		strings.Contains(text, "\nsecrets:")
}

func workflowScopedPermissions(text string) bool {
	return strings.Contains(text, "permissions: read-all") ||
		strings.Contains(text, "contents: read") ||
		strings.Contains(text, "pull-requests: read") ||
		strings.Contains(text, "issues: read")
}

func workflowPinnedActions(text string) bool {
	return looksPinned(text) ||
		regexp.MustCompile(`(?m)uses:\s*[^@\s]+@[0-9a-f]{12,}`).MatchString(text)
}

func gitlabWorkflowExecutesCode(text string) bool {
	return strings.Contains(text, "\nscript:") ||
		strings.Contains(text, "\n  script:") ||
		strings.Contains(text, "\n    script:") ||
		strings.Contains(text, "\nbefore_script:") ||
		strings.Contains(text, "\nafter_script:")
}

func gitlabWorkflowReadsRepo(text string) bool {
	return strings.Contains(text, "ci_project_dir") ||
		strings.Contains(text, "$ci_project_dir") ||
		strings.Contains(text, "git_strategy") ||
		strings.Contains(text, "git checkout") ||
		strings.Contains(text, "git fetch") ||
		strings.Contains(text, "git clone")
}

func gitlabWorkflowHasUntrustedTrigger(text string) bool {
	return strings.Contains(text, "merge_request_event") ||
		strings.Contains(text, "external_pull_request_event") ||
		strings.Contains(text, "ci_merge_request") ||
		strings.Contains(text, "only: merge_requests") ||
		strings.Contains(text, "source == \"web\"") ||
		strings.Contains(text, "source == \"trigger\"") ||
		strings.Contains(text, "source == \"pipeline\"") ||
		strings.Contains(text, "source == \"schedule\"")
}

func gitlabWorkflowHasWritePermission(text string) bool {
	return gitlabWorkflowHasRepositoryWritePermission(text) ||
		strings.Contains(text, "write_registry") ||
		strings.Contains(text, "ci_registry_password") ||
		strings.Contains(text, "deploy_token")
}

func gitlabWorkflowHasRepositoryWritePermission(text string) bool {
	return strings.Contains(text, "ci_job_token") ||
		strings.Contains(text, "job-token") ||
		strings.Contains(text, "private-token") ||
		strings.Contains(text, "write_repository") ||
		strings.Contains(text, "git push") ||
		strings.Contains(text, "glab mr") ||
		strings.Contains(text, "/api/v4/projects") ||
		strings.Contains(text, "merge_requests") ||
		strings.Contains(text, "repository/commits")
}

func gitlabWorkflowHasOIDCTokenPermission(text string) bool {
	return strings.Contains(text, "id_tokens:") ||
		strings.Contains(text, "\nidentity:") ||
		strings.Contains(text, "oidc") ||
		strings.Contains(text, "jwt")
}

func gitlabWorkflowReferencesSecrets(text string) bool {
	return containsAny(text, []string{
		"ci_job_token",
		"ci_registry_password",
		"deploy_token",
		"private-token",
		"variables:",
		"masked:",
		"protected:",
		"$openai_api_key",
		"$anthropic_api_key",
		"$api_key",
		"$token",
		"$secret",
	})
}

func gitlabWorkflowHasScopedRules(text string) bool {
	return strings.Contains(text, "\nrules:") ||
		strings.Contains(text, "\nonly:") ||
		strings.Contains(text, "\nexcept:") ||
		strings.Contains(text, "protected: true")
}

func gitlabWorkflowPinnedImage(text string) bool {
	return strings.Contains(text, "@sha256:") ||
		regexp.MustCompile(`(?m)image:\s*[^@\s]+@[0-9a-f]{12,}`).MatchString(text)
}

func gitlabWorkflowRequiresApproval(text string) bool {
	return strings.Contains(text, "when: manual") ||
		strings.Contains(text, "manual_confirmation") ||
		strings.Contains(text, "\nenvironment:") ||
		strings.Contains(text, "protected: true")
}

type observabilitySignals struct {
	files       int
	lines       int
	toolCall    bool
	approval    bool
	requestID   bool
	timestamp   bool
	eventRecord bool
}

func collectObservabilityMetadata(c *model.Collection, s model.Surface) {
	signals := inspectObservabilityMetadata(s.Path)
	if signals.files == 0 || signals.lines == 0 {
		return
	}
	if signals.toolCall && signals.timestamp {
		addObservedControl(c, "control:tool-call-audit-evidence", "tool-call-audit-evidence", s.Runtime, s.Source, fmt.Sprintf("Structured agent transcript metadata includes tool-call event shape in %d sampled line(s); content suppressed.", signals.lines))
	}
	if signals.approval && signals.timestamp {
		addObservedControl(c, "control:approval-log-evidence", "approval-log-evidence", s.Runtime, s.Source, fmt.Sprintf("Structured agent transcript metadata includes approval or permission decision event shape in %d sampled line(s); content suppressed.", signals.lines))
	}
	if signals.requestID {
		addObservedControl(c, "control:observed-request-traceability", "observed-request-traceability", s.Runtime, s.Source, "Structured agent transcript metadata includes request, trace, correlation, or session identifiers.")
	}
	if signals.eventRecord && signals.timestamp {
		addObservedControl(c, "control:agent-action-log-evidence", "agent-action-log-evidence", s.Runtime, s.Source, fmt.Sprintf("Structured agent transcript metadata includes timestamped event records across %d sampled file(s).", signals.files))
	}
}

func inspectObservabilityMetadata(path string) observabilitySignals {
	var out observabilitySignals
	info, err := os.Stat(path)
	if err != nil {
		return out
	}
	if !info.IsDir() {
		inspectObservabilityFile(path, &out)
		return out
	}
	const maxFiles = 12
	_ = filepath.WalkDir(path, func(child string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || out.files >= maxFiles {
			return nil
		}
		if !observabilityFileName(child) {
			return nil
		}
		inspectObservabilityFile(child, &out)
		return nil
	})
	return out
}

func observabilityFileName(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".jsonl") ||
		strings.HasSuffix(lower, ".ndjson") ||
		strings.HasSuffix(lower, ".log")
}

func inspectObservabilityFile(path string, out *observabilitySignals) {
	if !observabilityFileName(path) {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	out.files++
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	const maxLines = 80
	for scanner.Scan() {
		if out.lines >= maxLines {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var value any
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			continue
		}
		out.lines++
		inspectJSONForObservability(value, "", out)
	}
}

func inspectJSONForObservability(value any, key string, out *observabilitySignals) {
	lowerKey := strings.ToLower(key)
	if strings.Contains(lowerKey, "tool") {
		out.toolCall = true
	}
	if strings.Contains(lowerKey, "approval") || strings.Contains(lowerKey, "permission") || strings.Contains(lowerKey, "decision") {
		out.approval = true
	}
	if strings.Contains(lowerKey, "request_id") || strings.Contains(lowerKey, "trace_id") || strings.Contains(lowerKey, "correlation_id") || strings.Contains(lowerKey, "session_id") {
		out.requestID = true
	}
	if lowerKey == "timestamp" || lowerKey == "time" || lowerKey == "ts" || strings.HasSuffix(lowerKey, ".timestamp") {
		out.timestamp = true
	}
	if lowerKey == "type" || strings.HasSuffix(lowerKey, ".type") || strings.Contains(lowerKey, "event") {
		out.eventRecord = true
	}
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			nextKey := childKey
			if key != "" {
				nextKey = key + "." + childKey
			}
			inspectJSONForObservability(child, nextKey, out)
		}
	case []any:
		for _, child := range typed {
			inspectJSONForObservability(child, key, out)
		}
	case string:
		inspectSafeEventValue(lowerKey, strings.ToLower(typed), out)
	}
}

func inspectSafeEventValue(key, value string, out *observabilitySignals) {
	switch {
	case key == "type" || strings.HasSuffix(key, ".type") || strings.Contains(key, "event"):
		out.eventRecord = true
		if strings.Contains(value, "tool_use") || strings.Contains(value, "tool_call") || strings.Contains(value, "tool_result") {
			out.toolCall = true
		}
		if strings.Contains(value, "approval") || strings.Contains(value, "permission") || strings.Contains(value, "decision") {
			out.approval = true
		}
	case strings.Contains(key, "name") || strings.Contains(key, "tool"):
		if value != "" {
			out.toolCall = true
		}
	case strings.Contains(key, "decision"):
		if value != "" {
			out.approval = true
		}
	}
}

func networkRestricted(text string) bool {
	return strings.Contains(text, "network_access = false") ||
		strings.Contains(text, "network_access=false") ||
		strings.Contains(text, "\"network_access\": false") ||
		strings.Contains(text, "\"external_network\": false") ||
		strings.Contains(text, "external_network = false") ||
		strings.Contains(text, "block_external_network") ||
		strings.Contains(text, "deny_network")
}

func networkEnabled(text string) bool {
	return strings.Contains(text, "network_access = true") ||
		strings.Contains(text, "network_access=true") ||
		strings.Contains(text, "\"network_access\": true") ||
		strings.Contains(text, "\"external_network\": true") ||
		strings.Contains(text, "external_network = true")
}

func egressDestinationAllowlistConfigured(text string) bool {
	return strings.Contains(text, "egress_destination_allowlist") ||
		strings.Contains(text, "external_destination_allowlist") ||
		strings.Contains(text, "destination_allowlist") ||
		strings.Contains(text, "allowed_destinations") ||
		strings.Contains(text, "allowed_domains") ||
		strings.Contains(text, "allowlisted_domains") ||
		strings.Contains(text, "outbound_allowlist")
}

func webhookAllowlistConfigured(text string) bool {
	return strings.Contains(text, "webhook_allowlist") ||
		strings.Contains(text, "allowed_webhooks") ||
		strings.Contains(text, "approved_webhooks") ||
		strings.Contains(text, "approved_webhook_destinations") ||
		strings.Contains(text, "webhook_destinations")
}

func perToolNetworkScopeConfigured(text string) bool {
	return strings.Contains(text, "per_tool_network_scope") ||
		strings.Contains(text, "tool_network_scope") ||
		strings.Contains(text, "tool_egress_scope") ||
		strings.Contains(text, "network_scope_per_tool") ||
		strings.Contains(text, "allowed_network_by_tool")
}

func egressContentFilterConfigured(text string) bool {
	return strings.Contains(text, "egress_content_filter") ||
		strings.Contains(text, "external_content_filter") ||
		strings.Contains(text, "output_filter") ||
		strings.Contains(text, "output_filtering") ||
		strings.Contains(text, "sensitive_output_filter") ||
		strings.Contains(text, "dlp") ||
		strings.Contains(text, "block_secret_like")
}

func egressAuditConfigured(text string) bool {
	return strings.Contains(text, "egress_audit") ||
		strings.Contains(text, "outbound_audit") ||
		strings.Contains(text, "network_audit") ||
		strings.Contains(text, "external_communication_logging") ||
		strings.Contains(text, "outbound_logging") ||
		strings.Contains(text, "egress_log")
}

func outputSensitiveDataFilterConfigured(text string) bool {
	return strings.Contains(text, "output_sensitive_data_filter") ||
		strings.Contains(text, "sensitive_output_filter") ||
		strings.Contains(text, "output_filter") ||
		strings.Contains(text, "output_filtering") ||
		strings.Contains(text, "output_dlp") ||
		strings.Contains(text, "dlp") ||
		strings.Contains(text, "pii_filter") ||
		strings.Contains(text, "credential_filter") ||
		strings.Contains(text, "sensitive_data_patterns")
}

func outputRedactionConfigured(text string) bool {
	return strings.Contains(text, "output_redaction") ||
		strings.Contains(text, "redact_outputs") ||
		strings.Contains(text, "redact_sensitive_output") ||
		strings.Contains(text, "block_sensitive_output") ||
		strings.Contains(text, "block_secret_like") ||
		strings.Contains(text, "redact_secret_like") ||
		strings.Contains(text, "output_delivery_gate")
}

func outputFilterLoggingConfigured(text string) bool {
	return strings.Contains(text, "output_filter_logging") ||
		strings.Contains(text, "output_control_audit") ||
		strings.Contains(text, "filtering_events") ||
		strings.Contains(text, "dlp_logging") ||
		strings.Contains(text, "redaction_logging")
}

func semanticOutputAnalysisConfigured(text string) bool {
	return strings.Contains(text, "semantic_output_analysis") ||
		strings.Contains(text, "output_semantic_review") ||
		strings.Contains(text, "semantic_dlp") ||
		strings.Contains(text, "encoded_secret_detection") ||
		strings.Contains(text, "harmful_output_detection") ||
		strings.Contains(text, "social_engineering_output")
}

func highRiskOutputReviewConfigured(text string) bool {
	return strings.Contains(text, "high_risk_output_review") ||
		strings.Contains(text, "human_review_for_high_risk_output") ||
		strings.Contains(text, "human_in_loop_output") ||
		strings.Contains(text, "output_approval") ||
		strings.Contains(text, "approve_sensitive_output")
}

func perActionAuthorizationConfigured(text string) bool {
	return strings.Contains(text, "per_action_authorization") ||
		strings.Contains(text, "per-action authorization") ||
		strings.Contains(text, "authorize_each_action") ||
		strings.Contains(text, "authorize_every_action") ||
		strings.Contains(text, "per_tool_authorization") ||
		strings.Contains(text, "tool_invocation_authorization") ||
		strings.Contains(text, "authorization_at_each_action") ||
		strings.Contains(text, "authorize_tool_call")
}

func continuousAuthorizationConfigured(text string) bool {
	return strings.Contains(text, "continuous_authorization") ||
		strings.Contains(text, "continuous authorization") ||
		strings.Contains(text, "real_time_policy_evaluation") ||
		strings.Contains(text, "real-time policy evaluation") ||
		strings.Contains(text, "policy_evaluation_per_action") ||
		strings.Contains(text, "runtime_policy_evaluation") ||
		strings.Contains(text, "reauthorize_on_risk_change") ||
		strings.Contains(text, "risk_adaptive_authorization")
}

func dynamicPrivilegeScopingConfigured(text string) bool {
	return strings.Contains(text, "dynamic_privilege_scoping") ||
		strings.Contains(text, "dynamic privilege scoping") ||
		strings.Contains(text, "dynamic_permission_scope") ||
		strings.Contains(text, "dynamic_access_scoping") ||
		strings.Contains(text, "just_enough_access") ||
		strings.Contains(text, "just-enough-access") ||
		strings.Contains(text, "jea") ||
		strings.Contains(text, "task_scoped_privileges")
}

func jitElevationConfigured(text string) bool {
	return strings.Contains(text, "jit_elevation") ||
		strings.Contains(text, "jit_privilege") ||
		strings.Contains(text, "jit_access") ||
		strings.Contains(text, "just_in_time_access") ||
		strings.Contains(text, "just-in-time access") ||
		strings.Contains(text, "privilege_elevation_ttl") ||
		strings.Contains(text, "elevate_permissions_only_when_needed")
}

func standingAccessDeniedConfigured(text string) bool {
	return strings.Contains(text, "standing_access = false") ||
		strings.Contains(text, "standing_access=false") ||
		strings.Contains(text, "\"standing_access\": false") ||
		strings.Contains(text, "\"standing_access\":false") ||
		strings.Contains(text, "no_standing_access") ||
		strings.Contains(text, "no standing access") ||
		strings.Contains(text, "no_standing_privileges") ||
		strings.Contains(text, "no_persistent_elevation") ||
		strings.Contains(text, "standing_privileges_denied")
}

func automaticAccessRevocationConfigured(text string) bool {
	return strings.Contains(text, "automatic_access_revocation") ||
		strings.Contains(text, "auto_revoke_access") ||
		strings.Contains(text, "revoke_on_risk_change") ||
		strings.Contains(text, "revoke_when_risk_changes") ||
		strings.Contains(text, "access_revocation_on_policy_failure") ||
		strings.Contains(text, "revoke_after_task") ||
		strings.Contains(text, "revoke_after_completion") ||
		strings.Contains(text, "revoke_on_anomaly") ||
		strings.Contains(text, "policy_failure_revocation")
}

func cryptographicIdentityConfigured(text string) bool {
	return strings.Contains(text, "cryptographic_identity") ||
		strings.Contains(text, "workload_identity") ||
		strings.Contains(text, "agent_certificate") ||
		strings.Contains(text, "certificate_identity") ||
		strings.Contains(text, "x509") ||
		strings.Contains(text, "m_tls") ||
		strings.Contains(text, "mtls") ||
		strings.Contains(text, "spiffe") ||
		strings.Contains(text, "spiffe_id")
}

func leastAgencyConfigured(text string) bool {
	return strings.Contains(text, "least_agency") ||
		strings.Contains(text, "least_privilege") ||
		strings.Contains(text, "deny_by_default") ||
		strings.Contains(text, "deny-by-default") ||
		strings.Contains(text, "rbac") ||
		strings.Contains(text, "tool_scope") ||
		strings.Contains(text, "permission_scope") ||
		strings.Contains(text, "scoped_permissions")
}

func denyByDefaultConfigured(text string) bool {
	return strings.Contains(text, "deny_by_default") ||
		strings.Contains(text, "deny-by-default") ||
		strings.Contains(text, "\"defaultmode\": \"default\"") ||
		strings.Contains(text, "\"default_mode\": \"default\"") ||
		strings.Contains(text, "default_mode = \"default\"") ||
		strings.Contains(text, "default_policy = \"deny\"") ||
		strings.Contains(text, "default_policy=\"deny\"") ||
		strings.Contains(text, "default_deny = true") ||
		strings.Contains(text, "\"default_deny\": true")
}

func scopedPermissionConfigured(text string) bool {
	if strings.Contains(text, "bypasspermissions") ||
		strings.Contains(text, "danger-full-access") ||
		strings.Contains(text, "dangerously-bypass") ||
		strings.Contains(text, "bash(*)") {
		return false
	}
	return strings.Contains(text, "sandbox_mode = \"workspace-write\"") ||
		strings.Contains(text, "sandbox_mode=\"workspace-write\"") ||
		strings.Contains(text, "sandbox_mode = \"read-only\"") ||
		strings.Contains(text, "sandbox_mode=\"read-only\"") ||
		strings.Contains(text, "allowed_sandbox_modes") ||
		strings.Contains(text, "deny_read") ||
		strings.Contains(text, "\"deny\"") ||
		strings.Contains(text, "read(") && !strings.Contains(text, "read(*)") ||
		strings.Contains(text, "bash(") && !strings.Contains(text, "bash(*)") ||
		strings.Contains(text, "scoped_permissions") ||
		strings.Contains(text, "permission_scope") ||
		strings.Contains(text, "tool_scope")
}

func identityBasedIsolationConfigured(text string) bool {
	return strings.Contains(text, "identity_based_isolation") ||
		strings.Contains(text, "identity-based isolation") ||
		strings.Contains(text, "workload_isolation") ||
		strings.Contains(text, "workload-isolation") ||
		strings.Contains(text, "identity_aware_proxy") ||
		strings.Contains(text, "identity-aware proxy")
}

func namedCallerConfigured(text string) bool {
	return strings.Contains(text, "named_callers") ||
		strings.Contains(text, "named-callers") ||
		strings.Contains(text, "allowed_callers") ||
		strings.Contains(text, "caller_allowlist") ||
		strings.Contains(text, "allowed_principals") ||
		strings.Contains(text, "principal_allowlist") ||
		strings.Contains(text, "service_account_allowlist") ||
		strings.Contains(text, "workload_allowlist")
}

func abacPolicyConfigured(text string) bool {
	return strings.Contains(text, "abac") ||
		strings.Contains(text, "attribute_based") ||
		strings.Contains(text, "attribute-based") ||
		strings.Contains(text, "attribute_conditions") ||
		strings.Contains(text, "subject_attributes") ||
		strings.Contains(text, "resource_attributes") ||
		strings.Contains(text, "context_attributes") ||
		strings.Contains(text, "policy_conditions") ||
		strings.Contains(text, "claims_required")
}

func networkSegmentationConfigured(text string) bool {
	return strings.Contains(text, "network_segmentation") ||
		strings.Contains(text, "network-segmentation") ||
		strings.Contains(text, "microsegmentation")
}

func toolScopePolicyConfigured(text string) bool {
	return strings.Contains(text, "tool_scope") ||
		strings.Contains(text, "tool-scopes") ||
		strings.Contains(text, "tool_scopes") ||
		strings.Contains(text, "per_tool_scope") ||
		strings.Contains(text, "allowed_tools") ||
		strings.Contains(text, "tool_allowlist") ||
		strings.Contains(text, "mcp_allowlist") ||
		strings.Contains(text, "permission_scope")
}

func delegationScopeConfigured(text string) bool {
	return strings.Contains(text, "delegation_scope") ||
		strings.Contains(text, "delegated_scope") ||
		strings.Contains(text, "subagent_scope") ||
		strings.Contains(text, "least_privilege_delegation") ||
		strings.Contains(text, "scoped_delegation") ||
		strings.Contains(text, "delegate_permissions") ||
		strings.Contains(text, "subagent_permissions")
}

func delegationAllowlistConfigured(text string) bool {
	return strings.Contains(text, "allowed_delegate_agents") ||
		strings.Contains(text, "delegation_allowlist") ||
		strings.Contains(text, "delegate_allowlist") ||
		strings.Contains(text, "approved_delegates") ||
		strings.Contains(text, "approved_subagents") ||
		strings.Contains(text, "allowed_subagents")
}

func agentToAgentAuthorizationConfigured(text string) bool {
	return strings.Contains(text, "agent_to_agent_authorization") ||
		strings.Contains(text, "agent-to-agent authorization") ||
		strings.Contains(text, "delegate_authorization") ||
		strings.Contains(text, "delegation_authorization") ||
		strings.Contains(text, "handoff_authorization") ||
		strings.Contains(text, "verify_delegate_identity") ||
		strings.Contains(text, "authorized_delegation")
}

func originIntentVerificationConfigured(text string) bool {
	return strings.Contains(text, "origin_intent_verification") ||
		strings.Contains(text, "original_user_intent") ||
		strings.Contains(text, "request_provenance") ||
		strings.Contains(text, "delegation_provenance") ||
		strings.Contains(text, "intent_verification") ||
		strings.Contains(text, "verify_user_intent")
}

func delegatedCredentialScopeConfigured(text string) bool {
	return strings.Contains(text, "delegated_credential_scope") ||
		strings.Contains(text, "delegated_credentials") ||
		strings.Contains(text, "subagent_credentials") ||
		strings.Contains(text, "reduced_delegate_credentials") ||
		strings.Contains(text, "no_inherited_credentials") ||
		strings.Contains(text, "credential_downscoping")
}

func subagentContextIsolationConfigured(text string) bool {
	return strings.Contains(text, "subagent_context_isolation") ||
		strings.Contains(text, "delegated_context_isolation") ||
		strings.Contains(text, "isolated_subagent_context") ||
		strings.Contains(text, "subagent_memory_isolation") ||
		strings.Contains(text, "separate_context_window")
}

func delegationAuditConfigured(text string) bool {
	return strings.Contains(text, "delegation_audit") ||
		strings.Contains(text, "handoff_audit") ||
		strings.Contains(text, "agent_to_agent_logging") ||
		strings.Contains(text, "inter_agent_logging") ||
		strings.Contains(text, "delegation_trace") ||
		strings.Contains(text, "handoff_trace")
}

func toolAllowlistConfigured(text string) bool {
	return strings.Contains(text, "approved_tools") ||
		strings.Contains(text, "allowed_tools") ||
		strings.Contains(text, "tool_allowlist") ||
		strings.Contains(text, "tool_allow_list") ||
		strings.Contains(text, "approved_mcp_servers") ||
		strings.Contains(text, "mcp_allowlist") ||
		strings.Contains(text, "allowed_mcp_servers")
}

func mcpReviewOrPinningConfigured(text string) bool {
	return strings.Contains(text, "require_pinned_packages") ||
		strings.Contains(text, "pinned_packages") ||
		strings.Contains(text, "package_digest") ||
		strings.Contains(text, "package_lock") ||
		strings.Contains(text, "reviewed_mcp_servers") ||
		strings.Contains(text, "approved_mcp_servers") ||
		strings.Contains(text, "mcp_review_required") ||
		strings.Contains(text, "tool_review_required")
}

func toolDescriptorIntegrityConfigured(text string) bool {
	return strings.Contains(text, "tool_descriptor_integrity") ||
		strings.Contains(text, "descriptor_integrity") ||
		strings.Contains(text, "tool_schema_integrity") ||
		strings.Contains(text, "schema_integrity") ||
		strings.Contains(text, "metadata_integrity") ||
		strings.Contains(text, "descriptor_signature") ||
		strings.Contains(text, "schema_signature")
}

func toolArgumentValidationConfigured(text string) bool {
	return strings.Contains(text, "tool_argument_validation") ||
		strings.Contains(text, "argument_validation") ||
		strings.Contains(text, "tool_parameter_validation") ||
		strings.Contains(text, "parameter_validation") ||
		strings.Contains(text, "validate_tool_arguments") ||
		strings.Contains(text, "pretooluse") ||
		strings.Contains(text, "pre_tool_use")
}

func toolAuthRequiredConfigured(text string) bool {
	return strings.Contains(text, "tool_auth_required") ||
		strings.Contains(text, "tool_authentication") ||
		strings.Contains(text, "mcp_auth_required") ||
		strings.Contains(text, "certificate_based_tool_auth") ||
		strings.Contains(text, "mtls_tool_auth") ||
		strings.Contains(text, "oauth_tool_auth") ||
		strings.Contains(text, "short_lived_tool_token")
}

func signedToolArtifactsConfigured(text string) bool {
	return strings.Contains(text, "signed_tool_artifacts") ||
		strings.Contains(text, "signed_tools") ||
		strings.Contains(text, "signed_mcp_servers") ||
		strings.Contains(text, "tool_signature") ||
		strings.Contains(text, "mcp_signature") ||
		strings.Contains(text, "cosign") ||
		strings.Contains(text, "sigstore")
}

func toolDeploymentVerificationConfigured(text string) bool {
	return strings.Contains(text, "tool_deployment_verification") ||
		strings.Contains(text, "mcp_deployment_verification") ||
		strings.Contains(text, "verify_tool_before_deploy") ||
		strings.Contains(text, "verify_mcp_before_deploy") ||
		strings.Contains(text, "reject_unsigned_tools") ||
		strings.Contains(text, "tool_admission_verification")
}

func toolSandboxExecutionConfigured(text string) bool {
	return strings.Contains(text, "tool_sandbox_execution") ||
		strings.Contains(text, "sandboxed_tool_execution") ||
		strings.Contains(text, "mcp_sandbox") ||
		strings.Contains(text, "tool_filesystem_isolation") ||
		strings.Contains(text, "tool_network_isolation") ||
		strings.Contains(text, "microvm_tools") ||
		strings.Contains(text, "gvisor")
}

func toolCircuitBreakerConfigured(text string) bool {
	return strings.Contains(text, "tool_circuit_breaker") ||
		strings.Contains(text, "circuit_breaker") ||
		strings.Contains(text, "tool_rate_limit") ||
		strings.Contains(text, "rate_limit") ||
		strings.Contains(text, "spend_limit") ||
		strings.Contains(text, "usage_limit")
}

func toolRateLimitConfigured(text string) bool {
	return strings.Contains(text, "tool_rate_limit") ||
		strings.Contains(text, "tool_rate_limits") ||
		strings.Contains(text, "rate_limit") ||
		strings.Contains(text, "rate_limits") ||
		strings.Contains(text, "api_call_limit") ||
		strings.Contains(text, "request_limit") ||
		strings.Contains(text, "requests_per_minute") ||
		strings.Contains(text, "rpm_limit") ||
		strings.Contains(text, "calls_per_minute")
}

func spendLimitConfigured(text string) bool {
	return strings.Contains(text, "spend_limit") ||
		strings.Contains(text, "budget_limit") ||
		strings.Contains(text, "cost_limit") ||
		strings.Contains(text, "billing_cap") ||
		strings.Contains(text, "max_spend") ||
		strings.Contains(text, "token_budget") ||
		strings.Contains(text, "token_limit") ||
		strings.Contains(text, "usage_limit") ||
		strings.Contains(text, "quota_limit")
}

func loopGuardConfigured(text string) bool {
	return strings.Contains(text, "loop_guard") ||
		strings.Contains(text, "loop_detection") ||
		strings.Contains(text, "loop_amplification") ||
		strings.Contains(text, "max_iterations") ||
		strings.Contains(text, "iteration_limit") ||
		strings.Contains(text, "recursion_limit") ||
		strings.Contains(text, "runaway_loop") ||
		strings.Contains(text, "repeat_call_guard")
}

func toolTimeoutConfigured(text string) bool {
	return strings.Contains(text, "tool_timeout") ||
		strings.Contains(text, "timeout_seconds") ||
		strings.Contains(text, "execution_timeout") ||
		strings.Contains(text, "max_tool_runtime") ||
		strings.Contains(text, "tool_runtime_limit") ||
		strings.Contains(text, "wall_clock_limit") ||
		strings.Contains(text, "max_duration")
}

func concurrencyLimitConfigured(text string) bool {
	return strings.Contains(text, "concurrency_limit") ||
		strings.Contains(text, "max_concurrency") ||
		strings.Contains(text, "parallel_tool_limit") ||
		strings.Contains(text, "max_parallel_tools") ||
		strings.Contains(text, "max_parallel") ||
		strings.Contains(text, "worker_limit") ||
		strings.Contains(text, "parallelism_limit")
}

func resourceUsageAuditConfigured(text string) bool {
	return strings.Contains(text, "resource_usage_audit") ||
		strings.Contains(text, "usage_audit") ||
		strings.Contains(text, "usage_logging") ||
		strings.Contains(text, "tool_usage_logging") ||
		strings.Contains(text, "cost_logging") ||
		strings.Contains(text, "budget_alert") ||
		strings.Contains(text, "quota_alert") ||
		strings.Contains(text, "token_usage_logging") ||
		strings.Contains(text, "spend_alert")
}

func approvalRequired(text string) bool {
	return strings.Contains(text, "approval_policy = \"on-request\"") ||
		strings.Contains(text, "approval_policy=\"on-request\"") ||
		strings.Contains(text, "approval_policy = \"on-failure\"") ||
		strings.Contains(text, "approval_policy=\"on-failure\"") ||
		strings.Contains(text, "approval_policy = \"untrusted\"") ||
		strings.Contains(text, "approval_policy=\"untrusted\"") ||
		strings.Contains(text, "\"approval_required\": true") ||
		strings.Contains(text, "approval_required = true") ||
		strings.Contains(text, "\"require_approval\": true") ||
		strings.Contains(text, "require_approval = true") ||
		strings.Contains(text, "\"defaultmode\": \"default\"") ||
		strings.Contains(text, "\"ask\"") ||
		strings.Contains(text, "pretooluse")
}

func sandboxIsolated(text string) bool {
	return strings.Contains(text, "sandbox_mode = \"workspace-write\"") ||
		strings.Contains(text, "sandbox_mode=\"workspace-write\"") ||
		strings.Contains(text, "sandbox_mode = \"read-only\"") ||
		strings.Contains(text, "sandbox_mode=\"read-only\"") ||
		strings.Contains(text, "\"sandbox_required\": true") ||
		strings.Contains(text, "sandbox_required = true") ||
		strings.Contains(text, "\"filesystem_isolation\": true") ||
		strings.Contains(text, "filesystem_isolation = true") ||
		strings.Contains(text, "\"network_isolation\": true") ||
		strings.Contains(text, "network_isolation = true")
}

func credentialHelperConfigured(text string) bool {
	return strings.Contains(text, "apikeyhelper") ||
		strings.Contains(text, "api_key_helper") ||
		strings.Contains(text, "credentialhelper") ||
		strings.Contains(text, "credential_helper") ||
		strings.Contains(text, "credential_process") ||
		strings.Contains(text, "secret_manager") ||
		strings.Contains(text, "vault") ||
		strings.Contains(text, "keychain")
}

func shortLivedCredentialConfigured(text string) bool {
	return strings.Contains(text, "oauth") ||
		strings.Contains(text, "oidc") ||
		strings.Contains(text, "pkce") ||
		strings.Contains(text, "short_lived") ||
		strings.Contains(text, "short-lived") ||
		strings.Contains(text, "federated_identity") ||
		strings.Contains(text, "jit_access") ||
		strings.Contains(text, "jit")
}

func credentialIsolationConfigured(text string) bool {
	return strings.Contains(text, "credential_isolation") ||
		strings.Contains(text, "credential-isolation") ||
		strings.Contains(text, "per_agent_credentials") ||
		strings.Contains(text, "per-agent credentials") ||
		strings.Contains(text, "unique_agent_credentials") ||
		strings.Contains(text, "unique agent credentials") ||
		strings.Contains(text, "agent_scoped_credentials") ||
		strings.Contains(text, "agent-scoped credentials") ||
		strings.Contains(text, "no_shared_credentials") ||
		strings.Contains(text, "no shared credentials")
}

func jitAccessConfigured(text string) bool {
	return strings.Contains(text, "jit_access") ||
		strings.Contains(text, "just_in_time") ||
		strings.Contains(text, "just-in-time") ||
		strings.Contains(text, "standing_access = false") ||
		strings.Contains(text, "standing_access=false") ||
		strings.Contains(text, "\"standing_access\": false") ||
		strings.Contains(text, "\"standing_access\":false")
}

func tokenLifetimePolicyConfigured(text string) bool {
	return strings.Contains(text, "token_lifetime") ||
		strings.Contains(text, "credential_lifetime") ||
		strings.Contains(text, "credential_ttl") ||
		strings.Contains(text, "max_token_ttl") ||
		strings.Contains(text, "max_session_duration") ||
		strings.Contains(text, "ttl_minutes") ||
		strings.Contains(text, "expires_in") ||
		strings.Contains(text, "expiration_minutes")
}

func hardwareBoundCredentialConfigured(text string) bool {
	return strings.Contains(text, "hardware_bound") ||
		strings.Contains(text, "hardware-bound") ||
		strings.Contains(text, "hardware_backed") ||
		strings.Contains(text, "hardware-backed") ||
		strings.Contains(text, "passkey") ||
		strings.Contains(text, "fido2") ||
		strings.Contains(text, "webauthn") ||
		strings.Contains(text, "secure_enclave") ||
		strings.Contains(text, "tpm") ||
		strings.Contains(text, "yubikey")
}

func identityLifecycleConfigured(text string) bool {
	return strings.Contains(text, "identity_lifecycle") ||
		strings.Contains(text, "credential_rotation") ||
		strings.Contains(text, "certificate_lifecycle") ||
		strings.Contains(text, "rotation_days") ||
		strings.Contains(text, "\"revocation\": true") ||
		strings.Contains(text, "revocation = true") ||
		strings.Contains(text, "revoke_on_exit") ||
		strings.Contains(text, "deprovision")
}

func auditLoggingConfigured(text string) bool {
	return strings.Contains(text, "audit_logging") ||
		strings.Contains(text, "approval_logging") ||
		strings.Contains(text, "tool_call_logging") ||
		strings.Contains(text, "otel") ||
		strings.Contains(text, "opentelemetry") ||
		strings.Contains(text, "telemetry") ||
		strings.Contains(text, "trace")
}

func telemetryExportConfigured(text string) bool {
	return strings.Contains(text, "telemetry_export") ||
		strings.Contains(text, "siem_export") ||
		strings.Contains(text, "otlp") ||
		strings.Contains(text, "opentelemetry") ||
		strings.Contains(text, "exporters:") ||
		strings.Contains(text, "\"exporters\"") ||
		strings.Contains(text, "service:") && strings.Contains(text, "pipelines:") ||
		strings.Contains(text, "splunk") ||
		strings.Contains(text, "datadog") ||
		strings.Contains(text, "honeycomb") ||
		strings.Contains(text, "cloudwatch") ||
		strings.Contains(text, "eventhub")
}

func immutableAuditConfigured(text string) bool {
	return strings.Contains(text, "immutable_audit") ||
		strings.Contains(text, "append_only") ||
		strings.Contains(text, "append-only") ||
		strings.Contains(text, "object_lock") ||
		strings.Contains(text, "worm") ||
		strings.Contains(text, "tamper_resistant") ||
		strings.Contains(text, "tamper-resistant")
}

func configVersionControlled(text string) bool {
	return strings.Contains(text, "version_controlled_config") ||
		strings.Contains(text, "version-controlled config") ||
		strings.Contains(text, "config_version_control") ||
		strings.Contains(text, "config_in_git") ||
		strings.Contains(text, "settings_in_git") ||
		strings.Contains(text, "policy_in_git") ||
		strings.Contains(text, "configuration_history") ||
		strings.Contains(text, "change_history")
}

func configReviewRequired(text string) bool {
	return strings.Contains(text, "config_review_required") ||
		strings.Contains(text, "configuration_review_required") ||
		strings.Contains(text, "required_config_review") ||
		strings.Contains(text, "required_review") ||
		strings.Contains(text, "pull_request_required") ||
		strings.Contains(text, "code_owner_review") ||
		strings.Contains(text, "change_approval_required") ||
		strings.Contains(text, "two_person_review")
}

func signedConfigConfigured(text string) bool {
	return strings.Contains(text, "signed_config") ||
		strings.Contains(text, "signed_configuration") ||
		strings.Contains(text, "config_signature") ||
		strings.Contains(text, "policy_signature") ||
		strings.Contains(text, "signature_required") ||
		strings.Contains(text, "cosign") ||
		strings.Contains(text, "sigstore")
}

func configDeploymentVerificationConfigured(text string) bool {
	return strings.Contains(text, "deployment_verification") ||
		strings.Contains(text, "config_deployment_verification") ||
		strings.Contains(text, "verify_before_deploy") ||
		strings.Contains(text, "verify_signature_before_deploy") ||
		strings.Contains(text, "reject_unsigned") ||
		strings.Contains(text, "admission_verification")
}

func managedSettingsEnforced(text string) bool {
	return strings.Contains(text, "allowmanagedpermissionrulesonly") ||
		strings.Contains(text, "allow_managed_permission_rules_only") ||
		strings.Contains(text, "managed_settings_enforced") ||
		strings.Contains(text, "managed_only") ||
		strings.Contains(text, "server_managed_settings") ||
		strings.Contains(text, "users_cannot_override") ||
		strings.Contains(text, "prevent_user_override") ||
		strings.Contains(text, "mdm_enforced")
}

func immutableRuntimeConfigured(text string) bool {
	return strings.Contains(text, "immutable_runtime") ||
		strings.Contains(text, "immutable_agent_runtime") ||
		strings.Contains(text, "immutable_infrastructure") ||
		strings.Contains(text, "replace_not_modify") ||
		strings.Contains(text, "ephemeral_vm") ||
		strings.Contains(text, "ephemeral_container") ||
		strings.Contains(text, "attested_image") ||
		strings.Contains(text, "image_attestation")
}

func rollbackProcedureConfigured(text string) bool {
	return strings.Contains(text, "rollback_procedure") ||
		strings.Contains(text, "documented_rollback") ||
		strings.Contains(text, "restore_previous_config") ||
		strings.Contains(text, "previous_versions") ||
		strings.Contains(text, "recovery_procedure")
}

func automatedRollbackConfigured(text string) bool {
	return strings.Contains(text, "automated_rollback") ||
		strings.Contains(text, "auto_rollback") ||
		strings.Contains(text, "health_check_rollback") ||
		strings.Contains(text, "rollback_on_failure") ||
		strings.Contains(text, "self_healing")
}

func traceabilityConfigured(text string) bool {
	return strings.Contains(text, "request_id") ||
		strings.Contains(text, "trace_id") ||
		strings.Contains(text, "correlation_id") ||
		strings.Contains(text, "distributed_tracing") ||
		strings.Contains(text, "provenance_chain") ||
		strings.Contains(text, "input_to_output_trace")
}

func inputValidationConfigured(text string) bool {
	return strings.Contains(text, "input_validation") ||
		strings.Contains(text, "schema_validation") ||
		strings.Contains(text, "max_input_length") ||
		strings.Contains(text, "prompt_injection_filter") ||
		strings.Contains(text, "payload_filter") ||
		strings.Contains(text, "content_filter") ||
		strings.Contains(text, "spotlighting")
}

func inputIsolationConfigured(text string) bool {
	return strings.Contains(text, "input_isolation") ||
		strings.Contains(text, "input-isolation") ||
		strings.Contains(text, "instruction_isolation") ||
		strings.Contains(text, "instruction-isolation") ||
		strings.Contains(text, "untrusted_instruction_isolation") ||
		strings.Contains(text, "untrusted-instruction isolation") ||
		strings.Contains(text, "treat_untrusted_as_data") ||
		strings.Contains(text, "instructions_as_data") ||
		strings.Contains(text, "data_only_context")
}

func trustedSourcePolicyConfigured(text string) bool {
	return strings.Contains(text, "trusted_sources") ||
		strings.Contains(text, "trusted_instruction_sources") ||
		strings.Contains(text, "trusted_repo_sources") ||
		strings.Contains(text, "trusted_source_policy") ||
		strings.Contains(text, "instruction_allowlist") ||
		strings.Contains(text, "allowed_instruction_sources") ||
		strings.Contains(text, "allow_untrusted_instructions = false") ||
		strings.Contains(text, "allow_untrusted_instructions=false") ||
		strings.Contains(text, "\"allow_untrusted_instructions\": false") ||
		strings.Contains(text, "\"allow_untrusted_instructions\":false")
}

func instructionProvenanceConfigured(text string) bool {
	return strings.Contains(text, "instruction_provenance") ||
		strings.Contains(text, "instruction-provenance") ||
		strings.Contains(text, "source_provenance") ||
		strings.Contains(text, "source_attribution") ||
		strings.Contains(text, "signed_instructions") ||
		strings.Contains(text, "instruction_signature") ||
		strings.Contains(text, "instruction_hash") ||
		strings.Contains(text, "source_digest")
}

func untrustedInputDelimitingConfigured(text string) bool {
	return strings.Contains(text, "untrusted_input_delimiting") ||
		strings.Contains(text, "untrusted-content delimiting") ||
		strings.Contains(text, "explicit_delimiters") ||
		strings.Contains(text, "spotlighting") ||
		strings.Contains(text, "quote_untrusted") ||
		strings.Contains(text, "mark_untrusted_content")
}

func promptInjectionFilterConfigured(text string) bool {
	return strings.Contains(text, "prompt_injection_filter") ||
		strings.Contains(text, "prompt-injection filter") ||
		strings.Contains(text, "injection_filter") ||
		strings.Contains(text, "jailbreak_filter") ||
		strings.Contains(text, "instruction_override_filter")
}

func automatedTriageConfigured(text string) bool {
	return strings.Contains(text, "automated_triage") ||
		strings.Contains(text, "first_pass_investigation") ||
		strings.Contains(text, "first-pass investigation") ||
		strings.Contains(text, "alert_triage") ||
		strings.Contains(text, "siem_triage")
}

func behavioralMonitoringConfigured(text string) bool {
	return strings.Contains(text, "behavioral_monitoring") ||
		strings.Contains(text, "behavioural_monitoring") ||
		strings.Contains(text, "anomaly_detection") ||
		strings.Contains(text, "behavior_baseline") ||
		strings.Contains(text, "behaviour_baseline") ||
		strings.Contains(text, "statistical_baseline") ||
		strings.Contains(text, "drift_detection") ||
		strings.Contains(text, "dwell_time")
}

func sessionTerminationConfigured(text string) bool {
	return strings.Contains(text, "session_termination") ||
		strings.Contains(text, "terminate_session") ||
		strings.Contains(text, "terminate_suspicious_sessions") ||
		strings.Contains(text, "kill_session") ||
		strings.Contains(text, "end_agent_session") ||
		strings.Contains(text, "stop_compromised_agent")
}

func credentialRevocationConfigured(text string) bool {
	return strings.Contains(text, "credential_revocation") ||
		strings.Contains(text, "revoke_credentials") ||
		strings.Contains(text, "revoke_tokens") ||
		strings.Contains(text, "token_revocation") ||
		strings.Contains(text, "invalidate_tokens") ||
		strings.Contains(text, "disable_agent_credentials")
}

func containmentQuarantineConfigured(text string) bool {
	return strings.Contains(text, "containment_quarantine") ||
		strings.Contains(text, "automatic_containment") ||
		strings.Contains(text, "automated_containment") ||
		strings.Contains(text, "quarantine_agent") ||
		strings.Contains(text, "network_quarantine") ||
		strings.Contains(text, "isolate_workload") ||
		strings.Contains(text, "isolate_agent") ||
		strings.Contains(text, "containment_action")
}

func dynamicAccessReductionConfigured(text string) bool {
	return strings.Contains(text, "dynamic_access_reduction") ||
		strings.Contains(text, "dynamic_access_control") ||
		strings.Contains(text, "privilege_reduction") ||
		strings.Contains(text, "reduce_privileges") ||
		strings.Contains(text, "step_down_permissions") ||
		strings.Contains(text, "downscope_on_risk") ||
		strings.Contains(text, "risk_based_access_reduction")
}

func responseEscalationConfigured(text string) bool {
	return strings.Contains(text, "response_escalation") ||
		strings.Contains(text, "escalation_paths") ||
		strings.Contains(text, "containment_approval") ||
		strings.Contains(text, "human_containment_review") ||
		strings.Contains(text, "human_approval_for_high_impact_response") ||
		strings.Contains(text, "incident_response_runbook")
}

func agentInventoryConfigured(text string) bool {
	return strings.Contains(text, "agent_inventory") ||
		strings.Contains(text, "agent_registry") ||
		strings.Contains(text, "registered_agents") ||
		strings.Contains(text, "approved_agents") ||
		strings.Contains(text, "deployment_catalog") ||
		strings.Contains(text, "ai_inventory") ||
		strings.Contains(text, "llm_inventory")
}

func deploymentOwnerConfigured(text string) bool {
	return strings.Contains(text, "deployment_owner") ||
		strings.Contains(text, "accountable_owner") ||
		strings.Contains(text, "business_owner") ||
		strings.Contains(text, "security_owner") ||
		strings.Contains(text, "service_owner") ||
		strings.Contains(text, "responsible_team") ||
		strings.Contains(text, "owning_team")
}

func deploymentApprovalConfigured(text string) bool {
	return strings.Contains(text, "deployment_approval") ||
		strings.Contains(text, "new_agent_approval") ||
		strings.Contains(text, "agent_approval_process") ||
		strings.Contains(text, "governance_approval") ||
		strings.Contains(text, "approved_deployment") ||
		strings.Contains(text, "approval_process") ||
		strings.Contains(text, "change_approval_required")
}

func riskAssessmentConfigured(text string) bool {
	return strings.Contains(text, "risk_assessment") ||
		strings.Contains(text, "risk_tier") ||
		strings.Contains(text, "risk_rating") ||
		strings.Contains(text, "impact_assessment") ||
		strings.Contains(text, "data_classification") ||
		strings.Contains(text, "sensitivity_classification") ||
		strings.Contains(text, "business_impact")
}

func governanceAuditConfigured(text string) bool {
	return strings.Contains(text, "governance_audit") ||
		strings.Contains(text, "governance_review") ||
		strings.Contains(text, "policy_review") ||
		strings.Contains(text, "periodic_review") ||
		strings.Contains(text, "compliance_review") ||
		strings.Contains(text, "governance_audit_trail") ||
		strings.Contains(text, "review_cadence")
}

func shadowAIDiscoveryConfigured(text string) bool {
	return strings.Contains(text, "shadow_ai_detection") ||
		strings.Contains(text, "shadow_ai_discovery") ||
		strings.Contains(text, "unauthorized_llm_detection") ||
		strings.Contains(text, "unapproved_ai_detection") ||
		strings.Contains(text, "unmanaged_agent_detection") ||
		strings.Contains(text, "ai_usage_discovery") ||
		strings.Contains(text, "llm_usage_discovery")
}

func aiBOMConfigured(text string) bool {
	return strings.Contains(text, "ai_bom") ||
		strings.Contains(text, "ai-bom") ||
		strings.Contains(text, "aibom") ||
		strings.Contains(text, "ml_bom") ||
		strings.Contains(text, "ml-bom") ||
		strings.Contains(text, "mlbom") ||
		strings.Contains(text, "cyclonedx") ||
		strings.Contains(text, "bill_of_materials") ||
		strings.Contains(text, "bom_format")
}

func modelProvenanceConfigured(text string) bool {
	return strings.Contains(text, "model_provenance") ||
		strings.Contains(text, "model-provenance") ||
		strings.Contains(text, "model_origin") ||
		strings.Contains(text, "model_provider") ||
		strings.Contains(text, "model_version") ||
		strings.Contains(text, "model_artifact") ||
		strings.Contains(text, "model_digest") ||
		strings.Contains(text, "model_signature") ||
		strings.Contains(text, "model_lineage")
}

func trainingDataLineageConfigured(text string) bool {
	return strings.Contains(text, "training_data_lineage") ||
		strings.Contains(text, "training_dataset_lineage") ||
		strings.Contains(text, "dataset_lineage") ||
		strings.Contains(text, "fine_tuning_data") ||
		strings.Contains(text, "fine-tuning data") ||
		strings.Contains(text, "training_data") ||
		strings.Contains(text, "dataset_provenance") ||
		strings.Contains(text, "source_dataset")
}

func dependencyHealthConfigured(text string) bool {
	return strings.Contains(text, "dependency_health") ||
		strings.Contains(text, "openssf") ||
		strings.Contains(text, "scorecard") ||
		strings.Contains(text, "maintainer_activity") ||
		strings.Contains(text, "signed_releases") ||
		strings.Contains(text, "vulnerability_scan") ||
		strings.Contains(text, "dependency_scan") ||
		strings.Contains(text, "unmaintained_package")
}

func providerRiskReviewConfigured(text string) bool {
	return strings.Contains(text, "provider_risk_review") ||
		strings.Contains(text, "vendor_assessment") ||
		strings.Contains(text, "supplier_review") ||
		strings.Contains(text, "third_party_risk") ||
		strings.Contains(text, "tool_provider_review") ||
		strings.Contains(text, "model_provider_review") ||
		strings.Contains(text, "framework_provider_review") ||
		strings.Contains(text, "provider_security_review")
}

func signedAIArtifactsConfigured(text string) bool {
	return strings.Contains(text, "signed_ai_artifacts") ||
		strings.Contains(text, "signed_model") ||
		strings.Contains(text, "signed_models") ||
		strings.Contains(text, "model_signature") ||
		strings.Contains(text, "dataset_signature") ||
		strings.Contains(text, "framework_signature") ||
		strings.Contains(text, "component_signature") ||
		strings.Contains(text, "sigstore") ||
		strings.Contains(text, "cosign")
}

func runtimeComponentValidationConfigured(text string) bool {
	return strings.Contains(text, "runtime_component_validation") ||
		strings.Contains(text, "runtime_validation") ||
		strings.Contains(text, "validate_components_at_runtime") ||
		strings.Contains(text, "runtime_integrity_validation") ||
		strings.Contains(text, "post_deployment_tamper_detection") ||
		strings.Contains(text, "component_attestation") ||
		strings.Contains(text, "artifact_attestation")
}

func reachabilityAnalysisConfigured(text string) bool {
	return strings.Contains(text, "reachability_analysis") ||
		strings.Contains(text, "vulnerable_code_reachability") ||
		strings.Contains(text, "dependency_reachability") ||
		strings.Contains(text, "dependency_redundancy") ||
		strings.Contains(text, "redundancy_audit") ||
		strings.Contains(text, "dependency_tree_audit")
}

func contextRetentionConfigured(text string) bool {
	return strings.Contains(text, "cleanupperioddays") ||
		strings.Contains(text, "cleanup_period_days") ||
		strings.Contains(text, "retention_days") ||
		strings.Contains(text, "retentiondays") ||
		strings.Contains(text, "ttl") ||
		strings.Contains(text, "time_to_live") ||
		strings.Contains(text, "context_retention") ||
		strings.Contains(text, "transcript_retention") ||
		strings.Contains(text, "memory_retention")
}

func memoryIsolationConfigured(text string) bool {
	return strings.Contains(text, "memory_isolation") ||
		strings.Contains(text, "context_isolation") ||
		strings.Contains(text, "session_isolation") ||
		strings.Contains(text, "workspace_isolation") ||
		strings.Contains(text, "tenant_isolation") ||
		strings.Contains(text, "user_isolation") ||
		strings.Contains(text, "isolated_memory") ||
		strings.Contains(text, "private_context_isolation")
}

func contextIntegrityConfigured(text string) bool {
	return strings.Contains(text, "context_integrity") ||
		strings.Contains(text, "memory_integrity") ||
		strings.Contains(text, "integrity_validation") ||
		strings.Contains(text, "hash_validation") ||
		strings.Contains(text, "content_hash") ||
		strings.Contains(text, "signed_context") ||
		strings.Contains(text, "signature_validation")
}

func contextProvenanceConfigured(text string) bool {
	return strings.Contains(text, "context_provenance") ||
		strings.Contains(text, "memory_provenance") ||
		strings.Contains(text, "source_attribution") ||
		strings.Contains(text, "source_metadata") ||
		strings.Contains(text, "provenance_metadata") ||
		strings.Contains(text, "origin_metadata") ||
		strings.Contains(text, "trusted_source")
}

func inlineCredentialConfigured(text string) bool {
	return inlineCredentialPattern.MatchString(text)
}

func looksPinned(text string) bool {
	return regexp.MustCompile(`@[0-9]+\.[0-9]+`).MatchString(text) || strings.Contains(text, "sha256:")
}

func declaresSecretDeny(text string) bool {
	return (strings.Contains(text, "deny_read") || strings.Contains(text, "deny") || strings.Contains(text, "disallow")) &&
		(strings.Contains(text, ".env") || strings.Contains(text, ".ssh") || strings.Contains(text, ".aws") || strings.Contains(text, "*.pem"))
}

func denySecretReadConfigured(text string) bool {
	return strings.Contains(text, "deny_secret_read") ||
		strings.Contains(text, "deny-secret-read") ||
		strings.Contains(text, "secret_read:false") ||
		declaresSecretDeny(text)
}

func evidence(id, kind, source, grade, summary string) model.Evidence {
	return model.Evidence{ID: id, Kind: kind, Grade: grade, Source: source, Summary: summary}
}

func trimPrefix(value, prefix string) string {
	return strings.TrimPrefix(value, prefix)
}

func rel(root, path string) string {
	if root == "" {
		return filepath.Clean(path)
	}
	if r, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	h := sha256.Sum256([]byte(filepath.Clean(path)))
	return "redacted-path-" + hex.EncodeToString(h[:])[:12]
}

func appendUniqueRuntime(in []model.RuntimeEvidence, next model.RuntimeEvidence) []model.RuntimeEvidence {
	for i, item := range in {
		if item.ID == next.ID && item.Scope == next.Scope {
			if prefersRuntimeSource(next.Source, item.Source) {
				in[i] = next
			}
			return in
		}
	}
	return append(in, next)
}

func prefersRuntimeSource(next, current string) bool {
	if strings.Contains(next, "settings") || strings.Contains(next, "config.toml") {
		return !strings.Contains(current, "settings") && !strings.Contains(current, "config.toml")
	}
	return false
}

func appendUniqueTrustInput(in []model.TrustInput, next model.TrustInput) []model.TrustInput {
	for i, item := range in {
		if item.ID == next.ID && item.Runtime == next.Runtime {
			if next.Risky && !item.Risky {
				in[i].Risky = true
				in[i].Summary = next.Summary
				in[i].Source = next.Source
			}
			return in
		}
	}
	return append(in, next)
}

func appendUniqueTool(in []model.Tool, next model.Tool) []model.Tool {
	for _, item := range in {
		if item.ID == next.ID && item.Runtime == next.Runtime && item.Source == next.Source {
			return in
		}
	}
	return append(in, next)
}

func appendUniqueBoundary(in []model.Boundary, next model.Boundary) []model.Boundary {
	for _, item := range in {
		if item.ID == next.ID {
			return in
		}
	}
	return append(in, next)
}

func appendUniqueAuthority(in []model.Authority, next model.Authority) []model.Authority {
	for _, item := range in {
		if item.ID == next.ID && item.Runtime == next.Runtime {
			return in
		}
	}
	return append(in, next)
}

// controlEnforcement classifies control provenance by source surface.
// Ariadne's own .ariadne/ policy vocabulary is self-declared: nothing executes
// it, so it is attestation at most. Controls parsed from real runtime,
// launcher, or CI platform configuration are treated as enforced.
func controlEnforcement(source string) string {
	normalized := strings.ReplaceAll(source, "\\", "/")
	if strings.HasPrefix(normalized, ".ariadne/") || strings.Contains(normalized, "/.ariadne/") {
		return model.EnforcementAttested
	}
	return model.EnforcementEnforced
}

func appendUniqueControl(in []model.Control, next model.Control) []model.Control {
	if next.Enforcement == "" {
		next.Enforcement = controlEnforcement(next.Source)
	}
	for i, item := range in {
		if item.ID == next.ID && item.Runtime == next.Runtime {
			if item.Enforcement == model.EnforcementAttested && next.Enforcement == model.EnforcementEnforced {
				in[i] = next
			}
			return in
		}
	}
	return append(in, next)
}

func appendUniqueEvidence(in []model.Evidence, next model.Evidence) []model.Evidence {
	for _, item := range in {
		if item.ID == next.ID && item.Source == next.Source {
			return in
		}
	}
	return append(in, next)
}

func appendUniqueFact(in []model.Fact, next model.Fact) []model.Fact {
	for _, item := range in {
		if item.ID == next.ID && item.Source == next.Source {
			return in
		}
	}
	return append(in, next)
}
