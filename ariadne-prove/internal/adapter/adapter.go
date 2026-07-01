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
	riskyInstructionPattern = regexp.MustCompile(`(?i)(read\s+\.env|read\s+.*secret|secret|token|always approve|ignore security|bypass|send\s+.*secret|send\s+.*token|private key|\.ssh|\.aws)`)
	inlineCredentialPattern = regexp.MustCompile(`(?i)(api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|password)\s*[:=]`)
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
	case "claude-md", "agents-md", "nested-agents-md", "cursor-rules", "windsurf-rules", "codex-agents-md", "claude-command", "claude-project-memory":
		collectInstruction(c, s)
	case "codex-config", "codex-requirements":
		collectCodexConfig(c, s)
	case "claude-settings", "claude-local-settings":
		collectClaudeSettings(c, s)
	case "mcp-config", "claude-mcp-config":
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
	case "input-policy":
		collectInputPolicy(c, s)
	case "identity-policy":
		collectIdentityPolicy(c, s)
	case "workload-policy":
		collectWorkloadPolicy(c, s)
	case "memory-policy":
		collectMemoryPolicy(c, s)
	case "integrity-policy":
		collectIntegrityPolicy(c, s)
	case "observability-policy":
		collectObservabilityPolicy(c, s)
	case "opentelemetry-config":
		collectTelemetryConfig(c, s)
	case "claude-plugin-config", "claude-installed-plugins":
		collectPluginSurface(c, s)
	case "claude-remote-settings", "claude-policy-limits":
		collectManagedControlSurface(c, s)
	}
	_ = opts
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
	if s.Kind == "claude-command" {
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
	if s.Kind == "claude-command" && containsAny(lower, []string{"bash", "shell", "exec", "npm ", "npx ", "python "}) {
		c.Tools = appendUniqueTool(c.Tools, model.Tool{ID: "tool:agent-command-shell", Kind: "agent-command-shell", Runtime: "claude", Source: s.Source, Risky: true, Summary: "Claude command surface appears able to steer shell or command execution."})
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:local-code-execution", Kind: "local-code-execution", Runtime: "claude", Source: s.Source, Summary: "Command surface can steer local command execution when invoked by the agent."})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:developer-execution-boundary", Kind: "developer-execution-boundary", Abstract: true, Summary: "Developer user execution context and local machine privileges."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:agent-command-shell", "tool", s.Source, "declared", "Agent command content was inspected for command-execution indicators."))
	}
	if s.Kind == "claude-command" && containsExternalCommunication(lower) {
		addExternalCommunication(c, "claude", s.Source, "Claude command surface contains external communication indicators.")
	}
}

func runtimeForTrustInput(s model.Surface) string {
	if s.Kind == "claude-command" || s.Kind == "claude-project-memory" {
		return "claude"
	}
	return ""
}

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
	text := strings.ToLower(string(data))
	if strings.Contains(text, "danger-full-access") || strings.Contains(text, "approval_policy = \"never\"") || strings.Contains(text, "bypass") || strings.Contains(text, "dangerously-bypass") {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:broad-local", Kind: "broad-local", Runtime: "codex", Source: source, Summary: "Codex config declares broad local authority or bypass posture."})
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: "codex", Source: source, Summary: "Codex can read files in the configured workspace."})
	} else if strings.Contains(text, "sandbox_mode") || strings.Contains(text, "allowed_sandbox_modes") || s.Kind == "codex-requirements" {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: "codex", Source: source, Summary: "Codex has normal file-read authority in the configured workspace."})
	}
	collectRuntimeSecurityControls(c, "codex", source, text)
	if networkEnabled(text) {
		addExternalCommunication(c, "codex", source, "Codex config declares external network access.")
	}
	if networkRestricted(text) {
		c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:network-restricted", Kind: "network-restricted", Runtime: "codex", Source: source, Summary: "Codex config restricts external network communication."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:control:network-restricted", "control", source, "declared", "Network restriction control was collected."))
	}
	if declaresSecretDeny(text) {
		c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:deny-secret-read", Kind: "deny-secret-read", Runtime: "codex", Source: source, Summary: "Codex deny-read policy covers secret-like paths."})
	}
	if strings.Contains(text, "mcp_servers") || strings.Contains(text, "[mcp") {
		c.Tools = appendUniqueTool(c.Tools, model.Tool{ID: "tool:mcp-configured", Kind: "mcp-configured", Runtime: "codex", Source: source, Summary: "Codex config includes MCP/tool configuration."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:mcp-configured", "tool", source, "declared", "Codex MCP configuration surface was collected."))
	}
}

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
	text := strings.ToLower(string(data))
	if strings.Contains(text, "bypasspermissions") || strings.Contains(text, "dontask") || strings.Contains(text, "bash(*)") {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:broad-local", Kind: "broad-local", Runtime: "claude", Source: source, Summary: "Claude Code settings declare broad local authority or bypass posture."})
	}
	if strings.Contains(text, "read(") || strings.Contains(text, "bypasspermissions") || strings.Contains(text, "acceptedits") {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: "claude", Source: source, Summary: "Claude Code can read files in the configured workspace."})
	}
	if strings.Contains(text, "bash(") || strings.Contains(text, "bypasspermissions") {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:local-code-execution", Kind: "local-code-execution", Runtime: "claude", Source: source, Summary: "Claude Code settings allow broad shell or local execution posture."})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:developer-execution-boundary", Kind: "developer-execution-boundary", Abstract: true, Summary: "Developer user execution context and local machine privileges."})
	}
	collectRuntimeSecurityControls(c, "claude", source, text)
	if containsAny(text, []string{"webfetch", "websearch", "bash(*)", "curl", "wget", "http://"}) {
		addExternalCommunication(c, "claude", source, "Claude Code settings allow web, shell, or external communication posture.")
	}
	if networkRestricted(text) || (strings.Contains(text, "deny") && (strings.Contains(text, "webfetch") || strings.Contains(text, "websearch") || strings.Contains(text, "curl") || strings.Contains(text, "wget"))) {
		c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:network-restricted", Kind: "network-restricted", Runtime: "claude", Source: source, Summary: "Claude Code settings restrict web or external network communication."})
		c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:control:network-restricted", "control", source, "declared", "Network restriction control was collected."))
	}
	if declaresSecretDeny(text) {
		c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:deny-secret-read", Kind: "deny-secret-read", Runtime: "claude", Source: source, Summary: "Claude Code deny/disallow policy covers secret-like paths."})
	}
}

func collectMCPConfig(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	var root struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
			URL     string   `json:"url"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return
	}
	if s.Runtime == "claude" {
		c.Runtimes = appendUniqueRuntime(c.Runtimes, model.RuntimeEvidence{ID: "runtime:claude", Kind: "claude", Source: s.Source, Scope: s.Scope, Summary: "Claude MCP configuration evidence was found."})
	}
	for serverName, server := range root.MCPServers {
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
	collectConfigIntegrityControls(c, "", s.Source, text)
	collectEgressControls(c, s.Source, text)
}

func collectToolPolicy(c *model.Collection, s model.Surface) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	text := strings.ToLower(string(data))
	collectToolIntegrityControls(c, "", s.Source, text)
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
	if auditLoggingConfigured(text) {
		addControl(c, "control:audit-logging", "audit-logging", "", s.Source, "Observability policy declares tool-call, approval, telemetry, or audit logging.")
	}
	if traceabilityConfigured(text) {
		addControl(c, "control:request-traceability", "request-traceability", "", s.Source, "Observability policy declares request, trace, correlation, or provenance IDs.")
	}
	if telemetryExportConfigured(text) {
		addControl(c, "control:telemetry-export", "telemetry-export", "", s.Source, "Observability policy declares telemetry export for agent audit correlation.")
	}
	if immutableAuditConfigured(text) {
		addControl(c, "control:immutable-audit-log", "immutable-audit-log", "", s.Source, "Observability policy declares append-only or immutable audit log storage.")
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
	c.Tools = appendUniqueTool(c.Tools, model.Tool{ID: "tool:agent-plugin-surface", Kind: "agent-plugin-surface", Runtime: "claude", Source: s.Source, Summary: "Claude plugin or skill configuration surface exists."})
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
	collectConfigIntegrityControls(c, runtime, source, text)
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

func containsExternalCommunication(text string) bool {
	return containsAny(text, []string{"curl ", "wget ", "http://", "https://", "webhook", "webfetch", "websearch", "post ", "upload", "send to"})
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
		if item.ID == next.ID && item.Source == next.Source {
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

func appendUniqueControl(in []model.Control, next model.Control) []model.Control {
	for _, item := range in {
		if item.ID == next.ID && item.Runtime == next.Runtime {
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
