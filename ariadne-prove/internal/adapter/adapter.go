package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

var riskyInstructionPattern = regexp.MustCompile(`(?i)(read\s+\.env|read\s+.*secret|secret|token|always approve|ignore security|bypass|send\s+.*secret|send\s+.*token|private key|\.ssh|\.aws)`)

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
	if strings.Contains(text, "read(*)") || strings.Contains(text, "bypasspermissions") || strings.Contains(text, "acceptedits") {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:file-read", Kind: "file-read", Runtime: "claude", Source: source, Summary: "Claude Code can read files in the configured workspace."})
	}
	if strings.Contains(text, "bash(*)") || strings.Contains(text, "bypasspermissions") {
		c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:local-code-execution", Kind: "local-code-execution", Runtime: "claude", Source: source, Summary: "Claude Code settings allow broad shell or local execution posture."})
		c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:developer-execution-boundary", Kind: "developer-execution-boundary", Abstract: true, Summary: "Developer user execution context and local machine privileges."})
	}
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
}

func collectPluginSurface(c *model.Collection, s model.Surface) {
	c.Tools = appendUniqueTool(c.Tools, model.Tool{ID: "tool:agent-plugin-surface", Kind: "agent-plugin-surface", Runtime: "claude", Source: s.Source, Summary: "Claude plugin or skill configuration surface exists."})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:tool:agent-plugin-surface", "tool", s.Source, "observed", "Plugin surface was observed; plugin code was not executed."))
}

func collectManagedControlSurface(c *model.Collection, s model.Surface) {
	c.Controls = appendUniqueControl(c.Controls, model.Control{ID: "control:managed-runtime-settings", Kind: "managed-runtime-settings", Runtime: "claude", Source: s.Source, Summary: "Managed or policy settings surface exists for Claude Code."})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:control:managed-runtime-settings", "control", s.Source, "observed", "Managed settings surface was observed."))
}

func addExternalCommunication(c *model.Collection, runtime, source, summary string) {
	c.Authorities = appendUniqueAuthority(c.Authorities, model.Authority{ID: "authority:external-communication", Kind: "external-communication", Runtime: runtime, Source: source, Summary: summary})
	c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:external-destination", Kind: "external-destination", Abstract: true, Summary: "External network, web, or remote service destination outside the local trust boundary."})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:authority:external-communication", "authority", source, "declared", "External communication authority was collected."))
}

func collectSummarySurface(c *model.Collection, s model.Surface) {
	c.Boundaries = appendUniqueBoundary(c.Boundaries, model.Boundary{ID: "boundary:agent-private-context", Kind: "agent-private-context", Source: s.Source, Abstract: false, Summary: "Agent private context cache/history exists; contents are not inspected or emitted by default."})
	c.Evidence = appendUniqueEvidence(c.Evidence, evidence("evidence:boundary:agent-private-context", "boundary", s.Source, "observed", "Private agent context surface was summarized without reading contents."))
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
