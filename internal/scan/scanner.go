package scan

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
)

const ScannerVersion = "0.1.0"

var (
	dangerPattern           = regexp.MustCompile(`(?i)(dangerously[-_a-z]*|--yolo|danger-full-access|bypassPermissions|bypass[-_ ]permissions|skip[-_ ]permissions|trust[-_ ]all[-_ ]tools)`)
	networkPattern          = regexp.MustCompile(`(?i)(network_access\s*=\s*true|allow_local_binding\s*=\s*true|dangerously_allow_non_loopback_proxy\s*=\s*true|dangerously_allow_all_unix_sockets\s*=\s*true|domains\s*=\s*\[[^\]]*"\*")`)
	riskyInstructionPattern = regexp.MustCompile(`(?i)(always approve|auto[- ]?approve|never ask|skip permissions|read \.env|read env files|auto[- ]?push|auto[- ]?deploy|ignore security|disable prompts|use network freely)`)
	packageLauncherPattern  = regexp.MustCompile(`(?i)\b(npx|uvx|pipx|npm|pnpm|yarn|node|python3?|docker|bash|sh|zsh)\b`)
)

var secretPolicyTargets = []string{
	"~/.ssh", "~/.aws", "~/.kube", "~/.docker", "~/.gnupg", "~/.npmrc", "~/.netrc",
	".env", "**/*.pem", "id_rsa", "id_ed25519",
}

func Run(opts Options) (Report, error) {
	if opts.Mode == "" {
		opts.Mode = ModeRepo
	}
	if opts.Path == "" {
		opts.Path = "."
	}
	root, err := filepath.Abs(opts.Path)
	if err != nil {
		return Report{}, err
	}
	started := time.Now().UTC()
	reader := NewSafeReader(root)
	report := Report{
		SchemaVersion:  SchemaVersion,
		ScannerVersion: ScannerVersion,
		ScanID:         randomID(),
		ScanMode:       opts.Mode,
		Platform:       platformName(),
		StartedAt:      started,
		Redaction: RedactionInfo{
			Level:                  "default",
			SensitivePathsIncluded: opts.IncludeSensitivePaths,
		},
	}

	report.Repo = collectRepo(root, reader, opts)
	collectAgentConfigs(&report, root, reader, opts)
	collectRepoFiles(&report, root, reader, opts)
	collectSuppressions(&report, root, reader, opts)
	report.Warnings = append(report.Warnings, RedactSlice(reader.Warnings, opts.IncludeSensitivePaths)...)
	applyRules(&report, opts)
	applySuppressions(&report)
	report.AttackPaths = synthesizeAttackPaths(report)
	report.Remediations = buildRemediations(report)
	report.CompletedAt = time.Now().UTC()
	redactReport(&report, opts.IncludeSensitivePaths)
	return report, nil
}

func Doctor(opts Options) []string {
	if opts.Mode == "" {
		opts.Mode = ModeRepo
	}
	if opts.Path == "" {
		opts.Path = "."
	}
	lines := []string{
		"Ariadne is read-only.",
		"It does not execute discovered commands, agent binaries, package managers, or MCP servers.",
		"It does not read secret values; it checks declared policy coverage and config posture.",
		"Reports are redacted by default and should still be treated as sensitive security artifacts.",
		"",
		"Scan mode: " + string(opts.Mode),
		"Scan path: " + opts.Path,
		"",
		"Data classes inspected:",
		"- Claude Code, Codex, and MCP config files",
		"- Repo instruction files such as CLAUDE.md and AGENTS.md",
		"- package.json, Makefile, and devcontainer metadata",
		"- Declared sandbox, approval, network, deny-read, and MCP settings",
	}
	if opts.Mode == ModeEndpoint || opts.Mode == ModeDevbox {
		lines = append(lines,
			"- User-level agent config paths under the current user's home directory",
			"- System Codex managed config paths when readable",
		)
	}
	return lines
}

func collectRepo(root string, reader *SafeReader, opts Options) RepoContext {
	repo := RepoContext{
		Root: RedactString(root, opts.IncludeSensitivePaths),
		Tier: "unknown",
	}
	if data, err := reader.ReadFile(filepath.Join(root, ".git", "HEAD"), opts.Mode); err == nil {
		text := strings.TrimSpace(string(data))
		if strings.HasPrefix(text, "ref:") {
			repo.Branch = strings.TrimPrefix(filepath.Base(text), "heads/")
		}
	}
	if remote := readGitRemote(root, reader, opts); remote != "" {
		repo.Remote = remote
	}
	repo.Tier = lookupRepoTier(root, repo.Remote, reader, opts)
	repo.RunningInContainer = runningInContainer()
	devPath := filepath.Join(root, ".devcontainer", "devcontainer.json")
	if data, err := reader.ReadFile(devPath, opts.Mode); err == nil {
		repo.DevcontainerPresent = true
		repo.DevcontainerRiskHints = analyzeDevcontainer(devPath, data)
	}
	for _, name := range []string{"CLAUDE.md", "AGENTS.md", ".cursorrules", ".cursor/rules"} {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err == nil {
			repo.InstructionFiles = append(repo.InstructionFiles, path)
		}
	}
	return repo
}

func readGitRemote(root string, reader *SafeReader, opts Options) string {
	data, err := reader.ReadFile(filepath.Join(root, ".git", "config"), opts.Mode)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	inOrigin := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[remote ") {
			inOrigin = strings.Contains(trimmed, `"origin"`)
			continue
		}
		if inOrigin && strings.HasPrefix(trimmed, "url") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func lookupRepoTier(root, remote string, reader *SafeReader, opts Options) string {
	path := filepath.Join(root, ".ariadne", "repo-tiers.yaml")
	data, err := reader.ReadFile(path, opts.Mode)
	if err != nil {
		return "unknown"
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "repos:") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		pattern := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
		tier := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		needle := strings.TrimSuffix(pattern, "*")
		if (remote != "" && strings.Contains(remote, needle)) || strings.Contains(root, needle) {
			return normalizeTier(tier)
		}
	}
	return "unknown"
}

func collectAgentConfigs(report *Report, root string, reader *SafeReader, opts Options) {
	paths := repoConfigPaths(root)
	if opts.Mode == ModeEndpoint || opts.Mode == ModeDevbox {
		paths = append(paths, endpointConfigPaths()...)
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		data, err := reader.ReadFile(path, opts.Mode)
		if err != nil {
			continue
		}
		kind := classifyAgentConfig(path, data)
		if kind == "mcp" {
			report.MCPServers = append(report.MCPServers, parseMCPJSON(path, data)...)
			continue
		}
		agent := parseAgentConfig(kind, path, data)
		if agent.Kind != "" {
			report.Agents = mergeAgent(report.Agents, agent)
		}
		if strings.Contains(strings.ToLower(path), "mcp") || strings.Contains(string(data), "mcpServers") || strings.Contains(string(data), "[mcp_servers") {
			report.MCPServers = append(report.MCPServers, parseMCPFromConfig(kind, path, data)...)
		}
	}
}

func repoConfigPaths(root string) []string {
	return []string{
		filepath.Join(root, ".codex", "config.toml"),
		filepath.Join(root, ".codex", "managed_config.toml"),
		filepath.Join(root, ".codex", "requirements.toml"),
		filepath.Join(root, ".claude", "settings.json"),
		filepath.Join(root, ".claude", "settings.local.json"),
		filepath.Join(root, ".mcp.json"),
		filepath.Join(root, "mcp.json"),
	}
}

func endpointConfigPaths() []string {
	home, _ := os.UserHomeDir()
	var paths []string
	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".codex", "config.toml"),
			filepath.Join(home, ".codex", "managed_config.toml"),
			filepath.Join(home, ".codex", "requirements.toml"),
			filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(home, ".claude.json"),
			filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		)
	}
	paths = append(paths,
		"/etc/codex/config.toml",
		"/etc/codex/managed_config.toml",
		"/etc/codex/requirements.toml",
	)
	return paths
}

func classifyAgentConfig(path string, data []byte) string {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))
	text := strings.ToLower(string(data))
	switch {
	case strings.Contains(lower, "/.codex/") || strings.HasPrefix(lower, "/etc/codex/"):
		return "codex"
	case strings.Contains(lower, "/.claude/") || base == ".claude.json" || base == "settings.json" && strings.Contains(lower, "claude"):
		return "claude-code"
	case base == "mcp.json" || base == ".mcp.json" || strings.Contains(text, "mcpservers"):
		return "mcp"
	default:
		return ""
	}
}

func parseAgentConfig(kind, path string, data []byte) Agent {
	text := string(data)
	agent := Agent{
		Kind:                kind,
		ConfigSources:       []string{path},
		ManagedVerification: managedVerification(path),
	}
	if agent.ManagedVerification != "local" {
		agent.ManagedEvidence = append(agent.ManagedEvidence, path)
	}
	if strings.Contains(strings.ToLower(path), "requirements.toml") || strings.Contains(strings.ToLower(path), "managed_config.toml") {
		agent.ManagedEvidence = append(agent.ManagedEvidence, path)
	}
	fields := parseFlatConfig(text)
	agent.PermissionMode = firstNonEmpty(fields["permission_mode"], fields["permissions.defaultMode"], fields["permissionMode"])
	agent.SandboxMode = firstNonEmpty(fields["sandbox_mode"], fields["sandbox"], fields["allowed_sandbox_modes"])
	agent.ApprovalPolicy = firstNonEmpty(fields["approval_policy"], fields["allowed_approval_policies"])
	agent.NetworkAccess = firstNonEmpty(fields["sandbox_workspace_write.network_access"], fields["network_access"], fields["experimental_network.enabled"])
	agent.DenyReadPatterns = append(agent.DenyReadPatterns, parseDenyRead(text)...)
	if dangerPattern.MatchString(text) {
		agent.DangerousIndicators = append(agent.DangerousIndicators, matchedSnippets(dangerPattern, text)...)
	}
	if networkPattern.MatchString(text) {
		agent.NetworkAccess = firstNonEmpty(agent.NetworkAccess, "true")
	}
	if strings.Contains(strings.ToLower(text), "otel") || strings.Contains(strings.ToLower(text), "telemetry") {
		agent.AuditTelemetryHints = append(agent.AuditTelemetryHints, "telemetry setting detected")
	}
	return agent
}

func parseFlatConfig(text string) map[string]string {
	out := map[string]string{}
	section := ""
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = stripInlineComment(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			section = strings.Trim(line, "[] ")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if section != "" {
			out[section+"."+key] = value
		}
		out[key] = value
	}
	return out
}

func parseDenyRead(text string) []string {
	var out []string
	lines := strings.Split(text, "\n")
	inDeny := false
	for _, line := range lines {
		trimmed := stripInlineComment(strings.TrimSpace(line))
		if strings.Contains(trimmed, "deny_read") {
			inDeny = true
			out = append(out, quotedValues(trimmed)...)
			if strings.Contains(trimmed, "]") {
				inDeny = false
			}
			continue
		}
		if inDeny {
			out = append(out, quotedValues(trimmed)...)
			if strings.Contains(trimmed, "]") {
				inDeny = false
			}
		}
	}
	return unique(out)
}

func parseMCPFromConfig(agentKind, path string, data []byte) []MCPServer {
	if strings.HasSuffix(strings.ToLower(path), ".json") || strings.Contains(string(data), "mcpServers") {
		return parseMCPJSON(path, data)
	}
	return parseMCPTOML(agentKind, path, string(data))
}

func parseMCPJSON(path string, data []byte) []MCPServer {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	serversValue, ok := root["mcpServers"]
	if !ok {
		serversValue = root["mcp_servers"]
	}
	servers, ok := serversValue.(map[string]any)
	if !ok {
		return nil
	}
	var out []MCPServer
	for name, raw := range servers {
		obj, _ := raw.(map[string]any)
		command := stringValue(obj["command"])
		urlValue := firstNonEmpty(stringValue(obj["url"]), stringValue(obj["serverUrl"]))
		args := stringArray(obj["args"])
		combined := strings.TrimSpace(command + " " + strings.Join(args, " "))
		transport := "stdio"
		commandOrURL := combined
		if urlValue != "" {
			transport = "http"
			commandOrURL = urlValue
		}
		server := classifyMCP(name, path, transport, commandOrURL)
		server.FilesystemRoots = append(server.FilesystemRoots, inferFilesystemRoots(obj)...)
		out = append(out, server)
	}
	return out
}

func parseMCPTOML(agentKind, path, text string) []MCPServer {
	var out []MCPServer
	var current *MCPServer
	for _, line := range strings.Split(text, "\n") {
		trimmed := stripInlineComment(strings.TrimSpace(line))
		if strings.HasPrefix(trimmed, "[mcp_servers.") && strings.HasSuffix(trimmed, "]") {
			if current != nil {
				out = append(out, *current)
			}
			name := strings.TrimSuffix(strings.TrimPrefix(trimmed, "[mcp_servers."), "]")
			current = &MCPServer{Name: name, Source: path, Transport: "stdio"}
			continue
		}
		if current == nil {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		switch key {
		case "command":
			current.CommandOrURL = value
			current.Transport = "stdio"
		case "url":
			current.CommandOrURL = value
			current.Transport = "http"
		case "args":
			current.CommandOrURL = strings.TrimSpace(current.CommandOrURL + " " + strings.Join(quotedValues(value), " "))
		}
	}
	if current != nil {
		out = append(out, *current)
	}
	for i := range out {
		out[i] = classifyMCP(out[i].Name, out[i].Source, out[i].Transport, out[i].CommandOrURL)
	}
	return out
}

func classifyMCP(name, source, transport, commandOrURL string) MCPServer {
	server := MCPServer{
		Name:             name,
		Source:           source,
		Transport:        transport,
		CommandOrURL:     commandOrURL,
		LaunchMechanism:  "unknown",
		PackagePinned:    "unknown",
		ApprovedEvidence: "not detected",
	}
	lower := strings.ToLower(commandOrURL + " " + name)
	if transport == "http" {
		server.LaunchMechanism = "remote"
		if parsed, err := url.Parse(commandOrURL); err == nil && parsed.Scheme == "https" {
			server.RiskClassifications = append(server.RiskClassifications, "remote-https")
		} else {
			server.RiskClassifications = append(server.RiskClassifications, "remote-non-https")
		}
		return server
	}
	if m := packageLauncherPattern.FindString(lower); m != "" {
		server.LaunchMechanism = m
		server.RiskClassifications = append(server.RiskClassifications, "local-command", "package-or-interpreter-launch")
	} else if commandOrURL != "" {
		server.LaunchMechanism = "local-command"
		server.RiskClassifications = append(server.RiskClassifications, "local-command")
	}
	if strings.Contains(lower, "@") && regexp.MustCompile(`@[0-9]+\.`).MatchString(lower) {
		server.PackagePinned = "likely-pinned"
	} else if server.LaunchMechanism == "npx" || server.LaunchMechanism == "uvx" || server.LaunchMechanism == "npm" || server.LaunchMechanism == "python" || server.LaunchMechanism == "node" {
		server.PackagePinned = "not detected"
	}
	if strings.Contains(lower, "filesystem") || strings.Contains(lower, "file-system") || strings.Contains(lower, "fs") {
		server.RiskClassifications = append(server.RiskClassifications, "filesystem-capable")
	}
	if strings.Contains(lower, "github") || strings.Contains(lower, "gitlab") || strings.Contains(lower, "git ") {
		server.RiskClassifications = append(server.RiskClassifications, "source-control-capable")
	}
	if strings.Contains(lower, "aws") || strings.Contains(lower, "gcloud") || strings.Contains(lower, "azure") || strings.Contains(lower, "kubectl") {
		server.RiskClassifications = append(server.RiskClassifications, "cloud-capable")
	}
	if strings.Contains(lower, "postgres") || strings.Contains(lower, "mysql") || strings.Contains(lower, "database") || strings.Contains(lower, "sqlite") {
		server.RiskClassifications = append(server.RiskClassifications, "database-capable")
	}
	if strings.Contains(lower, "browser") || strings.Contains(lower, "computer") || strings.Contains(lower, "playwright") {
		server.RiskClassifications = append(server.RiskClassifications, "browser-or-computer-use")
	}
	return server
}

func collectRepoFiles(report *Report, root string, reader *SafeReader, opts Options) {
	targets := map[string]bool{
		"CLAUDE.md": true, "AGENTS.md": true, ".cursorrules": true, "package.json": true, "Makefile": true, "makefile": true,
	}
	reader.Walk(root, opts.Mode, func(path string, d fs.DirEntry) {
		if d.IsDir() {
			return
		}
		base := filepath.Base(path)
		if !targets[base] && !strings.HasSuffix(path, ".mcp.json") {
			return
		}
		data, err := reader.ReadFile(path, opts.Mode)
		if err != nil {
			return
		}
		text := string(data)
		if riskyInstructionPattern.MatchString(text) || dangerPattern.MatchString(text) || networkPattern.MatchString(text) {
			report.Findings = append(report.Findings, Finding{
				ID:                 stableID("risky-instruction", path),
				RuleID:             "risky-instruction-guidance",
				Title:              "Risky agent instruction or command reference detected",
				Severity:           SeverityHigh,
				Confidence:         ConfidenceInferred,
				EvidenceSource:     path,
				EvidenceKind:       "repo-file",
				ScanMode:           opts.Mode,
				Platform:           platformName(),
				AffectedAsset:      path,
				WhyItMatters:       "Agent instruction files and repo scripts are untrusted context that can influence coding-agent behavior.",
				RuntimeLimitations: "Static scan only; the scanner did not execute the instruction or verify whether an agent loaded it.",
				RemediationRefs:    []string{"remediate-instruction-risk"},
			})
		}
		if strings.HasSuffix(path, ".json") || strings.Contains(text, "mcpServers") {
			report.MCPServers = append(report.MCPServers, parseMCPJSON(path, data)...)
		}
	})
}

func collectSuppressions(report *Report, root string, reader *SafeReader, opts Options) {
	path := filepath.Join(root, ".ariadne", "suppressions.yaml")
	data, err := reader.ReadFile(path, opts.Mode)
	if err != nil {
		return
	}
	var cur Suppression
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		switch key {
		case "finding_id":
			if cur.FindingID != "" {
				report.Suppressions = append(report.Suppressions, finalizeSuppression(cur, path))
			}
			cur = Suppression{FindingID: value, Source: path}
		case "scope":
			cur.Scope = value
		case "owner":
			cur.Owner = value
		case "reason":
			cur.Reason = value
		case "expires_at":
			if t, err := time.Parse("2006-01-02", value); err == nil {
				cur.ExpiresAt = t
			}
		}
	}
	if cur.FindingID != "" {
		report.Suppressions = append(report.Suppressions, finalizeSuppression(cur, path))
	}
}

func finalizeSuppression(s Suppression, source string) Suppression {
	s.Source = source
	if !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt) {
		s.Expired = true
	}
	return s
}

func analyzeDevcontainer(path string, data []byte) []string {
	var root map[string]any
	var hints []string
	text := strings.ToLower(string(data))
	if err := json.Unmarshal(data, &root); err == nil {
		if root["privileged"] == true {
			hints = append(hints, "privileged-mode")
		}
		if strings.Contains(strings.ToLower(strings.Join(stringArray(root["runArgs"]), " ")), "--privileged") {
			hints = append(hints, "privileged-run-arg")
		}
		for _, mount := range stringArray(root["mounts"]) {
			hints = append(hints, devcontainerMountRisk(mount)...)
		}
	}
	if strings.Contains(text, "docker.sock") {
		hints = append(hints, "docker-socket")
	}
	if strings.Contains(text, "network=host") || strings.Contains(text, `"networkmode"`+":"+`"host"`) || strings.Contains(text, "network_mode: host") {
		hints = append(hints, "host-network")
	}
	if strings.Contains(text, ".ssh") || strings.Contains(text, ".aws") || strings.Contains(text, ".kube") || strings.Contains(text, ".env") {
		hints = append(hints, "secret-adjacent-mount")
	}
	return unique(hints)
}

func devcontainerMountRisk(mount string) []string {
	lower := strings.ToLower(mount)
	var hints []string
	if strings.Contains(lower, "docker.sock") {
		hints = append(hints, "docker-socket")
	}
	if strings.Contains(lower, ".ssh") || strings.Contains(lower, ".aws") || strings.Contains(lower, ".kube") || strings.Contains(lower, ".env") {
		hints = append(hints, "secret-adjacent-mount")
	}
	if strings.Contains(lower, "source=~") || strings.Contains(lower, "source=${localenv:home}") {
		hints = append(hints, "home-directory-mount")
	}
	return hints
}

func runningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		lower := strings.ToLower(string(data))
		return strings.Contains(lower, "docker") || strings.Contains(lower, "containerd") || strings.Contains(lower, "kubepods")
	}
	return false
}

func mergeAgent(agents []Agent, next Agent) []Agent {
	for i := range agents {
		if agents[i].Kind == next.Kind {
			agents[i].ConfigSources = unique(append(agents[i].ConfigSources, next.ConfigSources...))
			agents[i].ManagedEvidence = unique(append(agents[i].ManagedEvidence, next.ManagedEvidence...))
			agents[i].DangerousIndicators = unique(append(agents[i].DangerousIndicators, next.DangerousIndicators...))
			agents[i].DenyReadPatterns = unique(append(agents[i].DenyReadPatterns, next.DenyReadPatterns...))
			agents[i].AuditTelemetryHints = unique(append(agents[i].AuditTelemetryHints, next.AuditTelemetryHints...))
			if next.ManagedVerification != "local" {
				agents[i].ManagedVerification = next.ManagedVerification
			}
			agents[i].PermissionMode = firstNonEmpty(agents[i].PermissionMode, next.PermissionMode)
			agents[i].SandboxMode = firstNonEmpty(agents[i].SandboxMode, next.SandboxMode)
			agents[i].ApprovalPolicy = firstNonEmpty(agents[i].ApprovalPolicy, next.ApprovalPolicy)
			agents[i].NetworkAccess = firstNonEmpty(agents[i].NetworkAccess, next.NetworkAccess)
			return agents
		}
	}
	return append(agents, next)
}

func applyRules(report *Report, opts Options) {
	for _, agent := range report.Agents {
		if len(agent.DangerousIndicators) > 0 || strings.Contains(strings.ToLower(agent.SandboxMode), "danger") || strings.Contains(strings.ToLower(agent.PermissionMode), "bypass") {
			report.Findings = append(report.Findings, finding("dangerous-agent-mode", SeverityCritical, ConfidenceConfirmed, "Dangerous full-access agent mode detected", agent.ConfigSources, agent.Kind, opts))
		}
		if strings.EqualFold(agent.NetworkAccess, "true") || strings.Contains(strings.ToLower(agent.NetworkAccess), "true") {
			report.Findings = append(report.Findings, finding("network-enabled-agent", SeverityHigh, ConfidenceConfirmed, "Network access is enabled in declared agent config", agent.ConfigSources, agent.Kind, opts))
		}
		if len(agent.ManagedEvidence) == 0 || agent.ManagedVerification == "local" {
			report.Findings = append(report.Findings, finding("managed-policy-not-detected", SeverityMedium, ConfidenceInferred, "Enterprise-enforced managed policy was not detected", agent.ConfigSources, agent.Kind, opts))
		}
		if !denyReadCoversSecrets(agent.DenyReadPatterns) {
			report.Findings = append(report.Findings, finding("missing-secret-deny-policy", SeverityHigh, ConfidenceInferred, "No deny-read policy detected for common secret-adjacent paths", agent.ConfigSources, agent.Kind, opts))
		}
		if len(agent.AuditTelemetryHints) == 0 {
			report.Findings = append(report.Findings, finding("audit-telemetry-not-detected", SeverityMedium, ConfidenceInferred, "Agent telemetry or audit export was not detected", agent.ConfigSources, agent.Kind, opts))
		}
	}
	for _, server := range report.MCPServers {
		if server.Name == "" {
			continue
		}
		if server.ApprovedEvidence == "not detected" {
			report.Findings = append(report.Findings, Finding{
				ID:                 stableID("unknown-mcp", server.Source, server.Name),
				RuleID:             "unknown-or-unapproved-mcp",
				Title:              "Unknown or unapproved MCP server detected",
				Severity:           SeverityHigh,
				Confidence:         ConfidenceInferred,
				EvidenceSource:     server.Source,
				EvidenceKind:       "mcp-config",
				ScanMode:           opts.Mode,
				Platform:           platformName(),
				AffectedAsset:      "mcp:" + server.Name,
				WhyItMatters:       "MCP servers bridge model output to tools and credentials. Unknown servers expand the agent blast radius.",
				RuntimeLimitations: "Static config scan only; MCP tools were not executed or introspected.",
				RemediationRefs:    []string{"remediate-mcp-allowlist"},
			})
		}
		if slices.Contains(server.RiskClassifications, "package-or-interpreter-launch") {
			report.Findings = append(report.Findings, Finding{
				ID:                 stableID("mcp-package-launch", server.Source, server.Name),
				RuleID:             "mcp-package-or-interpreter-launch",
				Title:              "MCP server launches through a local package manager or interpreter",
				Severity:           SeverityHigh,
				Confidence:         ConfidenceConfirmed,
				EvidenceSource:     server.Source,
				EvidenceKind:       "mcp-command",
				ScanMode:           opts.Mode,
				Platform:           platformName(),
				AffectedAsset:      "mcp:" + server.Name,
				WhyItMatters:       "Package-manager or interpreter-launched MCP servers can drift, download code, or execute local scripts in the developer environment.",
				RuntimeLimitations: "Static config scan only; package identity and runtime tools were not executed or verified.",
				RemediationRefs:    []string{"remediate-mcp-pinning"},
			})
		}
		if slices.Contains(server.RiskClassifications, "remote-non-https") {
			report.Findings = append(report.Findings, Finding{
				ID:                 stableID("mcp-non-https", server.Source, server.Name),
				RuleID:             "mcp-remote-non-https",
				Title:              "Remote MCP server does not use HTTPS",
				Severity:           SeverityHigh,
				Confidence:         ConfidenceConfirmed,
				EvidenceSource:     server.Source,
				EvidenceKind:       "mcp-url",
				ScanMode:           opts.Mode,
				Platform:           platformName(),
				AffectedAsset:      "mcp:" + server.Name,
				WhyItMatters:       "Non-HTTPS tool channels can expose prompts, arguments, and tool results to interception or tampering.",
				RuntimeLimitations: "Static config scan only; no network connection was attempted.",
				RemediationRefs:    []string{"remediate-mcp-https"},
			})
		}
		if hasBroadFilesystem(server) {
			report.Findings = append(report.Findings, Finding{
				ID:                 stableID("mcp-broad-filesystem", server.Source, server.Name),
				RuleID:             "mcp-broad-filesystem",
				Title:              "MCP server appears to expose broad filesystem access",
				Severity:           SeverityHigh,
				Confidence:         ConfidenceInferred,
				EvidenceSource:     server.Source,
				EvidenceKind:       "mcp-command",
				ScanMode:           opts.Mode,
				Platform:           platformName(),
				AffectedAsset:      "mcp:" + server.Name,
				WhyItMatters:       "Broad filesystem tools can let prompt-injected agents traverse beyond the intended workspace.",
				RuntimeLimitations: "Static config scan only; actual MCP capabilities were not introspected.",
				RemediationRefs:    []string{"remediate-mcp-filesystem"},
			})
		}
	}
	if report.Repo.DevcontainerPresent && !report.Repo.RunningInContainer {
		report.Findings = append(report.Findings, Finding{
			ID:                 stableID("devcontainer-not-running", report.Repo.Root),
			RuleID:             "devcontainer-present-not-runtime-verified",
			Title:              "Devcontainer config is present, but runtime isolation was not verified",
			Severity:           SeverityMedium,
			Confidence:         ConfidenceInferred,
			EvidenceSource:     ".devcontainer/devcontainer.json",
			EvidenceKind:       "devcontainer-config",
			ScanMode:           opts.Mode,
			Platform:           platformName(),
			AffectedAsset:      "repo",
			WhyItMatters:       "A devcontainer file only indicates intent. It does not prove the agent actually ran inside an isolated environment.",
			RuntimeLimitations: "Static scan only; container runtime state was not verified beyond local environment indicators.",
			RemediationRefs:    []string{"remediate-devcontainer-runtime"},
		})
	}
	for _, hint := range report.Repo.DevcontainerRiskHints {
		severity := SeverityHigh
		if hint == "docker-socket" || hint == "privileged-mode" || hint == "host-network" {
			severity = SeverityCritical
		}
		report.Findings = append(report.Findings, Finding{
			ID:                 stableID("devcontainer-risk", hint),
			RuleID:             "devcontainer-risk-" + hint,
			Title:              "Risky devcontainer setting detected: " + hint,
			Severity:           severity,
			Confidence:         ConfidenceConfirmed,
			EvidenceSource:     ".devcontainer/devcontainer.json",
			EvidenceKind:       "devcontainer-config",
			ScanMode:           opts.Mode,
			Platform:           platformName(),
			AffectedAsset:      "devcontainer",
			WhyItMatters:       "Weak container boundaries can let an agent escape intended workspace limits or access host resources.",
			RuntimeLimitations: "Static config scan only; the scanner did not start or inspect the container runtime.",
			RemediationRefs:    []string{"remediate-devcontainer-hardening"},
		})
	}
}

func finding(rule string, sev Severity, conf Confidence, title string, sources []string, asset string, opts Options) Finding {
	source := ""
	if len(sources) > 0 {
		source = sources[0]
	}
	return Finding{
		ID:                 stableID(rule, source, asset),
		RuleID:             rule,
		Title:              title,
		Severity:           sev,
		Confidence:         conf,
		EvidenceSource:     source,
		EvidenceKind:       "agent-config",
		ScanMode:           opts.Mode,
		Platform:           platformName(),
		AffectedAsset:      asset,
		WhyItMatters:       whyForRule(rule),
		RuntimeLimitations: "Static config scan only; runtime access, process behavior, and network reachability were not verified.",
		RemediationRefs:    []string{"remediate-" + rule},
	}
}

func whyForRule(rule string) string {
	switch rule {
	case "dangerous-agent-mode":
		return "Full-access or bypass modes remove approval and sandbox boundaries around model-directed actions."
	case "network-enabled-agent":
		return "Network-enabled agent subprocesses may be able to send data from the developer environment."
	case "managed-policy-not-detected":
		return "Local user-controlled config can drift from enterprise policy and may be changed by users or repo content."
	case "missing-secret-deny-policy":
		return "Agents commonly operate near developer credentials. Missing deny-read coverage increases secret exposure risk."
	case "audit-telemetry-not-detected":
		return "Without telemetry, security teams may be unable to reconstruct agent actions after an incident."
	default:
		return "This posture increases AI coding-agent blast radius."
	}
}

func synthesizeAttackPaths(report Report) []AttackPath {
	has := func(rule string) []string {
		var ids []string
		for _, f := range report.Findings {
			if f.RuleID == rule && !f.Suppressed {
				ids = append(ids, f.ID)
			}
		}
		return ids
	}
	hasPrefix := func(prefix string) []string {
		var ids []string
		for _, f := range report.Findings {
			if strings.HasPrefix(f.RuleID, prefix) && !f.Suppressed {
				ids = append(ids, f.ID)
			}
		}
		return ids
	}
	var paths []AttackPath
	danger := has("dangerous-agent-mode")
	network := has("network-enabled-agent")
	noSecrets := has("missing-secret-deny-policy")
	unknownMCP := has("unknown-or-unapproved-mcp")
	mcpPackage := has("mcp-package-or-interpreter-launch")
	mcpFS := has("mcp-broad-filesystem")
	unmanaged := has("managed-policy-not-detected")
	auditBlind := has("audit-telemetry-not-detected")
	devRisks := hasPrefix("devcontainer-risk-")
	riskyInstructions := has("risky-instruction-guidance")
	sensitive := isSensitiveTier(report.Repo.Tier)
	if (sensitive || len(riskyInstructions) > 0) && len(noSecrets) > 0 && (len(danger) > 0 || len(mcpFS) > 0 || len(unknownMCP) > 0) {
		paths = append(paths, attackPath("prompt-injection-secret-exposure", SeverityCritical, appendAll(noSecrets, danger, mcpFS, unknownMCP, riskyInstructions),
			"Prompt injection to secret exposure",
			[]string{"Sensitive or instruction-bearing repo context", "Missing secret-adjacent deny policy", "Broad shell, bypass, or MCP access"},
			"A malicious instruction in repo content or MCP tool metadata could steer the local coding agent toward developer credentials or token caches while operating near sensitive code.",
			"Treats local agent context as a data-egress bridge from source-controlled text to developer secrets.",
			[]string{"Enforce deny-read coverage for secret-adjacent paths", "Disable bypass/full-access modes", "Restrict MCP servers and filesystem roots"}))
	}
	if len(network) > 0 && len(noSecrets) > 0 && (len(unknownMCP) > 0 || len(danger) > 0) {
		paths = append(paths, attackPath("agent-network-data-egress", SeverityCritical, appendAll(network, noSecrets, unknownMCP, danger),
			"Agent-to-network data-egress path",
			[]string{"Declared network-enabled agent config", "Missing secret-adjacent deny policy", "Unknown MCP or bypass-capable agent"},
			"An agent with network-enabled execution and weak local secret boundaries could be manipulated to move sensitive data out of the developer environment.",
			"Network-enabled agent posture is the point where local prompt injection can become data movement.",
			[]string{"Disable network by default", "Use allowlisted network policy", "Add secret deny rules", "Remove unknown MCP servers"}))
	}
	if len(mcpPackage) > 0 && (sensitive || len(mcpFS) > 0) {
		paths = append(paths, attackPath("mutable-tool-launch-execution", SeverityHigh, appendAll(mcpPackage, mcpFS),
			"Mutable tool launch execution path",
			[]string{"MCP launched via package manager or interpreter", "Sensitive repo or broad filesystem scope"},
			"A package-manager or interpreter-launched MCP server can drift or execute local code with the same user privileges as the developer agent.",
			"MCP turns model tool access into local code execution when tool launchers are mutable or unreviewed.",
			[]string{"Use reviewed/pinned MCP binaries", "Avoid package-manager launched MCP", "Restrict filesystem scope"}))
	}
	if len(danger) > 0 && report.ScanMode == ModeEndpoint {
		paths = append(paths, attackPath("full-access-local-agent", SeverityCritical, danger,
			"Full-access local coding agent",
			[]string{"Endpoint scan", "Dangerous full-access or bypass mode detected"},
			"A local coding agent with bypassed approvals can act at machine speed under the developer's user privileges.",
			"Same-user local agents may inherit files, tokens, SSH agent access, package credentials, and VPN-visible services unless separately contained.",
			[]string{"Disable bypass/full-access modes", "Use managed requirements", "Run high-risk work in devboxes or containers"}))
	}
	if len(devRisks) > 0 {
		paths = append(paths, attackPath("false-devcontainer-isolation", SeverityCritical, devRisks,
			"False devcontainer isolation",
			[]string{"Devcontainer config present", "Host escape or host-resource mount hint detected"},
			"A coding agent may appear containerized while still receiving access to Docker socket, host network, or host secret paths.",
			"Weak container configuration can invalidate the expected runtime boundary for local agents.",
			[]string{"Remove Docker socket mounts", "Disable privileged mode", "Avoid host networking", "Do not mount secret-adjacent host paths"}))
	}
	if sensitive && len(unmanaged) > 0 && (len(network) > 0 || len(danger) > 0) {
		paths = append(paths, attackPath("sensitive-repo-unmanaged-agent", SeverityHigh, appendAll(unmanaged, network, danger),
			"Sensitive repo with unmanaged local agent posture",
			[]string{"Tier2/Tier3 repo", "Enterprise-managed policy not detected", "Write-capable, network-capable, or bypass-capable posture"},
			"Sensitive code is being worked on with local agent posture that may not be constrained by enterprise policy.",
			"Sensitive repos require stronger guarantees than user-controlled local settings.",
			[]string{"Deploy managed Claude/Codex policy", "Restrict sensitive repos to devboxes", "Disable network and bypass modes"}))
	}
	if len(auditBlind) > 0 && (len(danger) > 0 || len(network) > 0 || len(unknownMCP) > 0) {
		paths = append(paths, attackPath("audit-blind-agent-activity", SeverityHigh, appendAll(auditBlind, danger, network, unknownMCP),
			"Audit-blind high-risk agent activity",
			[]string{"High-risk agent posture", "Telemetry or audit export not detected"},
			"If a local agent leaks data or mutates sensitive files, security teams may not have enough evidence to reconstruct the session.",
			"Audit gaps turn contained incidents into investigation failures.",
			[]string{"Enable supported telemetry", "Export agent events to approved collectors", "Capture tool approvals and command metadata"}))
	}
	return paths
}

func attackPath(id string, severity Severity, linked []string, title string, preconditions []string, story, why string, reductions []string) AttackPath {
	return AttackPath{
		ID:                  id,
		Title:               title,
		Severity:            severity,
		Confidence:          ConfidenceInferred,
		LinkedFindings:      unique(linked),
		Preconditions:       preconditions,
		CredibleAbuseStory:  story,
		WhyItMatters:        why,
		WhatWouldReduceRisk: reductions,
		RuntimeLimitations:  "Attack path synthesis is based on static posture. Runtime access, network reachability, and exploitability were not verified.",
	}
}

func buildRemediations(report Report) []Remediation {
	ids := map[string]bool{}
	for _, f := range report.Findings {
		for _, ref := range f.RemediationRefs {
			ids[ref] = true
		}
	}
	var out []Remediation
	if ids["remediate-dangerous-agent-mode"] {
		out = append(out, Remediation{
			ID:        "remediate-dangerous-agent-mode",
			Title:     "Disable dangerous full-access modes",
			AppliesTo: "Claude Code / Codex",
			Snippet: `# Codex requirements.toml
allowed_approval_policies = ["on-request", "untrusted"]
allowed_sandbox_modes = ["read-only", "workspace-write"]`,
			ManualSteps:      []string{"Disable Claude Code bypass permissions through managed settings.", "Block --yolo and danger-full-access in enterprise policy."},
			BehavioralImpact: "Agents can still read and edit within approved boundaries, but approval and sandbox controls remain active.",
		})
	}
	if ids["remediate-network-enabled-agent"] {
		out = append(out, Remediation{
			ID:        "remediate-network-enabled-agent",
			Title:     "Disable default agent network access",
			AppliesTo: "Codex",
			Snippet: `# Codex managed_config.toml
approval_policy = "on-request"
sandbox_mode = "workspace-write"

[sandbox_workspace_write]
network_access = false`,
			ManualSteps:      []string{"Only allow network through reviewed workflow-specific exceptions.", "Use allowlisted domains where supported."},
			BehavioralImpact: "Agent commands may need explicit approval or separate setup phases for dependency installation.",
		})
	}
	if ids["remediate-missing-secret-deny-policy"] {
		out = append(out, Remediation{
			ID:        "remediate-missing-secret-deny-policy",
			Title:     "Add deny-read coverage for secret-adjacent paths",
			AppliesTo: "Codex / Claude Code managed policy",
			Snippet: `# Codex requirements.toml
[permissions.filesystem]
deny_read = ["~/.ssh", "~/.aws", "~/.kube", "~/.docker", "~/.gnupg", "~/.npmrc", "~/.netrc", "/**/*.env", "/**/*.pem"]`,
			ManualSteps:      []string{"Mirror equivalent deny rules in Claude Code managed settings.", "Move long-lived credentials out of developer workstations where possible."},
			BehavioralImpact: "Agents lose access to common local credential stores while normal repo work remains available.",
		})
	}
	if ids["remediate-mcp-allowlist"] || ids["remediate-mcp-pinning"] || ids["remediate-mcp-filesystem"] || ids["remediate-mcp-https"] {
		out = append(out, Remediation{
			ID:        "remediate-mcp-allowlist",
			Title:     "Restrict MCP servers to reviewed, pinned, least-privilege tools",
			AppliesTo: "MCP",
			Snippet: `# Codex requirements.toml
# Empty mcp_servers disables all MCP servers until reviewed entries are added.
[mcp_servers]`,
			ManualSteps:      []string{"Replace npx/uvx-launched MCP servers with reviewed pinned binaries.", "Use HTTPS for remote MCP.", "Limit filesystem MCP roots to the active repo."},
			BehavioralImpact: "Agents may lose ad hoc tool access until MCP servers are reviewed and explicitly allowed.",
		})
	}
	if ids["remediate-devcontainer-hardening"] || ids["remediate-devcontainer-runtime"] {
		out = append(out, Remediation{
			ID:               "remediate-devcontainer-hardening",
			Title:            "Harden devcontainer runtime boundaries",
			AppliesTo:        "Devcontainer/devbox",
			Snippet:          `Remove Docker socket mounts, privileged mode, host networking, and host secret path mounts from devcontainer configuration.`,
			ManualSteps:      []string{"Verify agents actually run inside the container.", "Avoid mounting ~/.ssh, ~/.aws, ~/.kube, or the Docker socket.", "Use separate short-lived credentials inside the workspace."},
			BehavioralImpact: "Agent workspace setup may need explicit dependency and credential provisioning.",
		})
	}
	if ids["remediate-instruction-risk"] {
		out = append(out, Remediation{
			ID:               "remediate-instruction-risk",
			Title:            "Remove risky agent instructions",
			AppliesTo:        "Repo instruction files",
			Snippet:          `Replace broad approval/network/deploy instructions with explicit least-privilege workflow guidance.`,
			ManualSteps:      []string{"Remove instructions that tell agents to auto-approve, read env files, auto-push, deploy, or ignore security prompts."},
			BehavioralImpact: "Agents retain workflow guidance without weakening approval and security boundaries.",
		})
	}
	return out
}

func applySuppressions(report *Report) {
	active := map[string]Suppression{}
	for _, s := range report.Suppressions {
		if !s.Expired {
			active[s.FindingID] = s
		} else {
			report.Findings = append(report.Findings, Finding{
				ID:                 stableID("expired-suppression", s.FindingID),
				RuleID:             "expired-suppression",
				Title:              "Expired Ariadne suppression detected",
				Severity:           SeverityMedium,
				Confidence:         ConfidenceConfirmed,
				EvidenceSource:     s.Source,
				EvidenceKind:       "suppression",
				ScanMode:           report.ScanMode,
				Platform:           report.Platform,
				AffectedAsset:      s.FindingID,
				WhyItMatters:       "Expired suppressions can hide posture risk after the approved exception window ends.",
				RuntimeLimitations: "Suppression evaluation is based only on local suppression metadata.",
			})
		}
	}
	for i := range report.Findings {
		if _, ok := active[report.Findings[i].RuleID]; ok {
			report.Findings[i].Suppressed = true
		}
		if _, ok := active[report.Findings[i].ID]; ok {
			report.Findings[i].Suppressed = true
		}
	}
}

func redactReport(report *Report, includeSensitivePaths bool) {
	report.Repo.Root = RedactString(report.Repo.Root, includeSensitivePaths)
	report.Repo.Remote = RedactString(report.Repo.Remote, includeSensitivePaths)
	report.Repo.InstructionFiles = RedactSlice(report.Repo.InstructionFiles, includeSensitivePaths)
	for i := range report.Agents {
		report.Agents[i].ConfigSources = RedactSlice(report.Agents[i].ConfigSources, includeSensitivePaths)
		report.Agents[i].ManagedEvidence = RedactSlice(report.Agents[i].ManagedEvidence, includeSensitivePaths)
		report.Agents[i].DenyReadPatterns = RedactSlice(report.Agents[i].DenyReadPatterns, includeSensitivePaths)
		report.Agents[i].DangerousIndicators = RedactSlice(report.Agents[i].DangerousIndicators, includeSensitivePaths)
	}
	for i := range report.MCPServers {
		report.MCPServers[i].Source = RedactString(report.MCPServers[i].Source, includeSensitivePaths)
		report.MCPServers[i].CommandOrURL = RedactString(report.MCPServers[i].CommandOrURL, includeSensitivePaths)
		report.MCPServers[i].FilesystemRoots = RedactSlice(report.MCPServers[i].FilesystemRoots, includeSensitivePaths)
	}
	for i := range report.Findings {
		report.Findings[i].EvidenceSource = RedactString(report.Findings[i].EvidenceSource, includeSensitivePaths)
		report.Findings[i].AffectedAsset = RedactString(report.Findings[i].AffectedAsset, includeSensitivePaths)
	}
	for i := range report.Suppressions {
		report.Suppressions[i].Source = RedactString(report.Suppressions[i].Source, includeSensitivePaths)
	}
	report.Warnings = RedactSlice(report.Warnings, includeSensitivePaths)
}

func denyReadCoversSecrets(patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	joined := strings.ToLower(strings.Join(patterns, " "))
	hits := 0
	for _, target := range secretPolicyTargets {
		if strings.Contains(joined, strings.ToLower(target)) || strings.Contains(joined, strings.TrimPrefix(strings.ToLower(target), "~/")) {
			hits++
		}
	}
	return hits >= 3
}

func hasBroadFilesystem(server MCPServer) bool {
	lower := strings.ToLower(server.CommandOrURL + " " + strings.Join(server.FilesystemRoots, " "))
	if slices.Contains(server.RiskClassifications, "filesystem-capable") {
		for _, broad := range []string{" / ", " ~", " $home", "/users", "/home", "documents", "desktop"} {
			if strings.Contains(lower, broad) {
				return true
			}
		}
		return len(server.FilesystemRoots) == 0
	}
	for _, root := range server.FilesystemRoots {
		clean := strings.TrimSpace(strings.ToLower(root))
		if clean == "/" || clean == "~" || strings.Contains(clean, "/users") || strings.Contains(clean, "/home") {
			return true
		}
	}
	return false
}

func inferFilesystemRoots(obj map[string]any) []string {
	var roots []string
	for _, key := range []string{"roots", "root", "paths", "path", "directories", "directory"} {
		value := obj[key]
		roots = append(roots, stringArray(value)...)
		if s := stringValue(value); s != "" {
			roots = append(roots, s)
		}
	}
	return unique(roots)
}

func managedVerification(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasPrefix(lower, "/etc/codex"):
		return "system"
	case strings.Contains(lower, "managed_config.toml"), strings.Contains(lower, "requirements.toml"):
		return "system-or-local"
	default:
		return "local"
	}
}

func stripInlineComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return strings.TrimSpace(line[:idx])
	}
	return line
}

func quotedValues(text string) []string {
	re := regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
	var out []string
	for _, match := range re.FindAllStringSubmatch(text, -1) {
		if match[1] != "" {
			out = append(out, match[1])
		} else if match[2] != "" {
			out = append(out, match[2])
		}
	}
	return out
}

func matchedSnippets(re *regexp.Regexp, text string) []string {
	var out []string
	for _, m := range re.FindAllString(text, 20) {
		out = append(out, m)
	}
	return unique(out)
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func stringArray(v any) []string {
	switch value := v.(type) {
	case []string:
		return value
	case []any:
		var out []string
		for _, item := range value {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func normalizeTier(tier string) string {
	tier = strings.ToLower(strings.TrimSpace(tier))
	switch tier {
	case "tier2", "tier3", "sensitive", "regulated", "prod", "production", "payments", "infra":
		return tier
	case "tier1", "tier0", "unknown":
		return tier
	default:
		return "unknown"
	}
}

func isSensitiveTier(tier string) bool {
	switch normalizeTier(tier) {
	case "tier2", "tier3", "sensitive", "regulated", "prod", "production", "payments", "infra":
		return true
	default:
		return false
	}
}

func unique(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func appendAll(groups ...[]string) []string {
	var out []string
	for _, group := range groups {
		out = append(out, group...)
	}
	return unique(out)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func stableID(parts ...string) string {
	joined := strings.Join(parts, "|")
	sum := 0
	for _, r := range joined {
		sum = (sum*33 + int(r)) & 0x7fffffff
	}
	return fmt.Sprintf("%s-%08x", parts[0], sum)
}

func platformName() string {
	if runtime.GOOS == "linux" && os.Getenv("WSL_DISTRO_NAME") != "" {
		return "wsl-experimental"
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

func ValidateMode(mode string) (ScanMode, error) {
	switch ScanMode(mode) {
	case ModeRepo, ModeEndpoint, ModeDevbox:
		return ScanMode(mode), nil
	default:
		return "", errors.New("mode must be repo, endpoint, or devbox")
	}
}

func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
