package agentconfig

import (
	"strings"
	"unicode/utf8"
)

// CodexConfig is the structured shape of a .codex/config.toml or
// requirements.toml file that matters for exposure grading. Fields not
// modeled here are ignored.
type CodexConfig struct {
	SandboxMode        string   // e.g. "read-only", "workspace-write", "danger-full-access"; "" if absent
	SandboxModeLine    int      // 1-based line of sandbox_mode, when known
	ApprovalPolicy     string   // e.g. "never", "on-request", "on-failure", "untrusted"; "" if absent
	ApprovalPolicyLine int      // 1-based line of approval_policy, when known
	NetworkAccess      *bool    // nil if absent
	NetworkAccessLine  int      // 1-based line of network_access, when known
	DenyRead           []string // paths from deny_read / [permissions.filesystem] deny_read arrays
	DenyReadLines      []int    // 1-based line for each deny_read entry, when known
	HasMCPServers      bool     // true if an [mcp_servers...] table or mcp_servers key is present
	MCPServersLine     int      // 1-based line of the MCP table/key, when known
	IsRequirements     bool     // set by the caller from surface kind, never parsed

	// HasInlineCredential is true when a key/value line's key matches a
	// credential-like name (see isCredentialKeyName) and its value is a
	// non-empty quoted string literal. Commented-out lines never reach the
	// key/value parser (ParseCodexConfig skips them outright), so a
	// credential-named key inside a "#" comment never sets this. A
	// credential-named key with an empty ("") value, or a bare bool/number
	// value, never sets this either.
	HasInlineCredential bool
}

// ParseCodexConfig parses a Codex TOML config with a hand-rolled, minimal
// line-oriented reader (no external TOML library — house rule: zero
// external dependencies). It supports exactly the subset Codex configs use:
// "key = value" lines, "[table.header]" lines, comments, quoted and bare
// string values, booleans, and single-line string arrays.
//
// The reader is pure and total: it never panics. ok=false means the supported
// TOML subset could not be structurally parsed. Ariadne must not promote a
// partially parsed security configuration to conclusive evidence.
func ParseCodexConfig(data []byte) (CodexConfig, bool) {
	if !utf8.Valid(data) || !validCodexDocument(data) {
		return CodexConfig{}, false
	}

	var cfg CodexConfig
	currentTable := ""

	for idx, rawLine := range strings.Split(string(data), "\n") {
		lineNo := idx + 1
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// A fully commented-out line (first non-space char is '#') is
		// ignored entirely — its "key = value" text must never be read as
		// live configuration.
		if trimmed[0] == '#' {
			continue
		}

		if trimmed[0] == '[' {
			currentTable = parseTableHeader(trimmed)
			if isMCPServersTable(currentTable) {
				cfg.HasMCPServers = true
				cfg.MCPServersLine = lineNo
			}
			continue
		}

		key, value, ok := splitKeyValue(trimmed)
		if !ok {
			continue
		}
		applyKeyValue(&cfg, currentTable, key, value, lineNo)
	}

	return cfg, true
}

func validCodexDocument(data []byte) bool {
	for _, rawLine := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !balancedCodexDelimiters(trimmed) {
			return false
		}
		withoutComment := strings.TrimSpace(stripComment(trimmed))
		if strings.HasPrefix(withoutComment, "[") {
			if !strings.HasSuffix(withoutComment, "]") || strings.TrimSpace(withoutComment[1:len(withoutComment)-1]) == "" {
				return false
			}
			continue
		}
		key, value, ok := splitKeyValue(withoutComment)
		if !ok || key == "" || value == "" || !validCodexValue(value) {
			return false
		}
	}
	return true
}

func balancedCodexDelimiters(value string) bool {
	inQuote := false
	escaped := false
	square := 0
	curly := 0
	for _, r := range value {
		if escaped {
			escaped = false
			continue
		}
		if inQuote && r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		switch r {
		case '[':
			square++
		case ']':
			square--
		case '{':
			curly++
		case '}':
			curly--
		}
		if square < 0 || curly < 0 {
			return false
		}
	}
	return !inQuote && !escaped && square == 0 && curly == 0
}

func validCodexValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	switch value[0] {
	case '"':
		return len(value) >= 2 && value[len(value)-1] == '"'
	case '[':
		return strings.HasSuffix(value, "]")
	case '{':
		return strings.HasSuffix(value, "}")
	default:
		return !strings.ContainsAny(value, " \t")
	}
}

// parseTableHeader extracts the header name from a "[table.header]" line.
// Returns "" if the line has no closing bracket (malformed; caller keeps
// the previous table unset for this line but does not fail the parse).
func parseTableHeader(trimmed string) string {
	end := strings.Index(trimmed, "]")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(trimmed[1:end])
}

func isMCPServersTable(header string) bool {
	return header == "mcp_servers" || strings.HasPrefix(header, "mcp_servers.")
}

// applyKeyValue attributes one parsed key/value pair into cfg. deny_read is
// accepted regardless of table — both a top-level deny_read and one under
// [permissions.filesystem] must be attributed, and no other table is known
// to carry it in Codex configs, so a table restriction here would only add
// a way to silently drop real deny rules.
func applyKeyValue(cfg *CodexConfig, _ string, key, value string, lineNo int) {
	switch key {
	case "sandbox_mode":
		cfg.SandboxMode = parseStringValue(value)
		cfg.SandboxModeLine = lineNo
	case "approval_policy":
		cfg.ApprovalPolicy = parseStringValue(value)
		cfg.ApprovalPolicyLine = lineNo
	case "network_access":
		if b, ok := parseBoolValue(value); ok {
			cfg.NetworkAccess = &b
			cfg.NetworkAccessLine = lineNo
		}
	case "deny_read":
		if arr, ok := parseStringArray(value); ok {
			cfg.DenyRead = append(cfg.DenyRead, arr...)
			for range arr {
				cfg.DenyReadLines = append(cfg.DenyReadLines, lineNo)
			}
		}
	case "mcp_servers":
		cfg.HasMCPServers = true
		cfg.MCPServersLine = lineNo
	}
	if isCredentialKeyName(key) && isQuotedNonEmptyStringLiteral(value) {
		cfg.HasInlineCredential = true
	}
}

// isQuotedNonEmptyStringLiteral reports whether value is a TOML
// double-quoted string literal (e.g. "x") with non-empty content after
// unescaping. A bare token (unquoted enum-like value, bool, or number) or an
// empty quoted string ("") is not a credential literal.
func isQuotedNonEmptyStringLiteral(value string) bool {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	inner := parseStringValue(value)
	return inner != ""
}

// splitKeyValue splits a "key = value" line on the first '=' that is
// outside a quoted string, then strips a trailing "# comment" from the
// value when the '#' is outside a quoted string. Lines with no unquoted
// '=' are not key/value lines and are skipped by the caller.
func splitKeyValue(trimmed string) (key, value string, ok bool) {
	eq := indexUnquoted(trimmed, '=')
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(trimmed[:eq])
	if key == "" || !isBareKey(key) {
		return "", "", false
	}
	value = strings.TrimSpace(stripComment(trimmed[eq+1:]))
	return key, value, true
}

// isBareKey reports whether s looks like a plain TOML key (letters,
// digits, '_', '-'), rejecting lines whose "key" part is actually
// something else that happened to contain an unquoted '='.
func isBareKey(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
			continue
		default:
			return false
		}
	}
	return true
}

// indexUnquoted returns the index of the first occurrence of target that
// is not inside a "..." quoted string, or -1 if none.
func indexUnquoted(s string, target byte) int {
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' && !(inQuote && i > 0 && s[i-1] == '\\') {
			inQuote = !inQuote
			continue
		}
		if !inQuote && c == target {
			return i
		}
	}
	return -1
}

// stripComment removes a trailing "# ..." comment from s, but only when
// the '#' occurs outside a quoted string, so a literal '#' inside a
// string value (e.g. deny_read = ["path#1"]) is preserved.
func stripComment(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' && !(inQuote && i > 0 && s[i-1] == '\\') {
			inQuote = !inQuote
			continue
		}
		if !inQuote && c == '#' {
			return s[:i]
		}
	}
	return s
}

// parseStringValue strips surrounding double quotes (and minimal escaping)
// from a quoted value, or returns a bare token unchanged — bare tokens are
// how Codex configs sometimes write enum-like values such as sandbox_mode.
func parseStringValue(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		inner := value[1 : len(value)-1]
		inner = strings.ReplaceAll(inner, `\"`, `"`)
		inner = strings.ReplaceAll(inner, `\\`, `\`)
		return inner
	}
	return value
}

func parseBoolValue(value string) (bool, bool) {
	switch value {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// parseStringArray parses a single-line "[ "a", "b" ]" TOML string array.
// Returns ok=false if value is not bracket-delimited.
func parseStringArray(value string) ([]string, bool) {
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
		return nil, false
	}
	inner := v[1 : len(v)-1]
	var out []string
	for _, part := range splitUnquoted(inner, ',') {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, parseStringValue(part))
	}
	return out, true
}

// splitUnquoted splits s on sep, ignoring occurrences of sep inside a
// quoted string.
func splitUnquoted(s string, sep byte) []string {
	var out []string
	inQuote := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' && !(inQuote && i > 0 && s[i-1] == '\\') {
			inQuote = !inQuote
			continue
		}
		if !inQuote && c == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
