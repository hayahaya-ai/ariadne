package agentconfig

import (
	"encoding/json"
	"strings"
)

// PermRule is one entry from a Claude Code permissions.allow/deny/ask list,
// split into its tool and scope. "Bash(*)" -> Tool="Bash", Scope="*".
// "Read(~/.aws/**)" -> Tool="Read", Scope="~/.aws/**". A bare entry with no
// parens, e.g. "WebFetch", -> Tool="WebFetch", Scope="".
type PermRule struct {
	Raw   string // original rule string, case preserved
	Tool  string // parsed head, case preserved
	Scope string // parsed parenthesized body; "" if none
}

// ClaudeSettings is the structured shape of a .claude/settings.json or
// settings.local.json file that matters for exposure grading. Fields not
// modeled here (hooks, env, model, etc.) are ignored.
type ClaudeSettings struct {
	DefaultMode string // "" if absent; e.g. "default", "acceptEdits", "bypassPermissions"
	Allow       []PermRule
	Deny        []PermRule
	Ask         []PermRule

	// HasInlineCredential is true when a top-level JSON key, or a key
	// nested one level under "permissions", has a name matching
	// isCredentialKeyName and a non-empty JSON string value. Detection is
	// real JSON key/value-type inspection (encoding/json), never a raw
	// substring scan over file bytes.
	HasInlineCredential bool
}

// rawClaudeSettings mirrors only the JSON keys agentconfig cares about.
// Unknown keys are ignored by encoding/json automatically.
type rawClaudeSettings struct {
	DefaultMode string `json:"defaultMode"`
	Permissions *struct {
		DefaultMode string   `json:"defaultMode"`
		Allow       []string `json:"allow"`
		Deny        []string `json:"deny"`
		Ask         []string `json:"ask"`
	} `json:"permissions"`
}

// ParseClaudeSettings parses a Claude Code settings JSON file into a
// ClaudeSettings. It is a real encoding/json parse — no keyword scanning.
// On JSON syntax errors (including "settings" files with // comments,
// which are not valid JSON) it returns a zero-value ClaudeSettings and
// ok=false; callers must not fall back to keyword detection on failure.
func ParseClaudeSettings(data []byte) (ClaudeSettings, bool) {
	var raw rawClaudeSettings
	if err := json.Unmarshal(data, &raw); err != nil {
		return ClaudeSettings{}, false
	}

	var out ClaudeSettings
	switch {
	case raw.Permissions != nil && raw.Permissions.DefaultMode != "":
		out.DefaultMode = raw.Permissions.DefaultMode
	case raw.DefaultMode != "":
		out.DefaultMode = raw.DefaultMode
	}

	if raw.Permissions != nil {
		out.Allow = parsePermRules(raw.Permissions.Allow)
		out.Deny = parsePermRules(raw.Permissions.Deny)
		out.Ask = parsePermRules(raw.Permissions.Ask)
	}
	out.HasInlineCredential = detectInlineCredential(data)
	return out, true
}

// detectInlineCredential inspects the real JSON key/value structure for a
// credential-like key (top-level, or nested one level under "permissions")
// carrying a non-empty string value. It is a second, generic decode into
// map[string]json.RawMessage rather than a fixed struct, because
// rawClaudeSettings only models the keys agentconfig already understands
// (defaultMode/permissions) and would silently drop an arbitrary key like
// "apiKeyHelper" or a nested "permissions.api_key" during a struct decode.
// This never falls back to scanning raw bytes: every candidate value is
// type-checked via json.Unmarshal before being treated as a string.
func detectInlineCredential(data []byte) bool {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(data, &generic); err != nil {
		return false
	}
	if hasCredentialStringKey(generic) {
		return true
	}
	permsRaw, ok := generic["permissions"]
	if !ok {
		return false
	}
	var permsGeneric map[string]json.RawMessage
	if err := json.Unmarshal(permsRaw, &permsGeneric); err != nil {
		return false
	}
	return hasCredentialStringKey(permsGeneric)
}

// hasCredentialStringKey reports whether m contains a credential-named key
// (isCredentialKeyName) whose JSON value is a string and non-empty. A
// non-string value (object, array, number, bool, null) never matches,
// regardless of key name.
func hasCredentialStringKey(m map[string]json.RawMessage) bool {
	for key, raw := range m {
		if !isCredentialKeyName(key) {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			continue
		}
		if value != "" {
			return true
		}
	}
	return false
}

func parsePermRules(rules []string) []PermRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]PermRule, 0, len(rules))
	for _, raw := range rules {
		out = append(out, parsePermRule(raw))
	}
	return out
}

// parsePermRule splits a single rule string on the first '(' and a
// trailing ')'. A rule with no parens (or an unterminated one) is treated
// as a bare tool name with an empty scope.
func parsePermRule(raw string) PermRule {
	open := strings.Index(raw, "(")
	if open < 0 || !strings.HasSuffix(raw, ")") {
		return PermRule{Raw: raw, Tool: raw, Scope: ""}
	}
	return PermRule{
		Raw:   raw,
		Tool:  raw[:open],
		Scope: raw[open+1 : len(raw)-1],
	}
}

// HasAllowTool reports whether the allow list contains a rule for tool,
// matched case-insensitively.
func (s ClaudeSettings) HasAllowTool(tool string) bool {
	return rulesHaveTool(s.Allow, tool)
}

// HasDenyTool reports whether the deny list contains a rule for tool,
// matched case-insensitively.
func (s ClaudeSettings) HasDenyTool(tool string) bool {
	return rulesHaveTool(s.Deny, tool)
}

func rulesHaveTool(rules []PermRule, tool string) bool {
	for _, r := range rules {
		if strings.EqualFold(r.Tool, tool) {
			return true
		}
	}
	return false
}

// AllowReadScopes returns the parsed Scope of every Read rule in Allow.
func (s ClaudeSettings) AllowReadScopes() []string {
	return toolScopes(s.Allow, "Read")
}

// DenyReadScopes returns the parsed Scope of every Read rule in Deny.
func (s ClaudeSettings) DenyReadScopes() []string {
	return toolScopes(s.Deny, "Read")
}

func toolScopes(rules []PermRule, tool string) []string {
	var out []string
	for _, r := range rules {
		if strings.EqualFold(r.Tool, tool) {
			out = append(out, r.Scope)
		}
	}
	return out
}

// HasBroadBashAllow reports whether Allow contains a Bash rule scoped to
// "*" or unscoped — i.e. shell access without a path/command restriction.
func (s ClaudeSettings) HasBroadBashAllow() bool {
	return hasBroadToolRule(s.Allow, "Bash")
}

// HasBroadBashDeny reports whether Deny contains a Bash rule scoped to "*"
// or unscoped. A deny rule here only ever removes authority; it must never
// be read as granting it.
func (s ClaudeSettings) HasBroadBashDeny() bool {
	return hasBroadToolRule(s.Deny, "Bash")
}

func hasBroadToolRule(rules []PermRule, tool string) bool {
	for _, r := range rules {
		if strings.EqualFold(r.Tool, tool) && isBroadScope(r.Scope) {
			return true
		}
	}
	return false
}

// HasSecretReadDeny reports whether Deny contains a Read rule whose scope
// names a secret-like path (see IsSecretLikePath).
func (s ClaudeSettings) HasSecretReadDeny() bool {
	return anySecretLikeScope(s.DenyReadScopes())
}

// HasSecretReadAllow reports whether Allow contains a Read rule whose
// scope names a secret-like path. A secret path in Allow is file-read
// authority over that path, not a deny-secret-read control.
func (s ClaudeSettings) HasSecretReadAllow() bool {
	return anySecretLikeScope(s.AllowReadScopes())
}

func anySecretLikeScope(scopes []string) bool {
	for _, scope := range scopes {
		if IsSecretLikePath(scope) {
			return true
		}
	}
	return false
}
