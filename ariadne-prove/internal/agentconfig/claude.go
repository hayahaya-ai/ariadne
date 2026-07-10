package agentconfig

import (
	"bytes"
	"encoding/json"
	"io"
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
	Line  int    // 1-based line of the JSON string entry, when known
}

// ClaudeSettings is the structured shape of a .claude/settings.json or
// settings.local.json file that matters for exposure grading. Fields not
// modeled here (hooks, env, model, etc.) are ignored.
type ClaudeSettings struct {
	DefaultMode     string // "" if absent; e.g. "default", "acceptEdits", "bypassPermissions"
	DefaultModeLine int
	Allow           []PermRule
	Deny            []PermRule
	Ask             []PermRule

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
	positions := claudeSettingPositions(data)

	var out ClaudeSettings
	switch {
	case raw.Permissions != nil && raw.Permissions.DefaultMode != "":
		out.DefaultMode = raw.Permissions.DefaultMode
		out.DefaultModeLine = positions.PermissionsDefaultModeLine
	case raw.DefaultMode != "":
		out.DefaultMode = raw.DefaultMode
		out.DefaultModeLine = positions.DefaultModeLine
	}

	if raw.Permissions != nil {
		out.Allow = parsePermRulesWithLines(raw.Permissions.Allow, positions.AllowLines)
		out.Deny = parsePermRulesWithLines(raw.Permissions.Deny, positions.DenyLines)
		out.Ask = parsePermRulesWithLines(raw.Permissions.Ask, positions.AskLines)
	}
	out.HasInlineCredential = detectInlineCredential(data)
	return out, true
}

type claudePositions struct {
	DefaultModeLine            int
	PermissionsDefaultModeLine int
	AllowLines                 map[string][]int
	DenyLines                  map[string][]int
	AskLines                   map[string][]int
}

type jsonPositionContext struct {
	kind         byte
	path         []string
	expectingKey bool
	key          string
}

func claudeSettingPositions(data []byte) claudePositions {
	pos := claudePositions{
		AllowLines: map[string][]int{},
		DenyLines:  map[string][]int{},
		AskLines:   map[string][]int{},
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []jsonPositionContext
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return pos
		}
		line := lineForOffset(data, dec.InputOffset())
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				path := containerValuePath(stack)
				ctx := jsonPositionContext{kind: byte(delim), path: path}
				if delim == '{' {
					ctx.expectingKey = true
				}
				stack = append(stack, ctx)
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				markJSONValueConsumed(stack)
			}
			continue
		}
		if len(stack) == 0 {
			continue
		}
		ctx := &stack[len(stack)-1]
		if ctx.kind == '{' && ctx.expectingKey {
			key, ok := tok.(string)
			if !ok {
				return pos
			}
			ctx.key = key
			ctx.expectingKey = false
			continue
		}
		recordClaudeScalarPosition(&pos, valuePath(stack), tok, line)
		markJSONValueConsumed(stack)
	}
	return pos
}

func containerValuePath(stack []jsonPositionContext) []string {
	if len(stack) == 0 {
		return nil
	}
	parent := stack[len(stack)-1]
	if parent.kind == '{' && !parent.expectingKey && parent.key != "" {
		return appendPath(parent.path, parent.key)
	}
	return appendPath(parent.path)
}

func valuePath(stack []jsonPositionContext) []string {
	if len(stack) == 0 {
		return nil
	}
	ctx := stack[len(stack)-1]
	if ctx.kind == '{' {
		return appendPath(ctx.path, ctx.key)
	}
	return appendPath(ctx.path)
}

func appendPath(base []string, elems ...string) []string {
	out := make([]string, 0, len(base)+len(elems))
	out = append(out, base...)
	out = append(out, elems...)
	return out
}

func markJSONValueConsumed(stack []jsonPositionContext) {
	if len(stack) == 0 {
		return
	}
	ctx := &stack[len(stack)-1]
	if ctx.kind == '{' && !ctx.expectingKey {
		ctx.key = ""
		ctx.expectingKey = true
	}
}

func recordClaudeScalarPosition(pos *claudePositions, path []string, tok json.Token, line int) {
	if line <= 0 {
		return
	}
	switch {
	case pathEquals(path, "defaultMode"):
		pos.DefaultModeLine = line
	case pathEquals(path, "permissions", "defaultMode"):
		pos.PermissionsDefaultModeLine = line
	case pathEquals(path, "permissions", "allow"):
		if value, ok := tok.(string); ok {
			pos.AllowLines[value] = append(pos.AllowLines[value], line)
		}
	case pathEquals(path, "permissions", "deny"):
		if value, ok := tok.(string); ok {
			pos.DenyLines[value] = append(pos.DenyLines[value], line)
		}
	case pathEquals(path, "permissions", "ask"):
		if value, ok := tok.(string); ok {
			pos.AskLines[value] = append(pos.AskLines[value], line)
		}
	}
}

func pathEquals(path []string, elems ...string) bool {
	if len(path) != len(elems) {
		return false
	}
	for i := range path {
		if path[i] != elems[i] {
			return false
		}
	}
	return true
}

func lineForOffset(data []byte, offset int64) int {
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	return bytes.Count(data[:offset], []byte{'\n'}) + 1
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
	return parsePermRulesWithLines(rules, nil)
}

func parsePermRulesWithLines(rules []string, lines map[string][]int) []PermRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]PermRule, 0, len(rules))
	used := map[string]int{}
	for _, raw := range rules {
		rule := parsePermRule(raw)
		if values := lines[raw]; len(values) > used[raw] {
			rule.Line = values[used[raw]]
			used[raw]++
		}
		out = append(out, rule)
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
