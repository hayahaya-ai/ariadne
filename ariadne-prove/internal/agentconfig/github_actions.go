package agentconfig

import (
	"bufio"
	"regexp"
	"sort"
	"strings"
)

// GitHubWorkflow is the security-relevant projection of one GitHub Actions
// workflow. Values are derived from YAML keys and scalar nodes; comments and
// key-looking text inside unrelated scalar values never become trigger or
// permission facts.
type GitHubWorkflow struct {
	TriggerEvents               []string
	TriggerLines                map[string]int
	ReferencesSecrets           bool
	SecretReferenceLine         int
	OIDCTokenWrite              bool
	OIDCTokenWriteLine          int
	WritePermissions            bool
	WritePermissionsLine        int
	RepositoryWritePermissions  bool
	RepositoryWriteLine         int
	ScopedPermissions           bool
	ScopedPermissionsLine       int
	ExecutesCode                bool
	ExecutesCodeLine            int
	ReadsRepository             bool
	ReadsRepositoryLine         int
	ExternalCommunication       bool
	ExternalCommunicationLine   int
	DirectExternalCommunication bool
	AgentLike                   bool
	AgentLikeLine               int
	AgentAction                 bool
	UsesRemoteAction            bool
	PinnedAction                bool
	EnvironmentGate             bool
	EnvironmentGateLine         int
	InlineCredential            bool
	InlineCredentialLine        int
}

type yamlEntry struct {
	Path           []string
	Value          string
	Line           int
	SequenceScalar bool
}

type yamlContext struct {
	indent int
	key    string
}

var (
	githubAgentTerm     = regexp.MustCompile(`(?i)(^|[^a-z0-9])(claude|anthropic|codex|openai|copilot|gemini|aider|cursor-agent|continue|llm|ai[ _-]review|agent)([^a-z0-9]|$)`)
	githubCredentialKey = regexp.MustCompile(`(?i)(api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|password)`)
)

// ParseGitHubWorkflow parses the YAML mapping/list structure needed for
// managed-workflow facts without importing a YAML dependency. It deliberately
// does not attempt to implement YAML object construction or interpolation.
func ParseGitHubWorkflow(data []byte) (GitHubWorkflow, bool) {
	entries, ok := parseYAMLEntries(data)
	workflow := GitHubWorkflow{TriggerLines: map[string]int{}}
	if !ok {
		return workflow, false
	}

	for _, entry := range entries {
		collectGitHubTrigger(&workflow, entry)
		collectGitHubPermissions(&workflow, entry)
		collectGitHubJobFacts(&workflow, entry)
	}
	// Agent-adjacent automation (for example assigning an issue to Copilot)
	// is not itself a managed prompt path. Require either an agent action or
	// agent-labeled workflow logic that directly invokes an external endpoint.
	workflow.AgentLike = workflow.AgentAction || (workflow.AgentLike && workflow.DirectExternalCommunication)

	sort.Strings(workflow.TriggerEvents)
	return workflow, true
}

func collectGitHubTrigger(workflow *GitHubWorkflow, entry yamlEntry) {
	if len(entry.Path) == 0 || entry.Path[0] != "on" {
		return
	}
	if len(entry.Path) == 1 {
		switch {
		case entry.SequenceScalar:
			addGitHubTrigger(workflow, entry.Value, entry.Line)
		case strings.HasPrefix(strings.TrimSpace(entry.Value), "["):
			for _, value := range inlineYAMLList(entry.Value) {
				addGitHubTrigger(workflow, value, entry.Line)
			}
		case strings.HasPrefix(strings.TrimSpace(entry.Value), "{"):
			for _, value := range inlineYAMLMapKeys(entry.Value) {
				addGitHubTrigger(workflow, value, entry.Line)
			}
		case strings.TrimSpace(entry.Value) != "":
			addGitHubTrigger(workflow, entry.Value, entry.Line)
		}
		return
	}
	if len(entry.Path) == 2 {
		addGitHubTrigger(workflow, entry.Path[1], entry.Line)
	}
}

func addGitHubTrigger(workflow *GitHubWorkflow, value string, line int) {
	event := strings.ToLower(strings.TrimSpace(unquoteYAML(value)))
	if !yamlIdentifier(event) || event == "true" || event == "false" || event == "null" || event == "~" {
		return
	}
	if _, exists := workflow.TriggerLines[event]; exists {
		return
	}
	workflow.TriggerLines[event] = line
	workflow.TriggerEvents = append(workflow.TriggerEvents, event)
}

func collectGitHubPermissions(workflow *GitHubWorkflow, entry yamlEntry) {
	permission, ok := githubPermissionEntry(entry.Path)
	if !ok {
		return
	}
	value := strings.ToLower(strings.TrimSpace(unquoteYAML(entry.Value)))
	if permission == "permissions" {
		switch value {
		case "write-all":
			setFirstBoolLine(&workflow.WritePermissions, &workflow.WritePermissionsLine, entry.Line)
			setFirstBoolLine(&workflow.RepositoryWritePermissions, &workflow.RepositoryWriteLine, entry.Line)
			setFirstBoolLine(&workflow.OIDCTokenWrite, &workflow.OIDCTokenWriteLine, entry.Line)
		case "read-all":
			setFirstBoolLine(&workflow.ScopedPermissions, &workflow.ScopedPermissionsLine, entry.Line)
		}
		return
	}
	if value == "write" {
		if permission == "id-token" {
			setFirstBoolLine(&workflow.OIDCTokenWrite, &workflow.OIDCTokenWriteLine, entry.Line)
		} else {
			setFirstBoolLine(&workflow.WritePermissions, &workflow.WritePermissionsLine, entry.Line)
		}
		if githubRepositoryWritePermission(permission) {
			setFirstBoolLine(&workflow.RepositoryWritePermissions, &workflow.RepositoryWriteLine, entry.Line)
		}
	}
	if value == "read" {
		setFirstBoolLine(&workflow.ScopedPermissions, &workflow.ScopedPermissionsLine, entry.Line)
	}
}

func githubPermissionEntry(path []string) (string, bool) {
	if len(path) == 1 && path[0] == "permissions" {
		return "permissions", true
	}
	if len(path) == 2 && path[0] == "permissions" {
		return path[1], true
	}
	if len(path) == 3 && path[0] == "jobs" && path[2] == "permissions" {
		return "permissions", true
	}
	if len(path) == 4 && path[0] == "jobs" && path[2] == "permissions" {
		return path[3], true
	}
	return "", false
}

func githubRepositoryWritePermission(permission string) bool {
	switch permission {
	case "actions", "attestations", "checks", "contents", "deployments", "discussions", "issues", "packages", "pages", "pull-requests", "repository-projects", "security-events", "statuses":
		return true
	default:
		return false
	}
}

func collectGitHubJobFacts(workflow *GitHubWorkflow, entry yamlEntry) {
	if len(entry.Path) < 3 || entry.Path[0] != "jobs" {
		return
	}
	key := entry.Path[len(entry.Path)-1]
	value := strings.TrimSpace(entry.Value)
	lowerValue := strings.ToLower(value)

	secretExpression := githubScalarReferencesSecrets(value)
	if secretExpression || (key == "secrets" && strings.EqualFold(strings.TrimSpace(unquoteYAML(value)), "inherit")) {
		setFirstBoolLine(&workflow.ReferencesSecrets, &workflow.SecretReferenceLine, entry.Line)
	}
	if pathContains(entry.Path[2:], "secrets") && value != "" && value != "|" && value != ">" {
		setFirstBoolLine(&workflow.ReferencesSecrets, &workflow.SecretReferenceLine, entry.Line)
	}

	if key == "run" || key == "uses" {
		setFirstBoolLine(&workflow.ExecutesCode, &workflow.ExecutesCodeLine, entry.Line)
	}
	if key == "uses" {
		ref := strings.ToLower(strings.TrimSpace(unquoteYAML(value)))
		if strings.HasPrefix(ref, "actions/checkout@") {
			setFirstBoolLine(&workflow.ReadsRepository, &workflow.ReadsRepositoryLine, entry.Line)
		}
		if ref != "" && !strings.HasPrefix(ref, "./") {
			workflow.UsesRemoteAction = true
			setFirstBoolLine(&workflow.ExternalCommunication, &workflow.ExternalCommunicationLine, entry.Line)
			if githubActionPinned(ref) {
				workflow.PinnedAction = true
			}
		}
		if githubAgentTerm.MatchString(value) {
			workflow.AgentAction = true
		}
	}
	if key == "run" && shellHasExternalCommunication(lowerValue) {
		setFirstBoolLine(&workflow.ExternalCommunication, &workflow.ExternalCommunicationLine, entry.Line)
		workflow.DirectExternalCommunication = true
	}
	if githubAgentTerm.MatchString(value) {
		setFirstBoolLine(&workflow.AgentLike, &workflow.AgentLikeLine, entry.Line)
	}
	if len(entry.Path) == 3 && key == "environment" || len(entry.Path) == 4 && entry.Path[2] == "environment" && key == "name" {
		setFirstBoolLine(&workflow.EnvironmentGate, &workflow.EnvironmentGateLine, entry.Line)
	}
	if githubCredentialKey.MatchString(key) && !secretExpression {
		setFirstBoolLine(&workflow.InlineCredential, &workflow.InlineCredentialLine, entry.Line)
	}
}

func githubScalarReferencesSecrets(value string) bool {
	for offset := 0; offset < len(value); {
		start := strings.Index(value[offset:], "${{")
		if start < 0 {
			return false
		}
		start += offset + 3
		end := strings.Index(value[start:], "}}")
		if end < 0 {
			return false
		}
		if githubExpressionReferencesSecrets(value[start : start+end]) {
			return true
		}
		offset = start + end + 2
	}
	return false
}

func githubExpressionReferencesSecrets(expression string) bool {
	var quote byte
	for i := 0; i < len(expression); {
		ch := expression[i]
		if quote != 0 {
			if ch == quote {
				if quote == '\'' && i+1 < len(expression) && expression[i+1] == '\'' {
					i += 2
					continue
				}
				quote = 0
			}
			i++
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			i++
			continue
		}
		if !yamlIdentifierByte(ch) {
			i++
			continue
		}
		start := i
		for i < len(expression) && yamlIdentifierByte(expression[i]) {
			i++
		}
		if !strings.EqualFold(expression[start:i], "secrets") {
			continue
		}
		for i < len(expression) && (expression[i] == ' ' || expression[i] == '\t' || expression[i] == '\n' || expression[i] == '\r') {
			i++
		}
		if i < len(expression) && (expression[i] == '.' || expression[i] == '[') {
			return true
		}
	}
	return false
}

func yamlIdentifierByte(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '_' || value == '-'
}

func setFirstBoolLine(value *bool, line *int, nextLine int) {
	if !*value {
		*value = true
		*line = nextLine
	}
}

func pathContains(path []string, want string) bool {
	for _, value := range path {
		if value == want {
			return true
		}
	}
	return false
}

func githubActionPinned(ref string) bool {
	at := strings.LastIndex(ref, "@")
	if at < 0 || at == len(ref)-1 {
		return false
	}
	version := ref[at+1:]
	if len(version) >= 12 && allHex(version) {
		return true
	}
	if version[0] == 'v' {
		version = version[1:]
	}
	if version == "" {
		return false
	}
	for _, r := range version {
		if (r < '0' || r > '9') && r != '.' && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func allHex(value string) bool {
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return value != ""
}

func shellHasExternalCommunication(value string) bool {
	for _, field := range strings.Fields(value) {
		token := strings.Trim(field, `"'();|&\\`)
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			return true
		}
		switch lower {
		case "curl", "wget", "webhook", "webfetch", "websearch":
			return true
		}
	}
	return false
}

func parseYAMLEntries(data []byte) ([]yamlEntry, bool) {
	normalized, ok := joinMultilineYAMLFlows(strings.TrimPrefix(string(data), "\ufeff"))
	if !ok {
		return nil, false
	}
	scanner := bufio.NewScanner(strings.NewReader(normalized))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var entries []yamlEntry
	var stack []yamlContext
	blockEntry := -1
	blockIndent := -1
	lineNo := 0
	content := false
	mapping := false

	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSuffix(scanner.Text(), "\r")
		indent := leadingYAMLIndent(raw)
		if blockEntry >= 0 {
			if strings.TrimSpace(raw) == "" || indent > blockIndent {
				if strings.TrimSpace(raw) != "" {
					if entries[blockEntry].Value != "" {
						entries[blockEntry].Value += "\n"
					}
					entries[blockEntry].Value += strings.TrimSpace(raw)
				}
				continue
			}
			blockEntry = -1
			blockIndent = -1
		}

		line := strings.TrimSpace(stripYAMLComment(raw))
		if line == "" || line == "---" || line == "..." || strings.HasPrefix(line, "%YAML") {
			continue
		}
		if !validYAMLStructuralLine(raw) {
			return entries, false
		}
		content = true
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		parents := yamlContextPath(stack)

		if strings.HasPrefix(line, "-") && (len(line) == 1 || line[1] == ' ' || line[1] == '\t') {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if key, value, found := splitYAMLMapping(rest); found {
				mapping = true
				path := appendCopied(parents, normalizeYAMLKey(key))
				entries = append(entries, yamlEntry{Path: path, Value: value, Line: lineNo})
				if yamlStartsBlock(value) {
					blockEntry = len(entries) - 1
					blockIndent = indent
				}
				if strings.TrimSpace(value) == "" {
					stack = append(stack, yamlContext{indent: indent, key: normalizeYAMLKey(key)})
				}
				continue
			}
			entries = append(entries, yamlEntry{Path: parents, Value: rest, Line: lineNo, SequenceScalar: true})
			continue
		}

		key, value, found := splitYAMLMapping(line)
		if !found {
			return entries, false
		}
		mapping = true
		key = normalizeYAMLKey(key)
		path := appendCopied(parents, key)
		entries = append(entries, yamlEntry{Path: path, Value: value, Line: lineNo})
		if yamlStartsBlock(value) {
			blockEntry = len(entries) - 1
			blockIndent = indent
		}
		if strings.TrimSpace(value) == "" {
			stack = append(stack, yamlContext{indent: indent, key: key})
		}
	}
	if scanner.Err() != nil || !content || !mapping {
		return entries, false
	}
	return entries, true
}

// joinMultilineYAMLFlows joins balanced flow collections before the small
// dependency-free YAML reader parses mapping entries. It retains blank output
// lines for every consumed continuation line so evidence line numbers remain
// anchored to the original document.
func joinMultilineYAMLFlows(document string) (string, bool) {
	scanner := bufio.NewScanner(strings.NewReader(document))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var output strings.Builder
	var pending strings.Builder
	square := 0
	curly := 0
	continuations := 0
	blockIndent := -1

	for scanner.Scan() {
		raw := strings.TrimSuffix(scanner.Text(), "\r")
		indent := leadingYAMLIndent(raw)
		if blockIndent >= 0 {
			if strings.TrimSpace(raw) == "" || indent > blockIndent {
				output.WriteString(raw)
				output.WriteByte('\n')
				continue
			}
			blockIndent = -1
		}
		lineSquare, lineCurly, valid := yamlStructuralDelta(raw)
		if !valid {
			return "", false
		}
		if pending.Len() == 0 {
			if lineSquare == 0 && lineCurly == 0 {
				output.WriteString(raw)
				output.WriteByte('\n')
				if yamlLineStartsBlock(raw) {
					blockIndent = indent
				}
				continue
			}
			if lineSquare < 0 || lineCurly < 0 {
				return "", false
			}
			pending.WriteString(strings.TrimRight(stripYAMLComment(raw), " \t"))
			square = lineSquare
			curly = lineCurly
			continue
		}

		continuations++
		part := strings.TrimSpace(stripYAMLComment(raw))
		if part != "" {
			pending.WriteByte(' ')
			pending.WriteString(part)
		}
		square += lineSquare
		curly += lineCurly
		if square < 0 || curly < 0 {
			return "", false
		}
		if square == 0 && curly == 0 {
			output.WriteString(pending.String())
			output.WriteByte('\n')
			for i := 0; i < continuations; i++ {
				output.WriteByte('\n')
			}
			pending.Reset()
			continuations = 0
		}
	}
	if scanner.Err() != nil || pending.Len() != 0 {
		return "", false
	}
	return output.String(), true
}

func yamlLineStartsBlock(raw string) bool {
	line := strings.TrimSpace(stripYAMLComment(raw))
	if strings.HasPrefix(line, "-") && (len(line) == 1 || line[1] == ' ' || line[1] == '\t') {
		line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
	}
	_, value, found := splitYAMLMapping(line)
	return found && yamlStartsBlock(value)
}

// ValidateYAMLDocument checks the structural subset used by Ariadne's
// dependency-free workflow readers. It deliberately fails closed on
// unterminated quotes and inline collections that the collector cannot parse.
func ValidateYAMLDocument(data []byte) bool {
	_, ok := parseYAMLEntries(data)
	return ok
}

func validYAMLStructuralLine(line string) bool {
	square, curly, ok := yamlStructuralDelta(line)
	return ok && square == 0 && curly == 0
}

func yamlStructuralDelta(line string) (int, int, bool) {
	var quote rune
	escaped := false
	square := 0
	curly := 0
	for _, r := range stripYAMLComment(line) {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
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
	}
	return square, curly, quote == 0 && !escaped
}

func leadingYAMLIndent(line string) int {
	indent := 0
	for _, r := range line {
		switch r {
		case ' ':
			indent++
		case '\t':
			indent += 2
		default:
			return indent
		}
	}
	return indent
}

func stripYAMLComment(line string) string {
	var quote rune
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

func splitYAMLMapping(line string) (string, string, bool) {
	var quote rune
	escaped := false
	depth := 0
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
			}
		}
	}
	return "", "", false
}

func normalizeYAMLKey(value string) string {
	return strings.ToLower(strings.TrimSpace(unquoteYAML(value)))
}

func unquoteYAML(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		return value[1 : len(value)-1]
	}
	return value
}

func yamlStartsBlock(value string) bool {
	value = strings.TrimSpace(value)
	return value == "|" || value == ">" || value == "|-" || value == ">-" || value == "|+" || value == ">+"
}

func yamlContextPath(stack []yamlContext) []string {
	out := make([]string, 0, len(stack))
	for _, context := range stack {
		out = append(out, context.key)
	}
	return out
}

func appendCopied(values []string, value string) []string {
	out := make([]string, len(values), len(values)+1)
	copy(out, values)
	return append(out, value)
}

func inlineYAMLList(value string) []string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '[' || value[len(value)-1] != ']' {
		return nil
	}
	return splitInlineYAML(value[1 : len(value)-1])
}

func inlineYAMLMapKeys(value string) []string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '{' || value[len(value)-1] != '}' {
		return nil
	}
	var out []string
	for _, item := range splitInlineYAML(value[1 : len(value)-1]) {
		if key, _, ok := splitYAMLMapping(item); ok {
			out = append(out, key)
		}
	}
	return out
}

func splitInlineYAML(value string) []string {
	var out []string
	start := 0
	depth := 0
	var quote rune
	for i, r := range value {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(value[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(value[start:]))
	return out
}

func yamlIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}
