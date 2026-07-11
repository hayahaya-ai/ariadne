package agentconfig

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
)

// HookConfig captures the small, security-relevant part of Claude/Codex
// hooks.json-style configuration. It deliberately recognizes only a command
// hook attached to PreToolUse/Bash whose executable basename is exactly dcg.
// A filename or arbitrary substring containing "dcg" is not sufficient.
type HookConfig struct {
	HasDestructiveCommandGuard bool
	DestructiveCommandLine     int
	DestructiveCommand         string
}

type rawHookConfig struct {
	Hooks map[string]json.RawMessage `json:"hooks"`
}

type rawHookMatcher struct {
	Matcher string    `json:"matcher"`
	Hooks   []rawHook `json:"hooks"`
}

type rawHook struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// ParseHookConfig parses the JSON hook shape shared by Claude Code and Codex.
// ok=false means the hooks structure is malformed and must not be promoted to
// enforced control evidence.
func ParseHookConfig(data []byte) (HookConfig, bool) {
	var root rawHookConfig
	if err := json.Unmarshal(data, &root); err != nil {
		return HookConfig{}, false
	}
	if root.Hooks == nil {
		return HookConfig{}, true
	}
	raw, exists := root.Hooks["PreToolUse"]
	if !exists {
		return HookConfig{}, true
	}
	var matchers []rawHookMatcher
	if err := json.Unmarshal(raw, &matchers); err != nil {
		return HookConfig{}, false
	}
	var out HookConfig
	for _, matcher := range matchers {
		if matcher.Matcher != "Bash" {
			continue
		}
		for _, hook := range matcher.Hooks {
			if hook.Type != "" && hook.Type != "command" {
				continue
			}
			if !commandInvokesDCG(hook.Command) {
				continue
			}
			out.HasDestructiveCommandGuard = true
			out.DestructiveCommandLine = jsonStringLine(data, hook.Command)
			out.DestructiveCommand = hook.Command
			return out, true
		}
	}
	return out, true
}

func commandInvokesDCG(command string) bool {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) == 0 {
		return false
	}
	executable := strings.Trim(fields[0], `"'`)
	name := strings.ToLower(filepath.Base(filepath.ToSlash(executable)))
	name = strings.TrimSuffix(name, ".exe")
	return name == "dcg"
}

func jsonStringLine(data []byte, value string) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	offset := bytes.Index(data, encoded)
	if offset < 0 {
		return 0
	}
	return bytes.Count(data[:offset], []byte{'\n'}) + 1
}
