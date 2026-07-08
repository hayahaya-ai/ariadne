// Package agentconfig parses the real permission structure of Claude Code
// and Codex agent configuration files. It replaces keyword/substring
// detection (house rule #2) with structured parsing: JSON for Claude
// settings, a hand-rolled minimal TOML reader for Codex config. Both
// parsers are pure and total — they never panic, and malformed input
// yields a zero-value struct plus ok=false rather than a partial guess.
package agentconfig

import "strings"

// secretDotPatterns are dotfile/extension-style secret markers. A path
// segment matches if it equals the pattern exactly, or ends with it (e.g.
// "id.pem" ends with ".pem"). Because the check is scoped to one "/"
// separated segment at a time, this never produces the classic substring
// false positive of ".env" matching inside "environment.ts" — that whole
// segment is "environment.ts", and it does not end with ".env".
var secretDotPatterns = []string{
	".env",
	".ssh",
	".aws",
	".pem",
	".npmrc",
	".git-credentials",
}

// secretWordPatterns are bare words that must appear in a path segment at a
// word boundary (not as part of a longer identifier) to count as
// secret-like, e.g. "secrets.yaml" or "my-credentials" match, but
// "notsecrets" does not.
var secretWordPatterns = []string{
	"secrets",
	"credentials",
	"id_rsa",
}

// IsSecretLikePath reports whether a permission-rule scope (a filesystem
// path, possibly with glob segments like "**" or "*") names a secret-like
// file or directory. Matching is semantic over "/"-separated path segments,
// never a raw substring scan over the whole string — that is what let
// "src/environment.ts" false-positive as a secret path under the old
// keyword detector.
func IsSecretLikePath(scope string) bool {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return false
	}
	for _, seg := range strings.Split(scope, "/") {
		if isSecretSegment(seg) {
			return true
		}
	}
	return false
}

// isSecretSegment evaluates a single path segment (no "/" inside it).
func isSecretSegment(seg string) bool {
	// Strip leading/trailing glob wildcards so "*.env" or "id_rsa*" still
	// match on the meaningful part, and drop a lone "~" or "**" segment.
	trimmed := strings.ToLower(strings.Trim(strings.TrimSpace(seg), "*?"))
	if trimmed == "" || trimmed == "~" {
		return false
	}
	for _, pat := range secretDotPatterns {
		if trimmed == pat || strings.HasSuffix(trimmed, pat) {
			return true
		}
	}
	for _, pat := range secretWordPatterns {
		if containsWord(trimmed, pat) {
			return true
		}
	}
	return false
}

// containsWord reports whether word occurs in s bounded by non-word
// characters (or the start/end of s) on both sides, so "secrets" matches
// "secrets.yaml" and "my-secrets" but not "notsecrets".
func containsWord(s, word string) bool {
	if word == "" {
		return false
	}
	from := 0
	for {
		i := strings.Index(s[from:], word)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(word)
		beforeOK := start == 0 || !isWordChar(s[start-1])
		afterOK := end == len(s) || !isWordChar(s[end])
		if beforeOK && afterOK {
			return true
		}
		from = start + 1
	}
}

func isWordChar(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// isBroadScope reports whether a PermRule scope grants unrestricted access:
// no scope at all, or an explicit "*".
func isBroadScope(scope string) bool {
	return scope == "" || scope == "*"
}

// IsBroadScope is the exported form of isBroadScope, for callers outside
// this package (e.g. internal/adapter) that need to apply the same
// broad-scope test when implementing allow/deny cancellation semantics.
func IsBroadScope(scope string) bool {
	return isBroadScope(scope)
}
