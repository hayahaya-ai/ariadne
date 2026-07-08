package agentconfig

import "strings"

// credentialKeyPatterns are config key names (or "_"-separated key segments)
// that indicate a field is meant to carry credential material. Matching is
// structural — see isCredentialKeyName — never a raw substring scan over
// file text (house rule #2).
var credentialKeyPatterns = []string{
	"api_key",
	"apikey",
	"apikeyhelper",
	"api_token",
	"token",
	"secret",
	"secret_key",
	"client_secret",
	"access_key",
	"password",
	"passwd",
	"private_key",
}

// singleWordCredentialPatterns are the only patterns eligible for segment
// matching (form 2 below) — single-word, no internal separator. Compound
// patterns like "apikey"/"apikeyhelper" must only match a whole key (form
// 1); including them here would make a key like "my_apikey" match on its
// "apikey" segment, which is not the intended semantics.
var singleWordCredentialPatterns = []string{
	"token",
	"secret",
	"password",
	"passwd",
}

// isCredentialKeyName reports whether name (a TOML or JSON key) is a
// credential-carrying field name. Matching has two forms:
//
//  1. Whole-key match: name, lowercased with '_' removed, equals a pattern
//     lowercased with '_' removed. This matches compound names regardless of
//     separator style, e.g. "api_key", "apiKey", and "apikey" all match the
//     "api_key"/"apikey" patterns, and "apiKeyHelper" matches "apikeyhelper".
//  2. Segment match: name is split on '_' and each segment is compared
//     against the single-word patterns (those with no '_' of their own,
//     e.g. "token", "secret", "password", "passwd"). This lets
//     "refresh_token" match on its "token" segment while "tokenizer_mode"
//     does not, since "tokenizer" is not "token".
//
// isCredentialKeyName is pure, total, and deterministic: it never panics and
// always returns the same result for the same input.
func isCredentialKeyName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}

	flat := strings.ReplaceAll(lower, "_", "")
	for _, pat := range credentialKeyPatterns {
		if flat == strings.ReplaceAll(pat, "_", "") {
			return true
		}
	}

	for _, seg := range strings.Split(lower, "_") {
		if seg == "" {
			continue
		}
		for _, pat := range singleWordCredentialPatterns {
			if seg == pat {
				return true
			}
		}
	}
	return false
}
