package scan

import (
	"os"
	"regexp"
	"strings"
)

var credentialURLPattern = regexp.MustCompile(`(?i)(https?://)([^/\s:@]+):([^@\s]+)@`)
var tokenLikePattern = regexp.MustCompile(`(?i)(token|secret|apikey|api_key|password|passwd|authorization)(["'\s:=]+)([A-Za-z0-9._\-+/=]{8,})`)

func RedactString(input string, includeSensitivePaths bool) string {
	if input == "" {
		return input
	}
	out := input
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = strings.ReplaceAll(out, home, "~")
	}
	if user := os.Getenv("USER"); user != "" {
		out = strings.ReplaceAll(out, "/Users/"+user, "/Users/<user>")
		out = strings.ReplaceAll(out, "/home/"+user, "/home/<user>")
	}
	out = credentialURLPattern.ReplaceAllString(out, `${1}<redacted>:<redacted>@`)
	out = tokenLikePattern.ReplaceAllString(out, `${1}${2}<redacted>`)
	if !includeSensitivePaths {
		out = redactSensitivePathNames(out)
	}
	return out
}

func RedactSlice(values []string, includeSensitivePaths bool) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, RedactString(value, includeSensitivePaths))
	}
	return out
}

func redactSensitivePathNames(input string) string {
	replacements := map[string]string{
		".env":             "<env-file>",
		".aws":             "<aws-dir>",
		".ssh":             "<ssh-dir>",
		".kube":            "<kube-dir>",
		".docker":          "<docker-dir>",
		".gnupg":           "<gnupg-dir>",
		".npmrc":           "<npmrc>",
		".netrc":           "<netrc>",
		"id_rsa":           "<ssh-private-key>",
		"id_ed25519":       "<ssh-private-key>",
		"credentials.json": "<credentials-file>",
	}
	out := input
	for needle, repl := range replacements {
		out = strings.ReplaceAll(out, needle, repl)
	}
	return out
}
