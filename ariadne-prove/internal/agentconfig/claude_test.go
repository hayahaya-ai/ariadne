package agentconfig

import (
	"reflect"
	"testing"
)

func TestParseClaudeSettings_DenyNotAllow(t *testing.T) {
	data := []byte(`{"permissions":{"defaultMode":"default","deny":["Bash(*)","Read(~/.aws/**)","WebFetch"]}}`)
	got, ok := ParseClaudeSettings(data)
	if !ok {
		t.Fatalf("ParseClaudeSettings: ok=false, want true")
	}
	if got.DefaultMode != "default" {
		t.Errorf("DefaultMode = %q, want %q", got.DefaultMode, "default")
	}
	if len(got.Allow) != 0 {
		t.Errorf("Allow = %v, want empty", got.Allow)
	}
	wantDeny := []PermRule{
		{Raw: "Bash(*)", Tool: "Bash", Scope: "*"},
		{Raw: "Read(~/.aws/**)", Tool: "Read", Scope: "~/.aws/**"},
		{Raw: "WebFetch", Tool: "WebFetch", Scope: ""},
	}
	if len(got.Deny) != len(wantDeny) {
		t.Fatalf("Deny = %+v, want %+v", got.Deny, wantDeny)
	}
	for i, want := range wantDeny {
		if got.Deny[i] != want {
			t.Errorf("Deny[%d] = %+v, want %+v", i, got.Deny[i], want)
		}
	}

	if got.HasAllowTool("Bash") {
		t.Errorf("HasAllowTool(Bash) = true, want false")
	}
	if !got.HasDenyTool("Bash") {
		t.Errorf("HasDenyTool(Bash) = false, want true")
	}
	if !got.HasDenyTool("bash") {
		t.Errorf("HasDenyTool is case-sensitive, want case-insensitive match")
	}

	scopes := got.DenyReadScopes()
	found := false
	for _, s := range scopes {
		if IsSecretLikePath(s) {
			found = true
		}
	}
	if !found {
		t.Errorf("DenyReadScopes() = %v, want at least one secret-like scope", scopes)
	}

	// This is the exact bug the spec calls out: a deny-only config must
	// never look like broad-local authority or external communication.
	if got.HasBroadBashAllow() {
		t.Errorf("HasBroadBashAllow() = true, want false (Bash(*) is in deny, not allow)")
	}
	if got.HasBroadBashDeny() != true {
		t.Errorf("HasBroadBashDeny() = false, want true")
	}
	if !got.HasSecretReadDeny() {
		t.Errorf("HasSecretReadDeny() = false, want true")
	}
	if got.HasSecretReadAllow() {
		t.Errorf("HasSecretReadAllow() = true, want false")
	}
}

func TestParseClaudeSettings_SecretInAllow(t *testing.T) {
	data := []byte(`{"permissions":{"allow":["Read(.env)"]}}`)
	got, ok := ParseClaudeSettings(data)
	if !ok {
		t.Fatalf("ParseClaudeSettings: ok=false, want true")
	}
	if len(got.Allow) != 1 || got.Allow[0].Tool != "Read" || got.Allow[0].Scope != ".env" {
		t.Fatalf("Allow = %+v, want single Read(.env) rule", got.Allow)
	}
	if !IsSecretLikePath(got.Allow[0].Scope) {
		t.Errorf("IsSecretLikePath(%q) = false, want true", got.Allow[0].Scope)
	}
	// Secret-like in allow, not deny: must not read as a deny-secret-read
	// control, but should read as secret-scoped file-read authority.
	if got.HasSecretReadDeny() {
		t.Errorf("HasSecretReadDeny() = true, want false (the rule is in allow)")
	}
	if !got.HasSecretReadAllow() {
		t.Errorf("HasSecretReadAllow() = false, want true")
	}
}

func TestParsePermRule_WebFetchDomainScope(t *testing.T) {
	got := parsePermRule("WebFetch(domain:example.com)")
	want := PermRule{Raw: "WebFetch(domain:example.com)", Tool: "WebFetch", Scope: "domain:example.com"}
	if got != want {
		t.Errorf("parsePermRule = %+v, want %+v", got, want)
	}
}

func TestParseClaudeSettings_MalformedJSON(t *testing.T) {
	data := []byte(`{
		// this is a comment, which is not valid JSON
		"permissions": {"allow": ["Bash(*)"]}
	}`)
	got, ok := ParseClaudeSettings(data)
	if ok {
		t.Fatalf("ParseClaudeSettings: ok=true, want false for JSON with // comments")
	}
	if !reflect.DeepEqual(got, ClaudeSettings{}) {
		t.Errorf("ParseClaudeSettings on failure = %+v, want zero value", got)
	}
}

func TestIsSecretLikePath(t *testing.T) {
	cases := []struct {
		scope string
		want  bool
	}{
		{"~/.aws/**", true},
		{".env", true},
		{"src/environment.ts", false},
		{".ssh/id_rsa", true},
		{"config/secrets.yaml", true},
		{"notsecrets.yaml", false},
		{"key.pem", true},
		{"~/.npmrc", true},
		{".git-credentials", true},
		{"src/main.go", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsSecretLikePath(c.scope); got != c.want {
			t.Errorf("IsSecretLikePath(%q) = %v, want %v", c.scope, got, c.want)
		}
	}
}

func TestClaudeSettings_DefaultModeTopLevelFallback(t *testing.T) {
	data := []byte(`{"defaultMode":"bypassPermissions"}`)
	got, ok := ParseClaudeSettings(data)
	if !ok {
		t.Fatalf("ParseClaudeSettings: ok=false, want true")
	}
	if got.DefaultMode != "bypassPermissions" {
		t.Errorf("DefaultMode = %q, want %q", got.DefaultMode, "bypassPermissions")
	}
}

func TestClaudeSettings_PermissionsDefaultModeWins(t *testing.T) {
	data := []byte(`{"defaultMode":"acceptEdits","permissions":{"defaultMode":"default"}}`)
	got, ok := ParseClaudeSettings(data)
	if !ok {
		t.Fatalf("ParseClaudeSettings: ok=false, want true")
	}
	if got.DefaultMode != "default" {
		t.Errorf("DefaultMode = %q, want %q (permissions.defaultMode takes priority)", got.DefaultMode, "default")
	}
}

func TestClaudeSettings_BareToolNoParens(t *testing.T) {
	got := parsePermRule("WebSearch")
	want := PermRule{Raw: "WebSearch", Tool: "WebSearch", Scope: ""}
	if got != want {
		t.Errorf("parsePermRule = %+v, want %+v", got, want)
	}
}

func TestClaudeSettings_HasInlineCredential(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"apiKeyHelper top-level", `{"apiKeyHelper":"/bin/helper"}`, true},
		{"permissions only, no credential key", `{"permissions":{"allow":["Read(*)"]}}`, false},
		{"empty string value does not count", `{"apiKeyHelper":""}`, false},
		{"credential key nested under permissions", `{"permissions":{"api_key":"z"}}`, true},
		{"non-string value does not count", `{"apiKeyHelper":{"path":"/bin/helper"}}`, false},
		{"unrelated key does not match", `{"tokenizer_mode":"fast"}`, false},
		{"segment match on refresh_token", `{"refresh_token":"abc"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseClaudeSettings([]byte(tc.data))
			if !ok {
				t.Fatalf("ParseClaudeSettings(%q): ok=false, want true", tc.data)
			}
			if got.HasInlineCredential != tc.want {
				t.Errorf("HasInlineCredential = %v, want %v (data=%s)", got.HasInlineCredential, tc.want, tc.data)
			}
		})
	}
}
