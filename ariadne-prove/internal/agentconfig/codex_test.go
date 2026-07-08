package agentconfig

import (
	"reflect"
	"testing"
)

func TestParseCodexConfig_CommentedNetworkAccess(t *testing.T) {
	data := []byte(`
# network_access = true
network_access = false
`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if got.NetworkAccess == nil {
		t.Fatalf("NetworkAccess = nil, want pointer to false")
	}
	if *got.NetworkAccess != false {
		t.Errorf("NetworkAccess = %v, want false", *got.NetworkAccess)
	}
}

func TestParseCodexConfig_KeywordInStringValueDoesNotLeak(t *testing.T) {
	data := []byte(`
name = "danger-zone-app"
sandbox_mode = "workspace-write"
`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if got.SandboxMode != "workspace-write" {
		t.Errorf("SandboxMode = %q, want %q (must not leak from unrelated `name` field)", got.SandboxMode, "workspace-write")
	}
}

func TestParseCodexConfig_DangerFullAccessAndNever(t *testing.T) {
	data := []byte(`
sandbox_mode = "danger-full-access"
approval_policy = "never"
`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if got.SandboxMode != "danger-full-access" {
		t.Errorf("SandboxMode = %q, want %q", got.SandboxMode, "danger-full-access")
	}
	if got.ApprovalPolicy != "never" {
		t.Errorf("ApprovalPolicy = %q, want %q", got.ApprovalPolicy, "never")
	}
}

func TestParseCodexConfig_DenyReadUnderPermissionsFilesystemTable(t *testing.T) {
	data := []byte(`
[permissions.filesystem]
deny_read = [".env", "~/.ssh"]
`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	want := []string{".env", "~/.ssh"}
	if len(got.DenyRead) != len(want) {
		t.Fatalf("DenyRead = %v, want %v", got.DenyRead, want)
	}
	for i, w := range want {
		if got.DenyRead[i] != w {
			t.Errorf("DenyRead[%d] = %q, want %q", i, got.DenyRead[i], w)
		}
	}
}

func TestParseCodexConfig_TopLevelDenyReadAlsoCounts(t *testing.T) {
	data := []byte(`deny_read = ["credentials.json"]`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if len(got.DenyRead) != 1 || got.DenyRead[0] != "credentials.json" {
		t.Fatalf("DenyRead = %v, want [\"credentials.json\"]", got.DenyRead)
	}
	if !IsSecretLikePath(got.DenyRead[0]) {
		t.Errorf("IsSecretLikePath(%q) = false, want true", got.DenyRead[0])
	}
}

func TestParseCodexConfig_MCPServersTableHeader(t *testing.T) {
	data := []byte(`
[mcp_servers.filesystem]
command = "npx"
`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if !got.HasMCPServers {
		t.Errorf("HasMCPServers = false, want true")
	}
}

func TestParseCodexConfig_MCPServersBareTable(t *testing.T) {
	data := []byte(`[mcp_servers]`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if !got.HasMCPServers {
		t.Errorf("HasMCPServers = false, want true")
	}
}

func TestParseCodexConfig_HashInsideQuotedStringNotTruncated(t *testing.T) {
	data := []byte(`deny_read = ["path#1"]`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if len(got.DenyRead) != 1 || got.DenyRead[0] != "path#1" {
		t.Fatalf("DenyRead = %v, want [\"path#1\"]", got.DenyRead)
	}
}

func TestParseCodexConfig_InlineCommentAfterValue(t *testing.T) {
	data := []byte(`sandbox_mode = "read-only" # least privilege`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if got.SandboxMode != "read-only" {
		t.Errorf("SandboxMode = %q, want %q", got.SandboxMode, "read-only")
	}
}

func TestParseCodexConfig_BareTokenSandboxMode(t *testing.T) {
	data := []byte(`sandbox_mode = read-only`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if got.SandboxMode != "read-only" {
		t.Errorf("SandboxMode = %q, want %q", got.SandboxMode, "read-only")
	}
}

func TestParseCodexConfig_NetworkAccessAbsentIsNil(t *testing.T) {
	data := []byte(`sandbox_mode = "read-only"`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if got.NetworkAccess != nil {
		t.Errorf("NetworkAccess = %v, want nil", *got.NetworkAccess)
	}
}

func TestParseCodexConfig_EmptyInput(t *testing.T) {
	got, ok := ParseCodexConfig(nil)
	if !ok {
		t.Fatalf("ParseCodexConfig(nil): ok=false, want true")
	}
	if !reflect.DeepEqual(got, CodexConfig{}) {
		t.Errorf("ParseCodexConfig(nil) = %+v, want zero value", got)
	}
}

func TestParseCodexConfig_InvalidUTF8(t *testing.T) {
	data := []byte{0xff, 0xfe, 0xfd}
	got, ok := ParseCodexConfig(data)
	if ok {
		t.Fatalf("ParseCodexConfig: ok=true, want false for invalid UTF-8 input")
	}
	if !reflect.DeepEqual(got, CodexConfig{}) {
		t.Errorf("ParseCodexConfig on failure = %+v, want zero value", got)
	}
}

func TestParseCodexConfig_FullDocument(t *testing.T) {
	data := []byte(`
# Codex config
name = "my-project"

sandbox_mode = "workspace-write"
approval_policy = "on-request"
network_access = true

[permissions.filesystem]
deny_read = [".env", "secrets/*"]

[mcp_servers.github]
command = "npx"
args = ["-y", "@github/mcp"]
`)
	got, ok := ParseCodexConfig(data)
	if !ok {
		t.Fatalf("ParseCodexConfig: ok=false, want true")
	}
	if got.SandboxMode != "workspace-write" {
		t.Errorf("SandboxMode = %q, want %q", got.SandboxMode, "workspace-write")
	}
	if got.ApprovalPolicy != "on-request" {
		t.Errorf("ApprovalPolicy = %q, want %q", got.ApprovalPolicy, "on-request")
	}
	if got.NetworkAccess == nil || *got.NetworkAccess != true {
		t.Errorf("NetworkAccess = %v, want pointer to true", got.NetworkAccess)
	}
	if len(got.DenyRead) != 2 {
		t.Errorf("DenyRead = %v, want 2 entries", got.DenyRead)
	}
	if !got.HasMCPServers {
		t.Errorf("HasMCPServers = false, want true")
	}
}

func TestParseCodexConfig_HasInlineCredential(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"api_key quoted string", `api_key = "x"`, true},
		{"api_key commented out", `# api_key = "x"`, false},
		{"sandbox_mode alone", `sandbox_mode = "workspace-write"`, false},
		{"api_key empty string", `api_key = ""`, false},
		{"client_secret quoted string", `client_secret = "y"`, true},
		{"mcp_servers key not a credential", `mcp_servers = true`, false},
		{"approval_policy not a credential", `approval_policy = "on-request"`, false},
		{"network_access not a credential", `network_access = true`, false},
		{"deny_read not a credential", `deny_read = [".env"]`, false},
		{"tokenizer_mode segment does not match token", `tokenizer_mode = "fast"`, false},
		{"refresh_token segment matches token", `refresh_token = "abc"`, true},
		{"bare token value does not count", `api_key = bare-token-not-quoted`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseCodexConfig([]byte(tc.data))
			if !ok {
				t.Fatalf("ParseCodexConfig(%q): ok=false, want true", tc.data)
			}
			if got.HasInlineCredential != tc.want {
				t.Errorf("HasInlineCredential = %v, want %v (data=%s)", got.HasInlineCredential, tc.want, tc.data)
			}
		})
	}
}
