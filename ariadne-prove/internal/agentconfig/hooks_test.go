package agentconfig

import "testing"

func TestParseHookConfigRecognizesConnectedDCGOnly(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		ok        bool
		connected bool
	}{
		{"connected", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/dcg"}]}]}}`, true, true},
		{"windows", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"C:/Tools/dcg.exe"}]}]}}`, true, true},
		{"wrong event", `{"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"dcg"}]}]}}`, true, false},
		{"wrong matcher", `{"hooks":{"PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"dcg"}]}]}}`, true, false},
		{"substring", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/dcg-helper"}]}]}}`, true, false},
		{"malformed event", `{"hooks":{"PreToolUse":{}}}`, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseHookConfig([]byte(tc.data))
			if ok != tc.ok || got.HasDestructiveCommandGuard != tc.connected {
				t.Fatalf("ParseHookConfig() = (%+v, %v), want connected=%v ok=%v", got, ok, tc.connected, tc.ok)
			}
		})
	}
}
