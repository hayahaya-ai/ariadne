package agentconfig

import "testing"

// TestIsCredentialKeyName_SegmentMatchRestrictedToSingleWordPatterns guards
// against the compound patterns ("apikey", "apikeyhelper", and other
// underscore-containing patterns) leaking into segment matching. Per
// docs/parser-spec.md, segment matching applies only to the single-word
// patterns token/secret/password/passwd; compound patterns only match a
// whole (flattened) key.
func TestIsCredentialKeyName_SegmentMatchRestrictedToSingleWordPatterns(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want bool
	}{
		{"my_apikey does not match via segment", "my_apikey", false},
		{"whole key apikey still matches", "apikey", true},
		{"whole key api_key still matches", "api_key", true},
		{"apiKeyHelper whole key still matches", "apiKeyHelper", true},
		{"refresh_token still matches via segment", "refresh_token", true},
		{"tokenizer_mode still does not match", "tokenizer_mode", false},
		{"my_secret matches via segment", "my_secret", true},
		{"my_password matches via segment", "my_password", true},
		{"my_passwd matches via segment", "my_passwd", true},
		{"unrelated key does not match", "region", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCredentialKeyName(tc.key); got != tc.want {
				t.Errorf("isCredentialKeyName(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}
