package logscrub

import "testing"

// TestSocialSecretsScrubbed: Plan 39b secret-bearing fields — Facebook's
// appsecret_proof and the OAuth 1.0a token, token secret and verifier —
// are never logged under their names.
func TestSocialSecretsScrubbed(t *testing.T) {
	for _, k := range []string{"appsecret_proof", "oauth_token", "oauth_token_secret", "oauth_verifier", "oauthVerifier", "request_token_secret"} {
		if !SensitiveKey(k) {
			t.Errorf("%s not sensitive", k)
		}
	}
}
