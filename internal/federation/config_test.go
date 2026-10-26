package federation

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
)

func configSpec(t *testing.T, strategy string, options string) connrules.Spec {
	t.Helper()
	var s connrules.Spec
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{"name":"provider","strategy":%q,"options":%s}`, strategy, options)), &s); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestFederationConfig(t *testing.T) {
	const google = `{"client_id":"client","client_secret":"do-not-log"}`
	const oauth = `{"client_id":"client","client_secret":"do-not-log","authorizationURL":"https://provider.example/authorize","tokenURL":"https://provider.example/token","scope":"read profile","scripts":{"fetchUserProfile":"function fetchUserProfile() {}"}}`
	const oidc = `{"client_id":"client","client_secret":"do-not-log","discovery_url":"https://provider.example/.well-known/openid-configuration","scopes":"openid profile"}`
	for _, tc := range []struct {
		name, strategy, options string
		bad                     bool
	}{
		{"google", "google-oauth2", google, false}, {"oauth", "oauth2", oauth, false}, {"oidc", "oidc", oidc, false},
		{"unknown", "other", google, true}, {"database", "auth0", google, true},
		{"missing secret", "google-oauth2", `{"client_id":"client"}`, true},
		{"empty secret", "google-oauth2", `{"client_id":"client","client_secret":""}`, true},
		{"null secret", "google-oauth2", `{"client_id":"client","client_secret":null}`, true},
		{"front channel", "oidc", strings.TrimSuffix(oidc, "}") + `,"type":"front_channel"}`, true},
		{"missing openid", "oidc", strings.Replace(oidc, "openid profile", "profile", 1), true},
		{"oidc scope alias", "oidc", strings.TrimSuffix(oidc, "}") + `,"scope":"openid"}`, true},
		{"http endpoint", "oauth2", strings.Replace(oauth, "https://provider.example/token", "http://provider.example/token", 1), true},
		{"private literal endpoint", "oauth2", strings.Replace(oauth, "https://provider.example/token", "https://127.0.0.1/token", 1), true},
		{"reserved endpoint query", "oauth2", strings.Replace(oauth, "/authorize", "/authorize?prompt=login", 1), true},
		{"scope array", "oauth2", strings.Replace(oauth, `"read profile"`, `["read"]`, 1), true},
		{"PKCE disabled", "google-oauth2", strings.TrimSuffix(google, "}") + `,"pkce_enabled":false}`, true},
		{"nonce disabled", "oidc", strings.TrimSuffix(oidc, "}") + `,"send_back_channel_nonce":false}`, true},
		{"google flags", "google-oauth2", strings.TrimSuffix(google, "}") + `,"email":false,"profile":false,"scope":["openid"]}`, false},
		{"google mismatch", "google-oauth2", strings.TrimSuffix(google, "}") + `,"email":false,"scope":["openid","email","profile"]}`, true},
		{"domain policy", "google-oauth2", strings.TrimSuffix(google, "}") + `,"allowed_domains":[]}`, true},
		{"custom auth", "oauth2", strings.TrimSuffix(oauth, "}") + `,"customHeaders":{}}`, true},
		{"inert", "google-oauth2", strings.TrimSuffix(google, "}") + `,"upstream_params":{"login_hint":"a"},"icon_url":"retained"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := configSpec(t, tc.strategy, tc.options)
			c, err := ParseConfig(s)
			if (err != nil) != tc.bad {
				t.Fatalf("error=%v bad=%v", err, tc.bad)
			}
			if !tc.bad {
				if c.ClientID != "client" {
					t.Fatal("missing client")
				}
				if strings.Contains(fmt.Sprintf("%+v", c), "do-not-log") {
					t.Fatal("plaintext secret retained")
				}
			}
		})
	}
	t.Run("critical nested aliases every value", func(t *testing.T) {
		for _, m := range []string{"upstream_params", "authParams", "authParamsMap"} {
			for _, key := range []string{"acr_values", "max_age", "claims", "prompt", "state", "hd", "Authorization"} {
				for _, v := range []string{`null`, `""`, `false`, `"login"`} {
					for _, body := range []string{fmt.Sprintf(`{%q:%s}`, key, v), fmt.Sprintf(`{"nested":{"alias":%q}}`, key)} {
						s := configSpec(t, "google-oauth2", strings.TrimSuffix(google, "}")+fmt.Sprintf(`,%q:%s}`, m, body))
						if _, err := ParseConfig(s); err == nil {
							t.Fatalf("accepted %s %s", m, body)
						}
					}
				}
			}
		}
	})
	t.Run("sealed secret and immutable binding", func(t *testing.T) {
		s := configSpec(t, "google-oauth2", `{"client_id":"client"}`)
		s.FederationSecretsSealed = []byte("sealed")
		c, err := ParseConfig(s)
		if err != nil {
			t.Fatal(err)
		}
		s.FederationSecretsSealed[0] = 'X'
		if string(c.SecretReference) != "sealed" {
			t.Fatal("secret reference aliases input")
		}
		n := c
		n.ClientID = "other"
		if ValidateConfigUpdate(c, n) == nil {
			t.Fatal("changed client binding accepted")
		}
		n = c
		n.Scopes = []string{"openid"}
		if err := ValidateConfigUpdate(c, n); err != nil {
			t.Fatal(err)
		}
		s.Options.Extra["client_secret"] = ""
		if _, err := ParseConfig(s); err == nil {
			t.Fatal("empty replacement accepted over sealed secret")
		}
	})
	t.Run("social defaults and replacement", func(t *testing.T) {
		s := configSpec(t, "google-oauth2", google)
		connrules.CreateDefaults(&s)
		if errs := connrules.NormalizeAPI(&s); len(errs) > 0 {
			t.Fatal(errs)
		}
		if s.Options.PasswordOptions != nil || s.Options.BruteForceProtection != nil || s.Options.Extra["mfa"] != nil {
			t.Fatal("database defaults applied to social")
		}
		c, err := ParseConfig(s)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(c.Scopes, " ") != "openid profile email" {
			t.Fatal(c.Scopes)
		}
		s.Authentication = map[string]any{"active": false}
		c, err = ParseConfig(s)
		if err != nil || c.AuthenticationActive {
			t.Fatal("authentication purpose ignored")
		}
		s.Authentication = map[string]any{"enabled": true}
		if _, err := ParseConfig(s); err == nil {
			t.Fatal("enabled alias accepted")
		}
	})
}
