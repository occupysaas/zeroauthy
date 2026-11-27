package dcr

import (
	"slices"
	"strings"
	"testing"
)

func TestParseFieldTable(t *testing.T) {
	long := strings.Repeat("a", 256)
	many := `["https://a.example/cb"` + strings.Repeat(`,"https://a.example/cb"`, 20) + `]`
	cases := []struct {
		name, body, code string
	}{
		{"minimal", `{"redirect_uris":["https://app.example/cb"]}`, ""},
		{"unknown members ignored", `{"redirect_uris":["https://app.example/cb"],"client_uri":"https://x","contacts":["a@b"],"software_id":"x"}`, ""},
		{"not an object", `[1]`, "invalid_client_metadata"},
		{"not json", `{`, "invalid_client_metadata"},
		{"missing redirect_uris", `{"client_name":"x"}`, "invalid_redirect_uri"},
		{"empty redirect_uris", `{"redirect_uris":[]}`, "invalid_redirect_uri"},
		{"too many redirect_uris", `{"redirect_uris":` + many + `}`, "invalid_redirect_uri"},
		{"redirect_uris not a list", `{"redirect_uris":"https://app.example/cb"}`, "invalid_client_metadata"},
		{"client_name too long", `{"redirect_uris":["https://app.example/cb"],"client_name":"` + long + `"}`, "invalid_client_metadata"},
		{"client_name empty", `{"redirect_uris":["https://app.example/cb"],"client_name":""}`, "invalid_client_metadata"},
		{"client_name number", `{"redirect_uris":["https://app.example/cb"],"client_name":1}`, "invalid_client_metadata"},
		{"response type token", `{"redirect_uris":["https://app.example/cb"],"response_types":["token"]}`, "invalid_client_metadata"},
		{"response type code", `{"redirect_uris":["https://app.example/cb"],"response_types":["code"]}`, ""},
		{"basic auth", `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`, "invalid_client_metadata"},
		{"private_key_jwt", `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}`, "invalid_client_metadata"},
		{"grant_types not strings", `{"redirect_uris":["https://app.example/cb"],"grant_types":[1]}`, "invalid_client_metadata"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.body))
		got := ""
		if err != nil {
			got = err.Code
		}
		if got != c.code {
			t.Errorf("%s: code %q, want %q (%v)", c.name, got, c.code, err)
		}
	}
}

func TestParseDefaults(t *testing.T) {
	req, err := Parse([]byte(`{"redirect_uris":["https://app.example/cb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if req.Name != "My App" || req.AuthMethod != "client_secret_post" || !slices.Equal(req.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Fatalf("defaults: %+v", req)
	}
}

// Review Focus 1: a registration cannot escalate to other grants.
func TestRegisterFiltersGrants(t *testing.T) {
	for body, want := range map[string][]string{
		`["client_credentials","password","implicit","authorization_code"]`:                     {"authorization_code"},
		`["refresh_token","authorization_code","urn:ietf:params:oauth:grant-type:device_code"]`: {"authorization_code", "refresh_token"},
		`["client_credentials"]`:                      {"authorization_code"},
		`["password","implicit"]`:                     {"authorization_code"},
		`["authorization_code","authorization_code"]`: {"authorization_code"},
	} {
		req, err := Parse([]byte(`{"redirect_uris":["https://app.example/cb"],"grant_types":` + body + `}`))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if !slices.Equal(req.GrantTypes, want) {
			t.Errorf("%s: %v, want %v", body, req.GrantTypes, want)
		}
	}
}

func TestCheckRedirectURI(t *testing.T) {
	ok := []string{"https://app.example/cb", "https://app.example:8443/cb?x=1", "http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:8080/cb", "com.example.app:/callback", "myapp://callback"}
	bad := []string{"http://app.example/cb", "https://*.example.com/cb", "https://app.example/cb#frag", "/cb", "cb", "javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "vbscript:x", "https://user:pw@app.example/cb", "https:///cb", "", strings.Repeat("https://a.example/", 200)}
	for _, u := range ok {
		if err := CheckRedirectURI(u); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := CheckRedirectURI(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

func TestCallbackOrigins(t *testing.T) {
	got := CallbackOrigins([]string{"https://app.example/cb", "https://app.example/other", "http://localhost:3000/cb", "com.example.app:/cb", "https://b.example:8443/x"})
	want := []string{"https://app.example", "http://localhost:3000", "https://b.example:8443"}
	if !slices.Equal(got, want) {
		t.Fatalf("origins %v, want %v", got, want)
	}
}
