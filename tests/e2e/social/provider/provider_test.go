package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMicrosoftFixtureCanonicalMetadataAndCodeExchange(t *testing.T) {
	p, err := New("https://idp.e2e.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{"consumers", "organizations", "11111111-1111-4111-8111-111111111111"} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest("GET", "/"+authority+"/v2.0/.well-known/openid-configuration", nil))
		if w.Code != 200 {
			t.Fatalf("Microsoft discovery %s: %d", authority, w.Code)
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		issuer := "https://login.microsoftonline.com/{tenantid}/v2.0"
		if authority[0] == '1' {
			issuer = "https://login.microsoftonline.com/" + authority + "/v2.0"
		}
		if m["issuer"] != issuer || m["token_endpoint"] != "https://login.microsoftonline.com/"+authority+"/oauth2/v2.0/token" {
			t.Fatal("noncanonical metadata")
		}
	}
	for _, persona := range []string{"work", "school", "outlook", "hotmail", "noemail"} {
		authority := "organizations"
		if persona == "outlook" || persona == "hotmail" {
			authority = "consumers"
		}
		sum := sha256.Sum256([]byte("fixture-verifier"))
		form := url.Values{"redirect_uri": {"https://sdk.e2e.test/login/callback"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "subject": {persona}, "decision": {"allow"}}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/"+authority+"/oauth2/v2.0/authorize", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		p.ServeHTTP(w, r)
		cb, _ := url.Parse(w.Header().Get("Location"))
		if cb == nil || cb.Query().Get("code") == "" {
			t.Fatalf("no code: %d", w.Code)
		}
		form = url.Values{"grant_type": {"authorization_code"}, "client_id": {"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}, "client_secret": {ClientSecret}, "code": {cb.Query().Get("code")}, "code_verifier": {"fixture-verifier"}, "redirect_uri": {"https://sdk.e2e.test/login/callback"}}
		w = httptest.NewRecorder()
		r = httptest.NewRequest("POST", "/"+authority+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		p.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s exchange: %d", persona, w.Code)
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		raw, _ := out["id_token"].(string)
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Fatal("no signed ID token")
		}
		b, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(b, &claims)
		if claims["ver"] != "2.0" || claims["nonce"] != "nonce" || claims["aud"] != "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" {
			t.Fatal("missing Microsoft bindings")
		}
		if persona == "noemail" && claims["email"] != nil {
			t.Fatal("invented email")
		}
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/common/discovery/v2.0/keys", nil))
	var keys struct{ Keys []map[string]any }
	_ = json.Unmarshal(w.Body.Bytes(), &keys)
	if len(keys.Keys) != 2 || keys.Keys[0]["issuer"] == nil {
		t.Fatal("Microsoft keys require issuer metadata")
	}
}
