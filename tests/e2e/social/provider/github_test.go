package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const ghCallback = "https://sdk.e2e.test/login/callback"

// gitHubLogin runs the fixture's authorize form and token exchange and
// returns the token endpoint's parsed JSON body.
func gitHubLogin(t *testing.T, p *Provider, subject, scope, verifier string) map[string]string {
	t.Helper()
	sum := sha256.Sum256([]byte("verifier"))
	f := url.Values{"state": {"st"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "redirect_uri": {ghCallback}, "scope": {scope}, "subject": {subject}, "decision": {"allow"}}
	req := httptest.NewRequest(http.MethodPost, "https://idp.e2e.test/github/login/oauth/authorize", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize %d %s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Host != "sdk.e2e.test" || loc.Query().Get("state") != "st" || loc.Query().Get("code") == "" {
		t.Fatalf("callback %s", loc)
	}
	tf := url.Values{"client_id": {ClientID}, "client_secret": {ClientSecret}, "code": {loc.Query().Get("code")}, "redirect_uri": {ghCallback}, "code_verifier": {verifier}, "grant_type": {"authorization_code"}}
	req = httptest.NewRequest(http.MethodPost, "https://idp.e2e.test/github/login/oauth/access_token", strings.NewReader(tf.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status %d (GitHub reports errors with 200)", rec.Code)
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func gitHubGet(p *Provider, path, token string, headers bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://idp.e2e.test/github/api/"+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if headers {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", GitHubAPIVersion)
		req.Header.Set("User-Agent", "zeroauthy")
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

func TestGitHubFixtureLoginAndModes(t *testing.T) {
	p, err := New("https://idp.e2e.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []GitHubAccount{{ID: "042", Login: "a", Email: "a@x.test", Mode: "verified"}, {ID: "1", Login: "a", Email: "a@x.test", Mode: "odd"}, {ID: "9223372036854775808", Login: "a", Email: "a@x.test", Mode: "verified"}} {
		if p.RegisterGitHub(bad) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	const big = "9007199254740993"
	for _, mode := range []string{"verified", "unverified", "no-scope-403", "rate-limited", "rename"} {
		t.Run(mode, func(t *testing.T) {
			if err := p.RegisterGitHub(GitHubAccount{ID: big, Login: "octo", Email: "octo@github.e2e.test", Mode: mode}); err != nil {
				t.Fatal(err)
			}
			tok := gitHubLogin(t, p, big, "user:email read:user", "verifier")
			if tok["token_type"] != "bearer" || tok["scope"] != "user:email,read:user" || tok["access_token"] == "" || tok["refresh_token"] != "" {
				t.Fatalf("token %v", tok)
			}
			rec := gitHubGet(p, "user", tok["access_token"], true)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"id":`+big+`,`) {
				t.Fatalf("user %d %s", rec.Code, rec.Body)
			}
			if strings.Contains(rec.Body.String(), `"octo-renamed"`) != (mode == "rename") {
				t.Fatalf("rename %s", rec.Body)
			}
			rec = gitHubGet(p, "user/emails?per_page=100", tok["access_token"], true)
			want := map[string]int{"no-scope-403": 403, "rate-limited": 403}[mode]
			if want == 0 {
				want = 200
			}
			if rec.Code != want || (rec.Header().Get("x-ratelimit-remaining") == "0") != (mode == "rate-limited") {
				t.Fatalf("emails %d %v", rec.Code, rec.Header())
			}
			if want == 200 && strings.Contains(rec.Body.String(), `"primary":true,"verified":true`) == (mode == "unverified") {
				t.Fatalf("emails body %s", rec.Body)
			}
		})
	}
	// REST headers, bearer token, page size and scope are enforced.
	tok := gitHubLogin(t, p, big, "read:user", "verifier")
	if rec := gitHubGet(p, "user", tok["access_token"], false); rec.Code != 400 {
		t.Fatalf("headerless %d", rec.Code)
	}
	if rec := gitHubGet(p, "user", "wrong", true); rec.Code != 401 {
		t.Fatalf("bad token %d", rec.Code)
	}
	if rec := gitHubGet(p, "user/emails", tok["access_token"], true); rec.Code != 400 {
		t.Fatalf("no per_page %d", rec.Code)
	}
	if rec := gitHubGet(p, "user/emails?per_page=100", tok["access_token"], true); rec.Code != 404 {
		t.Fatalf("emails without user:email %d", rec.Code)
	}
	// A wrong PKCE verifier is an HTTP 200 error body, as on GitHub.
	if out := gitHubLogin(t, p, big, "user:email", "other-verifier"); out["error"] != "bad_verification_code" || out["access_token"] != "" {
		t.Fatalf("wrong verifier %v", out)
	}
}

func TestGitHubFixtureAuthorizeRequest(t *testing.T) {
	p, _ := New("https://idp.e2e.test")
	good := url.Values{"client_id": {ClientID}, "redirect_uri": {ghCallback}, "state": {"s"}, "code_challenge": {"c"}, "code_challenge_method": {"S256"}, "scope": {"user:email"}, "response_type": {"code"}}
	for name, mutate := range map[string]func(url.Values){
		"ok":        func(url.Values) {},
		"client":    func(q url.Values) { q.Set("client_id", "other") },
		"nonce":     func(q url.Values) { q.Set("nonce", "n") },
		"login":     func(q url.Values) { q.Set("login", "octo") },
		"plain":     func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"http":      func(q url.Values) { q.Set("redirect_uri", "http://sdk.e2e.test/login/callback") },
		"foreign":   func(q url.Values) { q.Set("redirect_uri", "https://example.com/login/callback") },
		"nostate":   func(q url.Values) { q.Del("state") },
		"challenge": func(q url.Values) { q.Del("code_challenge") },
	} {
		q := url.Values{}
		for k, v := range good {
			q[k] = append([]string(nil), v...)
		}
		mutate(q)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://idp.e2e.test/github/login/oauth/authorize?"+q.Encode(), nil))
		want := http.StatusBadRequest
		if name == "ok" {
			want = http.StatusOK
		}
		if rec.Code != want || (want == 200 && !strings.Contains(rec.Body.String(), "<title>Mock GitHub sign-in</title>")) {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}
