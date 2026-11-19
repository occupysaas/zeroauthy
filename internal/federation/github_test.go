package federation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const (
	ghTestToken  = "gho_throwaway-access-token"
	ghTestSecret = "throwaway-client-secret"
	ghTestUser   = `{"id":583231,"login":"octocat","name":"The Octocat","email":"public@example.com",` +
		`"avatar_url":"https://avatars.example/u/583231","html_url":"https://github.com/octocat","blog":"https://blog.example",` +
		`"company":"@github","location":"San Francisco","bio":null,"public_repos":8,"followers":20,"following":0,` +
		`"created_at":"2011-01-25T18:44:36Z","updated_at":"2026-01-01T00:00:00Z","site_admin":false,"type":"User"}`
	ghTestEmails = `[{"email":"secondary@example.com","primary":false,"verified":true},` +
		`{"email":"octo@example.com","primary":true,"verified":true,"visibility":"private"}]`
)

// ghFixture is a local GitHub over TLS: OAuth endpoints and the REST API.
type ghFixture struct {
	t          *testing.T
	srv        *httptest.Server
	mu         sync.Mutex
	token      func(w http.ResponseWriter, r *http.Request)
	user       func(w http.ResponseWriter, r *http.Request)
	emails     func(w http.ResponseWriter, r *http.Request)
	forms      []url.Values
	tokenHdrs  []http.Header
	apiHdrs    []http.Header
	userCalls  int
	emailCalls int
	emailQuery string
	other      []string
}

func jsonHandler(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func newGHFixture(t *testing.T) *ghFixture {
	t.Helper()
	f := &ghFixture{t: t,
		token:  jsonHandler(200, `{"access_token":"`+ghTestToken+`","token_type":"bearer","scope":"user:email"}`),
		user:   jsonHandler(200, ghTestUser),
		emails: jsonHandler(200, ghTestEmails),
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *ghFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	var h func(http.ResponseWriter, *http.Request)
	switch r.URL.Path {
	case "/login/oauth/access_token":
		_ = r.ParseForm()
		f.forms = append(f.forms, r.PostForm)
		f.tokenHdrs = append(f.tokenHdrs, r.Header.Clone())
		h = f.token
	case "/api/user":
		f.userCalls++
		f.apiHdrs = append(f.apiHdrs, r.Header.Clone())
		h = f.user
	case "/api/user/emails":
		f.emailCalls++
		f.emailQuery = r.URL.RawQuery
		f.apiHdrs = append(f.apiHdrs, r.Header.Clone())
		h = f.emails
	default:
		f.other = append(f.other, r.URL.Path)
		h = jsonHandler(404, `{}`)
	}
	f.mu.Unlock()
	h(w, r)
}

func (f *ghFixture) override() GitHubOverride {
	return GitHubOverride{APIBase: f.srv.URL + "/api", Endpoints: Endpoints{
		AuthorizationURL: f.srv.URL + "/login/oauth/authorize", TokenURL: f.srv.URL + "/login/oauth/access_token", TokenAuthMethod: authPost}}
}

func (f *ghFixture) policy() NetworkPolicy {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	return FixturePolicy(pool)
}

func (f *ghFixture) providers() *Providers {
	return NewProviders(f.policy(), func() time.Time { return fixedTime }).WithGitHubFixture(f.override())
}

func ghConfig(t *testing.T, extra string) Config {
	t.Helper()
	opts := `{"client_id":"Iv1.throwaway","client_secret":"` + ghTestSecret + `"` + extra + `}`
	cfg, err := ParseConfig(configSpec(t, StrategyGitHub, opts))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func (f *ghFixture) exchange(t *testing.T, ps *Providers, cfg Config) (ProviderResult, error) {
	t.Helper()
	return ps.For(cfg).Exchange(context.Background(), ExchangeInput{Config: cfg, Endpoints: f.override().Endpoints,
		CallbackURL: "https://login.example/login/callback", Code: "code-1", CodeVerifier: "verifier-1",
		Nonce: "unused-nonce", ClientSecret: ghTestSecret, Now: fixedTime})
}

// noSecretsIn fails when an error text carries the token or a response body.
func noSecretsIn(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range []string{ghTestToken, ghTestSecret, "octocat", "octo@example.com", "bad_verification_code", "message"} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error %q leaks %q", err, s)
		}
	}
}

func TestGitHubAuthorizationURL(t *testing.T) {
	f := newGHFixture(t)
	ps := f.providers()
	cfg := ghConfig(t, `,"read_user":true`)
	raw, err := ps.For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: f.override().Endpoints,
		CallbackURL: "https://login.example/login/callback", State: "st", Nonce: "n", CodeChallenge: "ch", LoginHint: "someone@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if !strings.HasPrefix(raw, f.srv.URL+"/login/oauth/authorize?") || q.Get("client_id") != "Iv1.throwaway" ||
		q.Get("redirect_uri") != "https://login.example/login/callback" || q.Get("scope") != "user:email read:user" ||
		q.Get("state") != "st" || q.Get("code_challenge") != "ch" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize %s", raw)
	}
	for _, k := range []string{"nonce", "prompt", "login", "login_hint", "allow_signup"} {
		if q.Has(k) {
			t.Errorf("authorize sends %s: %s", k, raw)
		}
	}
	// Production endpoints are GitHub's fixed hosts.
	prod := NewProviders(NetworkPolicy{}, nil)
	raw, err = prod.For(cfg).AuthorizationURL(StartInput{Config: cfg, CallbackURL: "https://login.example/login/callback", State: "st", CodeChallenge: "ch"})
	if err != nil || !strings.HasPrefix(raw, rules.GitHubAuthorizationURL+"?") {
		t.Fatalf("production authorize %s %v", raw, err)
	}
	e := GitHubEndpoints()
	if e.AuthorizationURL != rules.GitHubAuthorizationURL || e.TokenURL != rules.GitHubTokenURL || e.UserInfoURL != rules.GitHubAPIBase+"/user" || e.TokenAuthMethod != authPost {
		t.Fatalf("endpoints %+v", e)
	}
	// An empty effective scope is sent as an empty scope.
	cfg = ghConfig(t, `,"email":false`)
	raw, _ = ps.For(cfg).AuthorizationURL(StartInput{Config: cfg, CallbackURL: "https://login.example/login/callback", State: "st", CodeChallenge: "ch"})
	if u, _ := url.Parse(raw); u.Query().Get("scope") != "" {
		t.Fatalf("scope for email:false %s", raw)
	}
}

func TestGitHubTokenExchange(t *testing.T) {
	cases := []struct {
		name string
		h    func(http.ResponseWriter, *http.Request)
		ok   bool
	}{
		{"success", jsonHandler(200, `{"access_token":"`+ghTestToken+`","token_type":"bearer","scope":"user:email,repo","expires_in":28800,"refresh_token":"ghr_throwaway"}`), true},
		{"Bearer", jsonHandler(200, `{"access_token":"`+ghTestToken+`","token_type":"Bearer"}`), true},
		{"error with 200", jsonHandler(200, `{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}`), false},
		{"error with 400", jsonHandler(400, `{"error":"bad_verification_code"}`), false},
		{"form encoded", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = w.Write([]byte("access_token=" + ghTestToken + "&token_type=bearer"))
		}, false},
		{"missing access_token", jsonHandler(200, `{"token_type":"bearer"}`), false},
		{"empty access_token", jsonHandler(200, `{"access_token":"","token_type":"bearer"}`), false},
		{"mac", jsonHandler(200, `{"access_token":"`+ghTestToken+`","token_type":"mac"}`), false},
		{"missing token_type", jsonHandler(200, `{"access_token":"`+ghTestToken+`"}`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGHFixture(t)
			f.token = tc.h
			res, err := f.exchange(t, f.providers(), ghConfig(t, ""))
			noSecretsIn(t, err)
			if !tc.ok {
				if !errors.Is(err, ErrProviderResponse) {
					t.Fatalf("want ErrProviderResponse, got %v", err)
				}
				if f.userCalls != 0 || f.emailCalls != 0 {
					t.Fatal("profile fetched after a failed exchange")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			form := f.forms[0]
			if form.Get("client_secret") != ghTestSecret || form.Get("client_id") != "Iv1.throwaway" || form.Get("code_verifier") != "verifier-1" ||
				form.Get("redirect_uri") != "https://login.example/login/callback" || form.Get("code") != "code-1" {
				t.Fatalf("token form %v", form)
			}
			if f.tokenHdrs[0].Get("Accept") != "application/json" || f.tokenHdrs[0].Get("Authorization") != "" {
				t.Fatalf("token headers %v", f.tokenHdrs[0])
			}
			if res.Tokens.AccessToken != ghTestToken {
				t.Fatal("access token")
			}
			if tc.name == "success" && (res.Tokens.Scope != "user:email,repo" || res.Tokens.RefreshToken != "ghr_throwaway" || !res.Tokens.ExpiresAt.Equal(fixedTime.Add(8*time.Hour))) {
				t.Fatalf("tokens %+v", res.Tokens)
			}
		})
	}
	// One attempt only: a failed token request is never retried.
	f := newGHFixture(t)
	f.token = jsonHandler(502, `{}`)
	if _, err := f.exchange(t, f.providers(), ghConfig(t, "")); !errors.Is(err, ErrProviderResponse) || len(f.forms) != 1 {
		t.Fatalf("retry or wrong error: %d %v", len(f.forms), err)
	}
}

func TestGitHubProfile(t *testing.T) {
	f := newGHFixture(t)
	res, err := f.exchange(t, f.providers(), ghConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	p := res.Profile
	if p.Subject != "583231" || p.Nickname == nil || *p.Nickname != "octocat" || p.Name == nil || *p.Name != "The Octocat" ||
		p.Picture == nil || *p.Picture != "https://avatars.example/u/583231" {
		t.Fatalf("profile %+v", p)
	}
	want := map[string]any{"login": "octocat", "html_url": "https://github.com/octocat", "blog": "https://blog.example",
		"company": "@github", "location": "San Francisco", "public_repos": float64(8), "followers": float64(20), "following": float64(0),
		"created_at": "2011-01-25T18:44:36Z", "updated_at": "2026-01-01T00:00:00Z"}
	if fmt.Sprint(p.ProviderData) != fmt.Sprint(want) {
		t.Fatalf("provider data %v", p.ProviderData)
	}
	inv := githubInventoryProfile(t)
	for k := range p.ProviderData {
		if !slices.Contains(inv, k) {
			t.Errorf("provider data key %s not in inventory", k)
		}
	}
	if f.userCalls != 1 || len(f.apiHdrs) != 2 {
		t.Fatalf("calls user=%d api=%d", f.userCalls, len(f.apiHdrs))
	}
	for _, h := range f.apiHdrs {
		if h.Get("Accept") != "application/vnd.github+json" || h.Get("X-GitHub-Api-Version") != githubAPIVersion ||
			h.Get("User-Agent") != "zeroauthy" || h.Get("Authorization") != "Bearer "+ghTestToken {
			t.Fatalf("api headers %v", h)
		}
	}
	if githubAPIVersion != githubInventory(t).APIVersion {
		t.Fatalf("api version %s differs from the inventory", githubAPIVersion)
	}

	// name falls back to login; non-https avatars are dropped.
	for _, user := range []string{
		`{"id":1,"login":"someone","name":"","avatar_url":"http://avatars.example/u/1"}`,
		`{"id":1,"login":"someone","name":null,"avatar_url":"javascript:alert(1)"}`,
		`{"id":1,"login":"someone"}`,
	} {
		f := newGHFixture(t)
		f.user = jsonHandler(200, user)
		res, err := f.exchange(t, f.providers(), ghConfig(t, ""))
		if err != nil {
			t.Fatal(err)
		}
		p := res.Profile
		if p.Name == nil || *p.Name != "someone" || p.Nickname == nil || *p.Nickname != "someone" || p.Picture != nil {
			t.Fatalf("%s: profile %+v", user, p)
		}
		if len(p.ProviderData) != 1 || p.ProviderData["login"] != "someone" {
			t.Fatalf("%s: provider data %v", user, p.ProviderData)
		}
	}

	// /user failures fail the login.
	for _, h := range []func(http.ResponseWriter, *http.Request){
		jsonHandler(500, `{}`), jsonHandler(401, `{"message":"Bad credentials"}`), jsonHandler(200, `not json`),
		jsonHandler(200, `[]`), jsonHandler(200, `{"login":"octocat"}`),
	} {
		f := newGHFixture(t)
		f.user = h
		_, err := f.exchange(t, f.providers(), ghConfig(t, ""))
		noSecretsIn(t, err)
		if err == nil || !(errors.Is(err, ErrProviderResponse) || errors.Is(err, ErrProfile)) {
			t.Fatalf("user failure accepted: %v", err)
		}
		if f.emailCalls != 0 {
			t.Fatal("emails fetched after /user failed")
		}
	}

	// An oversized provider field is refused rather than stored.
	f = newGHFixture(t)
	f.user = jsonHandler(200, `{"id":1,"login":"someone","bio":"`+strings.Repeat("x", maxProfileBytes)+`"}`)
	if _, err := f.exchange(t, f.providers(), ghConfig(t, "")); !errors.Is(err, ErrProfile) {
		t.Fatalf("oversized provider data: %v", err)
	}
}

func TestGitHubProfileLargeID(t *testing.T) {
	f := newGHFixture(t)
	f.user = jsonHandler(200, `{"id":9007199254740993,"login":"big"}`)
	res, err := f.exchange(t, f.providers(), ghConfig(t, ""))
	if err != nil || res.Profile.Subject != "9007199254740993" {
		t.Fatalf("large id: %q %v", res.Profile.Subject, err)
	}
	f.user = jsonHandler(200, `{"id":9223372036854775807,"login":"max"}`)
	if res, err := f.exchange(t, f.providers(), ghConfig(t, "")); err != nil || res.Profile.Subject != "9223372036854775807" {
		t.Fatalf("max id: %q %v", res.Profile.Subject, err)
	}
	for _, id := range []string{`1.5`, `1e3`, `1E3`, `"42"`, `0`, `-1`, `9223372036854775808`, `null`, `true`, `42.0`} {
		f := newGHFixture(t)
		f.user = jsonHandler(200, `{"id":`+id+`,"login":"x"}`)
		if _, err := f.exchange(t, f.providers(), ghConfig(t, "")); !errors.Is(err, ErrProfile) {
			t.Errorf("id %s: %v", id, err)
		}
	}
}

func TestGitHubEmails(t *testing.T) {
	f := newGHFixture(t)
	res, err := f.exchange(t, f.providers(), ghConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.Profile.Email == nil || *res.Profile.Email != "octo@example.com" || res.Profile.EmailVerified == nil || !*res.Profile.EmailVerified {
		t.Fatalf("email %+v", res.Profile)
	}
	if f.emailCalls != 1 || f.emailQuery != "per_page=100" {
		t.Fatalf("emails calls=%d query=%q", f.emailCalls, f.emailQuery)
	}

	var full []string
	for i := range 100 {
		full = append(full, fmt.Sprintf(`{"email":"e%d@example.com","primary":false,"verified":true}`, i))
	}
	required := map[string]func(http.ResponseWriter, *http.Request){
		"unverified primary":  jsonHandler(200, `[{"email":"octo@example.com","primary":true,"verified":false},{"email":"b@example.com","primary":false,"verified":true}]`),
		"no primary":          jsonHandler(200, `[{"email":"b@example.com","primary":false,"verified":true}]`),
		"empty":               jsonHandler(200, `[]`),
		"100 without primary": jsonHandler(200, "["+strings.Join(full, ",")+"]"),
		"403 without signals": jsonHandler(403, `{"message":"Resource not accessible by integration"}`),
		"403 remaining 5": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "5")
			jsonHandler(403, `{}`)(w, r)
		},
		"404": jsonHandler(404, `{"message":"Not Found"}`),
	}
	for name, h := range required {
		t.Run(name, func(t *testing.T) {
			f := newGHFixture(t)
			f.emails = h
			_, err := f.exchange(t, f.providers(), ghConfig(t, ""))
			noSecretsIn(t, err)
			if !errors.Is(err, ErrEmailRequired) || errors.Is(err, ErrProviderResponse) {
				t.Fatalf("want ErrEmailRequired, got %v", err)
			}
		})
	}

	// email:false makes no /user/emails call, and the public /user email is
	// never used.
	f = newGHFixture(t)
	res, err = f.exchange(t, f.providers(), ghConfig(t, `,"email":false`))
	if err != nil || f.emailCalls != 0 || res.Profile.Email != nil || res.Profile.EmailVerified != nil {
		t.Fatalf("email:false calls=%d profile=%+v err=%v", f.emailCalls, res.Profile, err)
	}
	f = newGHFixture(t)
	f.emails = jsonHandler(200, `[]`)
	if _, err := f.exchange(t, f.providers(), ghConfig(t, "")); !errors.Is(err, ErrEmailRequired) {
		t.Fatalf("public /user email used: %v", err)
	}
}

func TestGitHubEmailsRateLimited(t *testing.T) {
	failures := map[string]func(http.ResponseWriter, *http.Request){
		"403 remaining 0": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			jsonHandler(403, `{"message":"API rate limit exceeded"}`)(w, r)
		},
		"403 retry-after": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "60")
			jsonHandler(403, `{"message":"You have exceeded a secondary rate limit"}`)(w, r)
		},
		"429": jsonHandler(429, `{}`),
		"429 remaining 0": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			jsonHandler(429, `{}`)(w, r)
		},
		"401":          jsonHandler(401, `{"message":"Bad credentials"}`),
		"500":          jsonHandler(500, `{}`),
		"503":          jsonHandler(503, `{}`),
		"invalid JSON": jsonHandler(200, `[{"email":`),
		"wrong shape":  jsonHandler(200, `{"email":"octo@example.com","primary":true,"verified":true}`),
		"timeout": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		},
	}
	for name, h := range failures {
		t.Run(name, func(t *testing.T) {
			f := newGHFixture(t)
			f.emails = h
			pol := f.policy()
			pol.RequestTimeout = 200 * time.Millisecond
			ps := NewProviders(pol, func() time.Time { return fixedTime }).WithGitHubFixture(f.override())
			_, err := f.exchange(t, ps, ghConfig(t, ""))
			noSecretsIn(t, err)
			if !errors.Is(err, ErrProviderResponse) || errors.Is(err, ErrEmailRequired) {
				t.Fatalf("want ErrProviderResponse, got %v", err)
			}
		})
	}
}

func TestGitHubUserTimeout(t *testing.T) {
	f := newGHFixture(t)
	f.user = func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}
	pol := f.policy()
	pol.RequestTimeout = 200 * time.Millisecond
	ps := NewProviders(pol, func() time.Time { return fixedTime }).WithGitHubFixture(f.override())
	res, err := f.exchange(t, ps, ghConfig(t, ""))
	noSecretsIn(t, err)
	if !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("want ErrProviderResponse, got %v", err)
	}
	if !reflect.DeepEqual(res, ProviderResult{}) {
		t.Fatalf("records returned after /user timeout: %+v", res)
	}
}

// githubInventory reads the inventory's GitHub protocol rows; runtime never
// reads the file.
type githubInventoryRows struct {
	APIVersion       string `json:"api_version"`
	RateLimitSignals []struct {
		Status, Header, Value string
	} `json:"rate_limit_signals"`
}

func githubInventory(t *testing.T) githubInventoryRows {
	t.Helper()
	b, err := os.ReadFile("inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Protocol map[string]githubInventoryRows `json:"provider_protocol"`
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	return inv.Protocol["github"]
}

func githubInventoryProfile(t *testing.T) []string {
	t.Helper()
	b, _ := os.ReadFile("inventory.json")
	var inv struct {
		Profile struct {
			ProviderData []string `json:"provider_data"`
		} `json:"github_profile"`
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	return inv.Profile.ProviderData
}

func TestGitHubRateLimitSignalsMatchInventory(t *testing.T) {
	rows := githubInventory(t).RateLimitSignals
	if len(rows) != len(githubRateLimitSignals) || len(rows) == 0 {
		t.Fatalf("inventory %d rows, constants %d", len(rows), len(githubRateLimitSignals))
	}
	for i, r := range rows {
		c := githubRateLimitSignals[i]
		if strconv.Itoa(c.Status) != r.Status || c.Header != r.Header || c.Value != r.Value {
			t.Errorf("row %d: inventory %+v, constant %+v", i, r, c)
		}
	}
	inv := githubInventoryProfile(t)
	if !slices.Equal(inv, githubProviderDataFields) {
		t.Fatalf("provider data fields %v, inventory %v", githubProviderDataFields, inv)
	}
}

func TestGitHubRedirectRefused(t *testing.T) {
	for _, target := range []string{"user", "emails"} {
		f := newGHFixture(t)
		redirect := func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, f.srv.URL+"/elsewhere", http.StatusFound)
		}
		if target == "user" {
			f.user = redirect
		} else {
			f.emails = redirect
		}
		_, err := f.exchange(t, f.providers(), ghConfig(t, ""))
		if !errors.Is(err, ErrProviderResponse) || len(f.other) != 0 {
			t.Fatalf("%s redirect followed or accepted: %v %v", target, f.other, err)
		}
	}
}

func TestGitHubOversizeBody(t *testing.T) {
	big := `{"id":1,"login":"x","bio":"` + strings.Repeat("x", 4096) + `"}`
	for _, target := range []string{"token", "user", "emails"} {
		f := newGHFixture(t)
		switch target {
		case "token":
			f.token = jsonHandler(200, `{"access_token":"`+ghTestToken+`","token_type":"bearer","pad":"`+strings.Repeat("x", 4096)+`"}`)
		case "user":
			f.user = jsonHandler(200, big)
		case "emails":
			f.emails = jsonHandler(200, `[{"email":"a@example.com","primary":true,"verified":true,"pad":"`+strings.Repeat("x", 4096)+`"}]`)
		}
		pol := f.policy()
		pol.MaxResponseBytes = 2048
		ps := NewProviders(pol, func() time.Time { return fixedTime }).WithGitHubFixture(f.override())
		if _, err := f.exchange(t, ps, ghConfig(t, "")); !errors.Is(err, ErrProviderResponse) {
			t.Fatalf("%s oversize accepted: %v", target, err)
		}
	}
}

// TestGitHubStrayOptionsIgnored: option keys a GitHub connection does not
// define never change the hosts the adapter calls.
func TestGitHubStrayOptionsIgnored(t *testing.T) {
	stray := `,"base_url":"https://evil.example","api_url":"https://evil.example/api","userinfo_url":"https://evil.example/user","api_base":"https://evil.example","emails_url":"https://evil.example/emails"`
	cfg := ghConfig(t, stray)
	prod := NewProviders(NetworkPolicy{}, nil)
	if got, base := prod.github(); got != GitHubEndpoints() || base != rules.GitHubAPIBase {
		t.Fatalf("production endpoints %+v %s", got, base)
	}
	raw, err := prod.For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: Endpoints{AuthorizationURL: "https://evil.example/authorize"},
		CallbackURL: "https://login.example/login/callback", State: "st", CodeChallenge: "ch"})
	if err != nil || !strings.HasPrefix(raw, rules.GitHubAuthorizationURL+"?") {
		t.Fatalf("authorize %s %v", raw, err)
	}
	f := newGHFixture(t)
	ps := f.providers()
	// Even an attempt snapshot naming other hosts does not redirect the calls.
	_, err = ps.For(cfg).Exchange(context.Background(), ExchangeInput{Config: cfg,
		Endpoints:   Endpoints{TokenURL: "https://evil.example/token", UserInfoURL: "https://evil.example/user", TokenAuthMethod: authBasic},
		CallbackURL: "https://login.example/login/callback", Code: "code-1", CodeVerifier: "verifier-1", ClientSecret: ghTestSecret, Now: fixedTime})
	if err != nil || len(f.forms) != 1 || f.userCalls != 1 || f.emailCalls != 1 {
		t.Fatalf("stray endpoints used: forms=%d user=%d emails=%d err=%v", len(f.forms), f.userCalls, f.emailCalls, err)
	}
	if f.forms[0].Get("client_secret") != ghTestSecret {
		t.Fatal("token auth method taken from the snapshot")
	}
}

func TestGitHubRefreshTokenCleared(t *testing.T) {
	e := newIdentityEnv(t, "")
	gh := &store.Connection{TenantID: "ten", ID: "con_gh", Name: "github", Strategy: StrategyGitHub}
	if err := e.st.Connections().Create(e.ctx, gh); err != nil {
		t.Fatal(err)
	}
	first := result("583231", nil)
	first.Tokens.RefreshToken = "r1"
	if _, err := e.login(gh, first); err != nil {
		t.Fatal(err)
	}
	if got := e.tokens(t, "con_gh", "583231"); got.RefreshToken != "r1" {
		t.Fatalf("first refresh %q", got.RefreshToken)
	}
	second := result("583231", nil)
	second.Tokens.AccessToken, second.Tokens.RefreshToken = "at-2", ""
	if _, err := e.login(gh, second); err != nil {
		t.Fatal(err)
	}
	if got := e.tokens(t, "con_gh", "583231"); got.RefreshToken != "" || got.AccessToken != "at-2" {
		t.Fatalf("github refresh kept: %+v", got.RefreshToken)
	}
	// Google keeps its previous refresh token (unchanged behavior).
	g1 := result("g-sub", nil)
	if _, err := e.login(e.conn, g1); err != nil {
		t.Fatal(err)
	}
	g2 := result("g-sub", nil)
	g2.Tokens.AccessToken, g2.Tokens.RefreshToken = "at-g2", ""
	if _, err := e.login(e.conn, g2); err != nil {
		t.Fatal(err)
	}
	if got := e.tokens(t, "con_g", "g-sub"); got.RefreshToken != "rt-1" || got.AccessToken != "at-g2" {
		t.Fatalf("google refresh %+v", got.RefreshToken)
	}
}

// ghFlowEnv drives FlowService Begin and Complete against a GitHub fixture.
type ghFlowEnv struct {
	ctx  context.Context
	st   *memory.Store
	svc  *FlowService
	conn *store.Connection
	n    int
}

func newGHFlowEnv(t *testing.T, f *ghFixture) *ghFlowEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	t.Cleanup(func() { st.Close() })
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten", Name: "ten"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Clients().Create(ctx, &store.Client{TenantID: "ten", ClientID: "client", IsFirstParty: true, GrantTypes: []string{"authorization_code"}}); err != nil {
		t.Fatal(err)
	}
	spec := connrules.Spec{Name: "github", Strategy: StrategyGitHub, EnabledClients: []string{"client"},
		Options: connrules.Options{Extra: map[string]any{"client_id": "Iv1.throwaway"}}}
	c := &store.Connection{TenantID: "ten", ID: "con_gh", FederationRevision: 1}
	connrules.Apply(&spec, c)
	c.FederationSecretsSealed, _ = SealCredentials(w, "ten", "con_gh", Credentials{ClientSecret: ghTestSecret})
	if err := st.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	svc := &FlowService{Service: Service{Wrapper: w, Now: func() time.Time { return fixedTime }}, Store: st, Providers: f.providers()}
	return &ghFlowEnv{ctx: ctx, st: st, svc: svc, conn: c}
}

func (e *ghFlowEnv) login(t *testing.T) (*Completion, error) {
	t.Helper()
	e.n++
	txn := &store.AuthTransaction{ID: fmt.Sprintf("txn-%d", e.n), TenantID: "ten", ClientID: "client", ExpiresAt: fixedTime.Add(time.Hour)}
	if err := e.st.AuthTransactions().Create(e.ctx, txn); err != nil {
		t.Fatal(err)
	}
	begun, err := e.svc.Begin(e.ctx, BeginInput{Tenant: &store.Tenant{ID: "ten"}, Origin: "https://login.example", Txn: txn,
		Client: &store.Client{TenantID: "ten", ClientID: "client", IsFirstParty: true}, Connection: e.conn})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(begun.URL)
	return e.svc.Complete(e.ctx, CompleteInput{Tenant: &store.Tenant{ID: "ten"}, Origin: "https://login.example",
		Params: CallbackParams{State: u.Query().Get("state"), Code: "code-1"}, CookieValue: begun.CookieValue})
}

// snapshot is the stored user, identity and token record as bytes.
func (e *ghFlowEnv) snapshot(t *testing.T) (string, string) {
	t.Helper()
	u, err := e.st.Users().Get(e.ctx, "ten", "github|583231")
	if errors.Is(err, store.ErrNotFound) {
		u = nil
	} else if err != nil {
		t.Fatal(err)
	}
	ub, _ := json.Marshal(u)
	tok, err := e.st.Federation().GetTokens(e.ctx, store.FederatedIdentityKey{TenantID: "ten", ConnectionID: "con_gh", Subject: "583231"})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return string(ub), string(tok)
}

func TestGitHubBeginCapability(t *testing.T) {
	f := newGHFixture(t)
	e := newGHFlowEnv(t, f)
	e.svc.Store = predecessorStore{e.st}
	txn := &store.AuthTransaction{ID: "txn", TenantID: "ten", ClientID: "client", ExpiresAt: fixedTime.Add(time.Hour)}
	if _, err := e.svc.Begin(e.ctx, BeginInput{Origin: "https://login.example", Txn: txn,
		Client: &store.Client{ClientID: "client", IsFirstParty: true}, Connection: e.conn}); !errors.Is(err, store.ErrFederationUnavailable) {
		t.Fatalf("begin on a store without github support: %v", err)
	}
	if ButtonLabel(&store.Connection{Name: "configured", Strategy: StrategyGitHub}) != "GitHub" {
		t.Fatal("button label")
	}
}

func TestGitHubEmailRequiredOnRepeatLogin(t *testing.T) {
	f := newGHFixture(t)
	e := newGHFlowEnv(t, f)
	done, err := e.login(t)
	if err != nil {
		t.Fatal(err)
	}
	if done.UserID != "github|583231" {
		t.Fatalf("user %s", done.UserID)
	}
	u, _ := e.st.Users().Get(e.ctx, "ten", "github|583231")
	if u.Email != "octo@example.com" || !u.EmailVerified || u.Identities[0].UserID != "583231" || u.Identities[0].Provider != "github" {
		t.Fatalf("stored %+v", u)
	}
	userBefore, tokBefore := e.snapshot(t)
	if tokBefore == "" {
		t.Fatal("no token record after first login")
	}

	// The user revoked user:email: /user/emails now answers 403.
	f.mu.Lock()
	f.emails = jsonHandler(403, `{"message":"Resource not accessible by integration"}`)
	f.user = jsonHandler(200, strings.Replace(ghTestUser, `"login":"octocat"`, `"login":"renamed"`, 1))
	f.mu.Unlock()
	if _, err := e.login(t); !errors.Is(err, ErrEmailRequired) {
		t.Fatalf("repeat login without verified email: %v", err)
	}
	userAfter, tokAfter := e.snapshot(t)
	if userAfter != userBefore || tokAfter != tokBefore {
		t.Fatalf("stored state changed\nbefore %s\nafter  %s", userBefore, userAfter)
	}
}

func TestGitHubNoRecordsAfterFailure(t *testing.T) {
	for name, set := range map[string]func(*ghFixture){
		"token error":    func(f *ghFixture) { f.token = jsonHandler(200, `{"error":"bad_verification_code"}`) },
		"user 500":       func(f *ghFixture) { f.user = jsonHandler(500, `{}`) },
		"email required": func(f *ghFixture) { f.emails = jsonHandler(200, `[]`) },
		"rate limited": func(f *ghFixture) {
			f.emails = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-RateLimit-Remaining", "0")
				jsonHandler(403, `{}`)(w, r)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGHFixture(t)
			set(f)
			e := newGHFlowEnv(t, f)
			if _, err := e.login(t); err == nil {
				t.Fatal("login succeeded")
			}
			if _, n, err := e.st.Users().List(e.ctx, "ten", nil, store.UserSort{}, store.Page{}); err != nil || n != 0 {
				t.Fatalf("%d users stored: %v", n, err)
			}
			if _, err := e.st.Users().FindByIdentity(e.ctx, "ten", "con_gh", "583231"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("identity stored: %v", err)
			}
			if _, tok := e.snapshot(t); tok != "" {
				t.Fatal("token record stored")
			}
		})
	}
}
