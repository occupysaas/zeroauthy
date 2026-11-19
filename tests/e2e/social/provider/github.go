package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// GitHubAPIVersion is the X-GitHub-Api-Version the fixture API requires,
// equal to the adapter's pinned version (inventory
// provider_protocol.github.api_version).
const GitHubAPIVersion = "2026-03-10"

// GitHub fixture account modes, selected by the test per account:
//   - verified: /user/emails lists a verified primary address;
//   - unverified: the primary address is not verified;
//   - no-scope-403: /user/emails answers 403 without rate-limit signals
//     (what GitHub returns when the token cannot read addresses);
//   - rate-limited: /user/emails answers 403 with x-ratelimit-remaining: 0;
//   - rename: as verified, but /user reports the login renamed.
var gitHubModes = []string{"verified", "unverified", "no-scope-403", "rate-limited", "rename"}

// GitHubAccount is one fixture GitHub user. ID is decimal text so that IDs
// above 2⁵³ survive the JSON control endpoint and are served exactly.
type GitHubAccount struct {
	ID, Login, Email, Mode string
}

type gitHubCode struct{ sub, challenge, redirect, scope string }
type gitHubToken struct{ sub, scope string }

// RegisterGitHub adds or replaces a fixture account. Re-registering with a
// new Mode is how a test changes what GitHub reports on the next login.
func (p *Provider) RegisterGitHub(a GitHubAccount) error {
	n, err := strconv.ParseInt(a.ID, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != a.ID || a.Login == "" || a.Email == "" || !slices.Contains(gitHubModes, a.Mode) {
		return errors.New("invalid GitHub fixture account")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.githubAccounts == nil {
		p.githubAccounts = map[string]GitHubAccount{}
		p.githubCodes = map[string]gitHubCode{}
		p.githubTokens = map[string]gitHubToken{}
	}
	p.githubAccounts[a.ID] = a
	return nil
}

func (p *Provider) serveGitHub(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, "/github/") {
	case "login/oauth/authorize":
		switch r.Method {
		case http.MethodGet:
			p.gitHubAuthorizePage(w, r)
		case http.MethodPost:
			p.gitHubAuthorizeSubmit(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "login/oauth/access_token":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		p.gitHubToken(w, r)
	case "api/user":
		p.gitHubUser(w, r)
	case "api/user/emails":
		p.gitHubEmails(w, r)
	default:
		http.NotFound(w, r)
	}
}

// gitHubCallback accepts any HTTPS fixture-host callback: the code stays
// bound to the exact redirect_uri, as on GitHub.
func gitHubCallback(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.HasSuffix(u.Hostname(), ".e2e.test") || u.Path != "/login/callback" || u.RawQuery != "" {
		return nil, false
	}
	return u, true
}

func (p *Provider) gitHubAuthorizePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	_, cbOK := gitHubCallback(q.Get("redirect_uri"))
	// GitHub has no nonce or ID token; the adapter never sends login.
	if q.Get("client_id") != ClientID || !cbOK || q.Get("state") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" ||
		q.Has("nonce") || q.Has("login") {
		http.Error(w, "invalid GitHub authorization request", http.StatusBadRequest)
		return
	}
	hidden := map[string]string{}
	for _, k := range []string{"state", "code_challenge", "redirect_uri", "scope"} {
		hidden[k] = q.Get(k)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = form.Execute(w, map[string]any{"Flavor": "GitHub", "Action": p.Base + "/github/login/oauth/authorize", "Hidden": hidden})
}

func (p *Provider) gitHubAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	cb, ok := gitHubCallback(f.Get("redirect_uri"))
	if !ok {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := url.Values{"state": {f.Get("state")}}
	if f.Get("decision") != "allow" {
		q.Set("error", "access_denied")
		q.Set("error_description", "The user has denied your application access.")
	} else {
		p.mu.Lock()
		_, known := p.githubAccounts[f.Get("subject")]
		if known {
			c := random()
			p.githubCodes[c] = gitHubCode{sub: f.Get("subject"), challenge: f.Get("code_challenge"), redirect: cb.String(), scope: f.Get("scope")}
			q.Set("code", c)
		}
		p.mu.Unlock()
		if !known {
			http.Error(w, "unknown GitHub fixture account", http.StatusBadRequest)
			return
		}
	}
	cb.RawQuery = q.Encode()
	http.Redirect(w, r, cb.String(), http.StatusFound)
}

// gitHubToken is GitHub's token endpoint: errors are HTTP 200 with an error
// member, and the body is form-encoded unless JSON is accepted.
func (p *Provider) gitHubToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f := r.PostForm
	p.mu.Lock()
	p.Exchanges["github"]++
	c, ok := p.githubCodes[f.Get("code")]
	delete(p.githubCodes, f.Get("code"))
	p.mu.Unlock()
	_, _, basic := r.BasicAuth()
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	out := url.Values{}
	if !ok || basic || f.Get("client_id") != ClientID || f.Get("client_secret") != ClientSecret || f.Get("redirect_uri") != c.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
		out.Set("error", "bad_verification_code")
		out.Set("error_description", "The code passed is incorrect or expired.")
	} else {
		access := "gho_" + random()
		p.mu.Lock()
		p.githubTokens[access] = gitHubToken{sub: c.sub, scope: c.scope}
		p.mu.Unlock()
		// A non-expiring OAuth app token: no refresh_token, no expires_in.
		out.Set("access_token", access)
		out.Set("token_type", "bearer")
		out.Set("scope", strings.Join(strings.Fields(c.scope), ","))
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		m := map[string]string{}
		for k := range out {
			m[k] = out.Get(k)
		}
		writeJSON(w, m)
		return
	}
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	_, _ = w.Write([]byte(out.Encode()))
}

// gitHubAPI checks the REST headers and bearer token and returns the account
// and the token's granted scopes.
func (p *Provider) gitHubAPI(w http.ResponseWriter, r *http.Request) (GitHubAccount, []string, bool) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return GitHubAccount{}, nil, false
	}
	if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != GitHubAPIVersion || r.Header.Get("User-Agent") != "zeroauthy" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"message": "fixture: GitHub REST headers missing or wrong"})
		return GitHubAccount{}, nil, false
	}
	access, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	t, ok := p.githubTokens[access]
	a := p.githubAccounts[t.sub]
	p.mu.Unlock()
	if !bearer || !ok {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"message": "Bad credentials"})
		return GitHubAccount{}, nil, false
	}
	return a, strings.Fields(t.scope), true
}

func (p *Provider) gitHubUser(w http.ResponseWriter, r *http.Request) {
	a, _, ok := p.gitHubAPI(w, r)
	if !ok {
		return
	}
	login := a.Login
	if a.Mode == "rename" {
		login += "-renamed"
	}
	// json.Number keeps an ID above 2⁵³ exact on the wire.
	writeJSON(w, map[string]any{"id": json.Number(a.ID), "login": login, "avatar_url": "https://avatars.e2e.test/u/" + a.ID,
		"html_url": "https://github.com/" + login, "public_repos": 3, "followers": 1, "created_at": "2020-01-02T03:04:05Z"})
}

func (p *Provider) gitHubEmails(w http.ResponseWriter, r *http.Request) {
	a, scopes, ok := p.gitHubAPI(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "per_page=100" {
		http.Error(w, "fixture: expected one page of 100", http.StatusBadRequest)
		return
	}
	if !slices.Contains(scopes, "user:email") {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]string{"message": "Not Found"})
		return
	}
	switch a.Mode {
	case "no-scope-403":
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]string{"message": "Resource not accessible by integration"})
		return
	case "rate-limited":
		w.Header().Set("x-ratelimit-remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]string{"message": "API rate limit exceeded"})
		return
	}
	writeJSON(w, []map[string]any{
		{"email": "secondary-" + a.ID + "@github.e2e.test", "primary": false, "verified": true, "visibility": nil},
		{"email": a.Email, "primary": true, "verified": a.Mode != "unverified", "visibility": "private"},
	})
}
