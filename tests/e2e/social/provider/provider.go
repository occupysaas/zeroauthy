// Package provider is the Plan 24 mock upstream: a Google-shaped provider, a
// back-channel OpenID provider and a plain OAuth 2 provider with a profile
// API. Each has a real sign-in form, single-use codes, exact redirect_uri
// and S256 PKCE checks, one client authentication method, and RS256 ID tokens
// with the request's nonce. Nothing here can mint a zeroauthy session: the
// only way back is the browser callback with a code.
package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Client credentials every mock provider accepts.
const (
	ClientID     = "m24-upstream-client"
	ClientSecret = "m24-upstream-secret-not-for-production"
)

type code struct {
	flavor, sub, nonce, challenge, redirect string
}

// Provider serves all three flavors under /google, /oidc and /oauth2 on the
// host it is mounted at.
type Provider struct {
	Base string // e.g. https://idp.e2e.test
	key  *rsa.PrivateKey
	mu   sync.Mutex
	// codes are single use; tokens map access tokens to subjects.
	codes  map[string]code
	tokens map[string]string
	// Exchanges counts token requests per flavor, for the control endpoint.
	Exchanges map[string]int
}

// New returns a provider for base.
func New(base string) (*Provider, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Provider{Base: strings.TrimSuffix(base, "/"), key: k, codes: map[string]code{}, tokens: map[string]string{}, Exchanges: map[string]int{}}, nil
}

func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

var form = template.Must(template.New("f").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Mock {{.Flavor}} sign-in</title></head>
<body><h1>Mock {{.Flavor}} sign-in</h1>
<form method="post" action="{{.Action}}">
{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<label for="subject">Account</label> <input id="subject" name="subject" required>
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form></body></html>`))

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	flavor, rest := parts[0], parts[1]
	if flavor != "google" && flavor != "oidc" && flavor != "oauth2" {
		http.NotFound(w, r)
		return
	}
	switch {
	case rest == ".well-known/openid-configuration" && flavor == "oidc":
		writeJSON(w, map[string]any{"issuer": p.Base + "/oidc", "authorization_endpoint": p.Base + "/oidc/authorize", "token_endpoint": p.Base + "/oidc/token",
			"jwks_uri": p.Base + "/oidc/jwks", "code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"}})
	case rest == "jwks" && flavor != "oauth2":
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "m24", Algorithm: "RS256", Use: "sig"}}})
	case rest == "authorize" && r.Method == http.MethodGet:
		p.authorizePage(w, r, flavor)
	case rest == "authorize" && r.Method == http.MethodPost:
		p.authorizeSubmit(w, r, flavor)
	case rest == "token" && r.Method == http.MethodPost:
		p.token(w, r, flavor)
	case rest == "userinfo" && flavor == "oauth2":
		p.mu.Lock()
		sub, ok := p.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		p.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"id": sub, "login": sub, "mail": strings.ToLower(sub) + "@oauth2.e2e.test", "display": "OAuth " + sub})
	default:
		http.NotFound(w, r)
	}
}

func (p *Provider) authorizePage(w http.ResponseWriter, r *http.Request, flavor string) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != ClientID || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("redirect_uri") == "" || (flavor != "oauth2" && q.Get("nonce") == "") {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	hidden := map[string]string{}
	for _, k := range []string{"state", "nonce", "code_challenge", "redirect_uri"} {
		hidden[k] = q.Get(k)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = form.Execute(w, map[string]any{"Flavor": flavor, "Action": p.Base + "/" + flavor + "/authorize", "Hidden": hidden})
}

func (p *Provider) authorizeSubmit(w http.ResponseWriter, r *http.Request, flavor string) {
	_ = r.ParseForm()
	cb, err := url.Parse(r.PostForm.Get("redirect_uri"))
	if err != nil || cb.Scheme != "https" || cb.Path != "/login/callback" {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := url.Values{"state": {r.PostForm.Get("state")}}
	if r.PostForm.Get("decision") != "allow" {
		q.Set("error", "access_denied")
		q.Set("error_description", "mock user denied")
	} else {
		c := random()
		p.mu.Lock()
		p.codes[c] = code{flavor: flavor, sub: r.PostForm.Get("subject"), nonce: r.PostForm.Get("nonce"), challenge: r.PostForm.Get("code_challenge"), redirect: cb.String()}
		p.mu.Unlock()
		q.Set("code", c)
	}
	cb.RawQuery = q.Encode()
	http.Redirect(w, r, cb.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request, flavor string) {
	_ = r.ParseForm()
	p.mu.Lock()
	p.Exchanges[flavor]++
	c, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	user, pass, basic := r.BasicAuth()
	if basic {
		user, _ = url.QueryUnescape(user)
		pass, _ = url.QueryUnescape(pass)
	}
	post := r.PostForm.Get("client_secret") != ""
	// Exactly one client authentication method, the one each flavor uses.
	wantBasic := flavor == "oidc"
	authOK := basic != post && basic == wantBasic &&
		((basic && user == ClientID && pass == ClientSecret) || (post && r.PostForm.Get("client_id") == ClientID && r.PostForm.Get("client_secret") == ClientSecret))
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || c.flavor != flavor || !authOK || r.PostForm.Get("grant_type") != "authorization_code" ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || r.PostForm.Get("redirect_uri") != c.redirect {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	access := random()
	p.mu.Lock()
	p.tokens[access] = c.sub
	p.mu.Unlock()
	out := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": "refresh-" + c.sub}
	if flavor != "oauth2" {
		now := time.Now()
		claims, _ := json.Marshal(map[string]any{"iss": p.Base + "/" + flavor, "aud": ClientID, "sub": c.sub, "nonce": c.nonce,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "email": strings.ToLower(c.sub) + "@" + flavor + ".e2e.test", "email_verified": true, "name": "Mock " + c.sub})
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "m24"))
		if err != nil {
			http.Error(w, "signing", 500)
			return
		}
		obj, _ := signer.Sign(claims)
		out["id_token"], _ = obj.CompactSerialize()
	}
	writeJSON(w, out)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ExchangeCounts returns a copy of the token request counts per flavor.
func (p *Provider) ExchangeCounts() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]int, len(p.Exchanges))
	for k, v := range p.Exchanges {
		out[k] = v
	}
	return out
}
