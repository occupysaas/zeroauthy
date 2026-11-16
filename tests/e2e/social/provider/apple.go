package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// AppleRegistration registers the real public key used to verify ES256
// client_secret JWTs for both the Services ID and optional native bundle ID.
type AppleRegistration struct {
	ServicesID, BundleID, TeamID, KeyID string
	PublicKey                           *ecdsa.PublicKey
	PKCES256                            bool
}

func (p *Provider) RegisterApple(a AppleRegistration) error {
	if a.ServicesID == "" || a.TeamID == "" || a.KeyID == "" || a.PublicKey == nil || a.PublicKey.Curve != elliptic.P256() || a.PublicKey.X == nil || a.PublicKey.Y == nil || !a.PublicKey.Curve.IsOnCurve(a.PublicKey.X, a.PublicKey.Y) {
		return errors.New("invalid Apple fixture registration")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.appleClients == nil {
		p.appleClients = map[string]AppleRegistration{}
		p.appleCodes = map[string]appleCode{}
		p.appleSeen = map[string]bool{}
	}
	p.appleClients[a.ServicesID] = a
	if a.BundleID != "" {
		p.appleClients[a.BundleID] = a
	}
	return nil
}

type appleCode struct{ client, sub, redirect, nonce, challenge string }

// AppleCode mints a single-use native code for a registered Services/bundle ID.
func (p *Provider) AppleCode(clientID, subject string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.appleClients[clientID]; !ok || subject == "" {
		return "", errors.New("unknown Apple fixture client")
	}
	c := random()
	p.appleCodes[c] = appleCode{client: clientID, sub: subject}
	if p.appleAudit {
		p.appleSecrets = append(p.appleSecrets, c)
	}
	return c, nil
}

var appleCallback = template.Must(template.New("apple-callback").Parse(`<!doctype html><html><body><form id="callback" method="post" action="{{.Action}}">{{range $k,$v:=.Fields}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}<button type="submit">Continue</button></form><script>document.getElementById('callback').submit()</script></body></html>`))

func (p *Provider) serveApple(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, "/apple/") {
	case ".well-known/openid-configuration":
		m := map[string]any{"issuer": p.Base + "/apple", "authorization_endpoint": p.Base + "/apple/authorize", "token_endpoint": p.Base + "/apple/token", "jwks_uri": p.Base + "/apple/jwks", "token_endpoint_auth_methods_supported": []string{"client_secret_post"}, "id_token_signing_alg_values_supported": []string{"RS256"}}
		p.mu.Lock()
		for _, a := range p.appleClients {
			if a.PKCES256 {
				m["code_challenge_methods_supported"] = []string{"S256"}
			}
		}
		p.mu.Unlock()
		writeJSON(w, m)
	case "jwks":
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "apple-fixture", Algorithm: "RS256", Use: "sig"}}})
	case "authorize":
		p.appleAuthorize(w, r)
	case "token":
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		p.appleToken(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (p *Provider) appleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	f := r.Form
	p.mu.Lock()
	a, ok := p.appleClients[f.Get("client_id")]
	p.mu.Unlock()
	mode := "query"
	for _, s := range strings.Fields(f.Get("scope")) {
		if s == "name" || s == "email" {
			mode = "form_post"
		} else {
			ok = false
		}
	}
	if !ok || f.Get("nonce") == "" || f.Get("state") == "" || f.Get("redirect_uri") == "" || f.Get("response_mode") != mode || (a.PKCES256 && (f.Get("code_challenge") == "" || (r.Method == http.MethodGet && f.Get("code_challenge_method") != "S256"))) || (r.Method == http.MethodGet && f.Get("response_type") != "code") {
		http.Error(w, "invalid Apple authorization", 400)
		return
	}
	if r.Method == http.MethodGet {
		hidden := map[string]string{}
		for _, k := range []string{"client_id", "state", "nonce", "code_challenge", "redirect_uri", "response_mode", "scope"} {
			hidden[k] = f.Get(k)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = form.Execute(w, map[string]any{"Flavor": "Apple", "Action": p.Base + "/apple/authorize", "Hidden": hidden})
		return
	}
	cb, err := url.Parse(f.Get("redirect_uri"))
	if err != nil || cb.Scheme != "https" || cb.Path != "/login/callback" {
		http.Error(w, "invalid redirect_uri", 400)
		return
	}
	fields := map[string]string{"state": f.Get("state")}
	if f.Get("decision") != "allow" {
		fields["error"] = "access_denied"
	} else {
		sub := f.Get("subject")
		c := random()
		p.mu.Lock()
		p.appleCodes[c] = appleCode{client: f.Get("client_id"), sub: sub, redirect: cb.String(), nonce: f.Get("nonce"), challenge: f.Get("code_challenge")}
		if p.appleAudit {
			p.appleSecrets = append(p.appleSecrets, c)
		}
		seen := p.appleSeen[sub]
		p.appleSeen[sub] = true
		p.mu.Unlock()
		fields["code"] = c
		if !seen && strings.Contains(f.Get("scope"), "name") {
			user, _ := json.Marshal(map[string]any{"name": map[string]string{"firstName": "Apple", "lastName": sub}, "email": "untrusted-posted@example.test"})
			fields["user"] = string(user)
		}
	}
	if mode == "query" {
		q := url.Values{}
		for k, v := range fields {
			q.Set(k, v)
		}
		cb.RawQuery = q.Encode()
		http.Redirect(w, r, cb.String(), 302)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = appleCallback.Execute(w, map[string]any{"Action": cb.String(), "Fields": fields})
}
func (p *Provider) appleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f := r.PostForm
	p.mu.Lock()
	p.Exchanges["apple"]++
	if p.appleAudit {
		p.appleSecrets = append(p.appleSecrets, f.Get("client_secret"))
	}
	a, registered := p.appleClients[f.Get("client_id")]
	c, ok := p.appleCodes[f.Get("code")]
	delete(p.appleCodes, f.Get("code"))
	p.mu.Unlock()
	_, _, basic := r.BasicAuth()
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	pkce := c.challenge == "" || base64.RawURLEncoding.EncodeToString(sum[:]) == c.challenge
	if !registered || !ok || basic || c.client != f.Get("client_id") || c.redirect != f.Get("redirect_uri") || !pkce || f.Get("grant_type") != "authorization_code" || !verifyAppleSecret(f.Get("client_secret"), c.client, a) {
		w.WriteHeader(400)
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	email := strings.ToLower(c.sub) + "@apple.e2e.test"
	private := "false"
	if c.sub == "relay" {
		email = "relay@privaterelay.appleid.com"
		private = "true"
	}
	claims := map[string]any{"iss": p.Base + "/apple", "aud": c.client, "sub": c.sub, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "email": email, "email_verified": "true", "is_private_email": private, "real_user_status": 2}
	if c.nonce != "" {
		claims["nonce"] = c.nonce
	}
	if c.sub == "wrong-audience" {
		claims["aud"] = "other.bundle"
	}
	if c.sub == "unverified" {
		claims["email_verified"] = "false"
	}
	if c.sub == "boolean-verified" {
		claims["email_verified"] = true
	}
	payload, _ := json.Marshal(claims)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "apple-fixture"))
	obj, _ := signer.Sign(payload)
	id, _ := obj.CompactSerialize()
	access, refresh := random(), "apple-refresh-"+c.sub
	p.mu.Lock()
	if p.appleAudit {
		p.appleSecrets = append(p.appleSecrets, access, refresh, id)
	}
	p.mu.Unlock()
	writeJSON(w, map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 3600, "id_token": id})
}
func verifyAppleSecret(raw, client string, a AppleRegistration) bool {
	obj, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(obj.Signatures) != 1 || obj.Signatures[0].Header.KeyID != a.KeyID {
		return false
	}
	payload, err := obj.Verify(a.PublicKey)
	if err != nil {
		return false
	}
	var c struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		Issued   int64  `json:"iat"`
		Expires  int64  `json:"exp"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return false
	}
	now := time.Now().Unix()
	return c.Issuer == a.TeamID && c.Subject == client && c.Audience == "https://appleid.apple.com" && c.Issued > 0 && c.Issued <= now+60 && c.Expires > now && c.Expires > c.Issued && c.Expires-c.Issued <= 15777000
}

// EnableAppleAudit records actual fixture credentials in memory for the isolated
// E2E secret scanner. Never enable it on a non-test provider.
func (p *Provider) EnableAppleAudit() { p.mu.Lock(); defer p.mu.Unlock(); p.appleAudit = true }
func (p *Provider) AppleAuditSecrets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.appleSecrets...)
}
