package provider

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// EnterpriseRegistration is test-only upstream client configuration. Public
// connection certificates are registered through the local control listener.
type EnterpriseRegistration struct {
	ClientID       string
	SigningCert    string
	EncryptionCert string
	EncryptionAlg  string
	PAR            bool
}
type enterpriseCode struct{ client, subject, nonce, challenge, method, redirect string }
type enterpriseState struct {
	clients    map[string]EnterpriseRegistration
	codes      map[string]enterpriseCode
	requests   map[string]url.Values
	assertions map[string]bool
	secrets    []string
}

func (p *Provider) RegisterEnterprise(in EnterpriseRegistration) error {
	if in.ClientID == "" {
		return errors.New("missing fixture client")
	}
	for _, cert := range []string{in.SigningCert, in.EncryptionCert} {
		if cert != "" {
			if _, e := fixtureCert(cert); e != nil {
				return e
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enterprise == nil {
		p.enterprise = &enterpriseState{clients: map[string]EnterpriseRegistration{}, codes: map[string]enterpriseCode{}, requests: map[string]url.Values{}, assertions: map[string]bool{}}
	}
	p.enterprise.clients[in.ClientID] = in
	return nil
}
func fixtureCert(raw string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(raw))
	if b == nil {
		return nil, errors.New("invalid fixture certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}
func (p *Provider) EnterpriseAudit() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enterprise == nil {
		return nil
	}
	return append([]string(nil), p.enterprise.secrets...)
}
func (p *Provider) enterpriseClient(id string) (EnterpriseRegistration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enterprise == nil {
		return EnterpriseRegistration{}, false
	}
	c, ok := p.enterprise.clients[id]
	return c, ok
}
func (p *Provider) enterpriseAuth(r *http.Request) (EnterpriseRegistration, bool) {
	id := r.PostForm.Get("client_id")
	user, pass, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(user)
		pass, _ = url.QueryUnescape(pass)
	}
	c, ok := p.enterpriseClient(id)
	if !ok {
		return c, false
	}
	assertion := r.PostForm.Get("client_assertion")
	if c.SigningCert == "" {
		return c, assertion == "" && ((basic && pass == ClientSecret && r.PostForm.Get("client_secret") == "") || (!basic && r.PostForm.Get("client_secret") == ClientSecret))
	}
	if basic || r.PostForm.Has("client_secret") || r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return c, false
	}
	cert, e := fixtureCert(c.SigningCert)
	if e != nil {
		return c, false
	}
	obj, e := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.ES256, jose.ES384})
	if e != nil {
		return c, false
	}
	b, e := obj.Verify(cert.PublicKey)
	if e != nil {
		return c, false
	}
	var claims struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		JTI      string `json:"jti"`
		Issued   int64  `json:"iat"`
		Expiry   int64  `json:"exp"`
	}
	if json.Unmarshal(b, &claims) != nil || claims.Issuer != id || claims.Subject != id || (claims.Audience != p.Base+"/enterprise" && claims.Audience != p.Base+"/enterprise/token") || claims.Expiry-claims.Issued != 60 || claims.Issued > time.Now().Unix()+5 || claims.Expiry < time.Now().Unix() || claims.JTI == "" {
		return c, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.enterprise.assertions[claims.JTI] {
		return c, false
	}
	p.enterprise.assertions[claims.JTI] = true
	p.enterprise.secrets = append(p.enterprise.secrets, assertion)
	return c, true
}

var enterprisePost = template.Must(template.New("enterprise-post").Parse(`<!doctype html><html><head><title>Returning to login</title></head><body><form method="post" action="{{.Action}}">{{range $k,$v:=.Fields}}<input type="hidden" name="{{$k}}" value="{{index $v 0}}">{{end}}<button>Continue</button></form><script>document.forms[0].submit()</script></body></html>`))

func (p *Provider) enterpriseToken(c EnterpriseRegistration, subject, nonce string) (map[string]any, error) {
	now := time.Now()
	claims := map[string]any{"iss": p.Base + "/enterprise", "aud": c.ClientID, "sub": subject, "nonce": nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "email": strings.ToLower(subject) + "@corp.example", "email_verified": true, "name": "Workforce " + subject, "groups": []string{"staff"}}
	b, _ := json.Marshal(claims)
	s, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "m36"))
	if e != nil {
		return nil, e
	}
	obj, e := s.Sign(b)
	if e != nil {
		return nil, e
	}
	raw, e := obj.CompactSerialize()
	if e != nil {
		return nil, e
	}
	p.mu.Lock()
	p.enterprise.secrets = append(p.enterprise.secrets, raw)
	p.mu.Unlock()
	if c.EncryptionCert != "" {
		cert, e := fixtureCert(c.EncryptionCert)
		if e != nil {
			return nil, e
		}
		enc, e := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.KeyAlgorithm(c.EncryptionAlg), Key: cert.PublicKey}, nil)
		if e != nil {
			return nil, e
		}
		obj, e := enc.Encrypt([]byte(raw))
		if e != nil {
			return nil, e
		}
		raw, e = obj.CompactSerialize()
		if e != nil {
			return nil, e
		}
		p.mu.Lock()
		p.enterprise.secrets = append(p.enterprise.secrets, raw)
		p.mu.Unlock()
	}
	access := "m36-upstream-" + random()
	p.mu.Lock()
	p.tokens[access] = subject
	p.enterprise.secrets = append(p.enterprise.secrets, access)
	p.mu.Unlock()
	return map[string]any{"access_token": access, "token_type": "Bearer", "id_token": raw, "expires_in": 3600}, nil
}
func (p *Provider) serveEnterprise(w http.ResponseWriter, r *http.Request) {
	endpoint := strings.TrimPrefix(r.URL.Path, "/enterprise/")
	switch endpoint {
	case ".well-known/openid-configuration":
		writeJSON(w, map[string]any{"issuer": p.Base + "/enterprise", "authorization_endpoint": p.Base + "/enterprise/authorize", "token_endpoint": p.Base + "/enterprise/token", "jwks_uri": p.Base + "/enterprise/jwks", "userinfo_endpoint": p.Base + "/enterprise/userinfo", "pushed_authorization_request_endpoint": p.Base + "/enterprise/par", "code_challenge_methods_supported": []string{"S256", "plain"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt"}})
	case "jwks":
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "m36", Algorithm: "RS256", Use: "sig"}}})
	case "par":
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		if e := r.ParseForm(); e != nil {
			http.Error(w, "form", 400)
			return
		}
		c, ok := p.enterpriseAuth(r)
		if !ok {
			http.Error(w, "authentication", 401)
			return
		}
		q := r.PostForm
		q.Del("client_assertion")
		q.Del("client_assertion_type")
		q.Del("client_secret")
		uri := "urn:example:par:" + random()
		p.mu.Lock()
		p.enterprise.requests[uri] = q
		p.mu.Unlock()
		if !c.PAR {
			http.Error(w, "PAR unavailable", 400)
			return
		}
		w.WriteHeader(201)
		writeJSON(w, map[string]any{"request_uri": uri, "expires_in": 60})
	case "authorize":
		if r.Method == "GET" {
			q := r.URL.Query()
			if uri := q.Get("request_uri"); uri != "" {
				p.mu.Lock()
				saved := p.enterprise.requests[uri]
				delete(p.enterprise.requests, uri)
				p.mu.Unlock()
				if saved == nil || saved.Get("client_id") != q.Get("client_id") {
					http.Error(w, "request_uri", 400)
					return
				}
				q = saved
			}
			c, ok := p.enterpriseClient(q.Get("client_id"))
			if !ok || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("redirect_uri") == "" || (q.Get("response_type") != "code" && q.Get("response_type") != "id_token") {
				http.Error(w, "authorization parameters", 400)
				return
			}
			if c.PAR && r.URL.Query().Get("request_uri") == "" {
				http.Error(w, "PAR required", 400)
				return
			}
			hidden := map[string]string{}
			for k := range q {
				hidden[k] = q.Get(k)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = form.Execute(w, map[string]any{"Flavor": "enterprise", "Action": p.Base + "/enterprise/authorize", "Hidden": hidden})
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		if e := r.ParseForm(); e != nil {
			http.Error(w, "form", 400)
			return
		}
		q := r.PostForm
		c, ok := p.enterpriseClient(q.Get("client_id"))
		cb, e := url.Parse(q.Get("redirect_uri"))
		if !ok || e != nil || cb.Scheme != "https" || cb.Path != "/login/callback" {
			http.Error(w, "callback", 400)
			return
		}
		fields := url.Values{"state": {q.Get("state")}}
		if q.Get("decision") != "allow" {
			fields.Set("error", "access_denied")
		} else if q.Get("response_type") == "id_token" {
			tokens, e := p.enterpriseToken(c, q.Get("subject"), q.Get("nonce"))
			if e != nil {
				http.Error(w, "signing", 500)
				return
			}
			fields.Set("id_token", tokens["id_token"].(string))
		} else {
			code := random()
			p.mu.Lock()
			p.enterprise.codes[code] = enterpriseCode{c.ClientID, q.Get("subject"), q.Get("nonce"), q.Get("code_challenge"), q.Get("code_challenge_method"), cb.String()}
			p.mu.Unlock()
			fields.Set("code", code)
		}
		if q.Get("response_type") == "id_token" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = enterprisePost.Execute(w, map[string]any{"Action": cb.String(), "Fields": fields})
			return
		}
		cb.RawQuery = fields.Encode()
		http.Redirect(w, r, cb.String(), 302)
	case "token":
		if e := r.ParseForm(); e != nil {
			http.Error(w, "form", 400)
			return
		}
		c, ok := p.enterpriseAuth(r)
		p.mu.Lock()
		code, exists := p.enterprise.codes[r.PostForm.Get("code")]
		delete(p.enterprise.codes, r.PostForm.Get("code"))
		p.Exchanges["enterprise"]++
		p.mu.Unlock()
		challenge := r.PostForm.Get("code_verifier")
		if code.method == "S256" {
			challenge = pkceChallenge(challenge)
		}
		if !ok || !exists || code.client != c.ClientID || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != code.redirect || challenge != code.challenge {
			http.Error(w, "invalid grant", 400)
			return
		}
		tokens, e := p.enterpriseToken(c, code.subject, code.nonce)
		if e != nil {
			http.Error(w, "token", 500)
			return
		}
		writeJSON(w, tokens)
	case "userinfo":
		p.mu.Lock()
		subject, ok := p.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		p.mu.Unlock()
		if !ok {
			http.Error(w, "token", 401)
			return
		}
		writeJSON(w, map[string]any{"sub": subject, "groups": []string{"engineering", "staff"}, "name": "Directory " + subject})
	default:
		http.NotFound(w, r)
	}
}
func pkceChallenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
