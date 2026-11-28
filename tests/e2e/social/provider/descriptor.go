package provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
)

// Plan 39b: one local stand-in for every descriptor strategy under
// <Base>/social/<strategy>. It reads the same descriptors zeroauthy uses and
// answers each strategy's authorize, token and profile shapes by inverting
// the descriptor's profile map, plus the hooks' extra calls (Salesforce
// identity URL, LINE verify, Bitbucket emails, Facebook appsecret_proof,
// Shopify's access-token header). No live provider is contacted.

type socialCode struct {
	strategy, sub, challenge, redirect string
}

type socialToken struct{ strategy, sub string }

func socialPath(raw string) string {
	raw = strings.Replace(raw, providers.ShopPlaceholder, "shop.example", 1)
	raw = strings.Replace(raw, providers.CommunityPlaceholder, "https://community.example", 1)
	raw = strings.Replace(raw, providers.BaseURLPlaceholder, "https://base.example", 1)
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}

// SocialEmail is the email the stand-in returns for subject.
func SocialEmail(strategy, sub string) string { return sub + "@" + strategy + ".e2e.test" }

func (p *Provider) serveSocial(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/social/")
	strategy, path, _ := strings.Cut(rest, "/")
	path = "/" + path
	d, ok := providers.Get(strategy)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case path == socialPath(d.AuthorizationURL):
		p.socialAuthorize(w, r, d)
	case path == socialPath(d.TokenURL) && (r.Method == http.MethodPost || d.TokenMethod == http.MethodGet && r.Method == http.MethodGet):
		p.socialToken(w, r, d)
	case d.EmailURL != "" && path == socialPath(d.EmailURL):
		p.socialProfile(w, r, d, true)
	case d.VerifyURL != "" && path == socialPath(d.VerifyURL) && r.Method == http.MethodPost:
		p.socialVerify(w, r, d)
	case path == socialPath(d.ProfileURL) || d.Hook == providers.HookSalesforce && strings.HasPrefix(path, "/id/"):
		p.socialProfile(w, r, d, false)
	default:
		http.NotFound(w, r)
	}
}

func (p *Provider) socialAuthorize(w http.ResponseWriter, r *http.Request, d *providers.Descriptor) {
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		rp := redirectParamOf(d)
		for k, v := range d.AuthorizeParams {
			if q.Get(k) != v {
				http.Error(w, "missing fixed parameter", http.StatusBadRequest)
				return
			}
		}
		if q.Get("client_id") != ClientID || q.Get("response_type") != "code" || q.Get("state") == "" || q.Get(rp) == "" ||
			d.PKCE == providers.PKCES256 && (q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256") {
			http.Error(w, "invalid authorization request", http.StatusBadRequest)
			return
		}
		hidden := map[string]string{"redirect_uri": q.Get(rp), "state": q.Get("state"), "code_challenge": q.Get("code_challenge")}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = form.Execute(w, map[string]any{"Flavor": d.DisplayName, "Action": r.URL.Path, "Hidden": hidden})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	redirect, err := url.Parse(r.PostForm.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	q := redirect.Query()
	q.Set("state", r.PostForm.Get("state"))
	if r.PostForm.Get("decision") != "allow" {
		q.Set("error", "access_denied")
	} else {
		c := random()
		p.mu.Lock()
		p.socialCodes[c] = socialCode{strategy: d.Strategy, sub: r.PostForm.Get("subject"), challenge: r.PostForm.Get("code_challenge"), redirect: redirect.String()}
		p.mu.Unlock()
		q.Set("code", c)
	}
	redirect.RawQuery = q.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *Provider) socialToken(w http.ResponseWriter, r *http.Request, d *providers.Descriptor) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	form := r.PostForm
	if d.TokenMethod == http.MethodGet {
		form = r.URL.Query()
	}
	id, secret := form.Get("client_id"), form.Get("client_secret")
	if d.TokenAuth == providers.AuthQuery {
		id, secret = r.URL.Query().Get("client_id"), r.URL.Query().Get("client_secret")
		if r.PostForm.Has("client_secret") {
			jsonError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
	}
	for k, v := range d.TokenParams {
		if form.Get(k) != v {
			jsonError(w, http.StatusBadRequest, "missing fixed parameter")
			return
		}
	}
	if d.TokenAuth == providers.AuthBasic {
		var ok bool
		if id, secret, ok = r.BasicAuth(); !ok || r.PostForm.Has("client_secret") {
			jsonError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	}
	if id != ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(ClientSecret)) != 1 {
		jsonError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	p.mu.Lock()
	c, ok := p.socialCodes[form.Get("code")]
	delete(p.socialCodes, form.Get("code"))
	p.mu.Unlock()
	if !ok || c.strategy != d.Strategy || c.redirect != form.Get(redirectParamOf(d)) {
		jsonError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if c.challenge != "" {
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			jsonError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
	}
	at := random()
	p.mu.Lock()
	p.socialTokens[at] = socialToken{strategy: d.Strategy, sub: c.sub}
	p.Exchanges[d.Strategy]++
	p.mu.Unlock()
	out := map[string]any{"access_token": at, "expires_in": 3600}
	if !d.TokenTypeOptional {
		out["token_type"] = "bearer"
	}
	switch d.Hook {
	case providers.HookSalesforce:
		out["id"] = p.Base + "/social/" + d.Strategy + "/id/00D000000000001/" + c.sub
	case providers.HookLine:
		out["id_token"] = "line-id-" + at
	}
	p.tokenProfile(d, c.sub, out)
	if d.TokenResponsePath != "" {
		wrapped := map[string]any{}
		setPath(wrapped, d.TokenResponsePath, out)
		writeJSON(w, wrapped)
		return
	}
	writeJSON(w, out)
}

func (p *Provider) bearer(r *http.Request, d *providers.Descriptor) (socialToken, string, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if name, ok := strings.CutPrefix(d.ProfileAuth, "header:"); ok {
		tok = r.Header.Get(name)
	} else if name, ok := strings.CutPrefix(d.ProfileAuth, "query:"); ok {
		tok = r.URL.Query().Get(name)
	} else if scheme, ok := strings.CutPrefix(d.ProfileAuth, "scheme:"); ok {
		tok = strings.TrimPrefix(r.Header.Get("Authorization"), scheme+" ")
	}
	p.mu.Lock()
	t, ok := p.socialTokens[tok]
	p.mu.Unlock()
	return t, tok, ok && t.strategy == d.Strategy
}

func (p *Provider) socialProfile(w http.ResponseWriter, r *http.Request, d *providers.Descriptor, emails bool) {
	t, tok, ok := p.bearer(r, d)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	want := d.ProfileMethod
	if want == "" || emails {
		want = http.MethodGet
	}
	if r.Method != want {
		jsonError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if d.Hook == providers.HookFacebook {
		mac := hmac.New(sha256.New, []byte(ClientSecret))
		mac.Write([]byte(tok))
		if r.URL.Query().Get("appsecret_proof") != hex.EncodeToString(mac.Sum(nil)) {
			jsonError(w, http.StatusBadRequest, "appsecret_proof")
			return
		}
	}
	for k, v := range d.ProfileParams {
		if r.URL.Query().Get(k) != v {
			jsonError(w, http.StatusBadRequest, "missing fixed parameter")
			return
		}
	}
	doc := map[string]any{}
	if emails {
		setPath(doc, d.Profile.Email, SocialEmail(d.Strategy, t.sub))
		if d.EmailVerified.Rule == providers.EmailField {
			setPath(doc, d.EmailVerified.Path, true)
		}
		writeJSON(w, doc)
		return
	}
	if !strings.HasPrefix(d.Profile.UserID, providers.TokenPrefix) {
		setPath(doc, d.Profile.UserID, t.sub)
	}
	for _, path := range []string{d.Profile.Name, d.Profile.Nickname} {
		if path != "" && !strings.HasPrefix(path, providers.TokenPrefix) {
			setPath(doc, path, "Name "+t.sub)
		}
	}
	if d.Profile.Email != "" && d.EmailURL == "" && !strings.HasPrefix(d.Profile.Email, providers.TokenPrefix) {
		setPath(doc, d.Profile.Email, SocialEmail(d.Strategy, t.sub))
		if d.EmailVerified.Rule == providers.EmailField {
			setPath(doc, d.EmailVerified.Path, true)
		}
	}
	writeJSON(w, doc)
}

// socialVerify is LINE's ID-token verify endpoint.
func (p *Provider) socialVerify(w http.ResponseWriter, r *http.Request, d *providers.Descriptor) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") != ClientID {
		jsonError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	at, ok := strings.CutPrefix(r.PostForm.Get("id_token"), "line-id-")
	p.mu.Lock()
	t, known := p.socialTokens[at]
	p.mu.Unlock()
	if !ok || !known || t.strategy != d.Strategy {
		jsonError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	writeJSON(w, map[string]any{"iss": "https://access.line.me", "sub": t.sub, "aud": ClientID, "email": SocialEmail(d.Strategy, t.sub)})
}

// setPath writes v at a descriptor profile path; a [?field] segment becomes a
// one-element array whose element has field true.
func setPath(doc map[string]any, path string, v any) {
	cur := doc
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		if i := strings.Index(seg, "["); i >= 0 && !strings.Contains(seg, "[?") {
			name := seg[:i]
			list, _ := cur[name].([]any)
			if len(list) == 0 {
				list = []any{map[string]any{}}
				cur[name] = list
			}
			cur = list[0].(map[string]any)
			continue
		}
		name, filter, hasFilter := strings.Cut(seg, "[?")
		if hasFilter {
			filter = strings.TrimSuffix(filter, "]")
			list, _ := cur[name].([]any)
			if len(list) == 0 {
				list = []any{map[string]any{filter: true}}
				cur[name] = list
			}
			cur = list[0].(map[string]any)
			continue
		}
		if i == len(segs)-1 {
			cur[name] = v
			return
		}
		next, ok := cur[name].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[name] = next
		}
		cur = next
	}
}

func jsonError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func redirectParamOf(d *providers.Descriptor) string {
	if d.RedirectParam != "" {
		return d.RedirectParam
	}
	return "redirect_uri"
}

// tokenProfile puts the token: profile values into a token response, and
// the {token.<field>} values a profile URL substitutes.
func (p *Provider) tokenProfile(d *providers.Descriptor, sub string, out map[string]any) {
	for _, m := range regexp.MustCompile(`\{token\.([a-z0-9_]+)\}`).FindAllStringSubmatch(d.ProfileURL, -1) {
		out[m[1]] = sub
	}
	if f, ok := strings.CutPrefix(d.Profile.UserID, providers.TokenPrefix); ok {
		setPath(out, f, sub)
	}
	if f, ok := strings.CutPrefix(d.Profile.Email, providers.TokenPrefix); ok {
		setPath(out, f, SocialEmail(d.Strategy, sub))
	}
}
