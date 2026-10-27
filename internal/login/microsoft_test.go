package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const msClient = "99999999-8888-7777-6666-555555555555"
const msBase = "https://login.microsoftonline.com"
const msTemplate = msBase + "/{tenantid}/v2.0"
const msTenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
const msTenant2 = "11111111-2222-3333-4444-555555555555"
const msConsumer = "9188040d-6c67-4c5b-b112-36a304b66dad"
const msOID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

func (p *fakeIDP) serveMicrosoft(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authority := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]
	switch {
	case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
		issuer := msTemplate
		if authority != "organizations" && authority != "consumers" {
			issuer = msBase + "/" + msTenant + "/v2.0"
		}
		if p.badMetadata {
			issuer = "https://evil.invalid/{tenantid}/v2.0"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": msBase + "/" + authority + "/oauth2/v2.0/authorize", "token_endpoint": msBase + "/" + authority + "/oauth2/v2.0/token", "jwks_uri": msBase + "/common/discovery/v2.0/keys", "token_endpoint_auth_methods_supported": []string{"client_secret_post"}, "code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
	case strings.HasSuffix(r.URL.Path, "/keys"):
		key := map[string]any{}
		b, _ := json.Marshal(jose.JSONWebKey{Key: &p.key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"})
		_ = json.Unmarshal(b, &key)
		key["issuer"] = msTemplate
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{key}})
	case strings.HasSuffix(r.URL.Path, "/token"):
		p.exchanges.Add(1)
		_ = r.ParseForm()
		p.mu.Lock()
		c, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || r.PostForm.Get("redirect_uri") != c.redirect || r.PostForm.Get("client_secret") != "provider-secret" {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		if p.beforeToken != nil {
			p.beforeToken()
		}
		claims := map[string]any{"iss": msBase + "/" + c.tenant + "/v2.0", "tid": c.tenant, "ver": "2.0", "oid": msOID, "aud": msClient, "sub": c.sub, "nonce": c.nonce, "iat": fixedNow().Unix(), "exp": fixedNow().Add(time.Hour).Unix(), "email": c.sub + "@idp.example", "email_verified": true}
		if p.badToken {
			claims["nonce"] = "wrong"
		}
		b, _ := json.Marshal(claims)
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
		obj, _ := signer.Sign(b)
		raw, _ := obj.CompactSerialize()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream-at", "token_type": "Bearer", "id_token": raw, "expires_in": 3600})
	default:
		http.NotFound(w, r)
	}
}

func newMicrosoftEnv(t *testing.T) *socialEnv {
	t.Helper()
	s := newSocialEnv(t)
	s.idp.microsoft = true
	s.idp.microsoftTenant = msTenant
	s.h.Federation.Providers.WithMicrosoftFixture(federation.MicrosoftOverride{AuthorityBaseURL: s.idp.base()})
	ctx := context.Background()
	for _, id := range []string{"con_corp", "con_hidden", "con_google"} {
		c, _ := s.st.Connections().Get(ctx, s.tenant.ID, id)
		spec := connrules.FromConnection(c)
		spec.Strategy = "waad"
		spec.DisplayName = ""
		spec.Options = connrules.Options{Extra: map[string]any{"client_id": msClient, "useCommonEndpoint": true}}
		if id == "con_google" {
			spec.Name = "personal"
			spec.Strategy = "windowslive"
			spec.Options = connrules.Options{Extra: map[string]any{"client_id": msClient}}
		}
		connrules.Apply(spec, c)
		spec.FederationIssuer = ""
		connrules.Apply(spec, c)
		c.FederationRevision = 1
		if err := s.st.Connections().Update(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (s *socialEnv) identityID(sub string) string {
	if s.idp.microsoft {
		return "waad|corp|" + msTenant + ":" + msOID
	}
	return "oidc|corp|" + sub
}

func TestMicrosoftFlow(t *testing.T) {
	ctx := context.Background()
	t.Run("two organizational directories retain template policy", func(t *testing.T) {
		s := newMicrosoftEnv(t)
		for _, tid := range []string{msTenant, msTenant2} {
			s.idp.microsoftTenant = tid
			b := s.browser("acme.example.test")
			toApp(t, s.explicitLogin(t, b, s.idp, "corp", "Same-Sub"), "app.acme.test")
			u, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_corp", tid+":"+msOID)
			if err != nil || u.UserID != "waad|corp|"+tid+":"+msOID || u.EmailVerified || b.cookies[session.CookieName] == nil {
				t.Fatalf("identity/session: %+v %v", u, err)
			}
			c, _ := s.st.Connections().Get(ctx, s.tenant.ID, "con_corp")
			if connrules.FromConnection(c).FederationIssuer != "" || c.FederationRevision != 1 {
				t.Fatalf("multitenant connection pinned: %+v", c)
			}
		}
	})
	t.Run("single directory pin and snapshot", func(t *testing.T) {
		s := newMicrosoftEnv(t)
		c, _ := s.st.Connections().Get(ctx, s.tenant.ID, "con_corp")
		spec := connrules.FromConnection(c)
		spec.Options.Extra["tenant_domain"] = "example.onmicrosoft.com"
		spec.Options.Extra["useCommonEndpoint"] = false
		connrules.Apply(spec, c)
		_ = s.st.Connections().Update(ctx, c)
		toApp(t, s.explicitLogin(t, s.browser("acme.example.test"), s.idp, "corp", "Dir"), "app.acme.test")
		c, _ = s.st.Connections().Get(ctx, s.tenant.ID, "con_corp")
		if connrules.FromConnection(c).FederationIssuer != msBase+"/"+msTenant+"/v2.0" || c.FederationRevision != 2 {
			t.Fatalf("not pinned: %+v", c)
		}
	})
	t.Run("hidden explicit selection", func(t *testing.T) {
		s := newMicrosoftEnv(t)
		toApp(t, s.explicitLogin(t, s.browser("acme.example.test"), s.idp, "hidden", "Hidden"), "app.acme.test")
	})
	for _, client := range []string{"spa", "social-only"} {
		t.Run(client+" buttons", func(t *testing.T) {
			s := newMicrosoftEnv(t)
			b := s.browser("acme.example.test")
			page := b.do(t, "GET", strings.TrimPrefix(s.authorizeTo(t, b, client), "https://acme.example.test"), nil)
			body := page.Body.String()
			if page.Code != 200 || !strings.Contains(body, "Microsoft personal account") || !strings.Contains(body, "Microsoft work or school account") || strings.Contains(body, `value="hidden"`) || strings.Contains(body, `name="password"`) != (client == "spa") {
				t.Fatalf("choices %d %s", page.Code, body)
			}
			rec := b.do(t, "POST", "/u/login/social", url.Values{"state": {regexpState.FindStringSubmatch(body)[1]}, "csrf": {csrfField.FindStringSubmatch(body)[1]}, "connection": {"personal"}})
			host := "app.acme.test"
			if client == "social-only" {
				host = "only.acme.test"
			}
			toApp(t, b.do(t, "GET", s.idp.authorize(t, providerURL(t, rec), "Personal-Case"), nil), host)
			u, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_google", "Personal-Case")
			if err != nil || u.UserID != "windowslive|Personal-Case" {
				t.Fatalf("personal %+v %v", u, err)
			}
		})
	}
	t.Run("prompt none never interacts", func(t *testing.T) {
		s := newMicrosoftEnv(t)
		b := s.browser("acme.example.test")
		rec := b.do(t, "GET", "/authorize?"+url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "prompt": {"none"}, "connection": {"corp"}}.Encode(), nil)
		u, _ := url.Parse(rec.Header().Get("Location"))
		if u.Query().Get("error") != "login_required" || s.idp.exchanges.Load() != 0 {
			t.Fatalf("none %d %s", rec.Code, u)
		}
	})
	t.Run("invalid token leaves no identity tokens or session", func(t *testing.T) {
		s := newMicrosoftEnv(t)
		s.idp.badToken = true
		b := s.browser("acme.example.test")
		rec := s.explicitLogin(t, b, s.idp, "corp", "Invalid")
		if rec.Code == 302 || b.cookies[session.CookieName] != nil {
			t.Fatal("invalid token created session")
		}
		if _, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_corp", msTenant+":"+msOID); err == nil {
			t.Fatal("invalid token provisioned user")
		}
		if _, err := s.st.Federation().GetTokens(ctx, store.FederatedIdentityKey{TenantID: s.tenant.ID, ConnectionID: "con_corp", Subject: msTenant + ":" + msOID}); err == nil {
			t.Fatal("invalid token persisted tokens")
		}
		if s.idp.exchanges.Load() != 1 {
			t.Fatal("exchange count")
		}
	})
}

func TestMicrosoftCallbackRace(t *testing.T) { testSocialCallbackRace(t, newMicrosoftEnv) }

func TestMicrosoftProtection(t *testing.T) {
	ctx := context.Background()
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "button", true: "explicit"}[explicit], func(t *testing.T) {
			s := newMicrosoftEnv(t)
			tn, _ := s.st.Tenants().Get(ctx, s.tenant.ID)
			tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "always"
			tn.ProtectionSettings.CAPTCHA.ActiveProviderID = "hcaptcha"
			tn.ProtectionSettings.CAPTCHA.HCaptcha.SiteKey = "site"
			_ = s.st.Tenants().Update(ctx, tn)
			s.h.Protection = &protection.Service{Store: s.st, Now: fixedNow, CaptchaVerifier: &captchaStub{}}
			b := s.browser("acme.example.test")
			extra := []string{}
			if explicit {
				extra = []string{"connection", "corp"}
			}
			page := b.do(t, "GET", strings.TrimPrefix(s.authorizeTo(t, b, "spa", extra...), "https://acme.example.test"), nil)
			body := page.Body.String()
			if page.Code != 200 || !strings.Contains(body, "js.hcaptcha.com") {
				t.Fatalf("challenge %d %s", page.Code, body)
			}
			form := url.Values{"state": {regexpState.FindStringSubmatch(body)[1]}, "csrf": {csrfField.FindStringSubmatch(body)[1]}, "connection": {"corp"}}
			rec := b.do(t, "POST", "/u/login/social", form)
			if handoffAction.MatchString(rec.Body.String()) || rec.Code == 303 {
				t.Fatal("CAPTCHA bypass")
			}
			form.Set("h-captcha-response", "good")
			rec = b.do(t, "POST", "/u/login/social", form)
			u, _ := url.Parse(providerURL(t, rec))
			cb := "/login/callback?" + url.Values{"state": {u.Query().Get("state")}, "error": {"access_denied"}}.Encode()
			if rec = b.do(t, "GET", cb, nil); rec.Code != 401 || s.idp.exchanges.Load() != 0 {
				t.Fatalf("denial %d", rec.Code)
			}
		})
	}
}
