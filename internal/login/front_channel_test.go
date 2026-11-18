package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func frontCallback(t *testing.T) (*socialEnv, *browser, url.Values) {
	t.Helper()
	s := newSocialEnv(t)
	c, e := s.st.Connections().Get(context.Background(), s.tenant.ID, "con_corp")
	if e != nil {
		t.Fatal(e)
	}
	c.Extra["type"] = "front_channel"
	c.FederationSecretsSealed = nil
	c.FederationRevision++
	if e := s.st.Connections().Update(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	b := s.browser("acme.example.test")
	page := s.authorizeTo(t, b, "spa", "connection", "corp")
	r := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil)
	u, e := url.Parse(providerURL(t, r))
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	if q.Get("response_type") != "id_token" || q.Get("response_mode") != "form_post" || q.Has("code_challenge") || q.Get("nonce") == "" {
		t.Fatal(q)
	}
	for _, c := range r.Result().Cookies() {
		if strings.HasPrefix(c.Name, federation.AttemptCookiePrefix) && c.SameSite != http.SameSiteNoneMode {
			t.Fatal("front-channel cookie must be SameSite=None")
		}
	}
	return s, b, q
}
func frontToken(t *testing.T, s *socialEnv, q url.Values, change func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{"iss": s.idp.base(), "sub": "front-user", "aud": "client", "nonce": q.Get("nonce"), "iat": fixedNow().Unix(), "exp": fixedNow().Add(time.Hour).Unix(), "email": "front@example.com"}
	if change != nil {
		change(claims)
	}
	payload, _ := json.Marshal(claims)
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.idp.key}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{"kid": "k"}})
	if e != nil {
		t.Fatal(e)
	}
	obj, e := signer.Sign(payload)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := obj.CompactSerialize()
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestFrontChannelComplete(t *testing.T) {
	s, b, q := frontCallback(t)
	key := store.FederatedIdentityKey{TenantID: s.tenant.ID, ConnectionID: "con_corp", Subject: "front-user"}
	if e := s.st.Federation().PutTokens(context.Background(), key, []byte("old-sealed-record")); e != nil {
		t.Fatal(e)
	}
	fields := url.Values{"state": {q.Get("state")}, "id_token": {frontToken(t, s, q, nil)}}
	toApp(t, b.do(t, "POST", "/login/callback", fields), "app.acme.test")
	u, e := s.st.Users().FindByIdentity(context.Background(), s.tenant.ID, "con_corp", "front-user")
	if e != nil || u.UserID != "oidc|corp|front-user" {
		t.Fatal(u, e)
	}
	if _, e := s.st.Federation().GetTokens(context.Background(), key); e != store.ErrNotFound {
		t.Fatal("front channel retained upstream tokens", e)
	}
	if s.idp.exchanges.Load() != 0 {
		t.Fatal("front channel exchanged a code")
	}
	if r := b.do(t, "POST", "/login/callback", fields); r.Code != 400 {
		t.Fatal("replay accepted", r.Code)
	}
}
func TestFrontChannelRefusals(t *testing.T) {
	for _, name := range []string{"nonce", "audience", "expired", "unsigned", "code", "get", "state"} {
		t.Run(name, func(t *testing.T) {
			s, b, q := frontCallback(t)
			change := func(c map[string]any) {
				switch name {
				case "nonce":
					c["nonce"] = "wrong"
				case "audience":
					c["aud"] = "wrong"
				case "expired":
					c["exp"] = fixedNow().Add(-time.Hour).Unix()
				}
			}
			token := frontToken(t, s, q, change)
			fields := url.Values{"state": {q.Get("state")}, "id_token": {token}}
			if name == "unsigned" {
				b64 := base64.RawURLEncoding.EncodeToString
				fields.Set("id_token", b64([]byte(`{"alg":"none"}`))+"."+b64([]byte(`{"sub":"attacker"}`))+".")
			}
			if name == "code" {
				fields.Del("id_token")
				fields.Set("code", "code")
			}
			if name == "state" {
				fields.Set("state", "wrong")
			}
			var status int
			if name == "get" {
				status = b.do(t, "GET", "/login/callback?"+fields.Encode(), nil).Code
			} else {
				status = b.do(t, "POST", "/login/callback", fields).Code
			}
			want := 400
			if name == "nonce" || name == "audience" || name == "expired" || name == "unsigned" {
				want = 502
			}
			if status != want {
				t.Fatal(status)
			}
			_, e := s.st.Users().FindByIdentity(context.Background(), s.tenant.ID, "con_corp", "front-user")
			if e != store.ErrNotFound {
				t.Fatal("user created", e)
			}
		})
	}
}

func TestFrontChannelError(t *testing.T) {
	s, b, q := frontCallback(t)
	recorder := &eventRecorder{}
	s.h.Recorder = recorder
	r := b.do(t, "POST", "/login/callback", url.Values{"state": {q.Get("state")}, "error": {"access_denied"}, "error_description": {"do-not-echo-provider-text"}})
	if r.Code != 401 || strings.Contains(r.Body.String(), "do-not-echo-provider-text") {
		t.Fatal(r.Code)
	}
	found := false
	for _, e := range recorder.events {
		if e.Type == "f" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing failed social log")
	}
}
func TestBackChannelRejectsPost(t *testing.T) {
	s := newSocialEnv(t)
	b := s.browser("acme.example.test")
	page := s.authorizeTo(t, b, "spa", "connection", "corp")
	r := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil)
	callback := s.idp.authorize(t, r.Header().Get("Location"), "post-user")
	u, e := url.Parse(callback)
	if e != nil {
		t.Fatal(e)
	}
	if r := b.do(t, "POST", "/login/callback", u.Query()); r.Code != 400 {
		t.Fatal(r.Code)
	}
	if s.idp.exchanges.Load() != 0 {
		t.Fatal("back-channel POST exchanged token")
	}
}
