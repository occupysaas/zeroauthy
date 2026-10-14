package oauth

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// issueCode stores a code for alice as /authorize would, and returns it.
func (f *fixture) issueCode(t *testing.T, clientID, redirectURI, audience string, scopes []string, challenge string) string {
	t.Helper()
	ctx := context.Background()
	tenantID := f.tenantID(t, "acme")
	u, err := f.st.Users().FindByLogin(ctx, tenantID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	code := secrets.RandomString(43)
	ac := &store.AuthCode{
		TenantID: tenantID, CodeHash: secrets.HashToken(code), ClientID: clientID, RedirectURI: redirectURI,
		UserID: u.UserID, SessionID: "sid-1", Scopes: scopes, Audience: audience, Nonce: "n-1",
		AuthTime: fixedNow().Add(-time.Minute), ExpiresAt: fixedNow().Add(time.Minute), CreatedAt: fixedNow(),
	}
	if challenge != "" {
		ac.CodeChallenge, ac.CodeChallengeMethod = challenge, "S256"
	}
	if err := f.st.AuthCodes().Create(ctx, ac); err != nil {
		t.Fatal(err)
	}
	return code
}

func codeForm(code, clientID, redirectURI, verifier string) url.Values {
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "redirect_uri": {redirectURI}}
	if verifier != "" {
		v.Set("code_verifier", verifier)
	}
	return v
}

func TestAuthorizationCodeSPA(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "code-spa", "https://app.acme.test/cb", "https://api.acme.test",
		[]string{"openid", "profile", "email", "read:things", "undefined:scope", "offline_access"}, pkceChallenge)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	if body["scope"] != "openid profile email read:things" || body["token_type"] != "Bearer" || body["expires_in"] != float64(3600) {
		t.Fatalf("body = %v", body)
	}
	tenantID := f.tenantID(t, "acme")
	at, _ := verifyToken(t, f.keys, tenantID, body["access_token"].(string))
	aud, _ := at["aud"].([]any)
	if len(aud) != 2 || aud[0] != "https://api.acme.test" || aud[1] != "https://acme.example.test/userinfo" ||
		!strings.HasPrefix(at["sub"].(string), "auth0|") || at["azp"] != "code-spa" || at["gty"] != nil {
		t.Fatalf("access token claims = %v", at)
	}
	idt, _ := verifyToken(t, f.keys, tenantID, body["id_token"].(string))
	if idt["aud"] != "code-spa" || idt["nonce"] != "n-1" || idt["sid"] != "sid-1" || idt["email"] != "alice@acme.test" ||
		idt["name"] != "Alice" || idt["at_hash"] == nil || idt["exp"].(float64)-idt["iat"].(float64) != 600 || idt["sub"] != at["sub"] {
		t.Fatalf("id token claims = %v", idt)
	}
}

func TestAuthorizationCodeWithoutAudience(t *testing.T) {
	f := newFixture(t)
	// The fixture tenant has default_audience set; codes carry the audience
	// chosen at /authorize, so an empty audience here means "none".
	code := f.issueCode(t, "code-web", "https://web.acme.test/cb", "", []string{"openid", "read:things"}, "")
	form := codeForm(code, "code-web", "https://web.acme.test/cb", "")
	form.Set("client_secret", "code-web-secret")
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
	if rec.Code != 200 || body["scope"] != "openid" || body["expires_in"] != float64(86400) {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["aud"] != "https://acme.example.test/userinfo" {
		t.Fatalf("aud = %v", at["aud"])
	}
}

func TestAuthorizationCodeNoOpenID(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "code-spa", "https://app.acme.test/cb", "https://api.acme.test", []string{"read:things"}, pkceChallenge)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 || body["id_token"] != nil {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["aud"] != "https://api.acme.test" {
		t.Fatalf("aud = %v (no openid scope: API audience only)", at["aud"])
	}
}

// Review focus 2.
func TestAuthorizationCodeMisuse(t *testing.T) {
	f := newFixture(t)
	spa := func() string {
		return f.issueCode(t, "code-spa", "https://app.acme.test/cb", "", []string{"openid"}, pkceChallenge)
	}

	t.Run("replay", func(t *testing.T) {
		code := spa()
		form := codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)
		if rec, _ := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 200 {
			t.Fatalf("first use = %d", rec.Code)
		}
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("replay = %d %v", rec.Code, body)
		}
	})

	cases := map[string]func() tokenCall{
		"unknown code": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm("nope", "code-spa", "https://app.acme.test/cb", pkceVerifier)}
		},
		"other client": func() tokenCall {
			form := codeForm(spa(), "code-web", "https://app.acme.test/cb", pkceVerifier)
			form.Set("client_secret", "code-web-secret")
			return tokenCall{host: "acme.example.test", form: form}
		},
		"other redirect_uri": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/other", pkceVerifier)}
		},
		"missing redirect_uri": func() tokenCall {
			form := codeForm(spa(), "code-spa", "https://app.acme.test/cb", pkceVerifier)
			form.Del("redirect_uri")
			return tokenCall{host: "acme.example.test", form: form}
		},
		"missing verifier": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/cb", "")}
		},
		"wrong verifier": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/cb", strings.Repeat("a", 43))}
		},
		"other tenant": func() tokenCall {
			return tokenCall{host: "globex.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/cb", pkceVerifier)}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			rec, body := f.call(t, true, mk())
			if rec.Code == 200 || body["access_token"] != nil {
				t.Fatalf("tokens issued: %d %v", rec.Code, body)
			}
			if e := body["error"]; e != "invalid_grant" && e != "invalid_client" {
				t.Fatalf("error = %v", e)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		code := spa()
		f.h.Now = func() time.Time { return fixedNow().Add(2 * time.Minute) }
		defer func() { f.h.Now = fixedNow }()
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)}); rec.Code != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("expired = %d %v", rec.Code, body)
		}
	})

	t.Run("blocked user", func(t *testing.T) {
		code := spa()
		ctx := context.Background()
		u, _ := f.st.Users().FindByLogin(ctx, f.tenantID(t, "acme"), "Username-Password-Authentication", "alice@acme.test")
		u.Blocked = true
		_ = f.st.Users().Update(ctx, u)
		defer func() { u.Blocked = false; _ = f.st.Users().Update(ctx, u) }()
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)}); rec.Code != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("blocked = %d %v", rec.Code, body)
		}
	})
}
