// internal/oauth/minter_test.go
package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func newTestKeys(t *testing.T, tenantIDs ...string) *keys.Manager {
	t.Helper()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{9}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	for _, id := range tenantIDs {
		if err := km.Ensure(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	return km
}

// verifyToken checks the signature against the tenant's JWKS and returns
// the raw claims and the header kid.
func verifyToken(t *testing.T, km *keys.Manager, tenantID, raw string) (map[string]any, string) {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	set, _ := km.JWKS(context.Background(), tenantID)
	kid := tok.Headers[0].KeyID
	ks := set.Key(kid)
	if len(ks) != 1 {
		t.Fatalf("kid %q not in tenant JWKS", kid)
	}
	var claims map[string]any
	if err := tok.Claims(ks[0].Key, &claims); err != nil {
		t.Fatal(err)
	}
	return claims, kid
}

func TestAccessTokenClaims(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	raw, err := m.AccessToken(context.Background(), AccessTokenParams{
		TenantID:  "ten_a",
		Issuer:    "https://a.example.test/",
		Subject:   "m2m@clients",
		Audience:  []string{"https://api.test"},
		ClientID:  "m2m",
		Scopes:    []string{"read:things", "write:things"},
		GrantType: "client-credentials",
		Lifetime:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := verifyToken(t, km, "ten_a", raw)
	iat := float64(fixedNow().Unix())
	want := map[string]any{
		"iss":   "https://a.example.test/",
		"sub":   "m2m@clients",
		"aud":   "https://api.test", // single audience is a string
		"azp":   "m2m",
		"scope": "read:things write:things",
		"gty":   "client-credentials",
		"iat":   iat,
		"exp":   iat + 3600,
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("%s = %#v, want %#v", k, claims[k], v)
		}
	}
	if jti, _ := claims["jti"].(string); len(jti) != 24 {
		t.Errorf("jti = %v", claims["jti"])
	}
}

func TestAccessTokenOptionalClaims(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	raw, err := m.AccessToken(context.Background(), AccessTokenParams{
		TenantID: "ten_a", Issuer: "https://a.example.test/", Subject: "u1", ClientID: "c",
		Audience: []string{"https://api.test", "https://a.example.test/userinfo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := verifyToken(t, km, "ten_a", raw)
	aud, _ := json.Marshal(claims["aud"])
	if string(aud) != `["https://api.test","https://a.example.test/userinfo"]` {
		t.Errorf("aud = %s, want array", aud)
	}
	if _, ok := claims["gty"]; ok {
		t.Error("empty gty must be omitted")
	}
	if _, ok := claims["scope"]; ok {
		t.Error("empty scope must be omitted")
	}
	if claims["exp"].(float64)-claims["iat"].(float64) != DefaultAccessTokenLifetime.Seconds() {
		t.Errorf("default lifetime not applied: %v", claims)
	}
}

func TestAccessTokenRequiresAudience(t *testing.T) {
	m := &Minter{Keys: newTestKeys(t, "ten_a"), Now: fixedNow}
	if _, err := m.AccessToken(context.Background(), AccessTokenParams{TenantID: "ten_a", Issuer: "https://a/", Subject: "s", ClientID: "c"}); err == nil {
		t.Fatal("token minted without an audience")
	}
}

func TestIDToken(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	u := &store.User{UserID: "auth0|1", Email: "alice@example.com", EmailVerified: true, Name: "Alice", UpdatedAt: fixedNow()}
	authTime := fixedNow().Add(-time.Minute)
	raw, err := m.IDToken(context.Background(), IDTokenParams{
		TenantID: "ten_a", Issuer: "https://a.example.test/", ClientID: "spa", User: u,
		Scopes: []string{"openid", "email"}, Nonce: "n-123", SessionID: "sid-1",
		AuthTime: authTime, AccessToken: "the-access-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := verifyToken(t, km, "ten_a", raw)
	iat := float64(fixedNow().Unix())
	sum := sha256.Sum256([]byte("the-access-token"))
	want := map[string]any{
		"iss": "https://a.example.test/", "sub": "auth0|1", "aud": "spa",
		"iat": iat, "exp": iat + DefaultIDTokenLifetime.Seconds(), "auth_time": float64(authTime.Unix()),
		"nonce": "n-123", "sid": "sid-1", "email": "alice@example.com", "email_verified": true,
		"at_hash": base64.RawURLEncoding.EncodeToString(sum[:16]),
	}
	if diff := cmp.Diff(want, claims); diff != "" {
		t.Fatalf("claims (-want +got):\n%s", diff)
	}
}

func TestAMRClaim(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	for _, at := range []time.Time{{}, fixedNow()} {
		raw, err := m.IDToken(context.Background(), IDTokenParams{TenantID: "ten_a", Issuer: "https://a/", ClientID: "spa", User: &store.User{UserID: "u"}, Scopes: []string{"openid"}, MFAAt: at})
		if err != nil {
			t.Fatal(err)
		}
		claims, _ := verifyToken(t, km, "ten_a", raw)
		if at.IsZero() {
			if _, ok := claims["amr"]; ok {
				t.Fatal("unproved MFA claim")
			}
		} else if diff := cmp.Diff([]any{"mfa"}, claims["amr"]); diff != "" {
			t.Fatal(diff)
		}
	}
}

func TestAMRAtCodeIssue(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	tid := f.tenantID(t, "acme")
	af := &actionsFixture{fixture: f, tid: tid, az: &authz.Handlers{Store: f.st, Sessions: &session.Manager{Store: f.st, Now: fixedNow}, Now: fixedNow, Wrapper: f.wrapper}}
	cookie := af.sessionCookie(t)
	sess, err := f.st.Sessions().GetByTokenHash(ctx, tid, secrets.HashToken(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	const client, redirect = "rt-spa", "https://rt.acme.test/cb"
	before := af.authorizeWithCookie(t, client, redirect, "openid offline_access", cookie)
	if err = f.st.Sessions().MarkMFA(ctx, tid, sess.ID, fixedNow()); err != nil {
		t.Fatal(err)
	}
	after := af.authorizeWithCookie(t, client, redirect, "openid", cookie)
	exchange := func(code string) map[string]any {
		t.Helper()
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, client, redirect, pkceVerifier)})
		if rec.Code != 200 {
			t.Fatalf("exchange: %d %v", rec.Code, body)
		}
		return body
	}
	body := exchange(before)
	claims, _ := verifyToken(t, f.keys, tid, body["id_token"].(string))
	if _, ok := claims["amr"]; ok {
		t.Fatalf("session step-up after issue changed code AMR: %v", claims["amr"])
	}
	// A refresh grant keeps its own live-session semantics.
	status, refreshed := f.refresh(t, refreshForm(client, body["refresh_token"].(string)))
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, refreshed)
	}
	claims, _ = verifyToken(t, f.keys, tid, refreshed["id_token"].(string))
	if diff := cmp.Diff([]any{"mfa"}, claims["amr"]); diff != "" {
		t.Fatal(diff)
	}
	if err := f.st.Sessions().Delete(ctx, tid, sess.ID); err != nil {
		t.Fatal(err)
	}
	claims, _ = verifyToken(t, f.keys, tid, exchange(after)["id_token"].(string))
	if diff := cmp.Diff([]any{"mfa"}, claims["amr"]); diff != "" {
		t.Fatal(diff)
	}
}

func TestACRClaim(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	for _, tc := range []struct {
		acr  string
		at   time.Time
		want bool
	}{
		{"http://schemas.openid.net/pape/policies/2007/06/multi-factor", fixedNow(), true},
		{"", fixedNow(), false}, {"unknown", fixedNow(), false}, {"http://schemas.openid.net/pape/policies/2007/06/multi-factor", time.Time{}, false},
	} {
		raw, err := m.IDToken(t.Context(), IDTokenParams{TenantID: "ten_a", Issuer: "https://a.example.test/", ClientID: "spa", User: &store.User{UserID: "u"}, Scopes: []string{"openid"}, ACR: tc.acr, MFAAt: tc.at})
		if err != nil {
			t.Fatal(err)
		}
		got, _ := verifyToken(t, km, "ten_a", raw)
		if tc.want {
			if got["acr"] != tc.acr {
				t.Fatal("satisfied requested acr missing")
			}
			if methods, ok := got["amr"].([]any); !ok || len(methods) != 1 || methods[0] != "mfa" {
				t.Fatal("MFA method missing")
			}
		} else if got["acr"] != nil {
			t.Fatal("unsatisfied or unrequested acr emitted")
		}
	}
}

func TestIDTokenScopeClaims(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	u := &store.User{UserID: "oidc|upstream", PhoneNumber: "+15555550100", PhoneVerified: false, Identities: []store.Identity{{Provider: "oidc", UserID: "upstream", ProviderData: map[string]any{"locale": "en", "address": map[string]any{"country": "GB"}, "app_metadata": "private"}}}}
	raw, err := m.IDToken(t.Context(), IDTokenParams{TenantID: "ten_a", Issuer: "https://a.example.test/", ClientID: "spa", User: u, Scopes: []string{"openid", "profile", "phone", "address"}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := verifyToken(t, km, "ten_a", raw)
	if got["locale"] != "en" || got["phone_number"] != "+15555550100" || got["phone_number_verified"] != false || got["address"].(map[string]any)["country"] != "GB" || got["app_metadata"] != nil {
		t.Fatal("standard ID token claims missing or metadata exposed")
	}
}

func TestAccessTokenCustomClaimsKeepNumericDates(t *testing.T) {
	km := newTestKeys(t, "t")
	m := &Minter{Keys: km, Now: fixedNow}
	raw, err := m.AccessToken(t.Context(), AccessTokenParams{TenantID: "t", Issuer: "https://tenant.example/", Subject: "test-user", ClientID: "test-client", Audience: []string{"https://tenant.example/userinfo"}, Scopes: []string{"openid"}, CustomClaims: map[string]any{"https://zeroauthy.dev/userinfo": map[string]any{"auth_time": fixedNow().Unix()}}})
	if err != nil {
		t.Fatal(err)
	}
	var standard jwt.Claims
	if err := km.Verify(t.Context(), "t", raw, &standard); err != nil {
		t.Fatalf("registered numeric claims invalid: %v", err)
	}
	if standard.IssuedAt == nil || standard.IssuedAt.Time().Unix() != fixedNow().Unix() || standard.Expiry == nil {
		t.Fatal("registered dates changed")
	}
}
