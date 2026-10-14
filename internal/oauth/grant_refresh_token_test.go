package oauth

import (
	"context"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const acmeAPI = "https://api.acme.test"

// issueRefresh stores a refresh token for alice under clientID's policy, as
// the code grant would, and returns its value and record.
func (f *fixture) issueRefresh(t *testing.T, clientID string, scopes []string, audience string) (string, *store.RefreshToken) {
	t.Helper()
	ctx := context.Background()
	tenantID := f.tenantID(t, "acme")
	u, err := f.st.Users().FindByLogin(ctx, tenantID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.st.Clients().Get(ctx, tenantID, clientID)
	if err != nil {
		t.Fatal(err)
	}
	raw := secrets.RandomString(48)
	absolute, idle := refreshLifetimes(c.RefreshToken)
	rt := &store.RefreshToken{
		TenantID: tenantID, ID: "rt_" + secrets.RandomString(24), TokenHash: secrets.HashToken(raw),
		FamilyID: "rtf_" + secrets.RandomString(16), ClientID: clientID, UserID: u.UserID, SessionID: "sid-1",
		Scopes: scopes, Audience: audience, AuthTime: fixedNow().Add(-time.Hour),
		Rotating: c.RefreshToken.Rotating, CreatedAt: fixedNow(),
	}
	if absolute > 0 {
		rt.ExpiresAt = fixedNow().Add(absolute)
	}
	if idle > 0 {
		rt.IdleExpiresAt = fixedNow().Add(idle)
	}
	if err := f.st.RefreshTokens().Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	return raw, rt
}

func refreshForm(clientID, token string, extra ...string) url.Values {
	v := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {token}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func (f *fixture) refresh(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
	return rec.Code, body
}

func (f *fixture) storedRT(t *testing.T, raw string) *store.RefreshToken {
	t.Helper()
	rt, err := f.st.RefreshTokens().GetByTokenHash(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestRefreshRotates(t *testing.T) {
	f := newFixture(t)
	tenantID := f.tenantID(t, "acme")
	raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "profile", "offline_access", "read:things"}, acmeAPI)

	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw)})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	next, _ := body["refresh_token"].(string)
	if len(next) != 48 || next == raw || body["scope"] != "openid profile offline_access read:things" {
		t.Fatalf("body = %v", body)
	}
	at, _ := verifyToken(t, f.keys, tenantID, body["access_token"].(string))
	if aud, _ := at["aud"].([]any); len(aud) != 2 || aud[0] != acmeAPI || at["azp"] != "rt-spa" {
		t.Fatalf("access token = %v", at)
	}
	idt, _ := verifyToken(t, f.keys, tenantID, body["id_token"].(string))
	if idt["aud"] != "rt-spa" || idt["sid"] != "sid-1" || idt["nonce"] != nil || idt["at_hash"] == nil ||
		idt["auth_time"] != float64(fixedNow().Add(-time.Hour).Unix()) || idt["sub"] != at["sub"] {
		t.Fatalf("id token = %v", idt)
	}
	if old := f.storedRT(t, raw); old.RotatedAt == nil || old.RevokedAt != nil {
		t.Fatalf("old token = %+v", old)
	}
	succ := f.storedRT(t, next)
	if succ.FamilyID != rt.FamilyID || !succ.ExpiresAt.Equal(rt.ExpiresAt) ||
		!succ.IdleExpiresAt.Equal(fixedNow().Add(DefaultRefreshTokenIdleLifetime)) || !slices.Equal(succ.Scopes, rt.Scopes) {
		t.Fatalf("successor = %+v", succ)
	}

	// Reuse of the rotated token revokes the family, successor included.
	if code, body := f.refresh(t, refreshForm("rt-spa", raw)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("reuse = %d %v", code, body)
	}
	if code, body := f.refresh(t, refreshForm("rt-spa", next)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("successor after reuse = %d %v", code, body)
	}
}

func TestRefreshLeeway(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c, _ := f.st.Clients().Get(ctx, f.tenantID(t, "acme"), "rt-spa")
	c.RefreshToken.Leeway = 30
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	code1, b1 := f.refresh(t, refreshForm("rt-spa", raw))
	code2, b2 := f.refresh(t, refreshForm("rt-spa", raw)) // a retry inside the leeway
	if code1 != 200 || code2 != 200 || b1["refresh_token"] == b2["refresh_token"] {
		t.Fatalf("within leeway: %d %v / %d %v", code1, b1, code2, b2)
	}
	f.h.Now = func() time.Time { return fixedNow().Add(31 * time.Second) }
	if code, body := f.refresh(t, refreshForm("rt-spa", raw)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("after leeway = %d %v", code, body)
	}
	if code, _ := f.refresh(t, refreshForm("rt-spa", b1["refresh_token"].(string))); code != 400 {
		t.Fatalf("successor after reuse = %d; want 400", code)
	}
}

func TestRefreshNonRotating(t *testing.T) {
	f := newFixture(t)
	raw, rt := f.issueRefresh(t, "rt-web", []string{"openid", "offline_access"}, "")
	if rt.Rotating || !rt.IdleExpiresAt.Equal(fixedNow().Add(time.Hour)) {
		t.Fatalf("fixture token = %+v", rt)
	}
	at := fixedNow().Add(30 * time.Minute)
	f.h.Now = func() time.Time { return at }
	code, body := f.refresh(t, refreshForm("rt-web", raw, "client_secret", "rt-web-secret"))
	if code != 200 || body["refresh_token"] != nil || body["id_token"] == nil {
		t.Fatalf("refresh = %d %v", code, body)
	}
	if got := f.storedRT(t, raw); !got.IdleExpiresAt.Equal(at.Add(time.Hour)) || got.RotatedAt != nil {
		t.Fatalf("after use = %+v; want idle expiry slid to %v", got, at.Add(time.Hour))
	}
	if code, _ := f.refresh(t, refreshForm("rt-web", raw, "client_secret", "rt-web-secret")); code != 200 {
		t.Fatalf("second use = %d", code)
	}
	f.h.Now = func() time.Time { return at.Add(time.Hour + time.Second) }
	if code, body := f.refresh(t, refreshForm("rt-web", raw, "client_secret", "rt-web-secret")); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("idle-expired = %d %v", code, body)
	}
}

func TestRefreshNarrowsScope(t *testing.T) {
	f := newFixture(t)
	raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access", "read:things"}, acmeAPI)
	code, body := f.refresh(t, refreshForm("rt-spa", raw, "scope", "read:things read:things"))
	if code != 200 || body["scope"] != "read:things" || body["id_token"] != nil {
		t.Fatalf("narrowed refresh = %d %v", code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["aud"] != acmeAPI {
		t.Fatalf("aud = %v; want the API only", at["aud"])
	}
	if succ := f.storedRT(t, body["refresh_token"].(string)); !slices.Equal(succ.Scopes, rt.Scopes) {
		t.Fatalf("successor scopes = %v; want the original %v", succ.Scopes, rt.Scopes)
	}
}

func TestRefreshByAnotherClientLeavesTokenUntouched(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	if code, body := f.refresh(t, refreshForm("rt-web", raw, "client_secret", "rt-web-secret")); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("other client = %d %v", code, body)
	}
	if got := f.storedRT(t, raw); got.RotatedAt != nil || got.RevokedAt != nil {
		t.Fatalf("token changed by another client's attempt: %+v", got)
	}
	if code, body := f.refresh(t, refreshForm("rt-spa", raw)); code != 200 {
		t.Fatalf("owner after foreign attempt = %d %v", code, body)
	}
}

func TestRefreshRejects(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		prepare func(f *fixture, raw string, rt *store.RefreshToken) url.Values
		status  int
		code    string
	}{
		"missing token": {func(*fixture, string, *store.RefreshToken) url.Values {
			return url.Values{"grant_type": {"refresh_token"}, "client_id": {"rt-spa"}}
		}, 400, "invalid_request"},
		"unknown token": {func(*fixture, string, *store.RefreshToken) url.Values {
			return refreshForm("rt-spa", "not-a-real-token")
		}, 400, "invalid_grant"},
		"revoked": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			_ = f.st.RefreshTokens().RevokeFamily(ctx, rt.TenantID, rt.FamilyID, fixedNow())
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"absolute expiry": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			f.h.Now = func() time.Time { return rt.ExpiresAt }
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"idle expiry": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			f.h.Now = func() time.Time { return rt.IdleExpiresAt }
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"blocked user": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			u, _ := f.st.Users().Get(ctx, rt.TenantID, rt.UserID)
			u.Blocked = true
			_ = f.st.Users().Update(ctx, u)
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"deleted API": {func(f *fixture, raw string, rt *store.RefreshToken) url.Values {
			rs, _ := f.st.ResourceServers().GetByIdentifier(ctx, rt.TenantID, acmeAPI)
			_ = f.st.ResourceServers().Delete(ctx, rt.TenantID, rs.ID)
			return refreshForm("rt-spa", raw)
		}, 400, "invalid_grant"},
		"scope escalation": {func(_ *fixture, raw string, _ *store.RefreshToken) url.Values {
			return refreshForm("rt-spa", raw, "scope", "openid write:things")
		}, 400, "invalid_scope"},
		"audience mismatch": {func(_ *fixture, raw string, _ *store.RefreshToken) url.Values {
			return refreshForm("rt-spa", raw, "audience", "https://billing.acme.test")
		}, 400, "invalid_request"},
		"client without refresh grant": {func(_ *fixture, raw string, _ *store.RefreshToken) url.Values {
			return refreshForm("code-spa", raw)
		}, 403, "unauthorized_client"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access", "read:things"}, acmeAPI)
			code, body := f.refresh(t, tc.prepare(f, raw, rt))
			if code != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v; want %d %s", code, body, tc.status, tc.code)
			}
		})
	}
}

func TestRefreshReuseNotMaskedByOtherChecks(t *testing.T) {
	for name, extra := range map[string][]string{
		"audience mismatch": {"audience", "https://billing.acme.test"},
		"scope escalation":  {"scope", "openid write:things"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access", "read:things"}, acmeAPI)
			code, body := f.refresh(t, refreshForm("rt-spa", raw))
			if code != 200 {
				t.Fatalf("rotate = %d %v", code, body)
			}
			next := body["refresh_token"].(string)
			if code, b := f.refresh(t, refreshForm("rt-spa", raw, extra...)); code != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("reuse = %d %v", code, b)
			}
			if code, b := f.refresh(t, refreshForm("rt-spa", next)); code != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("successor = %d %v", code, b)
			}
		})
	}
}
