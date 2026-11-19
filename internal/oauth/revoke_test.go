package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func (f *fixture) revoke(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	h := contract.WrapResponses(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthRevoke)))
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestRevokeRevokesFamily(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	_, body := f.refresh(t, refreshForm("rt-spa", raw)) // rotate once so the family has two tokens
	next := body["refresh_token"].(string)

	code, body := f.revoke(t, url.Values{"client_id": {"rt-spa"}, "token": {next}})
	if code != 200 || body != nil {
		t.Fatalf("revoke = %d %v", code, body)
	}
	for _, tok := range []string{raw, next} {
		if got := f.storedRT(t, tok); got.RevokedAt == nil {
			t.Errorf("token in the family not revoked: %+v", got)
		}
	}
	if code, body := f.refresh(t, refreshForm("rt-spa", next)); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh after revoke = %d %v", code, body)
	}
}

func TestRevokeVariants(t *testing.T) {
	f := newFixture(t)
	raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	f.revokeGrantFlag(t, rt.TenantID, true)
	sibling, _ := f.issueRefresh(t, rt.ClientID, rt.Scopes, rt.Audience)
	grantAudience := "https://acme.example.test/userinfo"
	_, err := f.st.UserGrants().Upsert(t.Context(), &store.UserGrant{TenantID: rt.TenantID, ID: "g", ClientID: rt.ClientID, UserID: rt.UserID, Audience: grantAudience})
	if err != nil {
		t.Fatal(err)
	}
	aliasRaw := secrets.RandomString(48)
	alias := *rt
	alias.ID, alias.FamilyID, alias.TokenHash, alias.Origin = "other-origin", "other-family", secrets.HashToken(aliasRaw), "https://alias.example.test"
	if err := f.st.RefreshTokens().Create(t.Context(), &alias); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		form   url.Values
		status int
		code   string
	}{
		"other origin":      {url.Values{"client_id": {"rt-spa"}, "token": {aliasRaw}}, 200, ""},
		"unknown token":     {url.Values{"client_id": {"rt-spa"}, "token": {"no-such-token"}}, 200, ""},
		"another client":    {url.Values{"client_id": {"rt-web"}, "client_secret": {"rt-web-secret"}, "token": {raw}}, 400, "invalid_grant"},
		"missing token":     {url.Values{"client_id": {"rt-spa"}}, 400, "invalid_request"},
		"bad client secret": {url.Values{"client_id": {"rt-web"}, "client_secret": {"wrong"}, "token": {raw}}, 401, "invalid_client"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			code, body := f.revoke(t, tc.form)
			if code != tc.status || (tc.code != "" && body["error"] != tc.code) {
				t.Fatalf("got %d %v; want %d %s", code, body, tc.status, tc.code)
			}
		})
	}
	for _, token := range []string{raw, sibling, aliasRaw} {
		if f.storedRT(t, token).RevokedAt != nil {
			t.Fatal("invalid presentation revoked a token")
		}
	}
	if _, err := f.st.UserGrants().Find(t.Context(), rt.TenantID, rt.ClientID, rt.UserID, grantAudience); err != nil {
		t.Fatal(err)
	}
}

// revokeRaw posts a revoke request with an arbitrary content type, body and
// optional HTTP Basic credentials.
func (f *fixture) revokeRaw(t *testing.T, contentType, body string, basic ...string) *httptest.ResponseRecorder {
	t.Helper()
	h := contract.WrapResponses(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthRevoke)))
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRevokeWithHTTPBasic(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "rt-basic", []string{"openid", "offline_access"}, "")
	form := "application/x-www-form-urlencoded"

	rec := f.revokeRaw(t, form, url.Values{"token": {raw}}.Encode(), "rt-basic", "wrong")
	if rec.Code != 401 || f.storedRT(t, raw).RevokedAt != nil {
		t.Fatalf("bad Basic secret = %d; token %+v", rec.Code, f.storedRT(t, raw))
	}
	rec = f.revokeRaw(t, form, url.Values{"token": {raw}}.Encode(), "rt-basic", "rt-basic-secret")
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("Basic revoke = %d %q", rec.Code, rec.Body)
	}
	if f.storedRT(t, raw).RevokedAt == nil {
		t.Fatal("token not revoked through HTTP Basic")
	}
}

func TestRevokeWithJSONBody(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, "")
	rec := f.revokeRaw(t, "application/json", `{"client_id":"rt-spa","token":"`+raw+`"}`)
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("JSON revoke = %d %q", rec.Code, rec.Body)
	}
	if f.storedRT(t, raw).RevokedAt == nil {
		t.Fatal("token not revoked through a JSON body")
	}
}

func TestRevokeUnknownTokenHasEmptyBody(t *testing.T) {
	f := newFixture(t)
	rec := f.revokeRaw(t, "application/x-www-form-urlencoded", url.Values{"client_id": {"rt-spa"}, "token": {"no-such-token"}}.Encode())
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("unknown token = %d %q", rec.Code, rec.Body)
	}
}

func TestRevokeDeletesGrantFlag(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		aud     string
	}{
		{"disabled", false, acmeAPI}, {"enabled", true, acmeAPI}, {"userinfo", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			ctx := t.Context()
			raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, tc.aud)
			sibling, _ := f.issueRefresh(t, "rt-spa", rt.Scopes, tc.aud)
			otherAudience := acmeAPI
			if tc.aud == acmeAPI {
				otherAudience = ""
			}
			other, _ := f.issueRefresh(t, "rt-spa", rt.Scopes, otherAudience)
			f.revokeGrantFlag(t, rt.TenantID, tc.enabled)
			aud := tc.aud
			if aud == "" {
				aud = "https://acme.example.test/userinfo"
			}
			_, err := f.st.UserGrants().Upsert(ctx, &store.UserGrant{ID: "g", TenantID: rt.TenantID, ClientID: rt.ClientID, UserID: rt.UserID, Audience: aud})
			if err != nil {
				t.Fatal(err)
			}
			u, err := f.st.Users().Get(ctx, rt.TenantID, rt.UserID)
			if err != nil {
				t.Fatal(err)
			}
			code, body := f.revoke(t, url.Values{"client_id": {rt.ClientID}, "token": {raw}})
			if code != 200 || body != nil {
				t.Fatalf("revoke = %d %v", code, body)
			}
			if rt := f.storedRT(t, raw); rt.RevokedAt == nil {
				t.Error("presented token remains live")
			}
			if rt := f.storedRT(t, sibling); (rt.RevokedAt != nil) != tc.enabled {
				t.Errorf("sibling revoked = %t", rt.RevokedAt != nil)
			}
			if rt := f.storedRT(t, other); rt.RevokedAt != nil {
				t.Error("other audience revoked")
			}
			_, err = f.st.UserGrants().Find(ctx, rt.TenantID, rt.ClientID, rt.UserID, aud)
			if tc.enabled && !errors.Is(err, store.ErrNotFound) || !tc.enabled && err != nil {
				t.Errorf("grant lookup = %v", err)
			}
			after, err := f.st.Users().Get(ctx, rt.TenantID, rt.UserID)
			if err != nil {
				t.Fatal(err)
			}
			want := u.Version
			if tc.enabled {
				want++
			}
			if after.Version != want {
				t.Errorf("user version = %d, want %d", after.Version, want)
			}
			code, body = f.refresh(t, refreshForm(rt.ClientID, sibling))
			if tc.enabled && (code != 400 || body["error"] != "invalid_grant") || !tc.enabled && code != 200 {
				t.Errorf("sibling exchange = %d %v", code, body["error"])
			}
			if code, body := f.refresh(t, refreshForm(rt.ClientID, other)); code != 200 {
				t.Errorf("other audience exchange = %d %v", code, body["error"])
			}
		})
	}
}

func (f *fixture) revokeGrantFlag(t *testing.T, tid string, enabled bool) {
	t.Helper()
	tn, err := f.st.Tenants().Get(t.Context(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if tn.SettingsExtra == nil {
		tn.SettingsExtra = map[string]any{}
	}
	tn.SettingsExtra["flags"] = map[string]any{"revoke_refresh_token_grant": enabled}
	if err := f.st.Tenants().Update(t.Context(), tn); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeGrantRotationOverlap(t *testing.T) {
	for _, tc := range []struct {
		name  string
		twice bool
	}{{"live parent", false}, {"spent ancestor", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.rotationPolicy(t, true, 30)
			raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, acmeAPI)
			next := f.exchangeSuccessor(t, raw)
			if tc.twice {
				next = f.exchangeSuccessor(t, next)
			}
			f.revokeGrantFlag(t, rt.TenantID, true)
			sibling, _ := f.issueRefresh(t, "rt-spa", rt.Scopes, acmeAPI)
			_, err := f.st.UserGrants().Upsert(t.Context(), &store.UserGrant{ID: "g", TenantID: rt.TenantID, ClientID: rt.ClientID, UserID: rt.UserID, Audience: acmeAPI})
			if err != nil {
				t.Fatal(err)
			}
			if code, body := f.revoke(t, url.Values{"client_id": {rt.ClientID}, "token": {raw}}); code != 200 {
				t.Fatalf("revoke = %d %v", code, body)
			}
			if f.storedRT(t, next).RevokedAt == nil {
				t.Error("own family remains live")
			}
			if revoked := f.storedRT(t, sibling).RevokedAt != nil; revoked == tc.twice {
				t.Errorf("sibling revoked = %t", revoked)
			}
			_, err = f.st.UserGrants().Find(t.Context(), rt.TenantID, rt.ClientID, rt.UserID, acmeAPI)
			if tc.twice && err != nil || !tc.twice && !errors.Is(err, store.ErrNotFound) {
				t.Errorf("grant lookup = %v", err)
			}
		})
	}
}

func TestRevokeGrantCapability(t *testing.T) {
	for _, tc := range []struct {
		name   string
		probe  error
		status int
	}{
		{"legacy", store.ErrRefreshTokensIIUnavailable, 200}, {"lost", store.ErrRefreshTokensIISupportLost, 500}, {"transport", errors.New("temporary store failure"), 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			raw, rt := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
			sibling, _ := f.issueRefresh(t, rt.ClientID, rt.Scopes, rt.Audience)
			f.revokeGrantFlag(t, rt.TenantID, true)
			f.h.Store = refreshProbeStore{f.st, tc.probe}
			code, _ := f.revoke(t, url.Values{"client_id": {rt.ClientID}, "token": {raw}})
			if code != tc.status || (f.storedRT(t, raw).RevokedAt != nil) != (tc.status == 200) || f.storedRT(t, sibling).RevokedAt != nil {
				t.Fatalf("revoke = %d, want %d with family-only success for legacy", code, tc.status)
			}
		})
	}
}

func TestRevokeGrantRechecksPresentedToken(t *testing.T) {
	f := newFixture(t)
	raw, rt := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
	sibling, _ := f.issueRefresh(t, rt.ClientID, rt.Scopes, rt.Audience)
	f.revokeGrantFlag(t, rt.TenantID, true)
	_, err := f.st.UserGrants().Upsert(t.Context(), &store.UserGrant{ID: "g", TenantID: rt.TenantID, ClientID: rt.ClientID, UserID: rt.UserID, Audience: rt.Audience})
	if err != nil {
		t.Fatal(err)
	}
	f.h.Store = nativeBeforeTxStore{f.st, func() {
		if err := f.st.RefreshTokens().Revoke(t.Context(), rt.TenantID, rt.ID, fixedNow()); err != nil {
			t.Fatal(err)
		}
	}}
	code, _ := f.revoke(t, url.Values{"client_id": {rt.ClientID}, "token": {raw}})
	if code != 200 || f.storedRT(t, sibling).RevokedAt != nil {
		t.Fatalf("stale revocation = %d, another family revoked = %t", code, f.storedRT(t, sibling).RevokedAt != nil)
	}
	if _, err := f.st.UserGrants().Find(t.Context(), rt.TenantID, rt.ClientID, rt.UserID, rt.Audience); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeGrantParentExpiresBeforeLock(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	f.rotationPolicy(t, true, 30)
	raw, parent := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, acmeAPI)
	deadline := fixedNow().Add(2 * time.Second)
	if err := f.st.RefreshTokens().Touch(ctx, parent.TenantID, parent.ID, deadline); err != nil {
		t.Fatal(err)
	}
	successor := f.exchangeSuccessor(t, raw)
	if refreshExpired(f.storedRT(t, successor), deadline) {
		t.Fatal("successor must still be live at the parent's idle deadline")
	}
	sibling, _ := f.issueRefresh(t, parent.ClientID, parent.Scopes, parent.Audience)
	f.revokeGrantFlag(t, parent.TenantID, true)
	g, err := f.st.UserGrants().Upsert(ctx, &store.UserGrant{ID: "g", TenantID: parent.TenantID, ClientID: parent.ClientID, UserID: parent.UserID, Audience: parent.Audience})
	if err != nil {
		t.Fatal(err)
	}
	user, err := f.st.Users().Get(ctx, parent.TenantID, parent.UserID)
	if err != nil {
		t.Fatal(err)
	}
	now := deadline.Add(-time.Second)
	f.h.Now = func() time.Time { return now }
	f.h.Store = nativeBeforeTxStore{f.st, func() { now = deadline }}
	if code, body := f.revoke(t, url.Values{"client_id": {parent.ClientID}, "token": {raw}}); code != 200 || body != nil {
		t.Fatalf("revoke = %d %v", code, body)
	}
	for name, token := range map[string]string{"parent": raw, "successor": successor} {
		if rt := f.storedRT(t, token); rt.RevokedAt == nil || !rt.RevokedAt.Equal(deadline) {
			t.Errorf("%s family member revoked at %v, want %v", name, rt.RevokedAt, deadline)
		}
	}
	if f.storedRT(t, sibling).RevokedAt != nil {
		t.Error("expired parent revoked an independent family")
	}
	if got, err := f.st.UserGrants().Find(ctx, g.TenantID, g.ClientID, g.UserID, g.Audience); err != nil || got.ID != g.ID {
		t.Errorf("consent after revoke = %v, %v", got, err)
	}
	after, err := f.st.Users().Get(ctx, parent.TenantID, parent.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != user.Version {
		t.Errorf("user version = %d, want %d", after.Version, user.Version)
	}
}
