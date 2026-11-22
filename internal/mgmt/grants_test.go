package mgmt_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (e *usersEnv) grantUserVersion(t *testing.T, uid string) int64 {
	t.Helper()
	u, err := e.st.Users().Get(t.Context(), e.tn.ID, uid)
	if err != nil {
		t.Fatal(err)
	}
	return u.Version
}

func (e *usersEnv) checkTokenRevoked(t *testing.T, token *store.RefreshToken, want bool) {
	t.Helper()
	rt, err := e.st.RefreshTokens().Get(t.Context(), token.TenantID, token.ID)
	if err != nil {
		t.Fatal(err)
	}
	if (rt.RevokedAt != nil) != want {
		t.Errorf("token %s revoked = %t, want %t", token.ID, rt.RevokedAt != nil, want)
	}
}

func (e *usersEnv) deleteGrant(t *testing.T, id string) int {
	t.Helper()
	code, _ := e.call2(t, "delete:grants", "DELETE", "/api/v2/grants/"+id, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteGrant(w, r, id) })
	return code
}

func TestDeleteGrantRevokesTokens(t *testing.T) {
	for _, aud := range []string{"https://api.acme.test", "", "https://alias.test/userinfo"} {
		t.Run(aud, func(t *testing.T) {
			e := newUsersEnv(t)
			uid := e.mustCreate(t, map[string]any{"email": "grant@example.test"})["user_id"].(string)
			e.addGrant(t, "g", uid, "spa", aud)
			api := e.addToken(t, "api", uid, now)
			online := e.addToken(t, "online", uid, now, func(r *store.RefreshToken) { r.Access = "online" })
			userinfo := e.addToken(t, "userinfo", uid, now, func(r *store.RefreshToken) { r.Audience = ""; r.Origin = "https://alias.test" })
			otherOrigin := e.addToken(t, "other-origin", uid, now, func(r *store.RefreshToken) { r.Audience = ""; r.Origin = "https://other.test" })
			other := e.addToken(t, "other-api", uid, now, func(r *store.RefreshToken) { r.Audience = "https://other.test" })
			client := e.addToken(t, "other-client", uid, now, func(r *store.RefreshToken) { r.ClientID = "web" })
			user := e.addToken(t, "other-user", "auth0|other", now)
			tenant := e.addToken(t, "api", uid, now, func(r *store.RefreshToken) { r.TenantID = "other" })
			v := e.grantUserVersion(t, uid)
			var calls []string
			e.h.Store = lockSpy{Store: e.st, log: &calls}
			if code := e.deleteGrant(t, "g"); code != 204 {
				t.Fatalf("delete = %d", code)
			}
			if want := []string{"lock " + uid + " (tx)", "revoke spa (tx)", "bump " + uid + " (tx)"}; !eqStrings(calls, want) {
				t.Errorf("calls = %v, want %v", calls, want)
			}
			for _, rt := range []*store.RefreshToken{api, online} {
				e.checkTokenRevoked(t, rt, aud == "" || aud == api.Audience)
			}
			e.checkTokenRevoked(t, userinfo, aud == "" || aud == "https://alias.test/userinfo")
			e.checkTokenRevoked(t, otherOrigin, aud == "")
			e.checkTokenRevoked(t, other, aud == "")
			for _, rt := range []*store.RefreshToken{client, user, tenant} {
				e.checkTokenRevoked(t, rt, false)
			}
			if _, err := e.st.UserGrants().Find(t.Context(), e.tn.ID, "spa", uid, aud); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("grant after delete: %v", err)
			}
			if code := e.deleteGrant(t, "g"); code != 204 {
				t.Errorf("repeat delete = %d", code)
			}
			if got := e.grantUserVersion(t, uid); got != v+1 {
				t.Errorf("user version = %d, want %d", got, v+1)
			}
		})
	}
}

func TestDeleteGrantsByUser(t *testing.T) {
	e := newUsersEnv(t)
	uid := e.mustCreate(t, map[string]any{"email": "grants@example.test"})["user_id"].(string)
	api := e.addToken(t, "a", uid, now)
	web := e.addToken(t, "b", uid, now, func(r *store.RefreshToken) { r.ClientID = "web" })
	other := e.addToken(t, "other", uid, now, func(r *store.RefreshToken) { r.Audience = "other" })
	for _, r := range []*store.RefreshToken{api, web} {
		e.addGrant(t, "g-"+r.ID, uid, r.ClientID, r.Audience)
	}
	v := e.grantUserVersion(t, uid)
	for range 2 {
		code, _ := e.call2(t, "delete:grants", "DELETE", "/api/v2/grants?user_id="+url.QueryEscape(uid), e.h.DeleteGrantsByUser)
		if code != 204 {
			t.Fatal(code)
		}
	}
	e.checkTokenRevoked(t, api, true)
	e.checkTokenRevoked(t, web, true)
	e.checkTokenRevoked(t, other, false)
	if grants, err := e.st.UserGrants().ListByUser(t.Context(), e.tn.ID, uid); err != nil || len(grants) != 0 {
		t.Fatalf("remaining grants = %d, %v", len(grants), err)
	}
	if got := e.grantUserVersion(t, uid); got != v+1 {
		t.Errorf("user version = %d, want %d", got, v+1)
	}
}

func TestUnlinkKeepsGrant(t *testing.T) {
	e := newUsersEnv(t)
	uid := e.mustCreate(t, map[string]any{"email": "unlink@example.test"})["user_id"].(string)
	rt := e.addToken(t, "device", uid, now)
	e.addGrant(t, "g", uid, rt.ClientID, rt.Audience)
	code, _ := e.call2(t, "delete:refresh_tokens", "DELETE", "/api/v2/refresh-tokens/device", func(w http.ResponseWriter, r *http.Request) { e.h.DeleteRefreshToken(w, r, rt.ID) })
	if code != 202 {
		t.Fatal(code)
	}
	e.checkTokenRevoked(t, rt, true)
	if g, err := e.st.UserGrants().Find(t.Context(), e.tn.ID, rt.ClientID, uid, rt.Audience); err != nil || g.ID != "g" {
		t.Fatalf("grant after unlink = %v, %v", g, err)
	}
}

type grantCascadeStore struct {
	store.Store
	probe, revoke error
}

func (s grantCascadeStore) CheckRefreshTokensIISupport(context.Context) error { return s.probe }
func (s grantCascadeStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error {
		s.Store = tx
		return fn(s)
	})
}
func (s grantCascadeStore) RefreshTokens() store.RefreshTokens {
	return grantCascadeTokens{s.Store.RefreshTokens(), s.revoke}
}

type grantCascadeTokens struct {
	store.RefreshTokens
	err error
}

func (r grantCascadeTokens) RevokeByUserClient(ctx context.Context, tid, user, client, aud string, at time.Time) (int, error) {
	n, err := r.RefreshTokens.RevokeByUserClient(ctx, tid, user, client, aud, at)
	if err != nil {
		return n, err
	}
	return n, r.err
}

func TestGrantCascadeCapabilityAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name          string
		probe, revoke error
		status        int
	}{
		{"legacy", store.ErrRefreshTokensIIUnavailable, nil, 204},
		{"lost", store.ErrRefreshTokensIISupportLost, nil, 500},
		{"transport", errors.New("temporary store failure"), nil, 500},
		{"after revoke", nil, errors.Join(store.ErrRefreshTokensIIUnavailable, store.ErrRefreshTokensIISupportLost), 500},
	} {
		for _, bulk := range []bool{false, true} {
			name := tc.name + "/single"
			if bulk {
				name = tc.name + "/bulk"
			}
			t.Run(name, func(t *testing.T) {
				e := newUsersEnv(t)
				uid := e.mustCreate(t, map[string]any{"email": "plugin@example.test"})["user_id"].(string)
				rt := e.addToken(t, "r", uid, now)
				e.addGrant(t, "g", uid, rt.ClientID, rt.Audience)
				v := e.grantUserVersion(t, uid)
				e.h.Store = grantCascadeStore{e.st, tc.probe, tc.revoke}
				var code int
				if bulk {
					code, _ = e.call2(t, "delete:grants", "DELETE", "/api/v2/grants?user_id="+url.QueryEscape(uid), e.h.DeleteGrantsByUser)
				} else {
					code = e.deleteGrant(t, "g")
				}
				if code != tc.status {
					t.Fatalf("status = %d, want %d", code, tc.status)
				}
				_, err := e.st.UserGrants().Find(t.Context(), e.tn.ID, rt.ClientID, uid, rt.Audience)
				if tc.status == 204 && !errors.Is(err, store.ErrNotFound) || tc.status == 500 && err != nil {
					t.Errorf("grant lookup = %v", err)
				}
				e.checkTokenRevoked(t, rt, false)
				if got := e.grantUserVersion(t, uid); got != v {
					t.Errorf("user version = %d, want %d", got, v)
				}
			})
		}
	}
}

func (r spyTokens) RevokeByUserClient(ctx context.Context, tid, user, client, aud string, at time.Time) (int, error) {
	r.s.note("revoke " + client)
	return r.RefreshTokens.RevokeByUserClient(ctx, tid, user, client, aud, at)
}

func (u spyUsers) BumpVersion(ctx context.Context, tid, user string) (int64, error) {
	u.s.note("bump " + user)
	return u.Users.BumpVersion(ctx, tid, user)
}
