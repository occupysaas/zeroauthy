package mgmt_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestListRefreshTokens(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "list@x.test"})["user_id"].(string)
	for _, id := range []string{"c", "a", "b", "online", "expired"} {
		e.addToken(t, id, u, now, func(rt *store.RefreshToken) {
			if id == "online" {
				rt.Access = "online"
			}
			if id == "expired" {
				rt.ExpiresAt = now
			}
			if id == "b" {
				rt.ClientID = "other"
			}
		})
	}
	call := func(q string) (int, map[string]any) {
		return e.call2(t, "read:refresh_tokens", "GET", "/api/v2/refresh-tokens"+q, e.h.GetRefreshTokens)
	}
	if c, _ := call(""); c != 400 {
		t.Fatalf("missing user=%d", c)
	}
	if c, _ := call("?user_id=auth0%7C000000000000000000000000"); c != 404 {
		t.Fatalf("unknown user=%d", c)
	}
	q := "?user_id=" + url.QueryEscape(u)
	c, out := call(q + "&take=1")
	if c != 200 || !eqStrings(ids(t, out, "refresh_tokens"), []string{"a"}) || out["next"] != "a" {
		t.Fatalf("first=%d %v", c, out)
	}
	c, out = call(q + "&take=1&from=a")
	if c != 200 || !eqStrings(ids(t, out, "refresh_tokens"), []string{"b"}) || out["next"] != "b" {
		t.Fatalf("next=%d %v", c, out)
	}
	c, out = call(q + "&client_id=spa&fields=id&include_fields=true")
	if c != 200 || !eqStrings(ids(t, out, "refresh_tokens"), []string{"a", "c"}) {
		t.Fatalf("filter=%d %v", c, out)
	}
	for _, v := range out["refresh_tokens"].([]any) {
		if len(v.(map[string]any)) != 1 {
			t.Fatalf("projection=%v", v)
		}
	}
}

func TestBulkRevoke(t *testing.T) {
	for _, sel := range []string{"ids", "user", "client", "audience"} {
		t.Run(sel, func(t *testing.T) {
			e := newUsersEnv(t)
			u := e.mustCreate(t, map[string]any{"email": "revoke@x.test"})["user_id"].(string)
			old := e.addToken(t, "old", u, now)
			next := *old
			next.ID = "next"
			next.TokenHash = "hash-next"
			if err := e.st.RefreshTokens().Rotate(context.Background(), e.tn.ID, "old", &next, now, time.Minute); err != nil {
				t.Fatal(err)
			}
			e.addToken(t, "online", u, now, func(r *store.RefreshToken) { r.Access = "online" })
			body := map[string]any{"user_id": u}
			switch sel {
			case "ids":
				body = map[string]any{"ids": []string{"old", "online", "absent"}}
			case "client":
				body["client_id"] = "spa"
			case "audience":
				body["client_id"] = "spa"
				body["audience"] = old.Audience
			}
			rec, _ := e.do(t, m2mCaller("delete:refresh_tokens"), "POST", "/api/v2/refresh-tokens/revoke", body, e.h.RevokeRefreshTokens)
			if rec.Code != 202 {
				t.Fatalf("revoke=%d %s", rec.Code, rec.Body)
			}
			for _, id := range []string{"old", "next"} {
				r, err := e.st.RefreshTokens().Get(context.Background(), e.tn.ID, id)
				if err != nil || r.RevokedAt == nil {
					t.Fatalf("not revoked %s", id)
				}
			}
			r, _ := e.st.RefreshTokens().Get(context.Background(), e.tn.ID, "online")
			if r.RevokedAt != nil {
				t.Fatal("online revoked")
			}
		})
	}
	e := newUsersEnv(t)
	for _, body := range []map[string]any{{}, {"ids": []string{}}, {"client_id": "spa"}, {"user_id": "auth0|u", "audience": "api"}, {"user_id": "auth0|u", "ids": []string{"id"}}, {"ids": make([]string, 101)}, {"user_id": "auth0|u", "unknown": true}} {
		rec, _ := e.do(t, m2mCaller("delete:refresh_tokens"), "POST", "/api/v2/refresh-tokens/revoke", body, e.h.RevokeRefreshTokens)
		if rec.Code != 400 {
			t.Errorf("invalid selector %v=%d", body, rec.Code)
		}
	}
}

func TestPatchRefreshTokenMetadata(t *testing.T) { testTokenMetadata(t, false) }
func TestPatchSessionMetadata(t *testing.T)      { testTokenMetadata(t, true) }
func testTokenMetadata(t *testing.T, session bool) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "metadata@x.test"})["user_id"].(string)
	e.addToken(t, "token", u, now)
	e.addToken(t, "online", u, now, func(r *store.RefreshToken) { r.Access = "online" })
	e.addSession(t, "session", u, now)
	key, scope, id := "refresh_token_metadata", "update:refresh_tokens", "token"
	handler := func(w http.ResponseWriter, r *http.Request) { e.h.UpdateRefreshToken(w, r, id) }
	if session {
		key, scope, id = "session_metadata", "update:sessions", "session"
		handler = func(w http.ResponseWriter, r *http.Request) { e.h.UpdateSession(w, r, id) }
	}
	for _, md := range []any{map[string]any{"name": "one"}, map[string]any{"other": "two"}, nil, map[string]any{}} {
		rec, out := e.do(t, m2mCaller(scope), "PATCH", "/metadata", map[string]any{key: md}, handler)
		if rec.Code != 200 {
			t.Fatalf("patch=%d %s", rec.Code, rec.Body)
		}
		if m, ok := md.(map[string]any); ok && len(m) > 0 {
			if !jsonEqual(out.(map[string]any)[key], m) {
				t.Fatalf("metadata=%v", out)
			}
		}
	}
	many := map[string]any{}
	for i := 0; i < 26; i++ {
		many[fmt.Sprint(i)] = "value"
	}
	for _, md := range []any{many, map[string]any{"v": strings.Repeat("x", 256)}, map[string]any{strings.Repeat("k", 256): "v"}, map[string]any{"v": 3}, []any{}} {
		rec, _ := e.do(t, m2mCaller(scope), "PATCH", "/metadata", map[string]any{key: md}, handler)
		if rec.Code != 400 {
			t.Errorf("invalid md=%d", rec.Code)
		}
	}
	rec, _ := e.do(t, m2mCaller(scope), "PATCH", "/metadata", map[string]any{"unknown": true}, handler)
	if rec.Code != 400 {
		t.Fatal("unknown accepted")
	}
	if !session {
		id = "online"
		rec, _ := e.do(t, m2mCaller(scope), "PATCH", "/metadata", map[string]any{key: map[string]string{"k": "v"}}, handler)
		if rec.Code != 404 {
			t.Fatal("ORT exposed")
		}
	}
}

// A failed protected write must leave both token state and mint version intact.
func TestRefreshTokenManagementRollbackAndCapability(t *testing.T) {
	for _, mode := range []string{"rollback", "legacy", "lost", "transport"} {
		t.Run(mode, func(t *testing.T) {
			e := newUsersEnv(t)
			u := e.mustCreate(t, map[string]any{"email": "rollback@x.test"})["user_id"].(string)
			e.addToken(t, "rt", u, now)
			before, _ := e.st.Users().Get(t.Context(), e.tn.ID, u)
			probe := error(nil)
			switch mode {
			case "legacy":
				probe = store.ErrRefreshTokensIIUnavailable
			case "lost":
				probe = store.ErrRefreshTokensIISupportLost
			case "transport":
				probe = errors.New("temporary transport")
			}
			e.h.Store = metadataFaultStore{Store: e.st, probe: probe, fail: mode == "rollback"}
			e.h.Log = slog.New(slog.DiscardHandler)
			rec, _ := e.do(t, m2mCaller("delete:refresh_tokens"), "POST", "/revoke", map[string]any{"user_id": u}, e.h.RevokeRefreshTokens)
			want := 500
			if mode == "legacy" {
				want = 501
			}
			if rec.Code != want {
				t.Fatalf("status %d want %d", rec.Code, want)
			}
			rt, _ := e.st.RefreshTokens().Get(t.Context(), e.tn.ID, "rt")
			after, _ := e.st.Users().Get(t.Context(), e.tn.ID, u)
			if rt.RevokedAt != nil || after.Version != before.Version {
				t.Fatal("failed revoke persisted state")
			}
			rec, _ = e.do(t, m2mCaller("update:refresh_tokens"), "PATCH", "/metadata", map[string]any{"refresh_token_metadata": map[string]string{"value": "new"}}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateRefreshToken(w, r, "rt") })
			if rec.Code != want {
				t.Fatalf("metadata status %d want%d", rec.Code, want)
			}
			rt, _ = e.st.RefreshTokens().Get(t.Context(), e.tn.ID, "rt")
			if len(rt.Metadata) != 0 {
				t.Fatal("failed metadata persisted")
			}
		})
	}
}

type metadataFaultStore struct {
	store.Store
	probe error
	fail  bool
}

func (s metadataFaultStore) CheckRefreshTokensIISupport(context.Context) error { return s.probe }
func (s metadataFaultStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(metadataFaultStore{Store: tx, probe: s.probe, fail: s.fail}) })
}
func (s metadataFaultStore) RefreshTokens() store.RefreshTokens {
	return metadataFaultTokens{s.Store.RefreshTokens(), s.fail}
}

type metadataFaultTokens struct {
	store.RefreshTokens
	fail bool
}

func (r metadataFaultTokens) RevokeOfflineByUser(ctx context.Context, tid, user, client string, aud *string, at time.Time) (int, error) {
	n, e := r.RefreshTokens.RevokeOfflineByUser(ctx, tid, user, client, aud, at)
	if e == nil && r.fail {
		return n, errors.New("write failed")
	}
	return n, e
}
func (r metadataFaultTokens) UpdateMetadata(ctx context.Context, tid, id string, md map[string]string) (*store.RefreshToken, error) {
	rt, e := r.RefreshTokens.UpdateMetadata(ctx, tid, id, md)
	if e == nil && r.fail {
		return nil, errors.New("write failed")
	}
	return rt, e
}

func TestBulkRevokeAudienceOriginAndRetainedRecords(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "origin@x.test"})["user_id"].(string)
	for _, id := range []string{"alias", "other", "api", "online", "spent"} {
		e.addToken(t, id, u, now, func(r *store.RefreshToken) {
			r.Audience = ""
			r.Origin = "https://alias.example"
			switch id {
			case "other":
				r.Origin = "https://other.example"
			case "api":
				r.Audience = "https://api.example"
			case "online":
				r.Access = "online"
			case "spent":
				at := now.Add(-time.Minute)
				r.RotatedAt = &at
			}
		})
	}
	rec, _ := e.do(t, m2mCaller("delete:refresh_tokens"), "POST", "/revoke", map[string]any{"user_id": u, "client_id": "spa", "audience": "https://alias.example/userinfo"}, e.h.RevokeRefreshTokens)
	if rec.Code != 202 {
		t.Fatal(rec.Code)
	}
	for _, id := range []string{"alias", "spent", "other", "api", "online"} {
		rt, err := e.st.RefreshTokens().Get(t.Context(), e.tn.ID, id)
		if err != nil || (rt.RevokedAt != nil) != (id == "alias" || id == "spent") {
			t.Fatalf("origin selection wrong for %s", id)
		}
	}
}

func TestRefreshTokenUserInfoAudienceOrigin(t *testing.T) {
	e := newUsersEnv(t)
	uid := e.mustCreate(t, map[string]any{"email": "audience-origin@x.test"})["user_id"].(string)
	for id, origin := range map[string]string{"alias": "https://alias.example.test", "canonical": "https://login.acme.test", "other": "https://other.example.test", "legacy": ""} {
		e.addToken(t, id, uid, now, func(rt *store.RefreshToken) { rt.Audience = ""; rt.Origin = origin })
	}
	audience := func(t *testing.T, value map[string]any) string {
		t.Helper()
		resources, ok := value["resource_servers"].([]any)
		if !ok || len(resources) != 1 {
			t.Fatalf("resource servers=%v", value["resource_servers"])
		}
		got, _ := resources[0].(map[string]any)["audience"].(string)
		return got
	}
	t.Run("reported audience revokes exact issuing origin", func(t *testing.T) {
		code, out := e.call2(t, "read:refresh_tokens", "GET", "/api/v2/refresh-tokens?user_id="+url.QueryEscape(uid), e.h.GetRefreshTokens)
		if code != 200 {
			t.Fatal(code)
		}
		byID := map[string]map[string]any{}
		for _, item := range out["refresh_tokens"].([]any) {
			m := item.(map[string]any)
			byID[m["id"].(string)] = m
		}
		advertised := audience(t, byID["alias"])
		if advertised != "https://alias.example.test/userinfo" {
			t.Fatalf("alias audience = %q", advertised)
		}
		rec, _ := e.do(t, m2mCaller("delete:refresh_tokens"), "POST", "/api/v2/refresh-tokens/revoke", map[string]any{"user_id": uid, "client_id": "spa", "audience": advertised}, e.h.RevokeRefreshTokens)
		if rec.Code != 202 {
			t.Fatalf("revoke=%d", rec.Code)
		}
		for _, id := range []string{"alias", "canonical", "other", "legacy"} {
			rt, err := e.st.RefreshTokens().Get(t.Context(), e.tn.ID, id)
			if err != nil || (rt.RevokedAt != nil) != (id == "alias") {
				t.Fatalf("revocation origin incorrect for %s", id)
			}
		}
	})
	t.Run("canonical legacy view through alias", func(t *testing.T) {
		for _, view := range []string{"checkpoint-list", "user-list", "get", "metadata"} {
			t.Run(view, func(t *testing.T) {
				var item map[string]any
				handler := func(w http.ResponseWriter, r *http.Request) {
					r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: e.tn, Host: "alias.example.test"}))
					switch view {
					case "checkpoint-list":
						e.h.GetRefreshTokens(w, r)
					case "user-list":
						e.h.GetUserRefreshTokens(w, r, uid)
					case "get":
						e.h.GetRefreshToken(w, r, "legacy")
					case "metadata":
						e.h.UpdateRefreshToken(w, r, "legacy")
					}
				}
				method, scope, body := "GET", "read:refresh_tokens", any(nil)
				if view == "metadata" {
					method, scope, body = "PATCH", "update:refresh_tokens", map[string]any{"refresh_token_metadata": map[string]string{"label": "legacy"}}
				}
				rec, out := e.do(t, m2mCaller(scope), method, "/view?user_id="+url.QueryEscape(uid), body, handler)
				if rec.Code != 200 {
					t.Fatalf("view=%d %s", rec.Code, rec.Body)
				}
				result := out.(map[string]any)
				switch view {
				case "checkpoint-list", "user-list":
					key := "refresh_tokens"
					if view == "user-list" {
						key = "tokens"
					}
					for _, v := range result[key].([]any) {
						m := v.(map[string]any)
						if m["id"] == "legacy" {
							item = m
						}
					}
				default:
					item = result
				}
				if item == nil || audience(t, item) != "https://login.acme.test/userinfo" {
					t.Fatalf("legacy audience via alias = %v", item)
				}
			})
		}
	})
}
