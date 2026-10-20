package mgmt_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (e *usersEnv) addSession(t *testing.T, id, userID string, created time.Time, mutate ...func(*store.LoginSession)) *store.LoginSession {
	t.Helper()
	s := &store.LoginSession{TenantID: e.tn.ID, ID: id, TokenHash: "hash-" + id, UserID: userID, Connection: dbConn,
		AuthenticatedAt: created, ClientIDs: []string{"spa"}, ExpiresAt: now.Add(24 * time.Hour), IdleExpiresAt: now.Add(time.Hour),
		CreatedAt: created, UpdatedAt: created, LastInteractedAt: created,
		InitialIP: "203.0.113.7", InitialUserAgent: "agent-1", LastIP: "198.51.100.9", LastUserAgent: "agent-2"}
	for _, m := range mutate {
		m(s)
	}
	if err := e.st.Sessions().Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *usersEnv) addToken(t *testing.T, id, userID string, created time.Time, mutate ...func(*store.RefreshToken)) *store.RefreshToken {
	t.Helper()
	tk := &store.RefreshToken{TenantID: e.tn.ID, ID: id, TokenHash: "hash-" + id, FamilyID: "fam-" + id, ClientID: "spa", UserID: userID,
		Scopes: []string{"openid", "offline_access", "read:things"}, Audience: "https://api.acme.test", Rotating: true,
		ExpiresAt: now.Add(24 * time.Hour), IdleExpiresAt: now.Add(time.Hour), CreatedAt: created}
	for _, m := range mutate {
		m(tk)
	}
	if err := e.st.RefreshTokens().Create(context.Background(), tk); err != nil {
		t.Fatal(err)
	}
	return tk
}

func (e *usersEnv) call2(t *testing.T, scope, method, target string, fn http.HandlerFunc) (int, map[string]any) {
	t.Helper()
	rec, out := e.do(t, m2mCaller(scope), method, target, nil, fn)
	m, _ := out.(map[string]any)
	return rec.Code, m
}

func (e *usersEnv) sessions(t *testing.T, id, query string) (int, map[string]any) {
	return e.call2(t, "read:sessions", "GET", "/api/v2/users/"+url.PathEscape(id)+"/sessions"+query, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetUserSessions(w, r, id)
	})
}

func (e *usersEnv) tokens(t *testing.T, id, query string) (int, map[string]any) {
	return e.call2(t, "read:refresh_tokens", "GET", "/api/v2/users/"+url.PathEscape(id)+"/refresh-tokens"+query, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetUserRefreshTokens(w, r, id)
	})
}

func ids(t *testing.T, out map[string]any, key string) []string {
	t.Helper()
	list, _ := out[key].([]any)
	var got []string
	for _, it := range list {
		got = append(got, it.(map[string]any)["id"].(string))
	}
	return got
}

func eqStrings(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

func TestUserSessionObject(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "s@x.test"})["user_id"].(string)
	created := now.Add(-time.Hour)
	s := e.addSession(t, "sess_a", u, created)
	code, out := e.sessions(t, u, "")
	if code != 200 {
		t.Fatalf("list = %d %v", code, out)
	}
	ts := "2026-10-18T11:00:00.000Z"
	want := map[string]any{
		"id": "sess_a", "user_id": u, "created_at": ts, "updated_at": ts, "authenticated_at": ts,
		"authentication":  map[string]any{"methods": []any{map[string]any{"name": "pwd", "timestamp": ts}}},
		"idle_expires_at": "2026-10-18T13:00:00.000Z", "expires_at": "2026-10-19T12:00:00.000Z",
		"device":  map[string]any{"initial_user_agent": "agent-1", "initial_ip": "203.0.113.7", "last_user_agent": "agent-2", "last_ip": "198.51.100.9"},
		"clients": []any{map[string]any{"client_id": "spa"}}, "last_interacted_at": ts, "cookie": map[string]any{"mode": "persistent"},
	}
	list := out["sessions"].([]any)
	if len(list) != 1 || !jsonEqual(list[0], want) {
		t.Fatalf("session = %v\nwant %v", list, want)
	}
	if out["next"] == nil || out["next"] == "" {
		t.Errorf("next missing on a non-empty page: %v", out)
	}
	// GET /sessions/{id} gives the same object.
	code, one := e.call2(t, "read:sessions", "GET", "/api/v2/sessions/"+s.ID, func(w http.ResponseWriter, r *http.Request) { e.h.GetSession(w, r, s.ID) })
	if code != 200 || !jsonEqual(one, want) {
		t.Errorf("get session = %d %v", code, one)
	}
	// Unknown, malformed: 404 with no errorCode.
	for _, id := range []string{"nope", "a b/c", strings.Repeat("x", 500)} {
		code, out := e.call2(t, "read:sessions", "GET", "/api/v2/sessions/x", func(w http.ResponseWriter, r *http.Request) { e.h.GetSession(w, r, id) })
		if code != 404 || out["errorCode"] != nil || out["message"] != "The session does not exist." {
			t.Errorf("get session %q = %d %v", id, code, out)
		}
	}
}

func TestUserSessionsListErrors(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "s@x.test"})["user_id"].(string)
	if code, out := e.sessions(t, "auth0|000000000000000000000000", ""); code != 404 || out["errorCode"] != "inexistent_user" {
		t.Errorf("unknown user = %d %v", code, out)
	}
	if code, out := e.sessions(t, "nope", ""); code != 400 || out["errorCode"] != "invalid_uri" {
		t.Errorf("malformed user = %d %v", code, out)
	}
	code, out := e.sessions(t, u, "?take=101")
	if code != 400 || out["errorCode"] != "invalid_query_string" ||
		out["message"] != "Query validation error: 'Value 101 is greater than maximum 100' on property take (Number of results per page. Defaults to 50)." {
		t.Errorf("take=101 = %d %v", code, out)
	}
	for _, q := range []string{"?take=0", "?take=x", "?take=-1"} {
		if code, out := e.sessions(t, u, q); code != 400 || out["errorCode"] != "invalid_query_string" {
			t.Errorf("%s = %d %v", q, code, out)
		}
	}
	code, out = e.sessions(t, u, "?from=garbage")
	if code != 400 || out["errorCode"] != "invalid_query_string" || !strings.HasPrefix(fmt.Sprint(out["message"]), "The checkpoint ID provided in the 'from' parameter has expired or is invalid") {
		t.Errorf("bad from = %d %v", code, out)
	}
	// An empty list has no next; paging parameters are ignored.
	code, out = e.sessions(t, u, "?page=3&per_page=1&include_totals=true")
	if _, has := out["next"]; code != 200 || has || len(out["sessions"].([]any)) != 0 {
		t.Errorf("empty = %d %v", code, out)
	}
}

func TestCheckpointPagingThreePages(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "s@x.test"})["user_id"].(string)
	// Five sessions, two sharing a creation time (the ID breaks the tie).
	times := []time.Duration{-5, -4, -3, -3, -1}
	for i, d := range times {
		e.addSession(t, fmt.Sprintf("s%d", i), u, now.Add(d*time.Minute))
	}
	want := []string{"s4", "s3", "s2", "s1", "s0"}
	var got []string
	from := ""
	for page := 0; page < 3; page++ {
		q := "?take=2"
		if from != "" {
			q += "&from=" + url.QueryEscape(from)
		}
		code, out := e.sessions(t, u, q)
		if code != 200 {
			t.Fatalf("page %d = %d %v", page, code, out)
		}
		got = append(got, ids(t, out, "sessions")...)
		next, _ := out["next"].(string)
		if next == "" {
			t.Fatalf("page %d has no next: %v", page, out)
		}
		from = next
	}
	if !eqStrings(got, want) {
		t.Errorf("three pages = %v, want %v", got, want)
	}
	// The page after the last is empty, with no next.
	code, out := e.sessions(t, u, "?take=2&from="+url.QueryEscape(from))
	if _, has := out["next"]; code != 200 || has || len(ids(t, out, "sessions")) != 0 {
		t.Errorf("past the end = %d %v", code, out)
	}
	// A session deleted between pages neither repeats nor skips another.
	_, first := e.sessions(t, u, "?take=2")
	_ = e.st.Sessions().Delete(context.Background(), e.tn.ID, "s4")
	_, second := e.sessions(t, u, "?take=2&from="+url.QueryEscape(first["next"].(string)))
	if g := ids(t, second, "sessions"); !eqStrings(g, []string{"s2", "s1"}) {
		t.Errorf("page 2 after a delete = %v", g)
	}
}

func TestExpiredEntriesFiltered(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "s@x.test"})["user_id"].(string)
	e.addSession(t, "live", u, now.Add(-time.Minute))
	e.addSession(t, "absolute", u, now.Add(-2*time.Minute), func(s *store.LoginSession) { s.ExpiresAt = now.Add(-time.Second) })
	e.addSession(t, "idle", u, now.Add(-3*time.Minute), func(s *store.LoginSession) { s.IdleExpiresAt = now.Add(-time.Second) })
	e.addSession(t, "zero", u, now.Add(-4*time.Minute), func(s *store.LoginSession) { s.ExpiresAt = time.Time{} })
	_, out := e.sessions(t, u, "")
	if g := ids(t, out, "sessions"); !eqStrings(g, []string{"live"}) {
		t.Errorf("sessions = %v, want [live]", g)
	}
	if code, _ := e.call2(t, "read:sessions", "GET", "/api/v2/sessions/absolute", func(w http.ResponseWriter, r *http.Request) { e.h.GetSession(w, r, "absolute") }); code != 404 {
		t.Errorf("get expired session = %d", code)
	}
	e.addToken(t, "t_live", u, now.Add(-time.Minute))
	e.addToken(t, "t_abs", u, now.Add(-2*time.Minute), func(r *store.RefreshToken) { r.ExpiresAt = now.Add(-time.Second) })
	e.addToken(t, "t_idle", u, now.Add(-3*time.Minute), func(r *store.RefreshToken) { r.IdleExpiresAt = now.Add(-time.Second) })
	e.addToken(t, "t_never", u, now.Add(-4*time.Minute), func(r *store.RefreshToken) { r.ExpiresAt, r.IdleExpiresAt = time.Time{}, time.Time{} })
	_, out = e.tokens(t, u, "")
	if g := ids(t, out, "tokens"); !eqStrings(g, []string{"t_live", "t_never"}) {
		t.Errorf("tokens = %v, want [t_live t_never]", g)
	}
}

func TestUserRefreshTokenObject(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "s@x.test"})["user_id"].(string)
	created := now.Add(-time.Hour)
	e.addSession(t, "sess_a", u, created)
	e.addToken(t, "rt_a", u, created, func(r *store.RefreshToken) { r.SessionID = "sess_a" })
	e.addToken(t, "rt_b", u, created.Add(-time.Minute), func(r *store.RefreshToken) {
		r.Audience, r.Rotating, r.ExpiresAt, r.IdleExpiresAt, r.Scopes = "", false, time.Time{}, time.Time{}, []string{"openid"}
	})
	code, out := e.tokens(t, u, "")
	if code != 200 {
		t.Fatalf("list = %d %v", code, out)
	}
	ts := "2026-10-18T11:00:00.000Z"
	wantA := map[string]any{
		"id": "rt_a", "user_id": u, "created_at": ts, "idle_expires_at": "2026-10-18T13:00:00.000Z", "expires_at": "2026-10-19T12:00:00.000Z",
		"client_id": "spa", "session_id": "sess_a", "rotating": true,
		"resource_servers":  []any{map[string]any{"audience": "https://api.acme.test", "scopes": "openid offline_access read:things"}},
		"device":            map[string]any{"initial_user_agent": "agent-1", "initial_ip": "203.0.113.7", "last_user_agent": "agent-2", "last_ip": "198.51.100.9"},
		"last_exchanged_at": nil,
	}
	wantB := map[string]any{
		"id": "rt_b", "user_id": u, "created_at": "2026-10-18T10:59:00.000Z", "idle_expires_at": nil, "expires_at": nil,
		"client_id": "spa", "session_id": nil, "rotating": false,
		"resource_servers":  []any{map[string]any{"audience": "https://login.acme.test/userinfo", "scopes": "openid"}},
		"last_exchanged_at": nil,
	}
	list := out["tokens"].([]any)
	if len(list) != 2 || !jsonEqual(list[0], wantA) || !jsonEqual(list[1], wantB) {
		t.Fatalf("tokens = %v\nwant %v %v", list, wantA, wantB)
	}
	if out["next"] == nil {
		t.Errorf("next missing")
	}
	code, one := e.call2(t, "read:refresh_tokens", "GET", "/api/v2/refresh-tokens/rt_a", func(w http.ResponseWriter, r *http.Request) { e.h.GetRefreshToken(w, r, "rt_a") })
	if code != 200 || !jsonEqual(one, wantA) {
		t.Errorf("get token = %d %v", code, one)
	}
	for _, id := range []string{"nope", "dcr_xxxxxxxxxxxxxxxx"} {
		code, out := e.call2(t, "read:refresh_tokens", "GET", "/api/v2/refresh-tokens/x", func(w http.ResponseWriter, r *http.Request) { e.h.GetRefreshToken(w, r, id) })
		if code != 404 || out["errorCode"] != nil || out["message"] != "The refresh token does not exist." {
			t.Errorf("get token %q = %d %v", id, code, out)
		}
	}
	// A revoked token is gone; a token whose session is gone has no device.
	_ = e.st.Sessions().Delete(context.Background(), e.tn.ID, "sess_a")
	_, one = e.call2(t, "read:refresh_tokens", "GET", "/api/v2/refresh-tokens/rt_a", func(w http.ResponseWriter, r *http.Request) { e.h.GetRefreshToken(w, r, "rt_a") })
	if _, has := one["device"]; has || one["id"] != "rt_a" {
		t.Errorf("token without session = %v", one)
	}
	_ = e.st.RefreshTokens().Revoke(context.Background(), e.tn.ID, "rt_a", now)
	if code, _ := e.call2(t, "read:refresh_tokens", "GET", "/api/v2/refresh-tokens/rt_a", func(w http.ResponseWriter, r *http.Request) { e.h.GetRefreshToken(w, r, "rt_a") }); code != 404 {
		t.Errorf("get revoked token = %d", code)
	}
}

func TestRefreshTokenPaging(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "s@x.test"})["user_id"].(string)
	for i := 0; i < 3; i++ {
		e.addToken(t, fmt.Sprintf("rt%d", i), u, now.Add(time.Duration(-3+i)*time.Minute))
	}
	var got []string
	from := ""
	for i := 0; i < 3; i++ {
		q := "?take=1"
		if from != "" {
			q += "&from=" + url.QueryEscape(from)
		}
		_, out := e.tokens(t, u, q)
		got = append(got, ids(t, out, "tokens")...)
		from, _ = out["next"].(string)
	}
	if !eqStrings(got, []string{"rt2", "rt1", "rt0"}) {
		t.Errorf("pages = %v", got)
	}
}

func TestDeleteSessionsAndTokens(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	u := e.mustCreate(t, map[string]any{"email": "s@x.test"})["user_id"].(string)
	other := e.mustCreate(t, map[string]any{"email": "o@x.test"})["user_id"].(string)
	e.addSession(t, "s1", u, now.Add(-time.Minute))
	e.addSession(t, "s2", u, now.Add(-2*time.Minute))
	e.addSession(t, "so", other, now.Add(-time.Minute))
	e.addToken(t, "t1", u, now.Add(-time.Minute), func(r *store.RefreshToken) { r.SessionID = "s1" })
	e.addToken(t, "t2", u, now.Add(-2*time.Minute))
	e.addToken(t, "to", other, now.Add(-time.Minute))

	del := func(scope, target string, fn http.HandlerFunc) (int, map[string]any) {
		return e.call2(t, scope, "DELETE", target, fn)
	}
	is202 := func(what string, code int, out map[string]any) {
		t.Helper()
		if code != 202 || len(out) != 0 {
			t.Errorf("%s = %d %v, want 202 {}", what, code, out)
		}
	}

	// One session, then again (nothing there): 202 {} both times.
	code, out := del("delete:sessions", "/api/v2/sessions/s2", func(w http.ResponseWriter, r *http.Request) { e.h.DeleteSession(w, r, "s2") })
	is202("delete session", code, out)
	code, out = del("delete:sessions", "/api/v2/sessions/s2", func(w http.ResponseWriter, r *http.Request) { e.h.DeleteSession(w, r, "s2") })
	is202("delete missing session", code, out)
	if _, err := e.st.Sessions().Get(ctx, e.tn.ID, "s2"); err == nil {
		t.Errorf("s2 survived")
	}

	// All of a user's sessions: version bumped, refresh tokens kept.
	before, _ := e.st.Users().Get(ctx, e.tn.ID, u)
	code, out = del("delete:sessions", "/x", func(w http.ResponseWriter, r *http.Request) { e.h.DeleteUserSessions(w, r, u) })
	is202("delete user sessions", code, out)
	after, _ := e.st.Users().Get(ctx, e.tn.ID, u)
	if after.Version <= before.Version {
		t.Errorf("Version %d -> %d, want a bump", before.Version, after.Version)
	}
	if l, _ := e.st.Sessions().ListByUser(ctx, e.tn.ID, u); len(l) != 0 {
		t.Errorf("sessions left: %v", l)
	}
	if l, _ := e.st.Sessions().ListByUser(ctx, e.tn.ID, other); len(l) != 1 {
		t.Errorf("another user's session was touched")
	}
	if l, _ := e.st.RefreshTokens().ListByUser(ctx, e.tn.ID, u); len(l) != 2 {
		t.Errorf("deleting sessions revoked refresh tokens: %d left", len(l))
	}
	code, out = del("delete:sessions", "/x", func(w http.ResponseWriter, r *http.Request) { e.h.DeleteUserSessions(w, r, u) })
	is202("delete user sessions again", code, out)
	if code, out := del("delete:sessions", "/x", func(w http.ResponseWriter, r *http.Request) {
		e.h.DeleteUserSessions(w, r, "auth0|000000000000000000000000")
	}); code != 404 || out["errorCode"] != "inexistent_user" {
		t.Errorf("unknown user = %d %v", code, out)
	}
	if code, out := del("delete:sessions", "/x", func(w http.ResponseWriter, r *http.Request) { e.h.DeleteUserSessions(w, r, "nope") }); code != 400 || out["errorCode"] != "invalid_uri" {
		t.Errorf("malformed user = %d %v", code, out)
	}

	// One token, then all of the user's.
	code, out = del("delete:refresh_tokens", "/x", func(w http.ResponseWriter, r *http.Request) { e.h.DeleteRefreshToken(w, r, "t1") })
	is202("delete token", code, out)
	code, out = del("delete:refresh_tokens", "/x", func(w http.ResponseWriter, r *http.Request) { e.h.DeleteRefreshToken(w, r, "nope") })
	is202("delete missing token", code, out)
	if l, _ := e.st.RefreshTokens().ListByUser(ctx, e.tn.ID, u); len(l) != 1 || l[0].ID != "t2" {
		t.Errorf("tokens after one delete: %v", l)
	}
	code, out = del("delete:refresh_tokens", "/x", func(w http.ResponseWriter, r *http.Request) { e.h.DeleteUserRefreshTokens(w, r, u) })
	is202("delete user tokens", code, out)
	if l, _ := e.st.RefreshTokens().ListByUser(ctx, e.tn.ID, u); len(l) != 0 {
		t.Errorf("tokens left: %v", l)
	}
	if l, _ := e.st.RefreshTokens().ListByUser(ctx, e.tn.ID, other); len(l) != 1 {
		t.Errorf("another user's token was touched")
	}
	if code, out := del("delete:refresh_tokens", "/x", func(w http.ResponseWriter, r *http.Request) {
		e.h.DeleteUserRefreshTokens(w, r, "auth0|000000000000000000000000")
	}); code != 404 || out["errorCode"] != "inexistent_user" {
		t.Errorf("unknown user = %d %v", code, out)
	}
	if !strings.Contains(e.logs.String(), "delete user sessions") {
		t.Errorf("deletes are not logged:\n%s", e.logs)
	}
}

func (e *usersEnv) addGrant(t *testing.T, id, userID, clientID, audience string, scopes ...string) {
	t.Helper()
	if _, err := e.st.UserGrants().Upsert(context.Background(), &store.UserGrant{TenantID: e.tn.ID, ID: id, ClientID: clientID, UserID: userID,
		Audience: audience, Scopes: scopes, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
}

func (e *usersEnv) grants(t *testing.T, query string) (int, any) {
	t.Helper()
	rec, out := e.do(t, m2mCaller("read:grants"), "GET", "/api/v2/grants"+query, nil, e.h.GetGrants)
	return rec.Code, out
}

func TestGrants(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	u1 := e.mustCreate(t, map[string]any{"email": "a@x.test"})["user_id"].(string)
	u2 := e.mustCreate(t, map[string]any{"email": "b@x.test"})["user_id"].(string)
	e.addGrant(t, "g1", u1, "spa", "https://api.acme.test", "read:things", "openid", "offline_access", "profile")
	e.addGrant(t, "g2", u1, "web", "https://api.acme.test", "openid")
	e.addGrant(t, "g3", u2, "spa", "https://login.acme.test/userinfo", "openid")

	code, out := e.grants(t, "")
	list, _ := out.([]any)
	if code != 200 || len(list) != 3 {
		t.Fatalf("list = %d %v", code, out)
	}
	want := map[string]any{"id": "g1", "clientID": "spa", "user_id": u1, "audience": "https://api.acme.test",
		"scope": []any{"offline_access", "openid", "profile", "read:things"}}
	if !jsonEqual(list[0], want) {
		t.Errorf("grant = %v\nwant %v", list[0], want)
	}
	for q, wantIDs := range map[string]string{
		"?user_id=" + url.QueryEscape(u1):                       "g1,g2",
		"?client_id=spa":                                        "g1,g3",
		"?audience=" + url.QueryEscape("https://api.acme.test"): "g1,g2",
		"?user_id=" + url.QueryEscape(u1) + "&client_id=web":    "g2",
		"?user_id=" + url.QueryEscape("auth0|nobody"):           "",
		"?user_id=nope":                                         "",
	} {
		code, out := e.grants(t, q)
		list, _ := out.([]any)
		var got []string
		for _, g := range list {
			got = append(got, g.(map[string]any)["id"].(string))
		}
		if code != 200 || out == nil || strings.Join(got, ",") != wantIDs {
			t.Errorf("%s = %d %v, want %q", q, code, out, wantIDs)
		}
	}
	code, out = e.grants(t, "?include_totals=true&per_page=2&page=1")
	m, _ := out.(map[string]any)
	if code != 200 || m["total"] != float64(3) || m["start"] != float64(2) || m["limit"] != float64(2) || len(m["grants"].([]any)) != 1 {
		t.Errorf("totals = %d %v", code, out)
	}

	// Delete one: 204, also when missing.
	rec, _ := e.do(t, m2mCaller("delete:grants"), "DELETE", "/api/v2/grants/g3", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteGrant(w, r, "g3") })
	if rec.Code != 204 {
		t.Errorf("delete grant = %d", rec.Code)
	}
	rec, _ = e.do(t, m2mCaller("delete:grants"), "DELETE", "/api/v2/grants/g3", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteGrant(w, r, "g3") })
	if rec.Code != 204 {
		t.Errorf("delete missing grant = %d", rec.Code)
	}
	// Delete by user; no user_id is 400.
	rec, out = e.do(t, m2mCaller("delete:grants"), "DELETE", "/api/v2/grants", nil, e.h.DeleteGrantsByUser)
	if m, _ := out.(map[string]any); rec.Code != 400 || m["errorCode"] != "invalid_query_string" {
		t.Errorf("delete without user_id = %d %v", rec.Code, out)
	}
	rec, _ = e.do(t, m2mCaller("delete:grants"), "DELETE", "/api/v2/grants?user_id="+url.QueryEscape(u1), nil, e.h.DeleteGrantsByUser)
	if l, _ := e.st.UserGrants().ListByUser(ctx, e.tn.ID, u1); rec.Code != 204 || len(l) != 0 {
		t.Errorf("delete by user = %d, %d grants left", rec.Code, len(l))
	}
}
