package mgmt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// withKeys gives the tenant signing keys and the handlers a key manager,
// for link_with.
func (e *usersEnv) withKeys(t *testing.T) *keys.Manager {
	t.Helper()
	km := keys.NewManager(e.st.SigningKeys(), e.w)
	if err := km.Ensure(context.Background(), e.tn.ID); err != nil {
		t.Fatal(err)
	}
	e.h.Keys = km
	return km
}

func (e *usersEnv) link(t *testing.T, id string, body any) (*httptest.ResponseRecorder, any) {
	t.Helper()
	return e.do(t, m2mCaller("update:users"), "POST", "/api/v2/users/"+url.PathEscape(id)+"/identities", body, func(w http.ResponseWriter, r *http.Request) {
		e.h.LinkUserIdentity(w, r, id)
	})
}

func (e *usersEnv) unlink(t *testing.T, id, provider, userID string) (*httptest.ResponseRecorder, any) {
	t.Helper()
	target := "/api/v2/users/" + url.PathEscape(id) + "/identities/" + url.PathEscape(provider) + "/" + url.PathEscape(userID)
	return e.do(t, m2mCaller("update:users"), "DELETE", target, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.UnlinkUserIdentity(w, r, id, provider, userID)
	})
}

func (e *usersEnv) mustLink(t *testing.T, primary, secondary string) []map[string]any {
	t.Helper()
	rec, out := e.link(t, primary, map[string]any{"provider": "auth0", "user_id": strings.TrimPrefix(secondary, "auth0|")})
	if rec.Code != 201 {
		t.Fatalf("link %s into %s = %d %s", secondary, primary, rec.Code, rec.Body)
	}
	return listUsers(t, out)
}

func errBody(out any) map[string]any {
	m, _ := out.(map[string]any)
	return m
}

func (e *usersEnv) login(t *testing.T, login, password string) (*store.User, error) {
	t.Helper()
	return (&identity.Database{Store: e.st}).Login(context.Background(), e.conn, login, password)
}

func identityWant(id, email string, verified bool) map[string]any {
	return map[string]any{"connection": dbConn, "provider": "auth0", "user_id": strings.TrimPrefix(id, "auth0|"), "isSocial": false,
		"profileData": map[string]any{"email": email, "email_verified": verified}}
}

// U7: linking by provider and user_id.
func TestLinkUserIdentity(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	p := e.mustCreate(t, map[string]any{"email": "primary@x.test", "password": "primary pass 1"})["user_id"].(string)
	s := e.mustCreate(t, map[string]any{"email": "second@x.test", "password": "second pass 2", "email_verified": true, "given_name": "Sec",
		"user_metadata": map[string]any{"a": 1}})["user_id"].(string)
	before, _ := e.st.Users().Get(ctx, e.tn.ID, p)
	err := e.st.Sessions().Create(ctx, &store.LoginSession{TenantID: e.tn.ID, ID: "sess_sec", TokenHash: "h", UserID: s, Connection: dbConn,
		AuthenticatedAt: now, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now, LastInteractedAt: now})
	if err != nil {
		t.Fatal(err)
	}

	rec, out := e.link(t, p, map[string]any{"provider": "auth0", "user_id": strings.TrimPrefix(s, "auth0|")})
	if rec.Code != 201 {
		t.Fatalf("link = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "argon2") {
		t.Fatalf("a hash leaked: %s", rec.Body)
	}
	got := listUsers(t, out)
	want := []map[string]any{identityWant(p, "primary@x.test", false), identityWant(s, "second@x.test", true)}
	if !jsonEqual(got, want) {
		t.Fatalf("identities = %v, want %v", got, want)
	}

	// The secondary stops existing; its session is gone.
	if rec, out := e.get(t, s, ""); rec.Code != 404 || out["errorCode"] != "inexistent_user" {
		t.Errorf("get secondary = %d %v", rec.Code, out)
	}
	if _, err := e.st.Sessions().Get(ctx, e.tn.ID, "sess_sec"); err == nil {
		t.Errorf("the secondary's session survived the link")
	}
	// GET of the primary shows profileData on the secondary identity only.
	rec, u := e.get(t, p, "")
	ids, _ := u["identities"].([]any)
	if rec.Code != 200 || len(ids) != 2 {
		t.Fatalf("get primary = %d %v", rec.Code, u)
	}
	want[0] = map[string]any{"connection": dbConn, "provider": "auth0", "user_id": strings.TrimPrefix(p, "auth0|"), "isSocial": false}
	if !jsonEqual(ids, want) {
		t.Errorf("primary identities = %v, want %v", ids, want)
	}
	// identities.user_id:<secondary> finds the primary.
	rec, list := e.list(t, "?q="+url.QueryEscape("identities.user_id:"+strings.TrimPrefix(s, "auth0|")))
	if users := listUsers(t, list); rec.Code != 200 || len(users) != 1 || users[0]["user_id"] != p {
		t.Errorf("search by the secondary identity = %d %v", rec.Code, list)
	}
	// The secondary's credentials log in as the primary; both passwords work.
	if u, err := e.login(t, "second@x.test", "second pass 2"); err != nil || u.UserID != p {
		t.Errorf("secondary login = %v, %v", u, err)
	}
	if u, err := e.login(t, "primary@x.test", "primary pass 1"); err != nil || u.UserID != p {
		t.Errorf("primary login = %v, %v", u, err)
	}
	if _, err := e.login(t, "second@x.test", "primary pass 1"); err == nil {
		t.Errorf("the primary's password logs in as the secondary identity")
	}
	after, _ := e.st.Users().Get(ctx, e.tn.ID, p)
	if after.Version <= before.Version {
		t.Errorf("primary Version %d -> %d, want a bump", before.Version, after.Version)
	}
	if !strings.Contains(e.logs.String(), "link user identity") {
		t.Errorf("the link is not logged:\n%s", e.logs)
	}
}

func TestLinkUserIdentityErrors(t *testing.T) {
	e := newUsersEnv(t)
	p := e.mustCreate(t, map[string]any{"email": "p@x.test"})["user_id"].(string)
	q := e.mustCreate(t, map[string]any{"email": "q@x.test"})["user_id"].(string)
	s := e.mustCreate(t, map[string]any{"email": "s@x.test"})["user_id"].(string)
	s2 := e.mustCreate(t, map[string]any{"email": "s2@x.test"})["user_id"].(string)
	e.mustLink(t, p, s)
	bare := func(id string) string { return strings.TrimPrefix(id, "auth0|") }
	for _, c := range []struct {
		name          string
		primary       string
		body          any
		status        int
		code, message string
	}{
		{"self", p, map[string]any{"provider": "auth0", "user_id": bare(p)}, 400, "operation_not_supported", "Main identity and the new one are the same."},
		{"already linked", p, map[string]any{"provider": "auth0", "user_id": bare(s)}, 409, "identity_conflict", "Specified identity already exists."},
		{"linked to another user", q, map[string]any{"provider": "auth0", "user_id": bare(s)}, 409, "identity_conflict", "Specified identity already exists."},
		{"unknown secondary", p, map[string]any{"provider": "auth0", "user_id": "000000000000000000000000"}, 400, "", "the provided secondary account does not exist"},
		{"missing user_id", p, map[string]any{"provider": "auth0"}, 400, "invalid_body", "Payload validation error: 'Missing required property: user_id'."},
		{"other provider", p, map[string]any{"provider": "google-oauth2", "user_id": "123"}, 400, "invalid_body", "linking to an inexistent identity is not allowed"},
		{"unknown primary", "auth0|000000000000000000000000", map[string]any{"provider": "auth0", "user_id": bare(s2)}, 404, "inexistent_user", "The user does not exist."},
		{"malformed primary", "nope", map[string]any{"provider": "auth0", "user_id": bare(s2)}, 400, "invalid_uri", ""},
		{"missing provider", p, map[string]any{"user_id": bare(s2)}, 400, "invalid_body", "Payload validation error: 'Missing required property: provider'."},
		{"unknown property", p, map[string]any{"provider": "auth0", "user_id": bare(s2), "colour": "blue"}, 400, "invalid_body", ""},
		{"wrong type", p, map[string]any{"provider": "auth0", "user_id": true}, 400, "invalid_body", ""},
		{"link_with and user_id", p, map[string]any{"provider": "auth0", "user_id": bare(s2), "link_with": "x.y.z"}, 400, "invalid_body", ""},
		{"other connection_id", p, map[string]any{"provider": "auth0", "user_id": bare(s2), "connection_id": "con_other"}, 400, "", "the provided secondary account does not exist"},
		{"not an object", p, `[]`, 400, "invalid_body", ""},
	} {
		rec, out := e.link(t, c.primary, c.body)
		wantUserError(t, c.name, rec, errBody(out), c.status, c.code, c.message)
	}
	// Nothing above changed s2 or q.
	for _, id := range []string{s2, q} {
		if rec, u := e.get(t, id, ""); rec.Code != 200 || len(u["identities"].([]any)) != 1 {
			t.Errorf("%s after the refusals = %d %v", id, rec.Code, u)
		}
	}
	// A matching connection_id and a numeric user_id are accepted.
	if rec, _ := e.link(t, q, map[string]any{"provider": "auth0", "user_id": bare(s2), "connection_id": e.conn.ID}); rec.Code != 201 {
		t.Errorf("link with connection_id = %d %s", rec.Code, rec.Body)
	}
	n := e.mustCreate(t, map[string]any{"email": "n@x.test", "user_id": "12345"})["user_id"].(string)
	if rec, _ := e.link(t, q, `{"provider":"auth0","user_id":12345}`); rec.Code != 201 {
		t.Errorf("link with a numeric user_id = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.get(t, n, ""); rec.Code != 404 {
		t.Errorf("numeric secondary still exists: %d", rec.Code)
	}
}

// link_with: an ID token issued by the tenant to the calling client.
func TestLinkWith(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	km := e.withKeys(t)
	p := e.mustCreate(t, map[string]any{"email": "p@x.test"})["user_id"].(string)
	s := e.mustCreate(t, map[string]any{"email": "s@x.test", "password": "second pass 2"})["user_id"].(string)
	sec, _ := e.st.Users().Get(ctx, e.tn.ID, s)
	other, err := tenantsetup.UpsertTenant(ctx, e.st, "globex", now, func(tn *store.Tenant) error {
		tn.Domains = []string{"login.globex.test"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := km.Ensure(ctx, other.ID); err != nil {
		t.Fatal(err)
	}
	mint := func(tenantID, iss, aud string, user *store.User, at time.Time) string {
		t.Helper()
		m := &oauth.Minter{Keys: km, Now: func() time.Time { return at }}
		raw, err := m.IDToken(ctx, oauth.IDTokenParams{TenantID: tenantID, Issuer: iss, ClientID: aud, User: user, Scopes: []string{"openid"}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	iss := "https://login.acme.test/"
	clock := time.Now()
	e.h.Now = func() time.Time { return clock }
	for _, c := range []struct {
		name, token, message string
	}{
		{"malformed", "not-a-jwt", "Invalid token (link_with)."},
		{"another tenant", mint(other.ID, iss, "m2m", sec, clock), "Invalid token (link_with)."},
		{"wrong issuer", mint(e.tn.ID, "https://login.globex.test/", "m2m", sec, clock), "Invalid token (link_with)."},
		{"expired", mint(e.tn.ID, iss, "m2m", sec, clock.Add(-24*time.Hour)), "Invalid token (link_with)."},
		{"other audience", mint(e.tn.ID, iss, "some-spa", sec, clock), "JWT (link_with) contains an invalid aud claim."},
		{"self", mint(e.tn.ID, iss, "m2m", &store.User{UserID: p}, clock), "Main identity and the new one are the same."},
	} {
		rec, out := e.link(t, p, map[string]any{"link_with": c.token})
		code := "invalid_body"
		if c.name == "self" {
			code = "operation_not_supported"
		}
		wantUserError(t, c.name, rec, errBody(out), 400, code, c.message)
	}
	rec, out := e.link(t, p, map[string]any{"link_with": mint(e.tn.ID, iss, "m2m", sec, clock)})
	if rec.Code != 201 {
		t.Fatalf("link_with = %d %s", rec.Code, rec.Body)
	}
	if ids := listUsers(t, out); len(ids) != 2 || ids[1]["user_id"] != strings.TrimPrefix(s, "auth0|") {
		t.Errorf("identities = %v", ids)
	}
	if u, err := e.login(t, "s@x.test", "second pass 2"); err != nil || u.UserID != p {
		t.Errorf("secondary login = %v, %v", u, err)
	}
}

// U7: unlinking recreates the secondary from its profileData.
func TestUnlinkUserIdentity(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	p := e.mustCreate(t, map[string]any{"email": "primary@x.test"})["user_id"].(string)
	s := e.mustCreate(t, map[string]any{"email": "second@x.test", "password": "second pass 2", "email_verified": true, "given_name": "Sec",
		"name": "Second Person", "nickname": "secnick", "picture": "https://img.test/s.png", "user_metadata": map[string]any{"a": 1},
		"app_metadata": map[string]any{"plan": "pro"}})["user_id"].(string)
	if err := e.st.Users().RecordLogin(ctx, e.tn.ID, s, now, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	orig, _ := e.st.Users().Get(ctx, e.tn.ID, s)
	e.mustLink(t, p, s)
	linked, _ := e.st.Users().Get(ctx, e.tn.ID, p)

	rec, out := e.unlink(t, p, "auth0", strings.TrimPrefix(s, "auth0|"))
	if rec.Code != 200 {
		t.Fatalf("unlink = %d %s", rec.Code, rec.Body)
	}
	if got, want := listUsers(t, out), []map[string]any{identityWant(p, "primary@x.test", false)}; !jsonEqual(got, want) {
		t.Errorf("identities = %v, want %v", got, want)
	}
	rec, u := e.get(t, s, "")
	if rec.Code != 200 {
		t.Fatalf("get recreated = %d %v", rec.Code, u)
	}
	want := map[string]any{"user_id": s, "email": "second@x.test", "email_verified": true, "name": "second@x.test", "nickname": "second",
		"created_at": u["created_at"], "updated_at": u["updated_at"],
		"identities": []any{map[string]any{"connection": dbConn, "provider": "auth0", "user_id": strings.TrimPrefix(s, "auth0|"), "isSocial": false}}}
	if !jsonEqual(u, want) {
		t.Errorf("recreated user = %v, want %v", u, want)
	}
	if created, _ := time.Parse(time.RFC3339, u["created_at"].(string)); !created.After(orig.CreatedAt) {
		t.Errorf("created_at %v is not after the original %v", created, orig.CreatedAt)
	}
	// Its own password logs in as itself again; the primary keeps its own.
	if got, err := e.login(t, "second@x.test", "second pass 2"); err != nil || got.UserID != s {
		t.Errorf("secondary login = %v, %v", got, err)
	}
	if got, err := e.login(t, "primary@x.test", "correct horse 1"); err != nil || got.UserID != p {
		t.Errorf("primary login = %v, %v", got, err)
	}
	re, _ := e.st.Users().Get(ctx, e.tn.ID, s)
	if re.Version < 1 || re.LoginsCount != 0 || re.LastLogin != nil {
		t.Errorf("recreated Version %d logins %d, want a bumped Version and no logins (identity.Database.Login records none)", re.Version, re.LoginsCount)
	}
	after, _ := e.st.Users().Get(ctx, e.tn.ID, p)
	if after.Version <= linked.Version || len(after.Identities) != 1 {
		t.Errorf("primary after unlink: Version %d -> %d, identities %v", linked.Version, after.Version, after.Identities)
	}

	// Not linked: 200 with the identities, nothing changes.
	rec, out = e.unlink(t, p, "auth0", strings.TrimPrefix(s, "auth0|"))
	if rec.Code != 200 || len(listUsers(t, out)) != 1 {
		t.Errorf("unlink again = %d %s", rec.Code, rec.Body)
	}
	if again, _ := e.st.Users().Get(ctx, e.tn.ID, p); again.Version != after.Version {
		t.Errorf("a no-op unlink bumped the Version")
	}
	rec, out = e.unlink(t, p, "auth0", strings.TrimPrefix(p, "auth0|"))
	wantUserError(t, "main identity", rec, errBody(out), 400, "delete_main_user_identity", "Main identity cannot be removed.")
	rec, out = e.unlink(t, "auth0|000000000000000000000000", "auth0", "x")
	wantUserError(t, "unknown primary", rec, errBody(out), 404, "inexistent_user", "The user does not exist.")
	rec, out = e.unlink(t, "nope", "auth0", "x")
	wantUserError(t, "malformed primary", rec, errBody(out), 400, "invalid_uri", "")
	if !strings.Contains(e.logs.String(), "unlink user identity") {
		t.Errorf("the unlink is not logged:\n%s", e.logs)
	}
}

// A username survives a link and unlink on a connection that requires one.
func TestLinkKeepsUsername(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	e.conn.RequiresUsername = true
	if err := e.st.Connections().Update(ctx, e.conn); err != nil {
		t.Fatal(err)
	}
	p := e.mustCreate(t, map[string]any{"email": "p@x.test", "username": "primary"})["user_id"].(string)
	s := e.mustCreate(t, map[string]any{"email": "s@x.test", "username": "second", "password": "second pass 2"})["user_id"].(string)
	ids := e.mustLink(t, p, s)
	if pd, _ := ids[1]["profileData"].(map[string]any); pd["username"] != "second" {
		t.Errorf("profileData = %v", ids[1]["profileData"])
	}
	if u, err := e.login(t, "second", "second pass 2"); err != nil || u.UserID != p {
		t.Errorf("username login through the link = %v, %v", u, err)
	}
	if rec, _ := e.unlink(t, p, "auth0", strings.TrimPrefix(s, "auth0|")); rec.Code != 200 {
		t.Fatalf("unlink = %d %s", rec.Code, rec.Body)
	}
	if u, err := e.login(t, "second", "second pass 2"); err != nil || u.UserID != s || u.Username != "second" {
		t.Errorf("username login after unlink = %v, %v", u, err)
	}
}

// jsonEqual compares got and want as JSON values.
func jsonEqual(got, want any) bool {
	norm := func(v any) any {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var out any
		_ = json.Unmarshal(b, &out)
		return out
	}
	return reflect.DeepEqual(norm(got), norm(want))
}

// A PATCH of the password or email writes the primary's own identity: a
// connection where it has only a linked identity is refused as one where it
// has none, and a linked identity's password survives (D-0043).
func TestPatchSkipsLinkedIdentity(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	other := &store.Connection{TenantID: e.tn.ID, ID: "con_other", Name: "Other-Db", Strategy: store.StrategyDatabase, CreatedAt: now}
	if err := e.st.Connections().Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	p := e.mustCreate(t, map[string]any{"email": "p@x.test", "password": "primary pass 1"})["user_id"].(string)
	same := e.mustCreate(t, map[string]any{"email": "same@x.test", "password": "same pass 2"})["user_id"].(string)
	far := e.mustCreate(t, map[string]any{"email": "far@x.test", "password": "far pass 3", "connection": other.Name})["user_id"].(string)
	e.mustLink(t, p, same)
	e.mustLink(t, p, far)
	before, _ := e.st.Users().Get(ctx, e.tn.ID, p)

	for _, body := range []map[string]any{
		{"password": "new pass 4", "connection": other.Name},
		{"email": "new@x.test", "connection": other.Name},
	} {
		rec, out := e.patch(t, p, body)
		wantUserError(t, "patch on the linked-only connection", rec, out, 400, "inexistent_connection", "")
	}
	if after, _ := e.st.Users().Get(ctx, e.tn.ID, p); after.Email != before.Email || after.Version != before.Version {
		t.Errorf("a refused PATCH changed the user: %+v", after)
	}
	// A password change without a connection hits the primary's own hash.
	if rec, _ := e.patch(t, p, map[string]any{"password": "new pass 4"}); rec.Code != 200 {
		t.Fatalf("patch password = %d %s", rec.Code, rec.Body)
	}
	if u, err := e.login(t, "p@x.test", "new pass 4"); err != nil || u.UserID != p {
		t.Errorf("primary's new password = %v, %v", u, err)
	}
	if u, err := e.login(t, "same@x.test", "same pass 2"); err != nil || u.UserID != p {
		t.Errorf("linked identity's password after the primary's change = %v, %v", u, err)
	}
	if _, err := e.login(t, "same@x.test", "new pass 4"); err == nil {
		t.Errorf("the primary's new password logs in through the linked identity")
	}
	farConn, _ := e.st.Connections().GetByName(ctx, e.tn.ID, other.Name)
	if u, err := (&identity.Database{Store: e.st}).Login(ctx, farConn, "far@x.test", "far pass 3"); err != nil || u.UserID != p {
		t.Errorf("linked identity on the other connection = %v, %v", u, err)
	}
}

// An imported user who has not signed in yet keeps its imported hash through
// a link and an unlink.
func TestLinkUnlinkKeepsImportedHash(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	const imported = `{"alg":"bcrypt","hash":"$2b$10$abc"}`
	p := e.mustCreate(t, map[string]any{"email": "primary@x.test"})["user_id"].(string)
	s := e.mustCreate(t, map[string]any{"email": "second@x.test"})["user_id"].(string)
	u, err := e.st.Users().Get(ctx, e.tn.ID, s)
	if err != nil {
		t.Fatal(err)
	}
	u.Identities[0].PasswordHash, u.Identities[0].ImportedHash = "", imported
	if err := e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}

	e.mustLink(t, p, s)
	linked, _ := e.st.Users().Get(ctx, e.tn.ID, p)
	if len(linked.Identities) != 2 || linked.Identities[1].ImportedHash != imported || linked.Identities[1].PasswordHash != "" {
		t.Fatalf("linked identities = %+v", linked.Identities)
	}
	if rec, _ := e.unlink(t, p, "auth0", strings.TrimPrefix(s, "auth0|")); rec.Code != 200 {
		t.Fatalf("unlink = %d %s", rec.Code, rec.Body)
	}
	back, err := e.st.Users().Get(ctx, e.tn.ID, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Identities) != 1 || back.Identities[0].ImportedHash != imported || back.Identities[0].PasswordHash != "" {
		t.Errorf("restored identities = %+v", back.Identities)
	}
}
