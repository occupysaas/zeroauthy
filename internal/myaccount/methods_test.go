package myaccount

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/authmethods"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func methodList(t *testing.T, out map[string]any) []map[string]any {
	t.Helper()
	raw, _ := out["authentication_methods"].([]any)
	list := make([]map[string]any, 0, len(raw))
	for _, v := range raw {
		list = append(list, v.(map[string]any))
	}
	return list
}

// A user with password, passkey, TOTP, phone, email and recovery code has
// six methods, with the Management API's IDs (LR42a-5).
func TestListMethodsAllTypes(t *testing.T) {
	e := newEnv(t)
	pub, _ := json.Marshal(map[string]any{"identity_user_id": "alice1", "user_handle": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "backup_eligible": true, "backed_up": true, "transports": []string{"internal"}, "aaguid": "00000000-0000-0000-0000-000000000000", "user_agent": "Firefox"})
	added := []store.Authenticator{
		e.addAuthenticator(t, store.Authenticator{ID: "passkey|dev_p1", Type: "passkey", Confirmed: true, CredentialID: []byte{1, 2, 3}, PublicKey: []byte{4, 5}, RPID: host, PublicData: pub, Name: "laptop"}),
		e.addAuthenticator(t, store.Authenticator{ID: "totp|dev_t1", Type: "totp", Confirmed: true, Name: "phone app"}),
		e.addAuthenticator(t, store.Authenticator{ID: "phone|dev_s1", Type: "phone", Confirmed: true, Phone: "+15555550100", PhoneMethod: "voice"}),
		e.addAuthenticator(t, store.Authenticator{ID: "email|dev_e1", Type: "email", Confirmed: true, Email: "alice@acme.test"}),
		e.addAuthenticator(t, store.Authenticator{ID: "recovery-code|dev_r1", Type: "recovery-code", Confirmed: true, CodeHash: "h"}),
	}
	// A pending enrollment is not a method yet.
	e.addAuthenticator(t, store.Authenticator{ID: "totp|dev_pending", Type: "totp"})
	rec, out := e.do(t, e.token(t), "GET", "/authentication-methods", nil)
	if rec.Code != 200 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	list := methodList(t, out)
	if len(list) != 6 {
		t.Fatalf("%d methods: %s", len(list), rec.Body)
	}
	byType := map[string]map[string]any{}
	for _, m := range list {
		byType[m["type"].(string)] = m
		if m["id"] == nil || m["created_at"] == nil || m["usage"] == nil {
			t.Errorf("method lacks common members: %v", m)
		}
	}
	for _, a := range added {
		if byType[a.Type]["id"] != a.ID {
			t.Errorf("%s id = %v, want %s", a.Type, byType[a.Type]["id"], a.ID)
		}
	}
	// The same IDs the Management API lists.
	mgmt, err := authmethods.Authenticators(context.Background(), e.st, e.tn.ID, e.user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range added {
		if !slices.ContainsFunc(mgmt, func(m store.Authenticator) bool { return m.ID == a.ID }) {
			t.Errorf("Management API listing lacks %s", a.ID)
		}
	}
	pw := byType["password"]
	if pw["id"] != authmethods.PasswordID("alice1") || pw["identity_user_id"] != "alice1" || !slices.Equal(usage(pw), []string{"primary"}) {
		t.Errorf("password = %v", pw)
	}
	pk := byType["passkey"]
	if pk["credential_device_type"] != "multi_device" || pk["credential_backed_up"] != true || pk["key_id"] != "AQID" || pk["relying_party_id"] != host || pk["identity_user_id"] != "alice1" || !slices.Equal(usage(pk), []string{"primary"}) {
		t.Errorf("passkey = %v", pk)
	}
	if _, ok := pk["confirmed"]; ok {
		t.Errorf("passkey has confirmed: %v", pk)
	}
	ph := byType["phone"]
	if ph["phone_number"] != "+15555550100" || ph["preferred_authentication_method"] != "voice" || ph["confirmed"] != true || !slices.Equal(usage(ph), []string{"secondary"}) {
		t.Errorf("phone = %v", ph)
	}
	if byType["email"]["email"] != "alice@acme.test" || byType["totp"]["name"] != "phone app" {
		t.Errorf("email/totp = %v %v", byType["email"], byType["totp"])
	}
	// The type filter.
	_, out = e.do(t, e.token(t), "GET", "/authentication-methods?type=totp", nil)
	if l := methodList(t, out); len(l) != 1 || l[0]["id"] != "totp|dev_t1" {
		t.Errorf("filtered = %v", l)
	}
	if rec, _ := e.do(t, e.token(t), "GET", "/authentication-methods?type=bogus", nil); rec.Code != 400 {
		t.Errorf("bad filter = %d", rec.Code)
	}
	// One method by ID.
	rec, out = e.do(t, e.token(t), "GET", "/authentication-methods/"+pathID("phone|dev_s1"), nil)
	if rec.Code != 200 || out["id"] != "phone|dev_s1" || out["phone_number"] != "+15555550100" {
		t.Errorf("get = %d %v", rec.Code, out)
	}
	rec, out = e.do(t, e.token(t), "GET", "/authentication-methods/"+pathID(authmethods.PasswordID("alice1")), nil)
	if rec.Code != 200 || out["type"] != "password" {
		t.Errorf("get password = %d %v", rec.Code, out)
	}
	if rec, _ := e.do(t, e.token(t), "GET", "/authentication-methods/"+pathID("totp|dev_pending"), nil); rec.Code != 404 {
		t.Errorf("pending = %d", rec.Code)
	}
}

func usage(m map[string]any) []string {
	raw, _ := m["usage"].([]any)
	out := []string{}
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

func pathID(id string) string { return url.PathEscape(id) }

// Another user's method ID is not found.
func TestGetMethodOtherUser(t *testing.T) {
	e := newEnv(t)
	bob := newUser(t, e.st, e.tn.ID, "auth0|bob1", "bob@acme.test", e.now)
	e.addAuthenticator(t, store.Authenticator{ID: "totp|dev_bob", Type: "totp", Confirmed: true, UserID: bob.UserID})
	for _, id := range []string{"totp|dev_bob", authmethods.PasswordID("bob1"), "password|%%%", "nonsense"} {
		if rec, out := e.do(t, e.token(t), "GET", "/authentication-methods/"+pathID(id), nil); rec.Code != 404 || out["status"] != float64(404) {
			t.Errorf("%s = %d %v", id, rec.Code, out)
		}
	}
}

// The factors the tenant offers this user, with usage.
func TestFactorsList(t *testing.T) {
	e := newEnv(t)
	rec, out := e.do(t, e.token(t), "GET", "/factors", nil)
	if rec.Code != 200 {
		t.Fatalf("factors = %d %s", rec.Code, rec.Body)
	}
	if got := factorTypes(out); !slices.Equal(got, []string{"password"}) {
		t.Errorf("no Guardian factors: %v", got)
	}
	e.guardian(t, "otp", "email", "push-notification")
	ctx := context.Background()
	e.conn.Extra = map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}, "password": map[string]any{"enabled": true}}}
	if err := e.st.Connections().Update(ctx, e.conn); err != nil {
		t.Fatal(err)
	}
	enableIdentifierFirst(t, e)
	_, out = e.do(t, e.token(t), "GET", "/factors", nil)
	got := factorTypes(out)
	if !slices.Equal(got, []string{"password", "passkey", "totp", "email"}) {
		t.Errorf("factors = %v (%v)", got, out)
	}
	for _, f := range out["factors"].([]any) {
		m := f.(map[string]any)
		want := "secondary"
		if m["type"] == "password" || m["type"] == "passkey" {
			want = "primary"
		}
		if u := usage(m); !slices.Equal(u, []string{want}) {
			t.Errorf("%v usage %v", m["type"], u)
		}
	}
}

func factorTypes(out map[string]any) []string {
	raw, _ := out["factors"].([]any)
	got := []string{}
	for _, f := range raw {
		got = append(got, f.(map[string]any)["type"].(string))
	}
	return got
}

func enableIdentifierFirst(t *testing.T, e *env) {
	t.Helper()
	ctx := context.Background()
	cfg, err := e.st.HostedLogins().Get(ctx, e.tn.ID)
	rev := int64(0)
	if err == nil {
		rev = cfg.Revision
	} else {
		cfg = &store.HostedLoginConfig{TenantID: e.tn.ID}
	}
	cfg.Prompts = map[string]any{"universal_login_experience": "new", "identifier_first": true}
	if err := e.st.HostedLogins().Put(ctx, cfg, rev); err != nil {
		t.Fatal(err)
	}
}
