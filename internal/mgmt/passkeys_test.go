package mgmt_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/resourceview"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const managementCOSE = "pQECAyYgASFYILcoes0rNGrjTOXVEqXyq9CPe41x3PDQohuYsMQiLmHyIlggt4P6gUXrCQdKoWIfVcnC3BXZGdtI1ZqT9O7H8fsUcrA"

func passkeyBody(key string) map[string]any {
	return map[string]any{"type": "passkey", "name": "My key", "key_id": base64.RawURLEncoding.EncodeToString([]byte(key)), "public_key": managementCOSE}
}
func savedPasskey(t *testing.T, e *usersEnv, uid, key, identity, handle string) store.Authenticator {
	t.Helper()
	pub, _ := json.Marshal(map[string]any{"backup_eligible": true, "backed_up": true, "aaguid": "00000000-0000-0000-0000-000000000000", "identity_user_id": strings.TrimPrefix(identity, "auth0|"), "user_handle": handle, "user_agent": "test agent", "transports": []string{"usb"}, "secret": "must-not-leak"})
	pk, _ := base64.RawURLEncoding.DecodeString(managementCOSE)
	a := store.Authenticator{TenantID: e.tn.ID, UserID: uid, ID: "passkey|dev_" + strings.Repeat(key[:1], 20), Type: "passkey", Confirmed: true, Name: "My key", CreatedAt: now, LastAuthAt: now, CredentialID: []byte(key), PublicKey: pk, RPID: "another.example.test", PublicData: pub}
	if err := e.st.WebAuthn().CreatePasskey(context.Background(), &a, 20); err != nil {
		t.Fatal(err)
	}
	return a
}
func TestPasskeyMethodsList(t *testing.T) {
	e, uid := mfaUser(t)
	a := savedPasskey(t, e, uid, "A", uid, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	r, out := mfaCall(t, e.clientsEnv, "GetAuthenticationMethods", uid, "", nil, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	got := out.([]any)[0].(map[string]any)
	want := []string{"id", "type", "name", "created_at", "last_auth_at", "key_id", "public_key", "relying_party_identifier", "credential_device_type", "credential_backed_up", "aaguid", "identity_user_id", "user_agent", "user_handle", "transports"}
	if len(got) != len(want) {
		t.Fatalf("unexpected fields: %v", got)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if got["id"] != a.ID || !regexp.MustCompile(`^passkey\|dev_[A-Za-z0-9]{20}$`).MatchString(a.ID) || got["credential_device_type"] != "multi_device" || got["credential_backed_up"] != true || got["relying_party_identifier"] != a.RPID {
		t.Fatal(got)
	}
	var pub map[string]any
	_ = json.Unmarshal(a.PublicData, &pub)
	pub["backup_eligible"] = false
	pub["backed_up"] = false
	a.PublicData, _ = json.Marshal(pub)
	if err := e.st.MFA().DeleteAuthenticator(context.Background(), a.TenantID, a.UserID, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.st.WebAuthn().CreatePasskey(context.Background(), &a, 20); err != nil {
		t.Fatal(err)
	}
	r, out = mfaCall(t, e.clientsEnv, "GetAuthenticationMethod", uid, a.ID, nil, "")
	if r.Code != 200 || out.(map[string]any)["credential_device_type"] != "single_device" || out.(map[string]any)["credential_backed_up"] != false {
		t.Fatal(r.Body)
	}
}
func TestPasskeyMethodsCreate(t *testing.T) {
	e, uid := mfaUser(t)
	for _, tc := range []struct {
		name  string
		patch map[string]any
	}{{"missing key", map[string]any{"key_id": ""}}, {"bad COSE", map[string]any{"public_key": "AQID"}}, {"wrong identity", map[string]any{"identity_user_id": "auth0|other"}}, {"bad handle", map[string]any{"user_handle": "AQID"}}, {"empty handle", map[string]any{"user_handle": ""}}, {"empty identity", map[string]any{"identity_user_id": ""}}, {"long agent", map[string]any{"user_agent": strings.Repeat("x", 4097)}}} {
		t.Run(tc.name, func(t *testing.T) {
			b := passkeyBody(tc.name)
			for k, v := range tc.patch {
				b[k] = v
			}
			r, _ := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", b, "")
			if r.Code != 400 {
				t.Fatalf("%d %s", r.Code, r.Body)
			}
		})
	}
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", passkeyBody("first"), "")
	if r.Code != 201 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	first := out.(map[string]any)
	if first["relying_party_identifier"] != e.tn.CanonicalHost || first["identity_user_id"] != strings.TrimPrefix(uid, "auth0|") {
		t.Fatal(first)
	}
	handle, err := base64.RawURLEncoding.DecodeString(first["user_handle"].(string))
	if err != nil || len(handle) != 32 {
		t.Fatal(first)
	}
	r, out = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", passkeyBody("second"), "")
	if r.Code != 201 || out.(map[string]any)["user_handle"] != first["user_handle"] {
		t.Fatal(r.Body)
	}
	r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", passkeyBody("first"), "")
	if r.Code != 409 {
		t.Fatalf("duplicate: %d %s", r.Code, r.Body)
	}
	for i := 2; i < 20; i++ {
		r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", passkeyBody(fmt.Sprint(i)), "")
		if r.Code != 201 {
			t.Fatalf("%d %s", r.Code, r.Body)
		}
	}
	r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", passkeyBody("21"), "")
	if r.Code != 400 {
		t.Fatalf("21st: %d %s", r.Code, r.Body)
	}
}
func TestPasskeyMethodsPatchDelete(t *testing.T) {
	e, uid := mfaUser(t)
	a := savedPasskey(t, e, uid, "A", uid, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	capture := logSetup(e.clientsEnv)
	r, _ := mfaCall(t, e.clientsEnv, "UpdateAuthenticationMethod", uid, a.ID, map[string]any{"name": "Renamed"}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	if hasPasskeyDomainEvent(capture.events) {
		t.Fatalf("passkey rename events: %v", capture.events)
	}
	for _, op := range []string{"DeleteAuthenticationMethods", "SetAuthenticationMethods", "DeleteUserAuthenticators"} {
		r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "webauthn-roaming", "key_id": "AQID", "public_key": managementCOSE, "relying_party_identifier": "example.test"}, "")
		if r.Code != 201 {
			t.Fatal(r.Body)
		}
		r, out := mfaCall(t, e.clientsEnv, "GetUserEnrollments", uid, "", nil, "")
		if r.Code != 200 || len(out.([]any)) != 1 || out.([]any)[0].(map[string]any)["auth_method"] != "webauthn-roaming" {
			t.Fatal(r.Body)
		}
		var b any
		if op == "SetAuthenticationMethods" {
			b = []any{}
		}
		r, _ = mfaCall(t, e.clientsEnv, op, uid, "", b, "")
		if r.Code != 200 && r.Code != 204 {
			t.Fatal(r.Body)
		}
		all, err := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, uid)
		if err != nil || len(all) != 1 || all[0].Type != "passkey" {
			t.Fatalf("bulk %s: %v %v", op, all, err)
		}
	}
	capture.events = nil
	r, _ = mfaCall(t, e.clientsEnv, "DeleteAuthenticationMethod", uid, a.ID, nil, "")
	if r.Code != 204 || hasPasskeyDomainEvent(capture.events) {
		t.Fatalf("delete: %d %s events %v", r.Code, r.Body, capture.events)
	}
}
func TestPasskeyMethodsLinkedIdentity(t *testing.T) {
	e, uid := mfaUser(t)
	secondary := e.mustCreate(t, map[string]any{"email": "import-linked@example.test"})["user_id"].(string)
	e.mustLink(t, uid, secondary)
	body := passkeyBody("linked-import")
	body["identity_user_id"] = strings.TrimPrefix(secondary, "auth0|")
	body["user_handle"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	body["relying_party_identifier"] = "foreign.example.test"
	body["credential_device_type"] = "multi_device"
	body["credential_backed_up"] = true
	body["user_agent"] = "Imported browser"
	body["aaguid"] = "00000000-0000-0000-0000-000000000000"
	body["transports"] = []string{"hybrid", "internal"}
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", body, "")
	if r.Code != 201 {
		t.Fatal(r.Body)
	}
	got := out.(map[string]any)
	for _, k := range []string{"identity_user_id", "user_handle", "relying_party_identifier", "credential_device_type", "credential_backed_up", "user_agent", "aaguid", "transports"} {
		if !jsonEqual(got[k], body[k]) {
			t.Errorf("%s: %v != %v", k, got[k], body[k])
		}
	}
	id := got["id"].(string)
	r, _ = mfaCall(t, e.clientsEnv, "GetGuardianEnrollment", strings.TrimPrefix(id, "passkey|"), "", nil, "")
	if r.Code != 404 {
		t.Fatalf("passkey Guardian enrollment: %d %s", r.Code, r.Body)
	}
	r, _ = mfaCall(t, e.clientsEnv, "CreateUserRecoveryCode", uid, "", nil, "")
	if r.Code != 400 {
		t.Fatalf("passkey MFA recovery eligibility: %d %s", r.Code, r.Body)
	}
}

func TestLinkMovesPasskeys(t *testing.T) {
	e, primary := mfaUser(t)
	secondary := e.mustCreate(t, map[string]any{"email": "second@example.test"})["user_id"].(string)
	handle := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	a := savedPasskey(t, e, secondary, "B", secondary, handle)
	e.mustLink(t, primary, secondary)
	got, err := e.st.WebAuthn().GetAuthenticatorByCredentialID(context.Background(), e.tn.ID, a.CredentialID)
	if err != nil || got.UserID != primary || !bytes.Equal(got.PublicData, a.PublicData) {
		t.Fatalf("linked credential: %v %v", got, err)
	}
	r, _ := e.unlink(t, primary, "auth0", strings.TrimPrefix(secondary, "auth0|"))
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	got, err = e.st.WebAuthn().GetAuthenticatorByCredentialID(context.Background(), e.tn.ID, a.CredentialID)
	if err != nil || got.UserID != secondary || !bytes.Equal(got.PublicData, a.PublicData) {
		t.Fatalf("unlinked credential: %v %v", got, err)
	}
}
func TestSessionAuthMethodsView(t *testing.T) {
	e, uid := mfaUser(t)
	s := &store.LoginSession{TenantID: e.tn.ID, ID: "recorded", UserID: uid, TokenHash: "recorded", AuthenticatedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour), AuthMethods: []store.AuthMethod{{Name: "passkey", At: now}, {Name: "mfa", Type: "webauthn-roaming", At: now.Add(time.Minute)}}}
	for _, legacy := range []bool{false, true} {
		if legacy {
			s.ID = "legacy"
			s.TokenHash = "legacy"
			s.AuthMethods = nil
		}
		if err := e.st.Sessions().Create(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		r, out := e.do(t, m2mCaller("read:sessions"), "GET", "/api/v2/sessions/"+s.ID, nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetSession(w, r, s.ID) })
		if r.Code != 200 {
			t.Fatal(r.Body)
		}
		got := out.(map[string]any)["authentication"].(map[string]any)["methods"].([]any)
		if legacy {
			if len(got) != 1 || got[0].(map[string]any)["name"] != "pwd" {
				t.Fatal(got)
			}
		} else {
			if len(got) != 2 || got[0].(map[string]any)["name"] != "passkey" || got[1].(map[string]any)["type"] != "webauthn-roaming" {
				t.Fatal(got)
			}
		}
	}
}
func TestClientMobileAndPasskeyGrant(t *testing.T) {
	e := newClientsEnv(t)
	mobile := map[string]any{"ios": map[string]any{"team_id": "ABCDE12345", "app_bundle_identifier": "com.example.App"}, "android": map[string]any{"app_package_name": "com.example.app", "sha256_cert_fingerprints": []string{strings.TrimSuffix(strings.Repeat("AB:", 32), ":")}}}
	r, out := e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Native", "app_type": "native", "mobile": mobile, "grant_types": []string{"urn:okta:params:oauth:grant-type:webauthn"}})
	if r.Code != 201 {
		t.Fatal(r.Body)
	}
	if !jsonEqual(out["mobile"], mobile) {
		t.Fatal(out)
	}
	c, err := e.st.Clients().Get(context.Background(), e.tn.ID, out["client_id"].(string))
	if err != nil || c.Mobile == nil || c.Mobile.IOS.TeamID != "ABCDE12345" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range []any{map[string]any{"ios": nil}, map[string]any{"ios": map[string]any{"team_id": 7}}, map[string]any{"ios": map[string]any{"app_bundle_identifier": false}}, map[string]any{"android": map[string]any{"app_package_name": 42}}, map[string]any{"android": map[string]any{"sha256_cert_fingerprints": []string{}}}, map[string]any{"android": map[string]any{"sha256_cert_fingerprints": []string{""}}}} {
		r, _ = e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Bad", "mobile": bad})
		if r.Code != 400 {
			t.Fatalf("bad mobile: %d %s", r.Code, r.Body)
		}
	}
	r, out = e.patch(t, m2mCaller(allClientScopes...), c.ClientID, map[string]any{"mobile": map[string]any{}})
	if r.Code != 200 || !jsonEqual(out["mobile"], map[string]any{}) {
		t.Fatal(r.Body)
	}
}

// webAuthnOff models the negotiated absence of webauthn.v1 while all old
// repositories continue working. Unexpected negotiation errors must propagate.
type webAuthnOff struct {
	store.Store
	err error
}

func (s webAuthnOff) CheckWebAuthnSupport(context.Context) error { return s.err }
func (s webAuthnOff) WebAuthnSupported() bool                    { return false }
func (s webAuthnOff) WebAuthn() store.WebAuthn                   { return store.UnimplementedWebAuthn{} }
func TestPasskeyMethodsUnavailable(t *testing.T) {
	e, uid := mfaUser(t)
	e.h.Store = webAuthnOff{e.st, store.ErrWebAuthnUnavailable}
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", passkeyBody("first"), "")
	if r.Code != 501 || out.(map[string]any)["errorCode"] != "webauthn_unavailable" {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
}
func TestClientMobileSchema(t *testing.T) {
	e := newClientsEnv(t)
	for _, mobile := range []any{map[string]any{"ios": map[string]any{"team_id": "", "app_bundle_identifier": "bad bundle", "future": true}}, map[string]any{"android": map[string]any{"app_package_name": "", "sha256_cert_fingerprints": []string{"AB"}}, "future": true}} {
		r, out := e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Native", "mobile": mobile})
		if r.Code != 201 || out["mobile"] == nil {
			t.Fatalf("%d %s", r.Code, r.Body)
		}
	}
	e.h.Store = webAuthnOff{e.st, store.ErrWebAuthnUnavailable}
	r, out := e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Old", "mobile": map[string]any{"ios": 3}})
	if r.Code != 201 || out["mobile"] != nil {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	e.h.Store = webAuthnOff{e.st, errors.New("negotiation failed")}
	r, _ = e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Failed", "mobile": map[string]any{}})
	if r.Code != 500 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
}
func TestPasskeyMethodsDefaultRP(t *testing.T) {
	e, uid := mfaUser(t)
	ctx := context.Background()
	d := &store.CustomDomain{TenantID: e.tn.ID, ID: "custom", Domain: "login.example.com", Status: "ready", RelyingPartyIdentifier: "example.com"}
	if err := e.st.CustomDomains().Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CustomDomains().PutHost(ctx, &store.HostBinding{TenantID: e.tn.ID, DomainID: d.ID, Host: d.Domain, Kind: store.HostPublic, Active: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CustomDomains().SetDefault(ctx, e.tn.ID, d.ID); err != nil {
		t.Fatal(err)
	}
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", passkeyBody("default"), "")
	if r.Code != 201 || out.(map[string]any)["relying_party_identifier"] != "example.com" {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	d.RelyingPartyIdentifier = "elsewhere.test"
	if err := e.st.CustomDomains().Update(ctx, d, d.Revision); err != nil {
		t.Fatal(err)
	}
	r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", passkeyBody("invalid-default"), "")
	if r.Code != 400 {
		t.Fatalf("invalid stored RP: %d %s", r.Code, r.Body)
	}
}

func hasPasskeyDomainEvent(events []logs.Event) bool {
	for _, e := range events {
		if e.Type != "sapi" {
			return true
		}
	}
	return false
}

func TestPasskeyMethodsNoResourceEvents(t *testing.T) {
	e, uid := mfaUser(t)
	ctx := context.Background()
	e.h.Store = events.Wrap(e.st, events.Config{})
	before, err := e.st.Events().LatestEventSeq(ctx, e.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", passkeyBody("event-free"), "")
	if r.Code != 201 {
		t.Fatal(r.Body)
	}
	id := out.(map[string]any)["id"].(string)
	r, _ = mfaCall(t, e.clientsEnv, "UpdateAuthenticationMethod", uid, id, map[string]any{"name": "Renamed"}, "")
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	all, err := e.st.MFA().ListAuthenticators(ctx, e.tn.ID, uid)
	if err != nil || len(resourceview.Multifactor(all)) != 0 {
		t.Fatalf("passkey multifactor: %v %v", all, err)
	}
	r, _ = mfaCall(t, e.clientsEnv, "DeleteAuthenticationMethod", uid, id, nil, "")
	if r.Code != 204 {
		t.Fatal(r.Body)
	}
	after, err := e.st.Events().LatestEventSeq(ctx, e.tn.ID)
	if err != nil || after != before {
		t.Fatalf("passkey event sequence %d -> %d: %v", before, after, err)
	}
}

type moveFailStore struct{ store.Store }

func (s moveFailStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(moveFailStore{tx}) })
}
func (s moveFailStore) WebAuthn() store.WebAuthn { return moveFailRepo{s.Store.WebAuthn()} }

type moveFailRepo struct{ store.WebAuthn }

func (r moveFailRepo) MovePasskeys(ctx context.Context, tid, from, to, identity string) error {
	if err := r.WebAuthn.MovePasskeys(ctx, tid, from, to, identity); err != nil {
		return err
	}
	return errors.New("injected move failure")
}
func TestLinkMovesPasskeysRollback(t *testing.T) {
	e, primary := mfaUser(t)
	ctx := context.Background()
	secondary := e.mustCreate(t, map[string]any{"email": "rollback@example.test"})["user_id"].(string)
	a := savedPasskey(t, e, secondary, "C", secondary, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	e.h.Store = moveFailStore{e.st}
	r, _ := e.link(t, primary, map[string]any{"provider": "auth0", "user_id": strings.TrimPrefix(secondary, "auth0|")})
	if r.Code != 500 {
		t.Fatal(r.Body)
	}
	got, err := e.st.WebAuthn().GetAuthenticatorByCredentialID(ctx, e.tn.ID, a.CredentialID)
	if err != nil || got.UserID != secondary {
		t.Fatalf("partial move: %v %v", got, err)
	}
	if _, err := e.st.Users().Get(ctx, e.tn.ID, secondary); err != nil {
		t.Fatal(err)
	}
	p, err := e.st.Users().Get(ctx, e.tn.ID, primary)
	if err != nil || len(p.Identities) != 1 {
		t.Fatalf("partial identities: %v %v", p, err)
	}
	e.h.Store = e.st
	e.mustLink(t, primary, secondary)
	e.h.Store = moveFailStore{e.st}
	r, _ = e.unlink(t, primary, "auth0", strings.TrimPrefix(secondary, "auth0|"))
	if r.Code != 500 {
		t.Fatal(r.Body)
	}
	got, err = e.st.WebAuthn().GetAuthenticatorByCredentialID(ctx, e.tn.ID, a.CredentialID)
	if err != nil || got.UserID != primary {
		t.Fatalf("partial unlink move: %v %v", got, err)
	}
	if _, err = e.st.Users().Get(ctx, e.tn.ID, secondary); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("partial recreated user: %v", err)
	}
	p, err = e.st.Users().Get(ctx, e.tn.ID, primary)
	if err != nil || len(p.Identities) != 2 {
		t.Fatalf("partial unlink identities: %v %v", p, err)
	}
}
func TestLinkMovesPasskeysLogin(t *testing.T) {
	e, primary := mfaUser(t)
	ctx := context.Background()
	secondary := e.mustCreate(t, map[string]any{"email": "login-linked@example.test"})["user_id"].(string)
	e.conn.Extra = map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}}}
	if err := e.st.Connections().Update(ctx, e.conn); err != nil {
		t.Fatal(err)
	}
	cfg := &store.HostedLoginConfig{TenantID: e.tn.ID}
	cfg.Prompts = map[string]any{"universal_login_experience": "new", "identifier_first": true}
	if err := e.st.HostedLogins().Put(ctx, cfg, cfg.Revision); err != nil {
		t.Fatal(err)
	}
	device := webauthntest.New(webauthntest.Options{UV: true, BE: true, BS: true})
	ch := bytes.Repeat([]byte{4}, 32)
	handle := bytes.Repeat([]byte{5}, 32)
	rp := e.tn.CanonicalHost
	origin := "https://" + rp
	raw := device.Create(webauthn.CreationOptions{RPID: rp, RPName: rp, UserID: handle, Challenge: ch, Algs: webauthn.DefaultAlgs}, origin)
	credential, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := webauthn.VerifyRegistration(credential, webauthn.Expect{RPID: rp, Origins: []string{origin}, Challenge: ch, RequireUV: true})
	if err != nil {
		t.Fatal(err)
	}
	b := passkeyBody("unused")
	b["key_id"] = base64.RawURLEncoding.EncodeToString(proof.CredentialID)
	b["public_key"] = base64.RawURLEncoding.EncodeToString(proof.PublicKeyCOSE)
	b["user_handle"] = base64.RawURLEncoding.EncodeToString(handle)
	b["credential_device_type"] = "multi_device"
	b["credential_backed_up"] = true
	r, _ := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", secondary, "", b, "")
	if r.Code != 201 {
		t.Fatal(r.Body)
	}
	own := savedPasskey(t, e, primary, "D", primary, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	e.mustLink(t, primary, secondary)
	svc := passkey.NewService(e.st, rpid.Policy{}, func() time.Time { return now })
	binding := passkey.Binding{Purpose: passkey.PasskeyLogin, RPID: rp, Origins: []string{origin}}
	device.Opts.SignCount = 1
	assertion := device.Get(svc.RequestOptions(rp, ch, time.Minute), origin)
	login, err := svc.Login(ctx, e.tn.ID, assertion, ch, binding)
	if err != nil || login.User.UserID != primary {
		t.Fatalf("linked login %v %v", login, err)
	}
	r, _ = e.unlink(t, primary, "auth0", strings.TrimPrefix(secondary, "auth0|"))
	if r.Code != 200 {
		t.Fatal(r.Body)
	}
	device.Opts.SignCount = 2
	assertion = device.Get(svc.RequestOptions(rp, ch, time.Minute), origin)
	login, err = svc.Login(ctx, e.tn.ID, assertion, ch, binding)
	if err != nil || login.User.UserID != secondary {
		t.Fatalf("unlinked login %v %v", login, err)
	}
	original, err := e.st.WebAuthn().GetAuthenticatorByCredentialID(ctx, e.tn.ID, own.CredentialID)
	if err != nil || original.UserID != primary {
		t.Fatalf("unrelated moved: %v %v", original, err)
	}
}
