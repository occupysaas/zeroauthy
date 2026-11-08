package seed

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func applySeed(t *testing.T, st store.Store, raw string, mode Mode) error {
	t.Helper()
	f, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	f.Mode = mode
	return Apply(context.Background(), st, f, fixedNow, testWrapper(t))
}

func TestSeedRoamingUserVerification(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := applySeed(t, st, `tenants: [{name: acme, guardian: {factors: {webauthn-roaming: true}, webauthn_roaming: {user_verification: required}}}]`, ModeApply); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	get := func() *store.GuardianSettings {
		t.Helper()
		g, err := st.MFA().GetGuardian(ctx, tn.ID)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := get()
	if mfa.RoamingUV(g) != "required" || !g.Factors["webauthn-roaming"] {
		t.Fatalf("user verification not applied: %s %+v", g.Stored["webauthn-roaming/settings"], g.Factors)
	}
	// The seed writes the same record as the operator extension route.
	var stored map[string]string
	if err := json.Unmarshal(g.Stored["webauthn-roaming/settings"], &stored); err != nil || !reflect.DeepEqual(stored, map[string]string{"user_verification": "required"}) {
		t.Fatalf("stored record = %s (%v)", g.Stored["webauthn-roaming/settings"], err)
	}
	// Identical seeds and omitted settings leave the configuration version alone.
	for _, raw := range []string{
		`tenants: [{name: acme, guardian: {webauthn_roaming: {user_verification: required}}}]`,
		`tenants: [{name: acme, guardian: {factors: {otp: false}}}]`,
		`tenants: [{name: acme}]`,
	} {
		before := get()
		if err := applySeed(t, st, raw, ModeApply); err != nil {
			t.Fatal(err)
		}
		if after := get(); after.Version != before.Version || mfa.RoamingUV(after) != "required" {
			t.Fatalf("%s changed the setting: v%d→v%d %s", raw, before.Version, after.Version, after.Stored["webauthn-roaming/settings"])
		}
	}
	// Other stored Guardian records survive a change.
	g = get()
	g.Stored["/guardian/settings"] = json.RawMessage(`{"display_remember_me_checkbox":true}`)
	if err := st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	if err := applySeed(t, st, `tenants: [{name: acme, guardian: {webauthn_roaming: {user_verification: preferred}}}]`, ModeApply); err != nil {
		t.Fatal(err)
	}
	if g = get(); mfa.RoamingUV(g) != "preferred" || string(g.Stored["/guardian/settings"]) != `{"display_remember_me_checkbox":true}` {
		t.Fatalf("change lost state: %+v", g.Stored)
	}
	if err := applySeed(t, st, `tenants: [{name: acme, guardian: {webauthn_roaming: {user_verification: discouraged}}}]`, ModeCreateOnly); err != nil {
		t.Fatal(err)
	}
	if mfa.RoamingUV(get()) != "preferred" {
		t.Fatal("create_only changed an existing tenant's user verification")
	}
	if err := applySeed(t, st, `tenants: [{name: acme, guardian: {webauthn_roaming: {user_verification: discouraged}}}]`, ModeApply); err != nil {
		t.Fatal(err)
	}
	if mfa.RoamingUV(get()) != "discouraged" {
		t.Fatal("discouraged (Never) not applied")
	}
}

func TestSeedRoamingUserVerificationValidation(t *testing.T) {
	for _, value := range []string{`null`, `{}`, `{user_verification: null}`, `{user_verification: always}`, `{user_verification: 1}`, `{user_verification: Required}`, `{user_verification: required, extra: true}`, `[required]`} {
		t.Run(value, func(t *testing.T) {
			_, err := Parse([]byte(`tenants: [{name: acme, guardian: {webauthn_roaming: ` + value + `}}]`))
			if err == nil {
				t.Fatal("invalid user verification accepted")
			}
		})
	}
	for _, value := range []string{"discouraged", "preferred", "required"} {
		if _, err := Parse([]byte(`tenants: [{name: acme, guardian: {webauthn_roaming: {user_verification: ` + value + `}}}]`)); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
}

const nativePasskeySeed = `tenants:
- name: acme
  clients:
  - client_id: native
    name: Native
    app_type: native
    token_endpoint_auth_method: none
    callbacks: [com.example.app://callback]
    grant_types: [authorization_code, refresh_token, "urn:okta:params:oauth:grant-type:webauthn"]
    mobile:
      ios: {team_id: ABCDE12345, app_bundle_identifier: com.example.app}
      android:
        app_package_name: com.example.app
        sha256_cert_fingerprints: ["AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"]
  connections:
  - name: Users
    strategy: auth0
    enabled_clients: [native]
    options:
      authentication_methods: {password: {enabled: true}, passkey: {enabled: true}}
      passkey_options: {challenge_ui: button, progressive_enrollment_enabled: false, local_enrollment_enabled: true}
`

func TestSeedPasskeyClientMobileAndGrant(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := applySeed(t, st, nativePasskeySeed, ModeApply); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	c, err := st.Clients().Get(ctx, tn.ID, "native")
	if err != nil {
		t.Fatal(err)
	}
	want := &store.ClientMobile{
		IOS:     &store.ClientMobileIOS{TeamID: "ABCDE12345", AppBundleIdentifier: "com.example.app"},
		Android: &store.ClientMobileAndroid{AppPackageName: "com.example.app", SHA256CertFingerprints: []string{"AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"}},
	}
	if !reflect.DeepEqual(c.Mobile, want) || !slices.Contains(c.GrantTypes, clientrules.GrantPasskey) {
		t.Fatalf("client = mobile %+v grants %v", c.Mobile, c.GrantTypes)
	}
	conn, err := st.Connections().GetByName(ctx, tn.ID, "Users")
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := conn.Extra["passkey_options"].(map[string]any)
	methods, _ := conn.Extra["authentication_methods"].(map[string]any)
	if opts["challenge_ui"] != "button" || opts["progressive_enrollment_enabled"] != false || methods["passkey"].(map[string]any)["enabled"] != true {
		t.Fatalf("connection passkey options = %+v %+v", methods, opts)
	}
	// Reapplying is a no-op; dropping mobile from the seed clears it like any
	// other seed-owned client setting; a partial mobile keeps only what is named.
	if err := applySeed(t, st, nativePasskeySeed, ModeApply); err != nil {
		t.Fatal(err)
	}
	partial := strings.Replace(nativePasskeySeed, "      android:\n        app_package_name: com.example.app\n        sha256_cert_fingerprints: [\"AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\"]\n", "", 1)
	if err := applySeed(t, st, partial, ModeApply); err != nil {
		t.Fatal(err)
	}
	if c, _ = st.Clients().Get(ctx, tn.ID, "native"); c.Mobile == nil || c.Mobile.Android != nil || c.Mobile.IOS == nil {
		t.Fatalf("partial mobile = %+v", c.Mobile)
	}
	without := strings.Replace(partial, "    mobile:\n      ios: {team_id: ABCDE12345, app_bundle_identifier: com.example.app}\n", "", 1)
	if err := applySeed(t, st, without, ModeApply); err != nil {
		t.Fatal(err)
	}
	if c, _ = st.Clients().Get(ctx, tn.ID, "native"); c.Mobile != nil {
		t.Fatalf("omitted mobile kept %+v", c.Mobile)
	}
}

func TestSeedClientMobileValidation(t *testing.T) {
	for name, mobile := range map[string]string{
		"not object":         `true`,
		"ios not object":     `{ios: x}`,
		"team id number":     `{ios: {team_id: 1}}`,
		"team id null":       `{ios: {team_id: null}}`,
		"unknown ios key":    `{ios: {team: ABC}}`,
		"unknown platform":   `{windows: {}}`,
		"empty fingerprints": `{android: {sha256_cert_fingerprints: []}}`,
		"empty fingerprint":  `{android: {sha256_cert_fingerprints: [""]}}`,
		"fingerprint number": `{android: {sha256_cert_fingerprints: [1]}}`,
		"unknown android":    `{android: {package: com.example}}`,
	} {
		t.Run(name, func(t *testing.T) {
			raw := `tenants: [{name: a, clients: [{client_id: c, app_type: native, mobile: ` + mobile + `}]}]`
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("invalid mobile accepted")
			}
		})
	}
	if _, err := Parse([]byte(`tenants: [{name: a, clients: [{client_id: c, app_type: native, mobile: {ios: {}, android: {}}}]}]`)); err != nil {
		t.Fatalf("documented empty platform objects refused: %v", err)
	}
}

// R1: an alias may name any registrable suffix of its own host; anything
// else, a public suffix and (strict) the deployment's own namespace are refused.
func TestSeedAliasRPIDRule(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		host, rp string
		strict   bool
		ok       bool
	}{
		{"login.example.com", "login.example.com", false, true},
		{"login.example.com", "example.com", false, true},
		{"login.example.com", "example.com", true, false}, // parent of the base domain id.example.com
		{"login.customer.test", "customer.test", true, true},
		{"login.example.com", "ample.com", false, false},
		{"login.example.com", "other.example.com", false, false},
		{"login.example.com", "com", false, false},
	} {
		raw := "tenants: [{name: acme, domains: [{host: " + tc.host + ", relying_party_identifier: " + tc.rp + "}]}]"
		f, err := Parse([]byte(raw))
		if err == nil {
			err = f.CheckManagementAPI("id.example.com")
		}
		if err == nil {
			err = Apply(ctx, memory.New(), f, fixedNow, testWrapper(t), Options{RPIDPolicy: rpid.Policy{BaseDomain: "id.example.com", RestrictShared: tc.strict}})
		}
		if (err == nil) != tc.ok {
			t.Errorf("%s → %s strict=%v: err=%v, want ok=%v", tc.host, tc.rp, tc.strict, err, tc.ok)
		}
	}
}

// webauthnlessStore is a plugin store that did not negotiate webauthn.v1.
type webauthnlessStore struct{ store.Store }

func (s webauthnlessStore) CheckWebAuthnSupport(context.Context) error {
	return store.ErrWebAuthnUnavailable
}
func (s webauthnlessStore) WebAuthnSupported() bool { return false }
func (s webauthnlessStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(webauthnlessStore{tx}) })
}

func TestSeedPasskeyFieldsNeedWebAuthn(t *testing.T) {
	ctx := context.Background()
	for name, raw := range map[string]string{
		"client mobile": nativePasskeySeed,
		"alias rp id":   `tenants: [{name: acme, domains: [{host: login.example.com, relying_party_identifier: example.com}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			mem := memory.New()
			f, err := Parse([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err = f.CheckManagementAPI("id.example.net"); err != nil {
				t.Fatal(err)
			}
			err = Apply(ctx, webauthnlessStore{mem}, f, fixedNow, testWrapper(t))
			if !errors.Is(err, store.ErrWebAuthnUnavailable) {
				t.Fatalf("passkey field silently accepted by a store without webauthn.v1: %v", err)
			}
			if !strings.Contains(err.Error(), "webauthn.v1") {
				t.Fatalf("error does not name the capability: %v", err)
			}
			if _, err = mem.Tenants().GetByName(ctx, "acme"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("refused seed still wrote the tenant")
			}
		})
	}
	// Stored-only passkey configuration survives an old plugin unchanged, so
	// it is accepted: the grant, connection passkey options and the
	// security-key user-verification record.
	mem := memory.New()
	storedOnly := strings.Replace(nativePasskeySeed, "    mobile:\n      ios: {team_id: ABCDE12345, app_bundle_identifier: com.example.app}\n      android:\n        app_package_name: com.example.app\n        sha256_cert_fingerprints: [\"AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\"]\n", "", 1)
	storedOnly = strings.Replace(storedOnly, "- name: acme\n", "- name: acme\n  guardian: {webauthn_roaming: {user_verification: required}}\n  domains: [login.example.com]\n", 1)
	if err := applySeed(t, webauthnlessStore{mem}, storedOnly, ModeApply); err != nil {
		t.Fatal(err)
	}
	tn, _ := mem.Tenants().GetByName(ctx, "acme")
	c, _ := mem.Clients().Get(ctx, tn.ID, "native")
	g, _ := mem.MFA().GetGuardian(ctx, tn.ID)
	if !slices.Contains(c.GrantTypes, clientrules.GrantPasskey) || mfa.RoamingUV(g) != "required" {
		t.Fatalf("stored-only passkey settings lost: %v %s", c.GrantTypes, g.Stored["webauthn-roaming/settings"])
	}
}
