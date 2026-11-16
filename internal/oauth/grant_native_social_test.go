package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/exchangerules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/tests/e2e/social/provider"
)

const appleSubjectType = "http://auth0.com/oauth/token-type/apple-authz-code"
const appleBundle = "com.example.native"

type nativeAppleFixture struct {
	*cteFixture
	idp      *provider.Provider
	during   func()
	requests int
}

func newNativeAppleFixture(t *testing.T) *nativeAppleFixture {
	t.Helper()
	f := &nativeAppleFixture{cteFixture: newCTEFixture(t)}
	var p *provider.Provider
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apple/token" {
			f.requests++
			if f.during != nil {
				f.during()
			}
		}
		p.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	var err error
	p, err = provider.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	f.idp = p
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err = p.RegisterApple(provider.AppleRegistration{ServicesID: "com.example.web", BundleID: appleBundle, TeamID: "ABCDEFGHIJ", KeyID: "1234567890", PublicKey: &key.PublicKey}); err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	ctx := context.Background()
	for _, id := range []string{"ropg", "ropg-public"} {
		c, _ := f.st.Clients().Get(ctx, f.tid, id)
		c.NativeSocialLogin = map[string]bool{"apple": true}
		c.Mobile = &store.ClientMobile{IOS: &store.ClientMobileIOS{AppBundleIdentifier: appleBundle}}
		c.TokenExchangeTypes = nil
		if err = f.st.Clients().Update(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	spec := connrules.Spec{Name: "apple", Strategy: "apple", EnabledClients: []string{"ropg", "ropg-public"}, Options: connrules.Options{Extra: map[string]any{"client_id": "com.example.web", "team_id": "ABCDEFGHIJ", "kid": "1234567890", "name": true, "email": true}}}
	conn := &store.Connection{TenantID: f.tid, ID: "con_native_apple", FederationRevision: 1}
	connrules.Apply(&spec, conn)
	conn.FederationSecretsSealed, err = federation.SealCredentials(f.wrapper, f.tid, conn.ID, federation.Credentials{ClientSecret: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.st.Connections().Create(ctx, conn); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	ps := federation.NewProviders(federation.FixturePolicy(roots), nil).WithAppleFixture(federation.AppleOverride{Endpoints: federation.Endpoints{AuthorizationURL: srv.URL + "/apple/authorize", TokenURL: srv.URL + "/apple/token", JWKSURL: srv.URL + "/apple/jwks", TokenAuthMethod: "client_secret_post"}, Issuer: srv.URL + "/apple", DiscoveryURL: srv.URL + "/apple/.well-known/openid-configuration"})
	f.h.Federation = &federation.FlowService{Service: federation.Service{Wrapper: f.wrapper, Now: time.Now}, Store: f.st, Providers: ps}
	return f
}
func (f *nativeAppleFixture) form(t *testing.T, subject string) url.Values {
	t.Helper()
	code, err := f.idp.AppleCode(appleBundle, subject)
	if err != nil {
		t.Fatal(err)
	}
	return cteForm("ropg-public", "", "subject_token_type", appleSubjectType, "subject_token", code, "scope", "openid offline_access read:things")
}
func TestNativeAppleDisabled(t *testing.T) {
	for _, mode := range []string{"flag", "bundle", "connection"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeAppleFixture(t)
			v := f.form(t, "alice")
			ctx := context.Background()
			c, _ := f.st.Clients().Get(ctx, f.tid, "ropg-public")
			switch mode {
			case "flag":
				c.NativeSocialLogin = nil
			case "bundle":
				c.Mobile = nil
			case "connection":
				conn, _ := f.st.Connections().Get(ctx, f.tid, "con_native_apple")
				conn.EnabledClients = nil
				_ = f.st.Connections().Update(ctx, conn)
			}
			_ = f.st.Clients().Update(ctx, c)
			s, b := f.token(t, v)
			if s != 400 || b["error"] != "invalid_request" || f.requests != 0 {
				t.Fatalf("%d %v requests=%d", s, b, f.requests)
			}
		})
	}
}
func TestNativeAppleSuccess(t *testing.T) {
	f := newNativeAppleFixture(t)
	f.actions.PostLogin(t, f.tid, "native-observe", `exports.onExecutePostLogin=async(event,api)=>{if(event.connection.strategy!=="apple"||event.transaction.protocol!=="oauth2-token-exchange")throw new Error("wrong native flow");api.idToken.setCustomClaim("https://example.test/native",true);};`)
	v := f.form(t, "relay")
	v.Set("user_profile", `{"name":{"firstName":"Native","lastName":"Apple"},"email":"attacker@example.test"}`)
	s, b := f.token(t, v)
	if s != 200 {
		t.Fatalf("%d %v", s, b)
	}
	claims, _ := verifyToken(t, f.keys, f.tid, b["id_token"].(string))
	if claims["https://example.test/native"] != true {
		t.Fatal(claims)
	}
	u := f.user(t, "apple|relay")
	if u.Name != "Native Apple" || u.Email == "attacker@example.test" {
		t.Fatalf("%+v", u)
	}
	v = f.form(t, "relay")
	v.Set("user_profile", `{"name":{"firstName":"Overwritten"}}`)
	s, b = f.token(t, v)
	if s != 200 || f.user(t, "apple|relay").Name != "Native Apple" {
		t.Fatalf("%d %v", s, b)
	}
}
func TestNativeAppleNoNonce(t *testing.T) {
	f := newNativeAppleFixture(t)
	s, b := f.token(t, f.form(t, "no-nonce"))
	if s != 200 {
		t.Fatalf("%d %v", s, b)
	}
}
func TestNativeAppleWrongBundle(t *testing.T) {
	f := newNativeAppleFixture(t)
	s, b := f.token(t, f.form(t, "wrong-audience"))
	if s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("%d %v", s, b)
	}
	if _, err := f.st.Users().Get(context.Background(), f.tid, "apple|wrong-audience"); err != store.ErrNotFound {
		t.Fatal(err)
	}
}
func TestNativeAppleAppleError(t *testing.T) {
	f := newNativeAppleFixture(t)
	v := f.form(t, "alice")
	v.Set("subject_token", "private-native-invalid-code")
	s, b := f.token(t, v)
	if s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("%d %v", s, b)
	}
	raw, _ := json.Marshal(f.rec.events)
	if strings.Contains(string(raw), v.Get("subject_token")) {
		t.Fatal("native code leaked")
	}
	if len(f.rec.events) == 0 || f.rec.events[len(f.rec.events)-1].Type != "fecte" {
		t.Fatal(f.codes())
	}
}
func TestNativeAppleProfileBounds(t *testing.T) {
	for _, raw := range []string{`[]`, `{"name":`, strings.Repeat(" ", 1025)} {
		f := newNativeAppleFixture(t)
		v := f.form(t, "alice")
		v.Set("user_profile", raw)
		s, b := f.token(t, v)
		if s != 400 || b["error"] != "invalid_request" || f.requests != 0 {
			t.Fatalf("%d %v requests=%d", s, b, f.requests)
		}
	}
}
func TestNativeAppleJSONProfile(t *testing.T) {
	f := newNativeAppleFixture(t)
	v := f.form(t, "json")
	m := map[string]any{}
	for k := range v {
		m[k] = v.Get(k)
	}
	m["user_profile"] = map[string]any{"name": map[string]any{"firstName": "JSON"}}
	raw, _ := json.Marshal(m)
	r, b := f.call(t, false, tokenCall{host: acmeHost, json: string(raw)})
	if r.Code != 200 || f.user(t, "apple|json").Name != "JSON" {
		t.Fatalf("%d %v", r.Code, b)
	}
}
func TestNativeAppleReconfiguredDuringExchange(t *testing.T) {
	for _, mode := range []string{"flag", "bundle", "revision", "identity epoch"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeAppleFixture(t)
			v := f.form(t, "race")
			f.during = func() {
				ctx := context.Background()
				if mode == "revision" {
					c, _ := f.st.Connections().Get(ctx, f.tid, "con_native_apple")
					c.FederationRevision++
					_ = f.st.Connections().Update(ctx, c)
				} else if mode == "identity epoch" {
					_ = f.st.Users().Delete(ctx, f.tid, f.aliceID(t))
				} else {
					c, _ := f.st.Clients().Get(ctx, f.tid, "ropg-public")
					if mode == "flag" {
						c.NativeSocialLogin = nil
					} else {
						c.Mobile.IOS.AppBundleIdentifier = "changed"
					}
					_ = f.st.Clients().Update(ctx, c)
				}
			}
			s, b := f.token(t, v)
			if s != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("%d %v", s, b)
			}
			if _, e := f.st.Users().Get(context.Background(), f.tid, "apple|race"); e != store.ErrNotFound {
				t.Fatal(e)
			}
		})
	}
}

func TestNativeAppleJSONProfileRawBound(t *testing.T) {
	f := newNativeAppleFixture(t)
	v := f.form(t, "oversize")
	m := map[string]any{}
	for k := range v {
		m[k] = v.Get(k)
	}
	raw, _ := json.Marshal(m)
	body := strings.TrimSuffix(string(raw), "}") + `,"user_profile":{` + strings.Repeat(" ", 1025) + `"name":{"firstName":"small"}}}`
	r, b := f.call(t, false, tokenCall{host: acmeHost, json: body})
	if r.Code != 400 || b["error"] != "invalid_request" || f.requests != 0 {
		t.Fatalf("%d %v requests=%d", r.Code, b, f.requests)
	}
}

func TestNativeAppleNotCustomProfile(t *testing.T) {
	f := newNativeAppleFixture(t)
	// Even an invalid legacy row cannot route the reserved type to an Action.
	a := f.actions.Deploy(t, f.tid, actions.TriggerCustomTokenExchange, "must-not-run", `exports.onExecuteCustomTokenExchange=async()=>{throw new Error("reserved Apple type reached custom Action")}`)
	if err := f.st.ClientCredentials().CreateProfile(context.Background(), &store.TokenExchangeProfile{TenantID: f.tid, ID: "tep_apple_legacy", Name: "legacy", SubjectTokenType: appleSubjectType, ActionID: a.ID, Type: "custom_authentication"}, 100); err != nil {
		t.Fatal(err)
	}
	f.h.Store = noClientCredentials{f.st}
	s, b := f.token(t, f.form(t, "reserved"))
	if s != 200 {
		t.Fatalf("%d %v", s, b)
	}
	if err := exchangerules.ValidateSubjectTokenType(appleSubjectType); err == nil {
		t.Fatal("reserved type allowed in profile rules")
	}
}
func TestNativeAppleConfidentialAuthentication(t *testing.T) {
	f := newNativeAppleFixture(t)
	v := f.form(t, "confidential")
	v.Set("client_id", "ropg")
	v.Set("client_secret", "wrong")
	s, b := f.token(t, v)
	if s != 401 || b["error"] != "invalid_client" || f.requests != 0 {
		t.Fatalf("%d %v", s, b)
	}
	v.Set("client_secret", "ropg-secret")
	s, b = f.token(t, v)
	if s != 200 {
		t.Fatalf("%d %v", s, b)
	}
}
func TestNativeAppleAudienceBeforeProvision(t *testing.T) {
	for _, aud := range []string{"https://unknown.test", "https://locked.test", "https://granted.test"} {
		f := newNativeAppleFixture(t)
		v := f.form(t, "audience")
		v.Set("audience", aud)
		s, b := f.token(t, v)
		if s == 200 || f.requests != 0 {
			t.Fatalf("%d %v requests=%d", s, b, f.requests)
		}
		if _, err := f.st.Users().Get(context.Background(), f.tid, "apple|audience"); err != store.ErrNotFound {
			t.Fatal(err)
		}
	}
}
func (f *nativeAppleFixture) organization(t *testing.T, assign bool) *store.Organization {
	t.Helper()
	ctx := context.Background()
	org := &store.Organization{TenantID: f.tid, ID: orgrules.NewID(), Name: "native-org", DisplayName: "Native", ThirdPartyClientAccess: "allow"}
	if err := f.st.Organizations().Create(ctx, org, []store.OrganizationConnection{{TenantID: f.tid, OrganizationID: org.ID, ConnectionID: "con_native_apple", ShowAsButton: true, AssignMembershipOnLogin: assign}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"ropg-public", "ropg"} {
		c, _ := f.st.Clients().Get(ctx, f.tid, id)
		c.OrganizationUsage = store.OrgUsageRequire
		if err := f.st.Clients().Update(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	return org
}
func TestNativeAppleOrganization(t *testing.T) {
	for _, assign := range []bool{true, false} {
		t.Run(fmt.Sprint(assign), func(t *testing.T) {
			f := newNativeAppleFixture(t)
			org := f.organization(t, assign)
			v := f.form(t, "org-user")
			v.Set("organization", org.ID)
			s, b := f.token(t, v)
			if !assign {
				if s != 400 || b["error"] != "invalid_grant" {
					t.Fatalf("%d %v", s, b)
				}
				if _, err := f.st.Users().Get(context.Background(), f.tid, "apple|org-user"); err != store.ErrNotFound {
					t.Fatalf("refused organization left user: %v", err)
				}
				return
			}
			if s != 200 {
				t.Fatalf("%d %v", s, b)
			}
			claims, _ := verifyToken(t, f.keys, f.tid, b["id_token"].(string))
			if claims["org_id"] != org.ID {
				t.Fatal(claims)
			}
			member, err := f.st.Organizations().IsMember(context.Background(), f.tid, org.ID, "apple|org-user")
			if err != nil || !member {
				t.Fatalf("member=%v err=%v", member, err)
			}
		})
	}
}
func (f *nativeAppleFixture) enableMFA(t *testing.T, action bool) {
	t.Helper()
	ctx := context.Background()
	g, err := f.st.MFA().GetGuardian(ctx, f.tid)
	if err != nil {
		t.Fatal(err)
	}
	g.Factors = map[string]bool{"otp": true, "recovery-code": true}
	if !action {
		g.Policies = []string{"all-applications"}
	} else {
		g.Policies = nil
		f.actions.PostLogin(t, f.tid, "native-mfa", `exports.onExecutePostLogin=async(event,api)=>{api.multifactor.enable("any")}`)
	}
	if err = f.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	c, _ := f.st.Clients().Get(ctx, f.tid, "ropg")
	c.GrantTypes = append(c.GrantTypes, otpGrant, recoveryGrant)
	if err = f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	f.h.MFA = mfa.NewService(f.st, f.wrapper, nil, nil, f.h.Log, f.h.now)
}
func TestNativeAppleMFAOrganizationContinuation(t *testing.T) {
	for _, action := range []bool{false, true} {
		t.Run(fmt.Sprint(action), func(t *testing.T) {
			f := newNativeAppleFixture(t)
			org := f.organization(t, true)
			f.enableMFA(t, action)
			v := f.form(t, "mfa-user")
			v.Set("client_id", "ropg")
			v.Set("client_secret", "ropg-secret")
			v.Set("organization", org.ID)
			s, b := f.token(t, v)
			if s != 403 || b["error"] != "mfa_required" {
				t.Fatalf("%d %v", s, b)
			}
			tok := b["mfa_token"].(string)
			secret, _ := f.associateOTP(t, tok)
			out := f.proveOTP(t, tok, secret)
			claims, _ := verifyToken(t, f.keys, f.tid, out["id_token"].(string))
			if claims["org_id"] != org.ID || out["issued_token_type"] != issuedTokenTypeAccessToken {
				t.Fatalf("claims=%v response=%v", claims, out)
			}
		})
	}
}
func TestNativeAppleMFAReconfiguration(t *testing.T) {
	for _, mode := range []string{"flag", "bundle", "revision", "connection"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeAppleFixture(t)
			f.enableMFA(t, false)
			v := f.form(t, "stale-mfa")
			v.Set("client_id", "ropg")
			v.Set("client_secret", "ropg-secret")
			s, b := f.token(t, v)
			if s != 403 || b["error"] != "mfa_required" {
				t.Fatalf("%d %v", s, b)
			}
			tok := b["mfa_token"].(string)
			secret, _ := f.associateOTP(t, tok)
			ctx := context.Background()
			switch mode {
			case "flag", "bundle":
				c, _ := f.st.Clients().Get(ctx, f.tid, "ropg")
				if mode == "flag" {
					c.NativeSocialLogin = nil
				} else {
					c.Mobile.IOS.AppBundleIdentifier = "changed"
				}
				_ = f.st.Clients().Update(ctx, c)
			default:
				c, _ := f.st.Connections().Get(ctx, f.tid, "con_native_apple")
				if mode == "revision" {
					c.FederationRevision++
				} else {
					c.EnabledClients = nil
				}
				_ = f.st.Connections().Update(ctx, c)
			}
			s, b = f.token(t, mfaForm(otpGrant, tok, "otp", otpAt(secret, f.h.now())))
			if s != 400 || b["error"] != "invalid_grant" || b["access_token"] != nil {
				t.Fatalf("%d %v", s, b)
			}
		})
	}
}

type nativeBeforeTxStore struct {
	store.Store
	before func()
}

func (s nativeBeforeTxStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	s.before()
	return s.Store.WithTx(ctx, fn)
}
func TestNativeAppleReconfiguredBeforeMint(t *testing.T) {
	f := newNativeAppleFixture(t)
	v := f.form(t, "late-race")
	f.h.Store = nativeBeforeTxStore{Store: f.st, before: func() {
		c, _ := f.st.Clients().Get(context.Background(), f.tid, "ropg-public")
		c.NativeSocialLogin = nil
		_ = f.st.Clients().Update(context.Background(), c)
	}}
	s, b := f.token(t, v)
	if s != 400 || b["error"] != "invalid_grant" || b["access_token"] != nil {
		t.Fatalf("%d %v", s, b)
	}
}

func TestNativeAppleFirstConnectionNoFallback(t *testing.T) {
	f := newNativeAppleFixture(t)
	ctx := context.Background()
	conn, _ := f.st.Connections().Get(ctx, f.tid, "con_native_apple")
	creds, err := federation.OpenCredentials(f.wrapper, f.tid, conn.ID, conn.FederationSecretsSealed)
	if err != nil {
		t.Fatal(err)
	}
	conn.ID = "con_apple_first"
	conn.Name = "Aapple"
	conn.FederationSecretsSealed, err = federation.SealCredentials(f.wrapper, f.tid, conn.ID, creds)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.st.Connections().Create(ctx, conn); err != nil {
		t.Fatal(err)
	}
	v := f.form(t, "first")
	s, b := f.token(t, v)
	if s != 200 {
		t.Fatalf("%d %v", s, b)
	}
	if f.rec.events[len(f.rec.events)-1].ConnectionID != conn.ID {
		t.Fatal(f.rec.events)
	}
	v = f.form(t, "first")
	v.Set("subject_token", "rejected-private-code")
	s, b = f.token(t, v)
	if s != 400 || b["error"] != "invalid_grant" || f.requests != 2 || f.rec.events[len(f.rec.events)-1].ConnectionID != conn.ID {
		t.Fatalf("%d %v requests=%d events=%+v", s, b, f.requests, f.rec.events)
	}
}
func TestNativeAppleSignupBudget(t *testing.T) {
	f := newNativeAppleFixture(t)
	ctx := context.Background()
	tn, _ := f.st.Tenants().Get(ctx, f.tid)
	tn.ProtectionSettings.SuspiciousIP.Stage.PreUserRegistration = store.ProtectionRate{MaxAttempts: 1, Rate: 3600000}
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"budget-one", "budget-one", "budget-two"} {
		s, b := f.token(t, f.form(t, sub))
		if sub == "budget-two" {
			if s != 429 {
				t.Fatalf("%d %v", s, b)
			}
		} else if s != 200 {
			t.Fatalf("%d %v", s, b)
		}
	}
	if _, err := f.st.Users().Get(ctx, f.tid, "apple|budget-two"); err != store.ErrNotFound {
		t.Fatal(err)
	}
}

func TestNativeAppleMFACountsCompletedLogin(t *testing.T) {
	f := newNativeAppleFixture(t)
	f.enableMFA(t, false)
	v := f.form(t, "mfa-count")
	v.Set("client_id", "ropg")
	v.Set("client_secret", "ropg-secret")
	s, b := f.token(t, v)
	if s != 403 || b["error"] != "mfa_required" {
		t.Fatalf("%d %v", s, b)
	}
	tok := b["mfa_token"].(string)
	secret, _ := f.associateOTP(t, tok)
	f.proveOTP(t, tok, secret)
	if u := f.user(t, "apple|mfa-count"); u.LoginsCount != 1 {
		t.Fatalf("completed native login count=%d", u.LoginsCount)
	}
}

func TestNativeAppleDeletedIdentityDuringExchange(t *testing.T) {
	f := newNativeAppleFixture(t)
	s, b := f.token(t, f.form(t, "deleted"))
	if s != 200 {
		t.Fatalf("%d %v", s, b)
	}
	f.during = func() {
		if err := f.st.Users().Delete(context.Background(), f.tid, "apple|deleted"); err != nil {
			panic(err)
		}
	}
	s, b = f.token(t, f.form(t, "deleted"))
	if s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("%d %v", s, b)
	}
	if _, err := f.st.Users().Get(context.Background(), f.tid, "apple|deleted"); err != store.ErrNotFound {
		t.Fatalf("identity recreated: %v", err)
	}
}
func TestNativeAppleBlockedUser(t *testing.T) {
	f := newNativeAppleFixture(t)
	s, b := f.token(t, f.form(t, "blocked"))
	if s != 200 {
		t.Fatalf("%d %v", s, b)
	}
	f.during = func() {
		u, err := f.st.Users().Get(context.Background(), f.tid, "apple|blocked")
		if err != nil {
			panic(err)
		}
		u.Blocked = true
		if err = f.st.Users().Update(context.Background(), u); err != nil {
			panic(err)
		}
	}
	s, b = f.token(t, f.form(t, "blocked"))
	if s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("%d %v", s, b)
	}
}

func TestNativeAppleCodeForOtherClient(t *testing.T) {
	f := newNativeAppleFixture(t)
	v := f.form(t, "wrong-client")
	code, err := f.idp.AppleCode("com.example.web", "wrong-client")
	if err != nil {
		t.Fatal(err)
	}
	v.Set("subject_token", code)
	s, b := f.token(t, v)
	if s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("%d %v", s, b)
	}
	if _, err = f.st.Users().Get(context.Background(), f.tid, "apple|wrong-client"); err != store.ErrNotFound {
		t.Fatalf("wrong client created user: %v", err)
	}
}
func TestNativeAppleIngressPrivacy(t *testing.T) {
	for _, tc := range []struct{ media, body string }{
		{"application/x-www-form-urlencoded", "subject_token=private-native-ingress-code&x=a&x=b"},
		{"application/json", `{"subject_token":"private-native-ingress-code","user_profile":{` + strings.Repeat(" ", 1025) + `"name":{}}}`},
	} {
		r := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.media)
		_, err := parseTokenRequest(httptest.NewRecorder(), r, "user_profile")
		if err == nil {
			t.Fatal("expected parse refusal")
		}
		if got := logscrub.MaskText(r.Context(), "private-native-ingress-code"); got != logscrub.Marker {
			t.Fatalf("native credential not registered before refusal: %s", got)
		}
	}
}

func TestNativeAppleFormContract(t *testing.T) {
	f := newNativeAppleFixture(t)
	r, b := f.call(t, true, tokenCall{host: acmeHost, form: cc("m2m", "m2m-secret", "audience", acmeAPI)})
	if r.Code != 200 {
		t.Fatalf("ordinary form %d %v", r.Code, b)
	}
	v := f.form(t, "contract")
	v.Set("user_profile", `{"name":{"firstName":"Contract"}}`)
	r, b = f.call(t, true, tokenCall{host: acmeHost, form: v})
	if r.Code != 200 {
		t.Fatalf("native form %d %v", r.Code, b)
	}
	v = f.form(t, "contract")
	v.Set("user_profile", `{"name":`)
	s, b := f.token(t, v)
	if s != 400 || b["error"] != "invalid_request" {
		t.Fatalf("malformed profile %d %v", s, b)
	}
}
