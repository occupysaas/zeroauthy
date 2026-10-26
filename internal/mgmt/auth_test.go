package mgmt_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

const (
	base       = "example.com"
	systemHost = "admin.example.test" // canonical; the system tenant also answers system.example.com
	acmeAPI    = "https://acme.example.com/api/v2/"
	globexAPI  = "https://globex.example.com/api/v2/"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

type env struct {
	st      store.Store
	km      *keys.Manager
	ids     map[string]string // tenant name → ID
	handler http.Handler
	hdr     http.Header // of the last response
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st.SigningKeys(), w)
	e := &env{st: st, km: km, ids: map[string]string{}}
	sys, err := system.Ensure(ctx, st, system.Config{Host: systemHost, Wrapper: w})
	if err != nil {
		t.Fatal(err)
	}
	e.ids[tenant.SystemName] = sys.ID
	for _, name := range []string{"acme", "globex"} {
		tn, err := tenantsetup.UpsertTenant(ctx, st, name, now, func(tn *store.Tenant) error {
			tn.Domains = []string{"login." + name + ".test"}
			return tenantsetup.InitializeCanonical(tn, base)
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := km.Ensure(ctx, tn.ID); err != nil {
			t.Fatal(err)
		}
		e.ids[name] = tn.ID
	}
	if err := st.Users().Create(ctx, &store.User{TenantID: sys.ID, UserID: "auth0|op", Email: "op@example.test"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: sys.ID, UserID: "auth0|op", Tenants: []string{store.OperatorAllTenants}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: sys.ID, UserID: "auth0|acme-op", Tenants: []string{"acme"}}); err != nil {
		t.Fatal(err)
	}
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := mgmt.CallerFrom(r.Context())
		_ = json.NewEncoder(w).Encode(c)
	})
	mux := http.NewServeMux()
	mux.Handle("/any", echo)
	mux.Handle("/read", mgmt.Require("read:clients")(echo))
	mux.Handle("/operator", mgmt.RequireOperator(echo))
	auth := mgmt.Auth(mgmt.Config{Store: st, Keys: km, BaseDomain: base, SystemHost: systemHost, Now: func() time.Time { return now }})
	e.handler = tenant.NewResolver(st.Tenants(), base, false).Middleware(auth(mux))
	return e
}

type tok struct {
	tenant   string // signing tenant
	iss      string
	aud      []string
	sub      string
	clientID string
	gty      string
	scopes   []string
	operator []string
	at       time.Time
}

func (e *env) mint(t *testing.T, p tok) string {
	t.Helper()
	at := p.at
	if at.IsZero() {
		at = now
	}
	m := &oauth.Minter{Keys: e.km, Now: func() time.Time { return at }}
	raw, err := m.AccessToken(context.Background(), oauth.AccessTokenParams{
		TenantID: e.ids[p.tenant], Issuer: p.iss, Subject: p.sub, Audience: p.aud, ClientID: p.clientID,
		Scopes: p.scopes, GrantType: p.gty, Lifetime: time.Hour, Operator: p.operator,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func m2m(tenantName, iss, aud string, scopes ...string) tok {
	return tok{tenant: tenantName, iss: iss, aud: []string{aud}, sub: "cli@clients", clientID: "cli", gty: "client-credentials", scopes: scopes}
}

func operator(iss string, claim []string) tok {
	return tok{tenant: tenant.SystemName, iss: iss, aud: []string{tenant.OperatorAudience, "https://" + systemHost + "/userinfo"},
		sub: "auth0|op", clientID: system.ConsoleClientID, scopes: []string{"openid"}, operator: claim}
}

func (e *env) do(t *testing.T, host, path, authz string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", "https://"+host+path, nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	e.hdr = rec.Header()
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func (e *env) checkError(t *testing.T, name string, code int, body map[string]any, want int, wantCode string) {
	t.Helper()
	if code != want || body["statusCode"] != float64(want) || body["error"] != http.StatusText(want) ||
		body["errorCode"] != wantCode || body["message"] == "" {
		t.Errorf("%s: %d %v, want %d %s", name, code, body, want, wantCode)
	}
	// RFC 6750 §3 (not observed on Auth0).
	if got, want := e.hdr.Get("WWW-Authenticate"), `Bearer error="`+wantCode+`"`; got != want {
		t.Errorf("%s: WWW-Authenticate = %q, want %q", name, got, want)
	}
}

func TestMgmtAuthM2MOnEveryHost(t *testing.T) {
	e := newEnv(t)
	for _, iss := range []string{"https://acme.example.com/", "https://login.acme.test/"} {
		raw := e.mint(t, m2m("acme", iss, acmeAPI, "read:clients", "update:clients"))
		for _, host := range []string{"acme.example.com", "login.acme.test"} {
			code, body := e.do(t, host, "/read", "Bearer "+raw)
			if code != 200 || body["Kind"] != float64(mgmt.M2M) || body["ClientID"] != "cli" ||
				!slices.Equal(toStrings(body["Scopes"]), []string{"read:clients", "update:clients"}) {
				t.Errorf("iss %s at %s: %d %v", iss, host, code, body)
			}
		}
	}
}

func toStrings(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, s := range l {
		out = append(out, s.(string))
	}
	return out
}

func TestMgmtAuthRejects(t *testing.T) {
	e := newEnv(t)
	good := e.mint(t, m2m("acme", "https://acme.example.com/", acmeAPI, "read:clients"))
	parts := strings.Split(good, ".")
	sig := []byte(parts[2])
	sig[5] ^= 1
	tampered := parts[0] + "." + parts[1] + "." + string(sig)
	user := m2m("acme", "https://acme.example.com/", acmeAPI, "read:clients")
	user.sub, user.gty = "auth0|someone", ""
	for _, tc := range []struct {
		name, authz string
	}{
		{"no token", ""},
		{"not bearer", "Basic Y2xpOnNlY3JldA=="},
		{"garbage", "Bearer not.a.jwt"},
		{"bad signature", "Bearer " + tampered},
		{"wrong audience", "Bearer " + e.mint(t, m2m("acme", "https://acme.example.com/", "https://api.acme.test", "read:clients"))},
		{"non-canonical audience", "Bearer " + e.mint(t, m2m("acme", "https://acme.example.com/", "https://login.acme.test/api/v2/", "read:clients"))},
		{"foreign issuer", "Bearer " + e.mint(t, m2m("acme", "https://evil.test/", acmeAPI, "read:clients"))},
		{"expired", "Bearer " + func() string {
			p := m2m("acme", "https://acme.example.com/", acmeAPI, "read:clients")
			p.at = now.Add(-2 * time.Hour)
			return e.mint(t, p)
		}()},
		{"user token", "Bearer " + e.mint(t, user)},
	} {
		code, body := e.do(t, "acme.example.com", "/any", tc.authz)
		e.checkError(t, tc.name, code, body, http.StatusUnauthorized, "invalid_token")
	}
}

func TestMgmtAuthMissingScope(t *testing.T) {
	e := newEnv(t)
	raw := e.mint(t, m2m("acme", "https://acme.example.com/", acmeAPI, "update:clients"))
	code, body := e.do(t, "acme.example.com", "/read", "Bearer "+raw)
	e.checkError(t, "missing scope", code, body, http.StatusForbidden, "insufficient_scope")
	if !strings.Contains(body["message"].(string), "read:clients") {
		t.Errorf("message = %v", body["message"])
	}
	code, body = e.do(t, "acme.example.com", "/operator", "Bearer "+raw)
	e.checkError(t, "M2M at operator-only", code, body, http.StatusForbidden, "insufficient_scope")
}

// Review Focus 1: a token for one tenant is never accepted by another.
func TestMgmtAuthCrossTenant(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name string
		tok  tok
	}{
		// acme's own token, presented at globex.
		{"acme token", m2m("acme", "https://acme.example.com/", acmeAPI, "read:clients")},
		// Signed by acme but claiming to be globex's.
		{"acme-signed, globex claims", m2m("acme", "https://globex.example.com/", globexAPI, "read:clients")},
		{"acme-signed, globex audience", m2m("acme", "https://acme.example.com/", globexAPI, "read:clients")},
		// The system tenant's M2M token for its own Management API.
		{"system M2M", m2m(tenant.SystemName, "https://"+systemHost+"/", "https://system.example.com/api/v2/", "read:clients")},
	} {
		code, body := e.do(t, "globex.example.com", "/read", "Bearer "+e.mint(t, tc.tok))
		e.checkError(t, tc.name, code, body, http.StatusUnauthorized, "invalid_token")
	}
	// The globex-signed equivalent passes, so the refusals above are about
	// the tenant.
	code, _ := e.do(t, "globex.example.com", "/read", "Bearer "+e.mint(t, m2m("globex", "https://globex.example.com/", globexAPI, "read:clients")))
	if code != 200 {
		t.Errorf("globex's own token: %d", code)
	}
}

// Only operators manage the system tenant: its own M2M tokens are refused
// there, even for its canonical identifier.
func TestMgmtAuthNoM2MOnSystemTenant(t *testing.T) {
	e := newEnv(t)
	for _, host := range []string{systemHost, "system.example.com"} {
		for _, iss := range []string{"https://" + systemHost + "/", "https://system.example.com/"} {
			raw := e.mint(t, m2m(tenant.SystemName, iss, "https://system.example.com/api/v2/", "read:clients"))
			code, body := e.do(t, host, "/read", "Bearer "+raw)
			e.checkError(t, host+" "+iss, code, body, http.StatusForbidden, "insufficient_scope")
		}
	}
}

func TestMgmtAuthOperator(t *testing.T) {
	e := newEnv(t)
	raw := e.mint(t, operator("https://"+systemHost+"/", []string{"*"}))
	for _, host := range []string{"acme.example.com", "login.globex.test", systemHost, "system.example.com"} {
		for _, path := range []string{"/read", "/operator"} {
			code, body := e.do(t, host, path, "Bearer "+raw)
			if code != 200 || body["Kind"] != float64(mgmt.Operator) || body["UserID"] != "auth0|op" ||
				!slices.Equal(toStrings(body["Tenants"]), []string{"*"}) || !slices.Contains(toStrings(body["Scopes"]), "delete:clients") {
				t.Errorf("%s%s: %d %v", host, path, code, body)
			}
		}
	}
}

func TestMgmtAuthOperatorRejects(t *testing.T) {
	e := newEnv(t)
	acmeSigned := operator("https://"+systemHost+"/", []string{"*"})
	acmeSigned.tenant = "acme"
	acmeIss := operator("https://acme.example.com/", []string{"*"})
	acmeIss.tenant = "acme"
	removed := operator("https://"+systemHost+"/", []string{"*"})
	removed.sub = "auth0|gone"
	expired := operator("https://"+systemHost+"/", []string{"*"})
	expired.at = now.Add(-2 * time.Hour)
	onlyAud := operator("https://"+systemHost+"/", []string{"*"})
	onlyAud.aud = []string{"https://" + systemHost + "/userinfo"}
	otherClient := operator("https://"+systemHost+"/", []string{"*"})
	otherClient.clientID = "another-spa"
	for _, tc := range []struct {
		name string
		tok  tok
	}{
		// Signed by the system tenant, but the issuer is not the canonical
		// system host: the alias system.<base>, another tenant, elsewhere.
		{"alias issuer", operator("https://system.example.com/", []string{"*"})},
		{"tenant issuer", operator("https://acme.example.com/", []string{"*"})},
		{"forged issuer", operator("https://evil.test/", []string{"*"})},
		{"no claim", operator("https://"+systemHost+"/", nil)},
		// Another tenant minting the operator audience (the seed refuses to
		// define it, but its keys could sign anything).
		{"other tenant's keys", acmeSigned},
		{"other tenant entirely", acmeIss},
		{"no longer an operator", removed},
		{"expired", expired},
		{"claim without the audience", onlyAud},
		// Operator tokens are bound to the console client.
		{"another client", otherClient},
	} {
		code, body := e.do(t, "acme.example.com", "/any", "Bearer "+e.mint(t, tc.tok))
		e.checkError(t, tc.name, code, body, http.StatusUnauthorized, "invalid_token")
	}
}

// An operator is limited to its tenants, by the stored operator and by the
// token's claim.
func TestMgmtAuthOperatorTenants(t *testing.T) {
	e := newEnv(t)
	acmeOp := operator("https://"+systemHost+"/", []string{"acme"})
	acmeOp.sub = "auth0|acme-op"
	raw := e.mint(t, acmeOp)
	if code, body := e.do(t, "acme.example.com", "/read", "Bearer "+raw); code != 200 {
		t.Errorf("own tenant: %d %v", code, body)
	}
	code, body := e.do(t, "globex.example.com", "/read", "Bearer "+raw)
	e.checkError(t, "other tenant", code, body, http.StatusForbidden, "insufficient_scope")
	// The claim narrows an operator of every tenant, too.
	raw = e.mint(t, operator("https://"+systemHost+"/", []string{"acme"}))
	code, body = e.do(t, "globex.example.com", "/read", "Bearer "+raw)
	e.checkError(t, "claim narrows", code, body, http.StatusForbidden, "insufficient_scope")
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Tokens that must never pass, whatever their claims.
func TestMgmtAuthHostileTokens(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	good := map[string]any{"iss": "https://acme.example.com/", "aud": acmeAPI, "sub": "cli@clients", "azp": "cli",
		"gty": "client-credentials", "scope": "read:clients", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	with := func(k string, v any) map[string]any {
		c := map[string]any{}
		for kk, vv := range good {
			c[kk] = vv
		}
		c[k] = v
		return c
	}
	sign := func(claims map[string]any) string {
		raw, err := e.km.Sign(ctx, e.ids["acme"], claims)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// Control: the hand-built claims pass when signed properly.
	if code, body := e.do(t, "acme.example.com", "/read", "Bearer "+sign(good)); code != 200 {
		t.Fatalf("control: %d %v", code, body)
	}

	set, err := e.km.JWKS(ctx, e.ids["acme"])
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(set.Keys[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	hs, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: pemKey},
		(&jose.SignerOptions{}).WithHeader("kid", set.Keys[0].KeyID))
	if err != nil {
		t.Fatal(err)
	}
	hsToken, err := jwt.Signed(hs).Claims(good).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	idTok, err := (&oauth.Minter{Keys: e.km, Now: func() time.Time { return now }}).IDToken(ctx, oauth.IDTokenParams{
		TenantID: e.ids[tenant.SystemName], Issuer: "https://" + systemHost + "/", ClientID: system.ConsoleClientID,
		User: &store.User{UserID: "auth0|op"}, Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, raw, host string }{
		{"alg none", b64(map[string]string{"alg": "none", "typ": "JWT"}) + "." + b64(good) + ".", "acme.example.com"},
		{"HS256 with the public key", hsToken, "acme.example.com"},
		{"system ID token at a tenant", idTok, "acme.example.com"},
		{"system ID token at the system tenant", idTok, systemHost},
		{"iat in the future", sign(with("iat", now.Add(10*time.Minute).Unix())), "acme.example.com"},
		{"nbf in the future", sign(with("nbf", now.Add(10*time.Minute).Unix())), "acme.example.com"},
		{"no exp", sign(with("exp", nil)), "acme.example.com"},
	} {
		code, body := e.do(t, tc.host, "/any", "Bearer "+tc.raw)
		e.checkError(t, tc.name, code, body, http.StatusUnauthorized, "invalid_token")
	}
}
