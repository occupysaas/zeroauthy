package authz

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/clientcred"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

const jarIssuer = "https://acme.example.test/"

func jarTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "clientcred", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func jarKey(t *testing.T, name string) *rsa.PrivateKey {
	t.Helper()
	blk, _ := pem.Decode([]byte(jarTestdata(t, name)))
	if blk == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*rsa.PrivateKey)
}

// newJAREnv is the authorize environment over a store on the fixture clock
// (so replay-table expiry follows it). The confidential client "web" has
// two credentials: cred_jar enabled for signed request objects and
// cred_pkjwt enabled only for private_key_jwt.
func newJAREnv(t *testing.T, required bool) *env {
	t.Helper()
	e := newEnvOn(t, newFixtureOn(t, memory.NewWithClock(fixedNow)))
	ctx := context.Background()
	for _, c := range []struct{ id, spki string }{{"cred_jar", "rsa2048.spki.pem"}, {"cred_pkjwt", "rsa2048b.spki.pem"}} {
		p, err := clientcred.ParsePEM("public_key", jarTestdata(t, c.spki), "RS256")
		if err != nil {
			t.Fatal(err)
		}
		if err := e.st.ClientCredentials().Create(ctx, &store.ClientCredential{TenantID: e.tenant.ID, ClientID: "web", ID: c.id,
			Type: "public_key", Name: c.id, KID: p.KID, Alg: "RS256", PublicKeyDER: p.DER, Thumbprint: p.Thumbprint,
			CreatedAt: fixedNow(), UpdatedAt: fixedNow()}, 2); err != nil {
			t.Fatal(err)
		}
	}
	c, err := e.st.Clients().Get(ctx, e.tenant.ID, "web")
	if err != nil {
		t.Fatal(err)
	}
	c.SignedRequestObject = &store.SignedRequestObject{Required: required, Credentials: []string{"cred_jar"}}
	c.PrivateKeyJWTCredentials = []string{"cred_pkjwt"}
	if err := e.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	return e
}

var jarJTI atomic.Int64

// jarClaims is a valid request object for "web"; kv overrides claims (nil
// deletes one).
func jarClaims(kv ...any) map[string]any {
	c := map[string]any{"iss": "web", "aud": jarIssuer, "client_id": "web",
		"response_type": "code", "redirect_uri": "https://web.acme.test/cb", "scope": "openid", "state": "inner-st",
		"jti": fmt.Sprintf("jar-%d", jarJTI.Add(1)), "iat": fixedNow().Unix(), "exp": fixedNow().Add(5 * time.Minute).Unix()}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(c, kv[i].(string))
		} else {
			c[kv[i].(string)] = kv[i+1]
		}
	}
	return c
}

func signJAR(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	pl, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.Sign(pl)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := o.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// jarQuery is the query of a JAR authorize request for "web".
func jarQuery(obj string, kv ...string) url.Values {
	return with(url.Values{
		"client_id": {"web"}, "response_type": {"code"}, "redirect_uri": {"https://web.acme.test/cb"},
		"scope": {"openid"}, "state": {"outer-st"}, "request": {obj},
	}, kv...)
}

func (e *env) txnParams(t *testing.T, loc *url.URL) map[string]string {
	t.Helper()
	if loc.Path != "/u/login" {
		t.Fatalf("Location = %s", loc)
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	return txn.Params
}

func wantAuthzError(t *testing.T, loc *url.URL, code, state string) {
	t.Helper()
	if loc.Host != "web.acme.test" || loc.Query().Get("error") != code || loc.Query().Get("state") != state {
		t.Fatalf("Location = %s, want error %s state %s", loc, code, state)
	}
}

func TestJARMergesInnerWins(t *testing.T) {
	e := newJAREnv(t, false)
	obj := signJAR(t, jarKey(t, "rsa2048.priv.pem"), jarClaims("scope", "openid profile", "nonce", "n-1", "ext-hint", "blue"))
	p := e.txnParams(t, location(t, e.get(t, jarQuery(obj))))
	if p["scope"] != "openid profile" || p["state"] != "inner-st" || p["nonce"] != "n-1" || p["ext-hint"] != "blue" || p["redirect_uri"] != "https://web.acme.test/cb" {
		t.Fatalf("transaction params = %v", p)
	}
	for k, v := range p {
		if strings.Contains(v, obj) || k == "request" {
			t.Fatalf("transaction keeps the request object: %v", p)
		}
	}
	// Parameters only in the query still apply.
	obj = signJAR(t, jarKey(t, "rsa2048.priv.pem"), jarClaims("state", nil, "scope", nil))
	p = e.txnParams(t, location(t, e.get(t, jarQuery(obj, "ui_locales", "fr"))))
	if p["state"] != "outer-st" || p["scope"] != "openid" || p["ui_locales"] != "fr" {
		t.Fatalf("transaction params = %v", p)
	}
	// POST /authorize carries a request object too.
	obj = signJAR(t, jarKey(t, "rsa2048.priv.pem"), jarClaims())
	if p = e.txnParams(t, location(t, e.post(t, jarQuery(obj)))); p["state"] != "inner-st" {
		t.Fatalf("POST transaction params = %v", p)
	}
}

func TestJARClientIDMismatch(t *testing.T) {
	e := newJAREnv(t, false)
	key := jarKey(t, "rsa2048.priv.pem")
	for name, claims := range map[string]map[string]any{
		"other client_id":   jarClaims("client_id", "spa"),
		"missing client_id": jarClaims("client_id", nil),
		"iss mismatch":      jarClaims("iss", "spa"),
	} {
		t.Run(name, func(t *testing.T) {
			rec := e.get(t, jarQuery(signJAR(t, key, claims)))
			// Delivered to the query's registered redirect_uri with the query's
			// state: nothing from an unverified object is trusted.
			wantAuthzError(t, location(t, rec), "invalid_request_object", "outer-st")
		})
	}
	// The query client_id selects the keys: another client's object is not
	// verified with them.
	rec := e.get(t, jarQuery(signJAR(t, key, jarClaims()), "client_id", "spa", "redirect_uri", "https://app.acme.test/callback",
		"code_challenge", challenge, "code_challenge_method", "S256"))
	if loc := location(t, rec); loc.Host != "app.acme.test" || loc.Query().Get("error") != "invalid_request_object" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestJARRefusals(t *testing.T) {
	e := newJAREnv(t, false)
	key, other := jarKey(t, "rsa2048.priv.pem"), jarKey(t, "rsa2048b.priv.pem")
	cases := map[string]string{
		// A credential enabled only for private_key_jwt never verifies a request object.
		"private_key_jwt credential": signJAR(t, other, jarClaims()),
		"expired":                    signJAR(t, key, jarClaims("exp", fixedNow().Add(-time.Minute).Unix())),
		"lifetime over 60 min":       signJAR(t, key, jarClaims("iat", nil, "exp", fixedNow().Add(61*time.Minute).Unix())),
		"request_uri inside":         signJAR(t, key, jarClaims("request_uri", RequestURIPrefix+"x")),
		"request inside":             signJAR(t, key, jarClaims("request", "x")),
		"not a JWS":                  "not-a-jwt",
		"over 16 KiB":                signJAR(t, key, jarClaims("ext-pad", strings.Repeat("a", 16<<10))),
		"jti over 64 bytes":          signJAR(t, key, jarClaims("jti", strings.Repeat("j", 65))),
	}
	for name, obj := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.get(t, jarQuery(obj))
			wantAuthzError(t, location(t, rec), "invalid_request_object", "outer-st")
		})
	}
	t.Run("16 KiB accepted", func(t *testing.T) {
		claims := jarClaims()
		base := len(signJAR(t, key, jarClaims("ext-pad", "")))
		// Base64url grows the padding by 4/3; aim just under the cap.
		claims["ext-pad"] = strings.Repeat("a", (16384-base)*3/4-4)
		obj := signJAR(t, key, claims)
		if len(obj) > 16384 || len(obj) < 16300 {
			t.Fatalf("object is %d bytes", len(obj))
		}
		e.txnParams(t, location(t, e.post(t, jarQuery(obj))))
	})
}

// LR35-4: an unsigned object is still request_not_supported, delivered with
// its own state and response_mode (D-0035).
func TestJARUnsignedStillRefused(t *testing.T) {
	e := newJAREnv(t, false)
	obj := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"web","client_id":"web","state":"obj-st"}`)) + "."
	rec := e.get(t, jarQuery(obj))
	wantAuthzError(t, location(t, rec), "request_not_supported", "obj-st")

	// Without client_credentials.v1 every request object keeps today's refusal.
	noCaps := newEnvOn(t, &fixture{st: noClientCredentialsStore{e.st}, tenant: e.tenant})
	rec = noCaps.get(t, jarQuery(signJAR(t, jarKey(t, "rsa2048.priv.pem"), jarClaims())))
	wantAuthzError(t, location(t, rec), "request_not_supported", "inner-st")
}

type noClientCredentialsStore struct{ store.Store }

func (noClientCredentialsStore) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}

func (e *env) pushSigned(t *testing.T, clientID string, params map[string]string, signed bool) string {
	t.Helper()
	id := secrets.RandomString(43)
	if err := e.st.PushedAuthRequests().Create(context.Background(), &store.PushedAuthRequest{
		TenantID: e.tenant.ID, IDHash: secrets.HashToken(id), ClientID: clientID, Params: params, Signed: signed,
		ExpiresAt: fixedNow().Add(PARLifetime), CreatedAt: fixedNow(),
	}); err != nil {
		t.Fatal(err)
	}
	return RequestURIPrefix + id
}

func TestJARRequired(t *testing.T) {
	e := newJAREnv(t, true)
	plain := jarQuery("", "request", "")
	rec := e.get(t, plain)
	wantAuthzError(t, location(t, rec), "invalid_request", "outer-st")

	pushed := map[string]string{"client_id": "web", "redirect_uri": "https://web.acme.test/cb", "response_type": "code", "scope": "openid", "state": "pushed-st", "za_pushed": "1"}
	rec = e.get(t, parQuery("web", e.pushSigned(t, "web", pushed, false)))
	wantAuthzError(t, location(t, rec), "invalid_request", "pushed-st")

	// A signed push satisfies the policy, and the mark survives the login
	// transaction for Resume.
	p := e.txnParams(t, location(t, e.get(t, parQuery("web", e.pushSigned(t, "web", pushed, true)))))
	if req := RequestFromParams(p); !req.Signed || !req.Pushed {
		t.Fatalf("transaction lost the signed mark: %v", p)
	} else if _, verr, _ := ValidateRequest(context.Background(), e.st, e.tenant, &req); verr != nil {
		t.Fatalf("revalidation failed: %+v", verr)
	}

	// A signed request object at /authorize satisfies it too.
	p = e.txnParams(t, location(t, e.get(t, jarQuery(signJAR(t, jarKey(t, "rsa2048.priv.pem"), jarClaims())))))
	if req := RequestFromParams(p); !req.Signed {
		t.Fatalf("transaction lost the signed mark: %v", p)
	}
	// The mark never comes from a browser query.
	if ParseRequest(url.Values{"za_signed": {"1"}}).Signed {
		t.Fatal("ParseRequest accepted za_signed from a query")
	}
	rec = e.get(t, with(plain, "za_signed", "1"))
	wantAuthzError(t, location(t, rec), "invalid_request", "outer-st")
}

// Review focus 3: an unregistered redirect_uri inside a valid object never
// receives a redirect.
func TestJARInnerRedirectUnregistered(t *testing.T) {
	e := newJAREnv(t, false)
	key := jarKey(t, "rsa2048.priv.pem")
	for name, q := range map[string]url.Values{
		"inner unregistered":               jarQuery(signJAR(t, key, jarClaims("redirect_uri", "https://evil.test/cb"))),
		"inner unregistered, query absent": jarQuery(signJAR(t, key, jarClaims("redirect_uri", "https://evil.test/cb")), "redirect_uri", ""),
		"bad object, query unregistered":   jarQuery(signJAR(t, key, jarClaims("client_id", "spa")), "redirect_uri", "https://evil.test/cb"),
		"bad object, inner unregistered":   jarQuery(signJAR(t, key, jarClaims("client_id", "spa", "redirect_uri", "https://evil.test/cb")), "redirect_uri", ""),
	} {
		t.Run(name, func(t *testing.T) {
			rec := e.get(t, q)
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || strings.Contains(rec.Body.String(), "evil.test") {
				t.Fatalf("= %d %v %s", rec.Code, rec.Header(), rec.Body)
			}
		})
	}
	// A failed object with a registered query redirect_uri is delivered there
	// only, with the query's response_mode: never the object's redirect_uri
	// or response_mode.
	rec := e.get(t, jarQuery(signJAR(t, key, jarClaims("aud", "https://evil.test/", "redirect_uri", "https://evil.test/cb", "response_mode", "form_post"))))
	wantAuthzError(t, location(t, rec), "invalid_request_object", "outer-st")
	if strings.Contains(rec.Body.String(), "evil.test") {
		t.Fatalf("body = %s", rec.Body)
	}
	// Without any redirect_uri the page names the object error.
	rec = e.get(t, jarQuery(signJAR(t, key, jarClaims("aud", "https://evil.test/", "redirect_uri", nil)), "redirect_uri", ""))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "the request object is invalid") {
		t.Fatalf("= %d %s", rec.Code, rec.Body)
	}
}

// Review focus 4: aud is the issuer of the host that received the request.
func TestJARAudPerHost(t *testing.T) {
	e := newJAREnv(t, false)
	ctx := context.Background()
	tn, _ := e.st.Tenants().Get(ctx, e.tenant.ID)
	tn.Domains = append(tn.Domains, "login.example.test")
	if err := e.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	key := jarKey(t, "rsa2048.priv.pem")
	for _, tc := range []struct {
		host, aud string
		ok        bool
	}{
		{"acme.example.test", jarIssuer, true},
		{"login.example.test", "https://login.example.test/", true},
		{"acme.example.test", "https://login.example.test/", false},
		{"login.example.test", jarIssuer, false},
		{"acme.example.test", strings.TrimSuffix(jarIssuer, "/"), false},
		{"acme.example.test", jarIssuer + "authorize", false},
	} {
		r := httptestRequest("https://" + tc.host + "/authorize?" + jarQuery(signJAR(t, key, jarClaims("aud", tc.aud))).Encode())
		loc := location(t, e.serve(t, r))
		if tc.ok && loc.Path != "/u/login" || !tc.ok && loc.Query().Get("error") != "invalid_request_object" {
			t.Errorf("host %s aud %s: Location = %s", tc.host, tc.aud, loc)
		}
	}
}

// LR35-7: a jti is single-use; an object without one may be reused.
func TestJARReplay(t *testing.T) {
	e := newJAREnv(t, false)
	key := jarKey(t, "rsa2048.priv.pem")
	obj := signJAR(t, key, jarClaims())
	e.txnParams(t, location(t, e.get(t, jarQuery(obj))))
	rec := e.get(t, jarQuery(obj))
	wantAuthzError(t, location(t, rec), "invalid_request_object", "outer-st")
	// Still refused later within the object's lifetime.
	e.h.Now = func() time.Time { return fixedNow().Add(4 * time.Minute) }
	rec = e.get(t, jarQuery(obj))
	wantAuthzError(t, location(t, rec), "invalid_request_object", "outer-st")
	e.h.Now = fixedNow

	noJTI := signJAR(t, key, jarClaims("jti", nil))
	for range 2 {
		e.txnParams(t, location(t, e.get(t, jarQuery(noJTI))))
	}
}

// A strict third-party client keeps D-0025's refusal of request.
func TestJARStrictClientUnchanged(t *testing.T) {
	e := newJAREnv(t, false)
	q := partnerQuery()
	q.Set("request", signJAR(t, jarKey(t, "rsa2048.priv.pem"), jarClaims()))
	rec := e.get(t, q)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "request is not supported") {
		t.Fatalf("= %d %v", rec.Code, rec.Header())
	}
}

// The request object is registered as a log mask at /authorize, so no sink
// that scrubs with the request context can carry it. The key name request
// is not a secret name: HTTP and Management log records use it for
// unrelated fields.
func TestJARValueRegisteredForScrub(t *testing.T) {
	e := newJAREnv(t, false)
	obj := signJAR(t, jarKey(t, "rsa2048.priv.pem"), jarClaims("client_id", "spa"))
	var seen string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.h.Authorize(w, r)
		seen = logscrub.MaskText(r.Context(), "logged "+obj)
	})
	srv := contract.Wrap(t, tenant.NewResolver(e.st.Tenants(), "", false).Middleware(inner))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptestRequest("https://acme.example.test/authorize?"+jarQuery(obj).Encode()))
	if rec.Code != http.StatusFound || strings.Contains(seen, obj) {
		t.Fatalf("= %d; log text %q", rec.Code, seen)
	}
}
