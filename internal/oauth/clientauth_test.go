// internal/oauth/clientauth_test.go
package oauth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/clientcred"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/ratelimit"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func authRequest(t *testing.T, body url.Values, basicID, basicSecret string, rawAuth ...string) (*http.Request, url.Values) {
	t.Helper()
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	if len(rawAuth) > 0 {
		req.Header.Set("Authorization", rawAuth[0])
	}
	form, oerr := parseTokenRequest(httptest.NewRecorder(), req)
	if oerr != nil {
		t.Fatal(oerr)
	}
	return req, form
}

func TestAuthenticateClient(t *testing.T) {
	f := newFixture(t)
	acme := f.tenantID(t, "acme")
	globex := f.tenantID(t, "globex")

	cases := []struct {
		name          string
		tenantID      string
		body          url.Values
		basicID       string
		basicSecret   string
		rawAuth       string
		wantClient    string
		wantCode      string
		wantStatus    int
		wantChallenge bool
	}{
		{name: "post", tenantID: acme, body: url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, wantClient: "m2m"},
		// Review focus 3: reserved characters in Basic credentials.
		{name: "basic with reserved chars", tenantID: acme, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantClient: "m2m-basic"},
		{name: "basic plus matching body client_id", tenantID: acme, body: url.Values{"client_id": {"m2m-basic"}}, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantClient: "m2m-basic"},
		{name: "public client", tenantID: acme, body: url.Values{"client_id": {"spa"}}, wantClient: "spa"},
		{name: "wrong secret post", tenantID: acme, body: url.Values{"client_id": {"m2m"}, "client_secret": {"nope"}}, wantCode: "invalid_client", wantStatus: 401},
		{name: "wrong secret basic", tenantID: acme, basicID: "m2m-basic", basicSecret: "nope", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		{name: "unknown client", tenantID: acme, body: url.Values{"client_id": {"ghost"}, "client_secret": {"x"}}, wantCode: "invalid_client", wantStatus: 401},
		{name: "no client id", tenantID: acme, body: url.Values{}, wantCode: "invalid_client", wantStatus: 401},
		{name: "method mismatch post for basic client", tenantID: acme, body: url.Values{"client_id": {"m2m-basic"}, "client_secret": {"p@ss:w+rd"}}, wantCode: "invalid_client", wantStatus: 401},
		{name: "method mismatch basic for post client", tenantID: acme, basicID: "m2m", basicSecret: "m2m-secret", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		{name: "confidential client without secret", tenantID: acme, body: url.Values{"client_id": {"m2m"}}, wantCode: "invalid_client", wantStatus: 401},
		// Review focus 2: two methods at once.
		{name: "basic and body secret", tenantID: acme, body: url.Values{"client_secret": {"p@ss:w+rd"}}, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantCode: "invalid_request", wantStatus: 400},
		{name: "basic and different body client_id", tenantID: acme, body: url.Values{"client_id": {"m2m"}}, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantCode: "invalid_request", wantStatus: 400},
		// A malformed Authorization header is never silently ignored.
		{name: "malformed basic with body credentials", tenantID: acme, body: url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, rawAuth: "Basic !!!not-base64", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		{name: "malformed basic alone", tenantID: acme, rawAuth: "Basic !!!not-base64", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		{name: "basic without colon", tenantID: acme, rawAuth: "Basic bm9jb2xvbg==", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		{name: "bearer scheme", tenantID: acme, body: url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, rawAuth: "Bearer abc", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		// Review focus 5: tenant isolation.
		{name: "client from other tenant", tenantID: globex, body: url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, wantCode: "invalid_client", wantStatus: 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw []string
			if tc.rawAuth != "" {
				raw = append(raw, tc.rawAuth)
			}
			req, form := authRequest(t, tc.body, tc.basicID, tc.basicSecret, raw...)
			c, oerr := f.h.authenticateClient(context.Background(), req, form, tc.tenantID)
			if tc.wantClient != "" {
				if oerr != nil {
					t.Fatalf("unexpected error %+v", oerr)
				}
				if c.ClientID != tc.wantClient {
					t.Fatalf("client = %s, want %s", c.ClientID, tc.wantClient)
				}
				return
			}
			if oerr == nil || oerr.Code != tc.wantCode || oerr.Status != tc.wantStatus || oerr.basicChallenge != tc.wantChallenge {
				t.Fatalf("err = %+v, want %s/%d challenge=%v", oerr, tc.wantCode, tc.wantStatus, tc.wantChallenge)
			}
		})
	}
}

func TestExpiredSecretRejected(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acme := f.tenantID(t, "acme")
	c, _ := f.st.Clients().Get(ctx, acme, "m2m")
	old, _ := secrets.Hash("old-secret")
	expired := fixedNow().Add(-time.Minute)
	c.Secrets = append([]store.ClientSecret{{Hash: old, CreatedAt: fixedNow().Add(-time.Hour), ExpiresAt: &expired}}, c.Secrets...)
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}

	req, form := authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"old-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr == nil || oerr.Code != "invalid_client" {
		t.Fatalf("expired secret accepted: %+v", oerr)
	}
	req, form = authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr != nil {
		t.Fatalf("current secret rejected: %+v", oerr)
	}
}

func TestWriteErrorHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, invalidClient("client authentication failed", true))
	if rec.Code != 401 {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if !strings.Contains(rec.Body.String(), `"error":"invalid_client"`) {
		t.Fatalf("body = %s", rec.Body)
	}
}

func TestAuthenticateSealedSecret(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acme := f.tenantID(t, "acme")
	c, err := f.st.Clients().Get(ctx, acme, "m2m")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Secrets) != 1 || c.Secrets[0].Sealed == nil || c.Secrets[0].Hash != "" {
		t.Fatalf("seeded secret is not sealed: %+v", c.Secrets)
	}
	req, form := authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr != nil {
		t.Fatalf("sealed secret rejected: %+v", oerr)
	}
	for _, bad := range []string{"m2m-secreT", "m2m-secret ", "m2m", "m2m-secret-and-more"} {
		req, form = authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {bad}}, "", "")
		if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr == nil || oerr.Code != "invalid_client" {
			t.Fatalf("wrong secret %q accepted: %+v", bad, oerr)
		}
	}
	// A blob sealed for one client does not authenticate another.
	other, _ := f.st.Clients().Get(ctx, acme, "web")
	other.Secrets = c.Secrets
	if err := f.st.Clients().Update(ctx, other); err != nil {
		t.Fatal(err)
	}
	req, form = authRequest(t, url.Values{"client_id": {"web"}, "client_secret": {"m2m-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr == nil {
		t.Fatal("secret sealed for m2m authenticated web")
	}
}

func TestAuthenticateLegacyHashedSecret(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acme := f.tenantID(t, "acme")
	c, _ := f.st.Clients().Get(ctx, acme, "m2m")
	h, _ := secrets.Hash("legacy-secret")
	c.Secrets = []store.ClientSecret{{Hash: h, CreatedAt: fixedNow()}}
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	req, form := authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"legacy-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr != nil {
		t.Fatalf("legacy hashed secret rejected: %+v", oerr)
	}
	req, form = authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr == nil {
		t.Fatal("replaced secret accepted")
	}
}

func TestSealedSecretWrongKeyFailsClosed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acme := f.tenantID(t, "acme")
	otherKey, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{4}, 32))
	for name, w := range map[string]keys.Wrapper{"wrong key": otherKey, "no wrapper": nil} {
		f.h.Wrapper = w
		req, form := authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, "", "")
		if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr == nil || oerr.Code != "invalid_client" {
			t.Fatalf("%s: authenticated: %+v", name, oerr)
		}
	}
	// Corrupt blob.
	f.h.Wrapper = f.wrapper
	c, _ := f.st.Clients().Get(ctx, acme, "m2m")
	c.Secrets[0].Sealed = []byte("not an envelope")
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	req, form := authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr == nil || oerr.Code != "invalid_client" {
		t.Fatalf("corrupt blob: authenticated: %+v", oerr)
	}
}

// Legacy secrets cost an argon2id verification (19 MiB) each, so their
// concurrency is capped; a request over the cap gets 429 instead of queueing.
func TestLegacySecretVerificationIsCapped(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acme := f.tenantID(t, "acme")
	c, _ := f.st.Clients().Get(ctx, acme, "m2m")
	legacy, _ := secrets.Hash("legacy-secret")
	c.Secrets = []store.ClientSecret{{Hash: legacy, CreatedAt: fixedNow().Add(-time.Hour)}}
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	f.h.LegacySecretSlots = ratelimit.NewSemaphore(1, 0)
	held, _ := f.h.LegacySecretSlots.Acquire(ctx)

	req, form := authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"legacy-secret"}}, "", "")
	_, oerr := f.h.authenticateClient(ctx, req, form, acme)
	if oerr == nil || oerr.Status != http.StatusTooManyRequests || oerr.Code != "too_many_requests" {
		t.Fatalf("over the cap: %+v, want 429 too_many_requests", oerr)
	}
	rec := httptest.NewRecorder()
	writeError(rec, oerr)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"too_many_requests"`) {
		t.Fatalf("response %d %v", rec.Code, rec.Header())
	}

	held()
	req, form = authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"legacy-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr != nil {
		t.Fatalf("under the cap: %+v", oerr)
	}
}

const acmeIssuer = "https://acme.example.test/"

func pkjwtTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "clientcred", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pkjwtKey(t *testing.T, name string) *rsa.PrivateKey {
	t.Helper()
	blk, _ := pem.Decode([]byte(pkjwtTestdata(t, name)))
	if blk == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*rsa.PrivateKey)
}

// pkjwtCred describes one credential to register on a client.
type pkjwtCred struct {
	id, spki, alg string
	expiresAt     *time.Time
}

// newPKJWTFixture is the oauth fixture over a store whose clock is the
// fixture clock, so replay-table expiry follows the injected time.
func newPKJWTFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureOn(t, memory.NewWithClock(fixedNow))
}

// addCredentials stores creds on clientID and returns them; it does not
// change the client's settings.
func (f *fixture) addCredentials(t *testing.T, clientID string, creds ...pkjwtCred) []*store.ClientCredential {
	t.Helper()
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	var out []*store.ClientCredential
	for _, c := range creds {
		p, err := clientcred.ParsePEM("public_key", pkjwtTestdata(t, c.spki), c.alg)
		if err != nil {
			t.Fatal(err)
		}
		cc := &store.ClientCredential{TenantID: tid, ClientID: clientID, ID: c.id, Type: "public_key", Name: c.id,
			KID: p.KID, Alg: c.alg, PublicKeyDER: p.DER, Thumbprint: p.Thumbprint, ExpiresAt: c.expiresAt,
			CreatedAt: fixedNow(), UpdatedAt: fixedNow()}
		if err := f.st.ClientCredentials().Create(ctx, cc, 2); err != nil {
			t.Fatal(err)
		}
		out = append(out, cc)
	}
	return out
}

// usePrivateKeyJWT registers creds on clientID and switches the client to
// private_key_jwt the way the Management API stores it: no
// token_endpoint_auth_method and the credential ids. Its secrets stay, so
// a refused secret proves the method check.
func (f *fixture) usePrivateKeyJWT(t *testing.T, clientID string, creds ...pkjwtCred) []*store.ClientCredential {
	t.Helper()
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	stored := f.addCredentials(t, clientID, creds...)
	c, err := f.st.Clients().Get(ctx, tid, clientID)
	if err != nil {
		t.Fatal(err)
	}
	c.TokenEndpointAuthMethod = ""
	c.PrivateKeyJWTCredentials = []string{}
	for _, s := range stored {
		c.PrivateKeyJWTCredentials = append(c.PrivateKeyJWTCredentials, s.ID)
	}
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	return stored
}

var jtiSeq atomic.Int64

func assertionClaims(clientID string, kv ...any) map[string]any {
	c := map[string]any{"iss": clientID, "sub": clientID, "aud": acmeIssuer,
		"jti": fmt.Sprintf("jti-%d", jtiSeq.Add(1)), "iat": fixedNow().Unix(), "exp": fixedNow().Add(2 * time.Minute).Unix()}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(c, kv[i].(string))
		} else {
			c[kv[i].(string)] = kv[i+1]
		}
	}
	return c
}

func signAssertion(t *testing.T, key *rsa.PrivateKey, alg jose.SignatureAlgorithm, kid string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader(jose.HeaderKey("kid"), kid)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
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

func withAssertion(v url.Values, raw string) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	out.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	out.Set("client_assertion", raw)
	return out
}

func jwtPayload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPrivateKeyJWTClientCredentials(t *testing.T) {
	f := newPKJWTFixture(t)
	aud := "https://api.acme.test"
	rec, secretBody := f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", aud)})
	if rec.Code != 200 {
		t.Fatalf("secret: %d %v", rec.Code, secretBody)
	}
	f.usePrivateKeyJWT(t, "m2m", pkjwtCred{id: "cred_a", spki: "rsa2048.spki.pem", alg: "RS256"})
	key := pkjwtKey(t, "rsa2048.priv.pem")
	form := withAssertion(url.Values{"grant_type": {"client_credentials"}, "audience": {aud}}, signAssertion(t, key, jose.RS256, "", assertionClaims("m2m")))
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
	if rec.Code != 200 {
		t.Fatalf("assertion: %d %v", rec.Code, body)
	}
	for _, k := range []string{"token_type", "expires_in", "scope"} {
		if fmt.Sprint(body[k]) != fmt.Sprint(secretBody[k]) {
			t.Errorf("%s = %v, want %v", k, body[k], secretBody[k])
		}
	}
	want, got := jwtPayload(t, secretBody["access_token"].(string)), jwtPayload(t, body["access_token"].(string))
	for _, k := range []string{"iat", "exp", "jti"} {
		delete(want, k)
		delete(got, k)
	}
	wj, _ := json.Marshal(want)
	gj, _ := json.Marshal(got)
	if !bytes.Equal(wj, gj) {
		t.Fatalf("claims differ:\nassertion %s\nsecret    %s", gj, wj)
	}
	if got["sub"] != "m2m@clients" {
		t.Fatalf("sub = %v", got["sub"])
	}
}

func TestPrivateKeyJWTEndpoints(t *testing.T) {
	key := pkjwtKey(t, "rsa2048.priv.pem")
	cred := pkjwtCred{id: "cred_a", spki: "rsa2048.spki.pem", alg: "RS256"}

	t.Run("revoke", func(t *testing.T) {
		f := newPKJWTFixture(t)
		raw, _ := f.issueRefresh(t, "rt-web", []string{"openid", "offline_access"}, "")
		f.usePrivateKeyJWT(t, "rt-web", cred)
		form := withAssertion(url.Values{"token": {raw}}, signAssertion(t, key, jose.RS256, "",
			assertionClaims("rt-web", "aud", acmeIssuer+"oauth/revoke")))
		rec := f.revokeRaw(t, formType, form.Encode())
		if rec.Code != 200 || f.storedRT(t, raw).RevokedAt == nil {
			t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("par", func(t *testing.T) {
		f := newPKJWTFixture(t)
		f.usePrivateKeyJWT(t, "par-web", cred)
		form := withAssertion(url.Values{"client_id": {"par-web"}, "response_type": {"code"}, "redirect_uri": {"https://par.acme.test/cb"}, "scope": {"openid"}},
			signAssertion(t, key, jose.RS256, "", assertionClaims("par-web")))
		rec, body := f.par(t, "acme.example.test", formType, form.Encode())
		if rec.Code != 201 || body["request_uri"] == nil {
			t.Fatalf("par = %d %v", rec.Code, body)
		}
	})
	t.Run("mfa challenge", func(t *testing.T) {
		f, _ := mfaFixture(t)
		tok := f.mfaRequired(t)
		f.associateOTP(t, tok)
		list, _ := f.st.MFA().ListAuthenticators(context.Background(), f.tenantID(t, "acme"), f.aliceID(t))
		id := ""
		for _, a := range list {
			if a.Type == "totp" {
				id = a.ID
			}
		}
		f.usePrivateKeyJWT(t, "ropg", cred)
		body, _ := json.Marshal(map[string]string{"mfa_token": tok, "challenge_type": "otp", "authenticator_id": id,
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			"client_assertion":      signAssertion(t, key, jose.RS256, "", assertionClaims("ropg", "aud", acmeIssuer+"mfa/challenge"))})
		w, b := f.mfaAPI(t, "POST", "/mfa/challenge", "", string(body))
		if w.Code != 200 {
			t.Fatalf("challenge = %d %v", w.Code, b)
		}
	})
	t.Run("passwordless start", func(t *testing.T) {
		f := newPasswordlessFixture(t)
		f.setFlag(t, true)
		f.usePrivateKeyJWT(t, "pwl", cred)
		body, _ := json.Marshal(map[string]string{"client_id": "pwl", "connection": "email", "email": "ada@acme.test", "send": "code",
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			"client_assertion":      signAssertion(t, key, jose.RS256, "", assertionClaims("pwl"))})
		if rec, b := f.start(t, string(body), nil); rec.Code != 200 || b["email"] != "ada@acme.test" {
			t.Fatalf("start = %d %v", rec.Code, b)
		}
		// The secret no longer authenticates the switched client.
		if rec, b := f.start(t, `{"client_id":"pwl","client_secret":"pwl-secret","connection":"email","email":"ada@acme.test","send":"code"}`, nil); rec.Code != 401 || b["error"] != "invalid_client" {
			t.Fatalf("secret = %d %v", rec.Code, b)
		}
	})
}

func TestPrivateKeyJWTRefusals(t *testing.T) {
	f := newPKJWTFixture(t)
	key, other := pkjwtKey(t, "rsa2048.priv.pem"), pkjwtKey(t, "rsa2048b.priv.pem")
	f.usePrivateKeyJWT(t, "m2m", pkjwtCred{id: "cred_m2m", spki: "rsa2048.spki.pem", alg: "RS256"})
	// A secret client that also holds a credential, never enabled for private_key_jwt.
	f.addCredentials(t, "m2m-basic", pkjwtCred{id: "cred_basic", spki: "rsa2048b.spki.pem", alg: "RS256"})
	// A credential listed only for signed request objects, with an empty
	// private_key_jwt list (as after a credential delete).
	f.addCredentials(t, "web", pkjwtCred{id: "cred_web", spki: "rsa2048.spki.pem", alg: "RS256"})
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	web, _ := f.st.Clients().Get(ctx, tid, "web")
	web.TokenEndpointAuthMethod, web.PrivateKeyJWTCredentials = "", []string{}
	web.SignedRequestObject = &store.SignedRequestObject{Credentials: []string{"cred_web"}}
	web.GrantTypes = append(web.GrantTypes, "client_credentials")
	if err := f.st.Clients().Update(ctx, web); err != nil {
		t.Fatal(err)
	}

	ccForm := url.Values{"grant_type": {"client_credentials"}, "audience": {"https://api.acme.test"}}
	good := func() string { return signAssertion(t, key, jose.RS256, "", assertionClaims("m2m")) }
	cases := []struct {
		name        string
		form        url.Values
		basicID     string
		basicSecret string
	}{
		{name: "wrong assertion type", form: func() url.Values {
			v := withAssertion(ccForm, good())
			v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
			return v
		}()},
		{name: "assertion without type", form: func() url.Values {
			v := withAssertion(ccForm, good())
			v.Del("client_assertion_type")
			return v
		}()},
		{name: "type without assertion", form: func() url.Values {
			v := withAssertion(cc("m2m", "", "audience", "https://api.acme.test"), "")
			v.Del("client_assertion")
			return v
		}()},
		{name: "secret client sends assertion", form: withAssertion(ccForm, signAssertion(t, other, jose.RS256, "", assertionClaims("m2m-basic")))},
		{name: "private_key_jwt client sends secret", form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test")},
		{name: "private_key_jwt client sends nothing", form: cc("m2m", "", "audience", "https://api.acme.test")},
		{name: "key of another client", form: withAssertion(ccForm, signAssertion(t, other, jose.RS256, "", assertionClaims("m2m")))},
		{name: "signed request object credential only", form: withAssertion(ccForm, signAssertion(t, key, jose.RS256, "", assertionClaims("web")))},
		{name: "unknown client", form: withAssertion(ccForm, signAssertion(t, key, jose.RS256, "", assertionClaims("ghost")))},
		{name: "alg differs from credential", form: withAssertion(ccForm, signAssertion(t, key, jose.PS256, "", assertionClaims("m2m")))},
		{name: "not a JWT", form: withAssertion(ccForm, "not.a.jwt")},
		{name: "oversized", form: withAssertion(ccForm, strings.Repeat("a", 2049))},
		{name: "sub too long", form: withAssertion(ccForm, signAssertion(t, key, jose.RS256, "", assertionClaims(strings.Repeat("m", 65))))},
		{name: "expired", form: withAssertion(ccForm, signAssertion(t, key, jose.RS256, "", assertionClaims("m2m", "exp", fixedNow().Add(-time.Minute).Unix())))},
		{name: "no jti", form: withAssertion(ccForm, signAssertion(t, key, jose.RS256, "", assertionClaims("m2m", "jti", nil)))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: tc.form, basicID: tc.basicID, basicSecret: tc.basicSecret})
			if rec.Code != 401 || body["error"] != "invalid_client" || body["error_description"] != authFailed {
				t.Fatalf("= %d %v, want 401 invalid_client %q", rec.Code, body, authFailed)
			}
		})
	}

	// Spec §3.3 "Combining methods": one method only, as for Basic plus
	// client_secret, and a client_id that is not the assertion's client.
	for _, tc := range []struct {
		name        string
		form        url.Values
		basicID     string
		basicSecret string
	}{
		{name: "assertion plus basic", form: withAssertion(ccForm, good()), basicID: "m2m", basicSecret: "m2m-secret"},
		{name: "assertion plus client_secret", form: withAssertion(cc("m2m", "m2m-secret", "audience", "https://api.acme.test"), good())},
		{name: "client_id differs from iss", form: withAssertion(cc("m2m-basic", "", "audience", "https://api.acme.test"), good())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: tc.form, basicID: tc.basicID, basicSecret: tc.basicSecret})
			if rec.Code != 400 || body["error"] != "invalid_request" {
				t.Fatalf("= %d %v, want 400 invalid_request", rec.Code, body)
			}
		})
	}

	t.Run("store without client credentials", func(t *testing.T) {
		saved := f.h.Store
		defer func() { f.h.Store = saved }()
		f.h.Store = noClientCredentialsStore{f.st}
		rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: withAssertion(ccForm, good())})
		if rec.Code != 401 || body["error"] != "invalid_client" || body["error_description"] != authFailed {
			t.Fatalf("= %d %v", rec.Code, body)
		}
	})
	t.Run("control: a good assertion passes", func(t *testing.T) {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: withAssertion(ccForm, good())})
		if rec.Code != 200 {
			t.Fatalf("= %d %v", rec.Code, body)
		}
	})
}

type noClientCredentialsStore struct{ store.Store }

func (noClientCredentialsStore) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}

// Review focus 1: the same assertion posted concurrently has one winner.
func TestPrivateKeyJWTReplayOneWinner(t *testing.T) {
	f := newPKJWTFixture(t)
	f.usePrivateKeyJWT(t, "m2m", pkjwtCred{id: "cred_a", spki: "rsa2048.spki.pem", alg: "RS256"})
	raw := signAssertion(t, pkjwtKey(t, "rsa2048.priv.pem"), jose.RS256, "", assertionClaims("m2m"))
	body := withAssertion(url.Values{"grant_type": {"client_credentials"}, "audience": {"https://api.acme.test"}}, raw).Encode()
	h := f.server(t, false)
	const n = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(body))
			req.Header.Set("Content-Type", formType)
			rec := httptest.NewRecorder()
			<-start
			h.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}()
	}
	close(start)
	wg.Wait()
	ok, refused := 0, 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case 401:
			refused++
		}
	}
	if ok != 1 || refused != n-1 {
		t.Fatalf("codes = %v: %d ok, %d refused; want exactly one 200", codes, ok, refused)
	}
	// Still refused later within the assertion's lifetime.
	f.h.Now = func() time.Time { return fixedNow().Add(time.Minute) }
	if rec, b := f.call(t, false, tokenCall{host: "acme.example.test", form: withAssertion(url.Values{"grant_type": {"client_credentials"}, "audience": {"https://api.acme.test"}}, raw)}); rec.Code != 401 {
		t.Fatalf("replay later = %d %v", rec.Code, b)
	}
}

// Review focus 2: key rotation with two credentials and no kid.
func TestPrivateKeyJWTTwoKeysNoKid(t *testing.T) {
	f := newPKJWTFixture(t)
	creds := f.usePrivateKeyJWT(t, "m2m",
		pkjwtCred{id: "cred_old", spki: "rsa2048.spki.pem", alg: "RS256"},
		pkjwtCred{id: "cred_new", spki: "rsa2048b.spki.pem", alg: "RS256"})
	oldKey, newKey := pkjwtKey(t, "rsa2048.priv.pem"), pkjwtKey(t, "rsa2048b.priv.pem")
	try := func(key *rsa.PrivateKey, kid string) int {
		form := withAssertion(url.Values{"grant_type": {"client_credentials"}, "audience": {"https://api.acme.test"}},
			signAssertion(t, key, jose.RS256, kid, assertionClaims("m2m")))
		rec, _ := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
		return rec.Code
	}
	if c := try(oldKey, ""); c != 200 {
		t.Fatalf("old key, no kid = %d", c)
	}
	if c := try(newKey, ""); c != 200 {
		t.Fatalf("new key, no kid = %d", c)
	}
	if c := try(newKey, creds[1].KID); c != 200 {
		t.Fatalf("new key, its kid = %d", c)
	}
	if c := try(newKey, creds[0].KID); c != 401 {
		t.Fatalf("new key, old kid = %d", c)
	}
	expired := fixedNow().Add(-time.Second)
	if err := f.st.ClientCredentials().UpdateExpiry(context.Background(), f.tenantID(t, "acme"), "m2m", "cred_old", &expired); err != nil {
		t.Fatal(err)
	}
	if c := try(oldKey, ""); c != 401 {
		t.Fatalf("expired key = %d, want 401", c)
	}
	if c := try(newKey, ""); c != 200 {
		t.Fatalf("new key after old expired = %d", c)
	}
}

// Review focus 3: aud follows the host that received the assertion.
func TestPrivateKeyJWTAudPerHost(t *testing.T) {
	f := newPKJWTFixture(t)
	ctx := context.Background()
	tn, _ := f.st.Tenants().Get(ctx, f.tenantID(t, "acme"))
	tn.Domains = append(tn.Domains, "login.example.test")
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	f.usePrivateKeyJWT(t, "m2m", pkjwtCred{id: "cred_a", spki: "rsa2048.spki.pem", alg: "RS256"})
	key := pkjwtKey(t, "rsa2048.priv.pem")
	for _, tc := range []struct {
		host, aud string
		want      int
	}{
		{"login.example.test", "https://login.example.test/", 200},
		{"acme.example.test", "https://login.example.test/", 401},
		{"login.example.test", acmeIssuer, 401},
		{"acme.example.test", acmeIssuer, 200},
		// LR35-3: the exact endpoint URL.
		{"acme.example.test", acmeIssuer + "oauth/token", 200},
		{"login.example.test", "https://login.example.test/oauth/token", 200},
		{"acme.example.test", "https://login.example.test/oauth/token", 401},
		{"acme.example.test", acmeIssuer + "oauth/revoke", 401},
		{"acme.example.test", strings.TrimSuffix(acmeIssuer, "/"), 401},
	} {
		form := withAssertion(url.Values{"grant_type": {"client_credentials"}, "audience": {"https://api.acme.test"}},
			signAssertion(t, key, jose.RS256, "", assertionClaims("m2m", "aud", tc.aud)))
		if rec, b := f.call(t, false, tokenCall{host: tc.host, form: form}); rec.Code != tc.want {
			t.Errorf("host %s aud %s = %d %v, want %d", tc.host, tc.aud, rec.Code, b, tc.want)
		}
	}
}

func TestPrivateKeyJWTNotLogged(t *testing.T) {
	f := newPKJWTFixture(t)
	var logBuf bytes.Buffer
	var mu sync.Mutex
	f.h.Log = slog.New(slog.NewJSONHandler(&lockedWriter{w: &logBuf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	events := &eventRecorder{}
	f.h.Recorder = events
	f.usePrivateKeyJWT(t, "m2m", pkjwtCred{id: "cred_a", spki: "rsa2048.spki.pem", alg: "RS256"})
	key := pkjwtKey(t, "rsa2048.priv.pem")
	var raws []string
	post := func(claims map[string]any, audience string, want int) {
		raw := signAssertion(t, key, jose.RS256, "", claims)
		raws = append(raws, raw)
		form := withAssertion(url.Values{"grant_type": {"client_credentials"}, "audience": {audience}}, raw)
		if rec, b := f.call(t, false, tokenCall{host: "acme.example.test", form: form}); rec.Code != want {
			t.Fatalf("= %d %v, want %d", rec.Code, b, want)
		}
	}
	post(assertionClaims("m2m"), "https://api.acme.test", 200)                                      // seccft
	post(assertionClaims("m2m"), "https://missing.test", 403)                                       // feccft after authentication
	post(assertionClaims("m2m", "aud", "https://evil.example.test/"), "https://api.acme.test", 401) // reason in server log
	if len(events.events) < 2 {
		t.Fatalf("events = %+v", events.events)
	}
	evJSON, err := json.Marshal(events.events)
	if err != nil {
		t.Fatal(err)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "aud not accepted") {
		t.Fatalf("server log lacks the failure reason: %s", logs)
	}
	for _, raw := range raws {
		parts := strings.Split(raw, ".")
		// The header segment is shared by every token; the payload and
		// signature identify this assertion.
		for _, s := range []string{raw, parts[1], parts[2]} {
			if strings.Contains(logs, s) {
				t.Errorf("server log contains the assertion: %s", logs)
			}
			if strings.Contains(string(evJSON), s) {
				t.Errorf("tenant log contains the assertion: %s", evJSON)
			}
		}
	}
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
