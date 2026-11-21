package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func (f *fixture) par(t *testing.T, host, contentType, body string, basic ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	h := contract.WrapResponses(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthPar)))
	req := httptest.NewRequest("POST", "https://"+host+"/oauth/par", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

const formType = "application/x-www-form-urlencoded"

func parForm(extra ...string) url.Values {
	v := url.Values{
		"client_id": {"par-web"}, "client_secret": {"par-web-secret"},
		"response_type": {"code"}, "redirect_uri": {"https://par.acme.test/cb"},
		"scope": {"openid"}, "state": {"s1"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestPARStoresRequest(t *testing.T) {
	f := newFixture(t)
	rec, body := f.par(t, "acme.example.test", formType, parForm("ext-tenant_hint", "blue", "foo", "bar").Encode())
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, body %v", rec.Code, body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || body["expires_in"] != float64(30) {
		t.Fatalf("headers %v body %v", rec.Header(), body)
	}
	uri, _ := body["request_uri"].(string)
	id, ok := strings.CutPrefix(uri, authz.RequestURIPrefix)
	if !ok || len(id) != 64 {
		t.Fatalf("request_uri = %q", uri)
	}
	p, err := f.st.PushedAuthRequests().Get(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(id))
	if err != nil {
		t.Fatal(err)
	}
	if p.ClientID != "par-web" || p.Params["state"] != "s1" || p.Params["ext-tenant_hint"] != "blue" ||
		p.Params["foo"] != "" || p.Params["client_secret"] != "" || p.Params["za_pushed"] != "1" {
		t.Fatalf("stored params = %v", p.Params)
	}
	if !p.ExpiresAt.Equal(fixedNow().Add(authz.PARLifetime)) {
		t.Fatalf("ExpiresAt = %v", p.ExpiresAt)
	}
}

func TestPARWithBasicAuth(t *testing.T) {
	f := newFixture(t)
	form := parForm()
	form.Del("client_secret")
	form.Set("client_id", "par-basic")
	rec, body := f.par(t, "acme.example.test", formType, form.Encode(), "par-basic", "par-basic-secret")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, body %v", rec.Code, body)
	}
}

func TestPARRefusals(t *testing.T) {
	f := newFixture(t)
	elevenExt := parForm()
	for i := range 11 {
		elevenExt.Set(fmt.Sprintf("ext-a%d", i), "x")
	}
	tenExt := parForm()
	for i := range 10 {
		tenExt.Set(fmt.Sprintf("ext-a%d", i), "x")
	}
	public := url.Values{"client_id": {"code-spa"}, "response_type": {"code"}, "redirect_uri": {"https://app.acme.test/cb"}}
	strict := parForm("client_id", "par-strict", "client_secret", "par-strict-secret", "redirect_uri", "https://partner.acme.test/cb",
		"code_challenge", strings.Repeat("a", 43), "code_challenge_method", "S256")
	cases := []struct {
		name, host, ctype, body string
		status                  int
		code                    string
	}{
		{"P2a bad redirect_uri", "acme.example.test", formType, parForm("redirect_uri", "https://evil.test/cb").Encode(), 400, "invalid_request"},
		{"P2b response_type", "acme.example.test", formType, parForm("response_type", "token").Encode(), 501, "unsupported_response_type"},
		{"unknown audience", "acme.example.test", formType, parForm("audience", "https://nope.test").Encode(), 403, "access_denied"},
		{"P2c eleven ext", "acme.example.test", formType, elevenExt.Encode(), 400, "invalid_request"},
		{"P2d oversized", "acme.example.test", formType, parForm("ext-big", strings.Repeat("x", 11000)).Encode(), 413, "payload_too_large"},
		{"P2e json", "acme.example.test", "application/json", `{"client_id":"par-web","client_secret":"par-web-secret","response_type":"code"}`, 400, "invalid_request"},
		{"repeated", "acme.example.test", formType, parForm().Encode() + "&state=s2", 400, "invalid_request"},
		{"P3a wrong secret", "acme.example.test", formType, parForm("client_secret", "nope").Encode(), 401, "invalid_client"},
		{"P3b public", "acme.example.test", formType, public.Encode(), 400, "invalid_request"},
		{"P6a request_uri", "acme.example.test", formType, parForm("request_uri", authz.RequestURIPrefix+"x").Encode(), 400, "invalid_request"},
		{"P6b tenant off", "globex.example.test", formType, url.Values{"client_id": {"globex-web"}, "client_secret": {"globex-web-secret"}, "response_type": {"code"}, "redirect_uri": {"https://web.globex.test/cb"}}.Encode(), 400, "invalid_request"},
		{"request object", "acme.example.test", formType, parForm("request", "eyJhbGciOiJub25lIn0.e30.").Encode(), 400, "request_not_supported"},
		{"P9 strict", "acme.example.test", formType, strict.Encode(), 400, "invalid_request"},
		{"P9 permissive", "acme.example.test", formType, url.Values{"client_id": {"partner"}, "client_secret": {"partner-secret"}, "response_type": {"code"}, "redirect_uri": {"https://partner.acme.test/cb"}}.Encode(), 400, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := f.par(t, tc.host, tc.ctype, tc.body)
			if rec.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v; want %d %s", rec.Code, body, tc.status, tc.code)
			}
		})
	}
	t.Run("ten ext allowed", func(t *testing.T) {
		if rec, body := f.par(t, "acme.example.test", formType, tenExt.Encode()); rec.Code != http.StatusCreated {
			t.Fatalf("got %d %v", rec.Code, body)
		}
	})
}

// useJAR registers cred_jar_<clientID> on clientID for signed request
// objects only.
func (f *fixture) useJAR(t *testing.T, clientID string, required bool) {
	t.Helper()
	credID := "cred_jar_" + clientID
	f.addCredentials(t, clientID, pkjwtCred{id: credID, spki: "rsa2048.spki.pem", alg: "RS256"})
	ctx := context.Background()
	c, err := f.st.Clients().Get(ctx, f.tenantID(t, "acme"), clientID)
	if err != nil {
		t.Fatal(err)
	}
	c.SignedRequestObject = &store.SignedRequestObject{Required: required, Credentials: []string{credID}}
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
}

func jarObject(t *testing.T, kv ...any) string {
	t.Helper()
	claims := assertionClaims("par-web", "sub", nil, "client_id", "par-web", "response_type", "code",
		"redirect_uri", "https://par.acme.test/cb", "scope", "openid profile", "state", "inner-st")
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(claims, kv[i].(string))
		} else {
			claims[kv[i].(string)] = kv[i+1]
		}
	}
	return signAssertion(t, pkjwtKey(t, "rsa2048.priv.pem"), jose.RS256, "", claims)
}

// jarPARForm is a PAR body whose authorization parameters are only in the
// signed request object.
func jarPARForm(obj string) url.Values {
	return url.Values{"client_id": {"par-web"}, "client_secret": {"par-web-secret"}, "request": {obj}}
}

func (f *fixture) storedPAR(t *testing.T, body map[string]any) *store.PushedAuthRequest {
	t.Helper()
	id, ok := strings.CutPrefix(fmt.Sprint(body["request_uri"]), authz.RequestURIPrefix)
	if !ok {
		t.Fatalf("body = %v", body)
	}
	p, err := f.st.PushedAuthRequests().Get(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(id))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPARSignedRequest(t *testing.T) {
	f := newPKJWTFixture(t)
	f.useJAR(t, "par-web", true)
	rec, body := f.par(t, "acme.example.test", formType, jarPARForm(jarObject(t)).Encode())
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, body %v", rec.Code, body)
	}
	p := f.storedPAR(t, body)
	if !p.Signed || p.Params["redirect_uri"] != "https://par.acme.test/cb" || p.Params["state"] != "inner-st" || p.Params["scope"] != "openid profile" || p.Params["request"] != "" {
		t.Fatalf("stored = signed %v params %v", p.Signed, p.Params)
	}

	// /authorize with its request_uri succeeds although the client requires
	// signed requests.
	ah := &authz.Handlers{Store: f.st, Now: fixedNow}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", ah.Authorize)
	srv := contract.Wrap(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(mux))
	q := url.Values{"client_id": {"par-web"}, "request_uri": {fmt.Sprint(body["request_uri"])}}
	arec := httptest.NewRecorder()
	srv.ServeHTTP(arec, httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil))
	loc, _ := url.Parse(arec.Header().Get("Location"))
	if arec.Code != http.StatusFound || loc.Path != "/u/login" {
		t.Fatalf("authorize = %d %v %s", arec.Code, arec.Header(), arec.Body)
	}

	// A client_secret_basic client pushes a signed request too: the client
	// authenticates with any of its methods.
	f.useJAR(t, "par-basic", false)
	form := url.Values{"request": {jarObject(t, "iss", "par-basic", "client_id", "par-basic")}}
	if rec, body := f.par(t, "acme.example.test", formType, form.Encode(), "par-basic", "par-basic-secret"); rec.Code != http.StatusCreated {
		t.Fatalf("basic: status %d, body %v", rec.Code, body)
	}
}

func TestPARSignedRequestRefusals(t *testing.T) {
	f := newPKJWTFixture(t)
	f.useJAR(t, "par-web", true)
	replayed := jarObject(t)
	if rec, body := f.par(t, "acme.example.test", formType, jarPARForm(replayed).Encode()); rec.Code != http.StatusCreated {
		t.Fatalf("first push: %d %v", rec.Code, body)
	}
	unsigned := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"par-web"}`)) + "."
	for _, tc := range []struct {
		name string
		form url.Values
		code string
	}{
		{"replayed jti", jarPARForm(replayed), "invalid_request_object"},
		{"client_id mismatch", jarPARForm(jarObject(t, "client_id", "web")), "invalid_request_object"},
		{"bad aud", jarPARForm(jarObject(t, "aud", "https://evil.test/")), "invalid_request_object"},
		{"not a JWS", jarPARForm("not-a-jwt"), "invalid_request_object"},
		{"unsigned", parForm("request", unsigned), "request_not_supported"},
		{"required, plain", parForm(), "invalid_request"},
		{"inner unregistered redirect", jarPARForm(jarObject(t, "redirect_uri", "https://evil.test/cb")), "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := f.par(t, "acme.example.test", formType, tc.form.Encode())
			if rec.Code != http.StatusBadRequest || body["error"] != tc.code {
				t.Fatalf("got %d %v; want 400 %s", rec.Code, body, tc.code)
			}
		})
	}
	// Without client_credentials.v1 a pushed request object keeps today's refusal.
	f.h.Store = noClientCredentialsStore{f.st}
	if rec, body := f.par(t, "acme.example.test", formType, parForm("request", jarObject(t)).Encode()); rec.Code != 400 || body["error"] != "request_not_supported" {
		t.Fatalf("no capability: %d %v", rec.Code, body)
	}
}

// The pushed request object is registered as a log mask at /oauth/par.
func TestPARRequestObjectRegisteredForScrub(t *testing.T) {
	f := newPKJWTFixture(t)
	f.useJAR(t, "par-web", false)
	obj := jarObject(t, "client_id", "web")
	var seen string
	h := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.h.OauthPar(w, r)
		seen = logscrub.MaskText(r.Context(), "logged "+obj)
	}))
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/par", strings.NewReader(jarPARForm(obj).Encode()))
	req.Header.Set("Content-Type", formType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || strings.Contains(seen, obj) {
		t.Fatalf("= %d; log text %q", rec.Code, seen)
	}
}

func TestPARClaimsParameter(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		raw    string
		ignore bool
		status int
	}{
		{`{"userinfo":{"email":null}}`, false, 201}, {`[]`, false, 400}, {strings.Repeat("x", 4097), false, 400}, {`[]`, true, 201},
	} {
		f.h.Compat.IgnoreClaimsParameter = tc.ignore
		form := parForm("claims", tc.raw)
		rec, out := f.par(t, "acme.example.test", formType, form.Encode())
		if rec.Code != tc.status {
			t.Fatalf("claims ignore=%v: %d %v", tc.ignore, rec.Code, out)
		}
		if rec.Code == 201 {
			id := strings.TrimPrefix(out["request_uri"].(string), authz.RequestURIPrefix)
			stored, err := f.st.PushedAuthRequests().Get(t.Context(), f.tenantID(t, "acme"), secrets.HashToken(id))
			if err != nil {
				t.Fatal(err)
			}
			if tc.ignore {
				if stored.Params["claims"] != "" {
					t.Fatal("ignored claims stored")
				}
			} else if stored.Params["claims"] != tc.raw {
				t.Fatal("claims not preserved")
			}
		}
	}
}

func TestPARResourceProfile(t *testing.T) {
	f := newFixture(t)
	tid := f.tenantID(t, "acme")
	tn, err := f.st.Tenants().Get(t.Context(), tid)
	if err != nil {
		t.Fatal(err)
	}
	tn.DefaultAudience = ""
	tn.SettingsExtra = map[string]any{"resource_parameter_profile": "compatibility"}
	if err := f.st.Tenants().Update(t.Context(), tn); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		multiple bool
		code     string
	}{{false, ""}, {true, "invalid_target"}} {
		form := parForm("resource", "https://api.acme.test")
		if tc.multiple {
			form.Add("resource", "https://api.acme.test")
		}
		rec, out := f.par(t, "acme.example.test", formType, form.Encode())
		if tc.code != "" {
			if rec.Code != 400 || out["error"] != tc.code {
				t.Fatalf("PAR resource refusal: %d %v", rec.Code, out["error"])
			}
		} else {
			if rec.Code != 201 {
				t.Fatalf("PAR resource alias: %d", rec.Code)
			}
			id := strings.TrimPrefix(out["request_uri"].(string), authz.RequestURIPrefix)
			saved, err := f.st.PushedAuthRequests().Get(t.Context(), tid, secrets.HashToken(id))
			if err != nil || saved.Params["audience"] != "https://api.acme.test" {
				t.Fatal("PAR audience not canonicalized")
			}
		}
	}
}
