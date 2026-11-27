package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const googleWebClient = "web-client.apps.googleusercontent.com"

// nativeSocialFixture serves Google's JWKS and Facebook's debug_token, and
// configures one google-oauth2 and one facebook connection enabled for
// ropg-public with native login on for both (Plan 39b).
type nativeSocialFixture struct {
	*cteFixture
	srv      *httptest.Server
	key      *rsa.PrivateKey
	debug    string
	requests int
}

func newNativeSocialFixture(t *testing.T) *nativeSocialFixture {
	t.Helper()
	f := &nativeSocialFixture{cteFixture: newCTEFixture(t)}
	f.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.debug = `{"data":{"app_id":"fb-app","type":"USER","is_valid":true,"user_id":"10150000000000001"}}`
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "g1", Algorithm: "RS256", Use: "sig"}}})
		case "/facebook/v24.0/debug_token":
			_, _ = w.Write([]byte(f.debug))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	ctx := context.Background()
	c, _ := f.st.Clients().Get(ctx, f.tid, "ropg-public")
	c.NativeSocialLogin = map[string]bool{"google": true, "facebook": true}
	c.TokenExchangeTypes = nil
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, conn := range []struct{ id, strategy, clientID string }{{"con_native_google", "google-oauth2", googleWebClient}, {"con_native_fb", "facebook", "fb-app"}} {
		spec := connrules.Spec{Name: conn.strategy, Strategy: conn.strategy, EnabledClients: []string{"ropg-public"}, Options: connrules.Options{Extra: map[string]any{"client_id": conn.clientID}}}
		sc := &store.Connection{TenantID: f.tid, ID: conn.id, FederationRevision: 1}
		connrules.Apply(&spec, sc)
		sc.FederationSecretsSealed, _ = federation.SealCredentials(f.wrapper, f.tid, sc.ID, federation.Credentials{ClientSecret: "throwaway-secret"})
		if err := f.st.Connections().Create(ctx, sc); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.srv.Certificate())
	ps := federation.NewProviders(federation.FixturePolicy(roots), nil).
		WithGoogleFixture(federation.GoogleOverride{Endpoints: federation.Endpoints{JWKSURL: f.srv.URL + "/jwks"}, Issuer: f.srv.URL}).
		WithSocialFixture(f.srv.URL)
	f.h.Federation = &federation.FlowService{Service: federation.Service{Wrapper: f.wrapper, Now: time.Now}, Store: f.st, Providers: ps}
	return f
}

func (f *nativeSocialFixture) googleToken(t *testing.T, aud string) string {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{"iss": f.srv.URL, "aud": aud, "azp": "android-client.apps.googleusercontent.com", "sub": "112233",
		"email": "g@example.com", "email_verified": true, "name": "Gee Native", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "g1"))
	obj, _ := s.Sign(claims)
	out, _ := obj.CompactSerialize()
	return out
}

func nativeForm(subjectType, token string, extra ...string) url.Values {
	return cteForm("ropg-public", "", append([]string{"subject_token_type", subjectType, "subject_token", token, "scope", "openid offline_access read:things"}, extra...)...)
}

func TestNativeGoogleFacebookDisabled(t *testing.T) {
	for _, kind := range []string{"google", "facebook"} {
		t.Run(kind, func(t *testing.T) {
			f := newNativeSocialFixture(t)
			ctx := context.Background()
			c, _ := f.st.Clients().Get(ctx, f.tid, "ropg-public")
			c.NativeSocialLogin = map[string]bool{"google": kind != "google", "facebook": kind != "facebook"}
			_ = f.st.Clients().Update(ctx, c)
			v := nativeForm(federation.NativeGoogleSubjectType, f.googleToken(t, googleWebClient))
			if kind == "facebook" {
				v = nativeForm(federation.NativeFacebookSubjectType, "fb-session-token")
			}
			f.requests = 0
			s, b := f.token(t, v)
			if s != 400 || b["error"] != "invalid_request" || f.requests != 0 {
				t.Fatalf("%d %v requests=%d", s, b, f.requests)
			}
		})
	}
}

func TestNativeGoogleSuccess(t *testing.T) {
	f := newNativeSocialFixture(t)
	f.actions.PostLogin(t, f.tid, "native-observe", `exports.onExecutePostLogin=async(event,api)=>{if(event.connection.strategy!=="google-oauth2"||event.transaction.protocol!=="oauth2-token-exchange")throw new Error("wrong native flow");};`)
	s, b := f.token(t, nativeForm(federation.NativeGoogleSubjectType, f.googleToken(t, googleWebClient)))
	if s != 200 || b["id_token"] == nil {
		t.Fatalf("%d %v", s, b)
	}
	if u := f.user(t, "google-oauth2|112233"); u.Email != "g@example.com" || !u.EmailVerified {
		t.Fatalf("%+v", u)
	}
	// A token issued to another app is refused.
	s, b = f.token(t, nativeForm(federation.NativeGoogleSubjectType, f.googleToken(t, "other-app.apps.googleusercontent.com")))
	if s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("other audience: %d %v", s, b)
	}
}

func TestNativeFacebookSuccess(t *testing.T) {
	f := newNativeSocialFixture(t)
	s, b := f.token(t, nativeForm(federation.NativeFacebookSubjectType, "fb-session-token", "user_profile", `{"id":"10150000000000001","name":"Fay Book","email":"fay@example.com"}`))
	if s != 200 {
		t.Fatalf("%d %v", s, b)
	}
	if u := f.user(t, "facebook|10150000000000001"); u.Name != "Fay Book" || u.EmailVerified {
		t.Fatalf("%+v", u)
	}
	f.debug = `{"data":{"app_id":"another-app","type":"USER","is_valid":true,"user_id":"1"}}`
	if s, b := f.token(t, nativeForm(federation.NativeFacebookSubjectType, "fb-session-token")); s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("other app: %d %v", s, b)
	}
	if s, b := f.token(t, nativeForm(federation.NativeFacebookSubjectType, "fb-session-token", "user_profile", `[1]`)); s != 400 || b["error"] != "invalid_request" {
		t.Fatalf("bad user_profile: %d %v", s, b)
	}
}
