package mgmt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	testKeys  = map[int]*rsa.PrivateKey{}
	certNotAt = time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
)

func rsaKey(t *testing.T, bits, n int) *rsa.PrivateKey {
	t.Helper()
	k := bits*10 + n
	if testKeys[k] == nil {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		testKeys[k] = key
	}
	return testKeys[k]
}

func spkiPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func certPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "app"},
		NotBefore: certNotAt.AddDate(-1, 0, 0), NotAfter: certNotAt}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

var credScopes = []string{"read:clients", "create:clients", "update:clients", "read:client_keys", "read:client_credentials", "create:client_credentials", "update:client_credentials", "delete:client_credentials"}

func credCall(t *testing.T, e *clientsEnv, method, target string, body any, fn http.HandlerFunc) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, m2mCaller(credScopes...), method, target, body, fn)
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *clientsEnv) postCred(t *testing.T, clientID string, body any) (*httptest.ResponseRecorder, map[string]any) {
	return credCall(t, e, "POST", "/api/v2/clients/"+clientID+"/credentials", body,
		func(w http.ResponseWriter, r *http.Request) { e.h.PostClientCredentials(w, r, clientID) })
}

func (e *clientsEnv) patchCred(t *testing.T, clientID, id string, body any) (*httptest.ResponseRecorder, map[string]any) {
	return credCall(t, e, "PATCH", "/api/v2/clients/"+clientID+"/credentials/"+id, body,
		func(w http.ResponseWriter, r *http.Request) { e.h.PatchClientCredential(w, r, clientID, id) })
}

func newCredClient(t *testing.T, e *clientsEnv) string {
	t.Helper()
	return e.mustCreate(t, map[string]any{"name": "app"})["client_id"].(string)
}

func TestCredentialCreateRead(t *testing.T) {
	e := newClientsEnv(t)
	cid := newCredClient(t, e)
	key := rsaKey(t, 2048, 1)
	pemText := spkiPEM(t, key)
	rec, got := e.postCred(t, cid, map[string]any{"credential_type": "public_key", "pem": pemText, "name": "main"})
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	id, _ := got["id"].(string)
	if !strings.HasPrefix(id, "cred_") || len(id) != len("cred_")+22 {
		t.Errorf("id = %q", id)
	}
	if got["alg"] != "RS256" || got["name"] != "main" || got["credential_type"] != "public_key" {
		t.Errorf("body = %v", got)
	}
	if got["kid"] == "" || got["kid"] != got["thumbprint_sha256"] {
		t.Errorf("kid/thumbprint = %v / %v", got["kid"], got["thumbprint_sha256"])
	}
	if _, ok := got["expires_at"]; ok {
		t.Errorf("a credential without expiry has expires_at: %v", got)
	}
	stored, err := e.st.ClientCredentials().Get(t.Context(), e.tn.ID, cid, id)
	if err != nil || stored.Alg != "RS256" || len(stored.PublicKeyDER) == 0 {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	// C1: no response carries the PEM.
	read := func(name string, rec *httptest.ResponseRecorder) {
		if strings.Contains(rec.Body.String(), "BEGIN") || strings.Contains(rec.Body.String(), `"pem"`) {
			t.Errorf("%s response carries the PEM: %s", name, rec.Body)
		}
	}
	read("create", rec)
	rec, _ = credCall(t, e, "GET", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetClientCredential(w, r, cid, id) })
	if rec.Code != 200 {
		t.Fatalf("get = %d %s", rec.Code, rec.Body)
	}
	read("get", rec)
	rec, _ = credCall(t, e, "GET", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetClientCredentials(w, r, cid) })
	if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "[") || !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	read("list", rec)
	rec, _ = credCall(t, e, "GET", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetClientCredential(w, r, cid, "cred_nope") })
	if rec.Code != 404 {
		t.Errorf("unknown credential = %d", rec.Code)
	}
	rec, _ = credCall(t, e, "GET", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetClientCredentials(w, r, "nope") })
	if rec.Code != 404 {
		t.Errorf("unknown client = %d", rec.Code)
	}

	// An x509 certificate with parse_expiry_from_cert takes its NotAfter and an explicit alg and kid.
	rec, got = e.postCred(t, cid, map[string]any{"credential_type": "x509_cert", "pem": certPEM(t, rsaKey(t, 2048, 2)),
		"parse_expiry_from_cert": true, "alg": "PS256", "kid": "my-key-id-0123456789"})
	if rec.Code != 201 {
		t.Fatalf("cert create = %d %s", rec.Code, rec.Body)
	}
	if got["alg"] != "PS256" || got["kid"] != "my-key-id-0123456789" || got["expires_at"] != certNotAt.Format(time.RFC3339) {
		t.Errorf("cert body = %v", got)
	}
}

func TestCredentialValidation(t *testing.T) {
	e := newClientsEnv(t)
	cid := newCredClient(t, e)
	good := spkiPEM(t, rsaKey(t, 2048, 1))
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}))
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	base := func(extra map[string]any) map[string]any {
		m := map[string]any{"credential_type": "public_key", "pem": good}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for name, body := range map[string]map[string]any{
		"cert_subject_dn":         {"credential_type": "cert_subject_dn"},
		"expiry from an SPKI key": base(map[string]any{"parse_expiry_from_cert": true}),
		"both expiry sources":     {"credential_type": "x509_cert", "pem": certPEM(t, rsaKey(t, 2048, 2)), "parse_expiry_from_cert": true, "expires_at": exp},
		"bad kid":                 base(map[string]any{"kid": "short"}),
		"1024-bit key":            base(map[string]any{"pem": spkiPEM(t, rsaKey(t, 1024, 1))}),
		"EC key":                  base(map[string]any{"pem": ecPEM}),
		"unknown property":        base(map[string]any{"cert_subject_dn": "CN=x"}),
		"no pem":                  {"credential_type": "public_key"},
		"bad alg":                 base(map[string]any{"alg": "HS256"}),
		"long name":               base(map[string]any{"name": strings.Repeat("n", 129)}),
		"null body":               nil,
	} {
		rec, got := e.postCred(t, cid, body)
		if rec.Code != 400 || got["error_code"] != "invalid_body" && got["errorCode"] != "invalid_body" {
			t.Errorf("%s: %d %s, want 400 invalid_body", name, rec.Code, rec.Body)
		}
	}
	if list, _ := e.st.ClientCredentials().List(t.Context(), e.tn.ID, cid); len(list) != 0 {
		t.Fatalf("rejected requests stored %d credentials", len(list))
	}
	for i := 1; i <= 2; i++ {
		if rec, _ := e.postCred(t, cid, base(map[string]any{"pem": spkiPEM(t, rsaKey(t, 2048, i))})); rec.Code != 201 {
			t.Fatalf("credential %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	rec, got := e.postCred(t, cid, base(map[string]any{"pem": certPEM(t, rsaKey(t, 2048, 2)), "credential_type": "x509_cert"}))
	if rec.Code != 400 || got["errorCode"] != "invalid_body" && got["error_code"] != "invalid_body" {
		t.Errorf("third credential: %d %s", rec.Code, rec.Body)
	}
}

func TestCredentialPatchOnlyExpiry(t *testing.T) {
	e := newClientsEnv(t)
	cid := newCredClient(t, e)
	_, cred := e.postCred(t, cid, map[string]any{"credential_type": "public_key", "pem": spkiPEM(t, rsaKey(t, 2048, 1))})
	id := cred["id"].(string)
	for name, body := range map[string]any{
		"name":          map[string]any{"name": "x"},
		"name+expiry":   map[string]any{"name": "x", "expires_at": "2031-01-01T00:00:00Z"},
		"missing field": map[string]any{},
		"bad time":      map[string]any{"expires_at": "tomorrow"},
	} {
		if rec, _ := e.patchCred(t, cid, id, body); rec.Code != 400 {
			t.Errorf("%s: %d %s, want 400", name, rec.Code, rec.Body)
		}
	}
	rec, got := e.patchCred(t, cid, id, map[string]any{"expires_at": "2031-01-01T00:00:00Z"})
	if rec.Code != 200 || got["expires_at"] != "2031-01-01T00:00:00Z" || got["name"] != "" {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body)
	}
	if got["updated_at"] == got["created_at"] {
		t.Errorf("updated_at did not move: %v", got)
	}
	rec, got = e.patchCred(t, cid, id, map[string]any{"expires_at": nil})
	if _, has := got["expires_at"]; rec.Code != 200 || has {
		t.Fatalf("clear expiry = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.patchCred(t, cid, "cred_nope", map[string]any{"expires_at": nil}); rec.Code != 404 {
		t.Errorf("unknown credential = %d", rec.Code)
	}
}

func TestCredentialDeleteDetaches(t *testing.T) {
	e := newClientsEnv(t)
	cid := newCredClient(t, e)
	_, cred := e.postCred(t, cid, map[string]any{"credential_type": "public_key", "pem": spkiPEM(t, rsaKey(t, 2048, 1))})
	id := cred["id"].(string)
	rec, got := e.patch(t, m2mCaller(credScopes...), cid, map[string]any{
		"token_endpoint_auth_method":    nil,
		"client_authentication_methods": map[string]any{"private_key_jwt": map[string]any{"credentials": []any{map[string]any{"id": id}}}},
		"signed_request_object":         map[string]any{"required": true, "credentials": []any{map[string]any{"id": id}}},
	})
	if rec.Code != 200 {
		t.Fatalf("attach = %d %s", rec.Code, rec.Body)
	}
	_ = got
	rec, _ = credCall(t, e, "DELETE", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteClientCredential(w, r, cid, id) })
	if rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	c, err := e.st.Clients().Get(t.Context(), e.tn.ID, cid)
	if err != nil || len(c.PrivateKeyJWTCredentials) != 0 || c.SignedRequestObject == nil || len(c.SignedRequestObject.Credentials) != 0 {
		t.Fatalf("client after delete = %+v, %v", c, err)
	}
	rec, _ = credCall(t, e, "DELETE", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteClientCredential(w, r, cid, id) })
	if rec.Code != 404 {
		t.Errorf("second delete = %d", rec.Code)
	}
}

func pkjSetting(ids ...string) map[string]any {
	refs := []any{}
	for _, id := range ids {
		refs = append(refs, map[string]any{"id": id})
	}
	return map[string]any{"private_key_jwt": map[string]any{"credentials": refs}}
}

func inlineRef(t *testing.T, n int) map[string]any {
	return map[string]any{"credential_type": "public_key", "name": "inline", "pem": spkiPEM(t, rsaKey(t, 2048, n)), "alg": "RS384"}
}

func TestClientPrivateKeyJWTSetting(t *testing.T) {
	e := newClientsEnv(t)
	caller := m2mCaller(credScopes...)
	cid := newCredClient(t, e)
	_, cred := e.postCred(t, cid, map[string]any{"credential_type": "public_key", "pem": spkiPEM(t, rsaKey(t, 2048, 1))})
	id := cred["id"].(string)

	// The setting needs token_endpoint_auth_method null in the same request.
	if rec, _ := e.patch(t, caller, cid, map[string]any{"client_authentication_methods": pkjSetting(id)}); rec.Code != 400 {
		t.Errorf("without null method = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.patch(t, caller, cid, map[string]any{"token_endpoint_auth_method": "client_secret_basic", "client_authentication_methods": pkjSetting(id)}); rec.Code != 400 {
		t.Errorf("with a method = %d %s", rec.Code, rec.Body)
	}
	// Another client's credential id is refused.
	other := newCredClient(t, e)
	_, oc := e.postCred(t, other, map[string]any{"credential_type": "public_key", "pem": spkiPEM(t, rsaKey(t, 2048, 2))})
	if rec, _ := e.patch(t, caller, cid, map[string]any{"token_endpoint_auth_method": nil, "client_authentication_methods": pkjSetting(oc["id"].(string))}); rec.Code != 400 {
		t.Errorf("foreign credential = %d %s", rec.Code, rec.Body)
	}
	for _, key := range []string{"tls_client_auth", "self_signed_tls_client_auth"} {
		if rec, _ := e.patch(t, caller, cid, map[string]any{"token_endpoint_auth_method": nil, "client_authentication_methods": map[string]any{key: map[string]any{}}}); rec.Code != 400 {
			t.Errorf("%s = %d %s", key, rec.Code, rec.Body)
		}
	}
	if c, _ := e.st.Clients().Get(t.Context(), e.tn.ID, cid); c.PrivateKeyJWTCredentials != nil || c.TokenEndpointAuthMethod == "" {
		t.Fatalf("a refused request changed the client: %+v", c)
	}

	rec, got := e.patch(t, caller, cid, map[string]any{"token_endpoint_auth_method": nil, "client_authentication_methods": pkjSetting(id)})
	if rec.Code != 200 {
		t.Fatalf("set = %d %s", rec.Code, rec.Body)
	}
	if v, ok := got["token_endpoint_auth_method"]; !ok || v != nil {
		t.Errorf("token_endpoint_auth_method = %v (present %v), want null", v, ok)
	}
	want := map[string]any{"private_key_jwt": map[string]any{"credentials": []any{map[string]any{"id": id}}}}
	if !jsonEqual(got["client_authentication_methods"], want) {
		t.Errorf("client_authentication_methods = %v", got["client_authentication_methods"])
	}
	// An unrelated patch keeps the setting and the null method.
	rec, got = e.patch(t, caller, cid, map[string]any{"name": "renamed"})
	if rec.Code != 200 || got["token_endpoint_auth_method"] != nil || got["client_authentication_methods"] == nil {
		t.Fatalf("rename = %d %s", rec.Code, rec.Body)
	}
	if c, _ := e.st.Clients().Get(t.Context(), e.tn.ID, cid); c.TokenEndpointAuthMethod != "" {
		t.Errorf("stored method = %q, want empty", c.TokenEndpointAuthMethod)
	}
	// A method cannot be set while the setting stands.
	if rec, _ := e.patch(t, caller, cid, map[string]any{"token_endpoint_auth_method": "client_secret_post"}); rec.Code != 400 {
		t.Errorf("method with setting = %d %s", rec.Code, rec.Body)
	}
	// Revert: null plus a method.
	rec, got = e.patch(t, caller, cid, map[string]any{"token_endpoint_auth_method": "client_secret_basic", "client_authentication_methods": nil})
	if rec.Code != 200 || got["token_endpoint_auth_method"] != "client_secret_basic" {
		t.Fatalf("revert = %d %s", rec.Code, rec.Body)
	}
	if _, has := got["client_authentication_methods"]; has {
		t.Errorf("reverted client still has client_authentication_methods: %v", got)
	}
	// Reverting without a method is refused.
	e.patch(t, caller, cid, map[string]any{"token_endpoint_auth_method": nil, "client_authentication_methods": pkjSetting()})
	if rec, _ := e.patch(t, caller, cid, map[string]any{"client_authentication_methods": nil}); rec.Code != 400 {
		t.Errorf("revert without method = %d %s", rec.Code, rec.Body)
	}

	// Inline creation on create and patch; the third credential is refused.
	rec, got = e.create(t, caller, map[string]any{"name": "inline", "token_endpoint_auth_method": nil,
		"client_authentication_methods": map[string]any{"private_key_jwt": map[string]any{"credentials": []any{inlineRef(t, 1)}}}})
	if rec.Code != 201 || got["token_endpoint_auth_method"] != nil {
		t.Fatalf("create with inline = %d %s", rec.Code, rec.Body)
	}
	icid := got["client_id"].(string)
	list, _ := e.st.ClientCredentials().List(t.Context(), e.tn.ID, icid)
	if len(list) != 1 || list[0].Alg != "RS384" || list[0].Name != "inline" {
		t.Fatalf("inline credentials = %+v", list)
	}
	c, _ := e.st.Clients().Get(t.Context(), e.tn.ID, icid)
	if len(c.PrivateKeyJWTCredentials) != 1 || c.PrivateKeyJWTCredentials[0] != list[0].ID || c.TokenEndpointAuthMethod != "" {
		t.Errorf("client = %+v", c)
	}
	if strings.Contains(rec.Body.String(), "BEGIN") {
		t.Errorf("the PEM was returned: %s", rec.Body)
	}
	// Creating a client with a bad inline credential leaves no client behind.
	_, before, _ := e.st.Clients().List(t.Context(), e.tn.ID, store.ClientFilter{}, store.Page{Limit: 1000})
	bad := inlineRef(t, 1)
	bad["pem"] = "nonsense"
	if rec, _ := e.create(t, caller, map[string]any{"name": "bad", "token_endpoint_auth_method": nil,
		"client_authentication_methods": map[string]any{"private_key_jwt": map[string]any{"credentials": []any{bad}}}}); rec.Code != 400 {
		t.Errorf("bad inline = %d %s", rec.Code, rec.Body)
	}
	if _, after, _ := e.st.Clients().List(t.Context(), e.tn.ID, store.ClientFilter{}, store.Page{Limit: 1000}); after != before {
		t.Errorf("a refused create left a client: %d -> %d", before, after)
	}
	// An id reference on create names no credential of the new client.
	if rec, _ := e.create(t, caller, map[string]any{"name": "ref", "token_endpoint_auth_method": nil,
		"client_authentication_methods": pkjSetting(id)}); rec.Code != 400 {
		t.Errorf("id on create = %d %s", rec.Code, rec.Body)
	}
	// Mixing an id with new-credential fields is refused.
	mixed := inlineRef(t, 2)
	mixed["id"] = id
	if rec, _ := e.patch(t, caller, icid, map[string]any{"client_authentication_methods": map[string]any{"private_key_jwt": map[string]any{"credentials": []any{mixed}}}}); rec.Code != 400 {
		t.Errorf("mixed ref = %d %s", rec.Code, rec.Body)
	}
	// One inline on patch fits (2 credentials), the next does not.
	rec, _ = e.patch(t, caller, icid, map[string]any{"signed_request_object": map[string]any{"required": true, "credentials": []any{inlineRef(t, 2)}}})
	if rec.Code != 200 {
		t.Fatalf("inline JAR credential = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.patch(t, caller, icid, map[string]any{"signed_request_object": map[string]any{"credentials": []any{inlineRef(t, 1)}}}); rec.Code != 400 {
		t.Errorf("third credential via setting = %d %s", rec.Code, rec.Body)
	}
	_, got = e.patch(t, caller, icid, map[string]any{"name": "x"})
	sro, _ := got["signed_request_object"].(map[string]any)
	if sro["required"] != true || len(sro["credentials"].([]any)) != 1 {
		t.Errorf("signed_request_object = %v", got["signed_request_object"])
	}
	// null clears the JAR setting.
	_, got = e.patch(t, caller, icid, map[string]any{"signed_request_object": nil})
	if _, has := got["signed_request_object"]; has {
		t.Errorf("cleared signed_request_object still present: %v", got["signed_request_object"])
	}
}

func TestClientTokenExchangeSetting(t *testing.T) {
	e := newClientsEnv(t)
	caller := m2mCaller(credScopes...)
	cid := newCredClient(t, e)
	setting := map[string]any{"allow_any_profile_of_type": []string{"custom_authentication"}}
	rec, got := e.patch(t, caller, cid, map[string]any{"token_exchange": setting})
	if rec.Code != 200 || !jsonEqual(got["token_exchange"], setting) {
		t.Fatalf("set = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.patch(t, caller, cid, map[string]any{"token_exchange": map[string]any{"allow_any_profile_of_type": []string{"other"}}}); rec.Code != 400 {
		t.Errorf("unknown type = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.patch(t, caller, cid, map[string]any{"token_exchange": map[string]any{"extra": true}}); rec.Code != 400 {
		t.Errorf("unknown member = %d %s", rec.Code, rec.Body)
	}
	_, got = e.patch(t, caller, cid, map[string]any{"token_exchange": nil})
	if _, has := got["token_exchange"]; has {
		t.Errorf("cleared token_exchange present: %v", got["token_exchange"])
	}
	// LR35-6: third-party applications are refused, on create and patch.
	if rec, _ := e.create(t, caller, map[string]any{"name": "tp", "is_first_party": false, "token_exchange": setting}); rec.Code != 400 {
		t.Errorf("third-party create = %d %s", rec.Code, rec.Body)
	}
	tp := e.mustCreate(t, map[string]any{"name": "tp", "is_first_party": false})["client_id"].(string)
	if rec, _ := e.patch(t, caller, tp, map[string]any{"token_exchange": setting}); rec.Code != 400 {
		t.Errorf("third-party patch = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.create(t, caller, map[string]any{"name": "fp", "token_exchange": setting}); rec.Code != 201 {
		t.Errorf("first-party create = %d %s", rec.Code, rec.Body)
	}
}

type noCredentialStore struct{ store.Store }

func (noCredentialStore) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}

func TestClientCredentialsPluginUnavailable(t *testing.T) {
	e := newClientsEnv(t)
	caller := m2mCaller(credScopes...)
	cid := newCredClient(t, e)
	e.h.Store = noCredentialStore{e.st}
	body := map[string]any{"credential_type": "public_key", "pem": spkiPEM(t, rsaKey(t, 2048, 1))}
	routes := map[string]*httptest.ResponseRecorder{}
	routes["list"], _ = credCall(t, e, "GET", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetClientCredentials(w, r, cid) })
	routes["create"], _ = e.postCred(t, cid, body)
	routes["get"], _ = credCall(t, e, "GET", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetClientCredential(w, r, cid, "cred_x") })
	routes["patch"], _ = e.patchCred(t, cid, "cred_x", map[string]any{"expires_at": nil})
	routes["delete"], _ = credCall(t, e, "DELETE", "/x", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteClientCredential(w, r, cid, "cred_x") })
	routes["client create"], _ = e.create(t, caller, map[string]any{"name": "x", "token_endpoint_auth_method": nil,
		"client_authentication_methods": map[string]any{"private_key_jwt": map[string]any{"credentials": []any{inlineRef(t, 1)}}}})
	routes["client patch"], _ = e.patch(t, caller, cid, map[string]any{"token_exchange": map[string]any{"allow_any_profile_of_type": []string{"custom_authentication"}}})
	routes["signed request object"], _ = e.patch(t, caller, cid, map[string]any{"signed_request_object": map[string]any{"required": true}})
	for name, rec := range routes {
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s = %d %s, want 501", name, rec.Code, rec.Body)
		}
	}
	// Clients without the new settings still work, and a null revert is harmless.
	if rec, _ := e.patch(t, caller, cid, map[string]any{"name": "still works", "client_authentication_methods": nil}); rec.Code != 200 {
		t.Errorf("plain patch = %d %s", rec.Code, rec.Body)
	}
}

// The token exchange profile routes stay 501 until Task 10.
func TestTokenExchangeProfileRoutesAnswerNotImplemented(t *testing.T) {
	h := &mgmt.Handlers{}
	routes := map[string]func(http.ResponseWriter, *http.Request){
		"GetTokenExchangeProfiles": func(w http.ResponseWriter, r *http.Request) {
			h.GetTokenExchangeProfiles(w, r, mgmtapi.GetTokenExchangeProfilesParams{})
		},
		"PostTokenExchangeProfile":   h.PostTokenExchangeProfile,
		"GetTokenExchangeProfile":    func(w http.ResponseWriter, r *http.Request) { h.GetTokenExchangeProfile(w, r, "tep_x") },
		"PatchTokenExchangeProfile":  func(w http.ResponseWriter, r *http.Request) { h.PatchTokenExchangeProfile(w, r, "tep_x") },
		"DeleteTokenExchangeProfile": func(w http.ResponseWriter, r *http.Request) { h.DeleteTokenExchangeProfile(w, r, "tep_x") },
	}
	for name, route := range routes {
		rec := httptest.NewRecorder()
		route(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s: status %d, want 501", name, rec.Code)
		}
	}
}
