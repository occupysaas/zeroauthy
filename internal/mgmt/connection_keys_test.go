package mgmt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func keysEnv(t *testing.T) *clientsEnv {
	e := newClientsEnv(t)
	if err := e.st.Connections().Create(context.Background(), &store.Connection{TenantID: e.tn.ID, ID: "con_enterprise", Name: "enterprise", Strategy: "oidc", Extra: map[string]any{"type": "back_channel", "client_id": "client", "token_endpoint_auth_method": "private_key_jwt", "scopes": "openid", "discovery_url": "https://provider.example/discovery"}}); err != nil {
		t.Fatal(err)
	}
	return e
}
func TestKeysGetEmpty(t *testing.T) {
	e := keysEnv(t)
	r, v := e.call(t, e.tn, m2mCaller(), "GET", "/keys", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetConnectionKeys(w, r, "con_enterprise") })
	if r.Code != 200 || len(v.([]any)) != 0 {
		t.Fatal(r.Code, v)
	}
}
func TestKeysPostSigning(t *testing.T) {
	e := keysEnv(t)
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/keys", map[string]any{}, func(w http.ResponseWriter, r *http.Request) { e.h.PostConnectionKeys(w, r, "con_enterprise") })
	if r.Code != 201 {
		t.Fatal(r.Code, v)
	}
	rows := v.([]any)
	if len(rows) != 2 {
		t.Fatal(v)
	}
	for _, row := range rows {
		m := row.(map[string]any)
		b, _ := pem.Decode([]byte(m["cert"].(string)))
		if b == nil {
			t.Fatal("bad certificate")
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			t.Fatal(err)
		}
		if m["algorithm"] != "RS256" || m["key_use"] != "signing" || !strings.Contains(m["pkcs"].(string), "BEGIN PKCS7") {
			t.Fatal(m)
		}
	}
	if strings.Contains(r.Body.String(), "PRIVATE KEY") {
		t.Fatal("private key exposed")
	}
}
func TestKeysPostConflict(t *testing.T) {
	e := keysEnv(t)
	for _, want := range []int{201, 409} {
		r, v := e.call(t, e.tn, m2mCaller(), "POST", "/keys", map[string]any{}, func(w http.ResponseWriter, r *http.Request) { e.h.PostConnectionKeys(w, r, "con_enterprise") })
		if r.Code != want {
			t.Fatal(r.Code, v)
		}
	}
}
func TestKeysPostEncryption(t *testing.T) {
	e := keysEnv(t)
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/keys", map[string]any{"key_use": "encryption", "encryption_alg": "ECDH-ES"}, func(w http.ResponseWriter, r *http.Request) { e.h.PostConnectionKeys(w, r, "con_enterprise") })
	if r.Code != 201 {
		t.Fatal(r.Code, v)
	}
	m := v.([]any)[0].(map[string]any)
	b, _ := pem.Decode([]byte(m["cert"].(string)))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil || cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatal(cert, err)
	}
}
func TestKeysRotate(t *testing.T) {
	e := keysEnv(t)
	e.call(t, e.tn, m2mCaller(), "POST", "/keys", map[string]any{}, func(w http.ResponseWriter, r *http.Request) { e.h.PostConnectionKeys(w, r, "con_enterprise") })
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/rotate", map[string]any{}, func(w http.ResponseWriter, r *http.Request) { e.h.PostConnectionKeysRotate(w, r, "con_enterprise") })
	if r.Code != 201 || v.(map[string]any)["current"] != true {
		t.Fatal(r.Code, v)
	}
}
func TestKeysStrategy(t *testing.T) {
	e := keysEnv(t)
	c, err := e.st.Connections().Get(context.Background(), e.tn.ID, "con_enterprise")
	if err != nil {
		t.Fatal(err)
	}
	c.Strategy = "auth0"
	if err := e.st.Connections().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	r, _ := e.call(t, e.tn, m2mCaller(), "GET", "/keys", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetConnectionKeys(w, r, c.ID) })
	if r.Code != 400 {
		t.Fatal(r.Code)
	}
}

type noConnectionKeys struct{ store.Store }

func (noConnectionKeys) ConnectionKeysSupported() bool { return false }
func (noConnectionKeys) ConnectionKeys() store.ConnectionKeys {
	return store.UnimplementedConnectionKeys{}
}
func TestKeysPlugin501(t *testing.T) {
	e := keysEnv(t)
	e.h.Store = noConnectionKeys{e.st}
	r, _ := e.call(t, e.tn, m2mCaller(), "GET", "/keys", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetConnectionKeys(w, r, "con_enterprise") })
	if r.Code != 501 {
		t.Fatal(r.Code)
	}
}
func TestKeysRotateRequiresConfig(t *testing.T) {
	for _, use := range []string{"signing", "encryption"} {
		e := keysEnv(t)
		c, err := e.st.Connections().Get(context.Background(), e.tn.ID, "con_enterprise")
		if err != nil {
			t.Fatal(err)
		}
		delete(c.Extra, "token_endpoint_auth_method")
		if err := e.st.Connections().Update(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		r, _ := e.call(t, e.tn, m2mCaller(), "POST", "/rotate", map[string]any{"key_use": use}, func(w http.ResponseWriter, r *http.Request) { e.h.PostConnectionKeysRotate(w, r, c.ID) })
		if r.Code != 400 {
			t.Fatal(r.Code)
		}
	}
}

func TestConnectionKeyOptionsPlugin(t *testing.T) {
	e := keysEnv(t)
	e.h.Store = noConnectionKeys{e.st}
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "new-enterprise", "strategy": "oidc", "options": map[string]any{"type": "back_channel", "client_id": "client", "scope": "openid", "discovery_url": "https://provider.example/discovery", "token_endpoint_auth_method": "private_key_jwt"}}, e.h.CreateConnection)
	if r.Code != 400 || !strings.Contains(r.Body.String(), "connection keys") {
		t.Fatal(r.Code, v)
	}
}

func samlTestCert(t *testing.T) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestSAMLConnectionManagement is Plan 37a: samlp connections are created
// with computed thumbprints, refuse supplied private keys, and use the
// connection keys API for SP signing and decryption keys.
func TestSAMLConnectionManagement(t *testing.T) {
	e := keysEnv(t)
	cert := samlTestCert(t)
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "corp-saml", "strategy": "samlp",
		"options": map[string]any{"signInEndpoint": "https://idp.example.test/sso", "signingCert": cert, "thumbprints": []string{"client-sent"}}}, e.h.CreateConnection)
	if r.Code != 201 {
		t.Fatalf("create: %d %v", r.Code, v)
	}
	body := v.(map[string]any)
	opts := body["options"].(map[string]any)
	tp, _ := opts["thumbprints"].([]any)
	if len(tp) != 1 || len(tp[0].(string)) != 40 || tp[0] == "client-sent" || len(opts["thumbprints_sha384"].([]any)) != 1 {
		t.Fatalf("thumbprints %v", opts)
	}
	id := body["id"].(string)
	r, _ = e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "corp-saml-2", "strategy": "samlp",
		"options": map[string]any{"signInEndpoint": "https://idp.example.test/sso", "signingCert": cert, "decryptionKey": map[string]any{"key": "-----BEGIN PRIVATE KEY-----x", "cert": cert}}}, e.h.CreateConnection)
	if r.Code != 400 {
		t.Fatalf("supplied private key: %d", r.Code)
	}
	r, keysOut := e.call(t, e.tn, m2mCaller(), "GET", "/keys", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetConnectionKeys(w, r, id) })
	if r.Code != 200 {
		t.Fatalf("keys API for samlp: %d %v", r.Code, keysOut)
	}
}
