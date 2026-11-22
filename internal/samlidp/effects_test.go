package samlidp

import (
	"bytes"
	"context"
	"html"
	"net/http/httptest"
	"regexp"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	"math/big"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func keyPair(t *testing.T) (string, string, *x509.Certificate) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "action"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(keyPEM), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert
}

func TestApplyEffects(t *testing.T) {
	yes, no, n := true, false, 120
	relay := "new-relay"
	addon := &store.SAMLAddon{Audience: "urn:addon", SignatureAlgorithm: "rsa-sha256"}
	b := Binding{ACS: "https://sp/acs", Audience: "urn:addon", RelayState: "old"}
	cfg, nb := applyEffects(addon, b, &actionresult.SAMLEffects{Audience: "urn:action", Issuer: "urn:iss", RelayState: &relay,
		SignResponse: &yes, CreateUpnClaim: &no, LifetimeInSeconds: &n, SignatureAlgorithm: "rsa-sha1", NameIdentifierProbes: []string{"p"}})
	if nb.Audience != "urn:action" || nb.RelayState != "new-relay" || nb.ACS != "https://sp/acs" {
		t.Fatalf("binding %+v", nb)
	}
	if cfg.Issuer != "urn:iss" || !*cfg.SignResponse || *cfg.CreateUpnClaim || *cfg.LifetimeInSeconds != 120 || cfg.SignatureAlgorithm != "rsa-sha1" || cfg.NameIdentifierProbes[0] != "p" {
		t.Fatalf("config %+v", cfg)
	}
	if addon.Issuer != "" || addon.SignResponse != nil {
		t.Fatal("effects changed the stored add-on")
	}
	if cfg, nb := applyEffects(addon, b, nil); cfg.Audience != "urn:addon" || nb != b {
		t.Fatal("nil effects changed something")
	}
}

func TestEffectAttributes(t *testing.T) {
	in := []samlcore.Attribute{{Name: "a", Values: []string{"1"}}, {Name: "b", Values: []string{"2"}}}
	out := overrideAttributes(in, &actionresult.SAMLEffects{Attributes: map[string][]string{"a": {"x", "y"}, "c": {"3"}}, RemovedAttributes: []string{"b"}})
	got := attrs(out)
	if len(got["a"]) != 2 || got["b"] != nil || got["c"][0] != "3" {
		t.Fatalf("attributes %v", got)
	}
}

func TestEffectSigner(t *testing.T) {
	keyPEM, certPEM, cert := keyPair(t)
	s, err := effectSigner(&actionresult.SAMLEffects{Key: keyPEM, Cert: certPEM})
	if err != nil || s == nil || !s.Cert.Equal(cert) {
		t.Fatalf("action signer: %v", err)
	}
	if s, err := effectSigner(&actionresult.SAMLEffects{}); s != nil || err != nil {
		t.Fatal("no key should mean the tenant key")
	}
	_, otherCert, _ := keyPair(t)
	for name, e := range map[string]*actionresult.SAMLEffects{
		"key without cert": {Key: keyPEM}, "cert without key": {Cert: certPEM}, "mismatched pair": {Key: keyPEM, Cert: otherCert}, "garbage": {Key: "x", Cert: "y"},
	} {
		if _, err := effectSigner(e); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestEffectEncryptionKey(t *testing.T) {
	_, certPEM, cert := keyPair(t)
	pub, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	for name, e := range map[string]*actionresult.SAMLEffects{"cert": {EncryptionCert: certPEM}, "public key": {EncryptionPublicKey: pubPEM}} {
		got, err := encryptionTarget(e)
		if err != nil || got == nil || !got.PublicKey.(*rsa.PublicKey).Equal(cert.PublicKey) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if got, err := encryptionTarget(&actionresult.SAMLEffects{}); got != nil || err != nil {
		t.Fatal("encryption without a key")
	}
	if _, err := encryptionTarget(&actionresult.SAMLEffects{EncryptionPublicKey: "nope"}); err == nil {
		t.Fatal("garbage public key accepted")
	}
}

// TestRespondWithEffects drives Respond with Action effects: attributes,
// audience, RelayState, the Action's own signing key and encryption.
func TestRespondWithEffects(t *testing.T) {
	st := memory.New()
	defer st.Close()
	ctx := context.Background()
	tn := &store.Tenant{ID: "t", Name: "t", CanonicalHost: "idp.example.test", Domains: []string{"idp.example.test"}}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	user := testUser()
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	sess := &store.LoginSession{TenantID: "t", ID: "sid", UserID: user.UserID, TokenHash: "h", ExpiresAt: time.Now().Add(time.Hour), IdleExpiresAt: time.Now().Add(time.Hour)}
	if err := st.Sessions().Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{9}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	if err := km.Ensure(ctx, "t"); err != nil {
		t.Fatal(err)
	}
	client := &store.Client{TenantID: "t", ClientID: "sp", Callbacks: []string{"https://sp.example.test/acs"}, Addons: &store.ClientAddons{SAMLP: &store.SAMLAddon{}}}
	signKey, signCert, actionCert := keyPair(t)
	encKeyPEM, encCertPEM, _ := keyPair(t)
	relay := "action-relay"
	eff := &actions.Effects{SAML: &actionresult.SAMLEffects{Attributes: map[string][]string{"department": {"R&D"}}, Audience: "urn:action-aud",
		RelayState: &relay, Key: signKey, Cert: signCert, EncryptionCert: encCertPEM}}
	h := &Handler{Store: st, Keys: km, Wrapper: w}
	res := tenant.Resolved{Tenant: tn, Host: "idp.example.test"}
	r := httptest.NewRequest("GET", "https://idp.example.test/samlp/sp", nil).WithContext(tenant.WithResolved(ctx, res))
	rec := httptest.NewRecorder()
	h.Respond(rec, r, res, client, Binding{RequestID: "_req", ACS: "https://sp.example.test/acs", Audience: "urn:sp", RelayState: "old"}.encode(), "", sess, eff)
	page := rec.Body.String()
	fields := map[string]string{}
	for _, m := range regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`).FindAllStringSubmatch(page, -1) {
		fields[m[1]] = html.UnescapeString(m[2])
	}
	if fields["RelayState"] != "action-relay" {
		t.Fatalf("RelayState %q", fields["RelayState"])
	}
	doc, err := samlcore.DecodePOST(fields["SAMLResponse"])
	if err != nil {
		t.Fatal(err)
	}
	encKey, _ := parseRSAKey(encKeyPEM)
	v, err := samlcore.VerifyResponse(doc, samlcore.Trust{Certs: []*x509.Certificate{actionCert}}, func(el *etree.Element) (*etree.Element, error) {
		return samlcore.DecryptAssertion(el, encKey, samlcore.Decryption{})
	})
	if err != nil {
		t.Fatalf("response does not verify with the Action's certificate or decrypt: %v", err)
	}
	a, _ := samlcore.ParseAssertion(v.Assertion)
	if a.Attributes["department"][0] != "R&D" || a.Audiences[0] != "urn:action-aud" {
		t.Fatalf("assertion %+v", a)
	}
	// A key without its certificate fails the response; nothing is signed with it.
	eff.SAML.Cert = ""
	rec = httptest.NewRecorder()
	h.Respond(rec, r, res, client, Binding{RequestID: "_req", ACS: "https://sp.example.test/acs", Audience: "urn:sp"}.encode(), "", sess, eff)
	m := regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("no error response")
	}
	errDoc, _ := samlcore.DecodePOST(html.UnescapeString(m[1]))
	if env, _ := samlcore.ParseResponseEnvelope(errDoc.Root()); env.StatusCode != samlcore.StatusResponder || errDoc.FindElement("//Assertion") != nil {
		t.Fatalf("expected a Responder error without an assertion: %+v", env)
	}
}
