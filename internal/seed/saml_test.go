package seed

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func seedCertPEM(t *testing.T) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestSeedSAML is Plan 37a: the seed carries the samlp add-on and samlp
// connections.
func TestSeedSAML(t *testing.T) {
	st := memory.New()
	defer st.Close()
	cert := strings.ReplaceAll(strings.TrimSpace(seedCertPEM(t)), "\n", "\\n")
	raw := fmt.Sprintf(`tenants:
 - name: acme
   clients:
    - client_id: sp
      app_type: regular_web
      client_secret: %s
      callbacks: [https://sp.example/acs]
      addons:
       samlp: {audience: "urn:sp", signResponse: true, mappings: {email: mail}}
   connections:
    - name: corp-saml
      strategy: samlp
      enabled_clients: [sp]
      options: {signInEndpoint: "https://idp.example/sso", signingCert: "%s", fieldsMap: {email: mail}}
`, secrets.RandomString(40), cert)
	f, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(t.Context(), st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tenant, _ := st.Tenants().GetByName(t.Context(), "acme")
	c, err := st.Clients().Get(t.Context(), tenant.ID, "sp")
	if err != nil || c.Addons == nil || c.Addons.SAMLP == nil || c.Addons.SAMLP.Audience != "urn:sp" || c.Addons.SAMLP.Mappings["email"][0] != "mail" {
		t.Fatalf("seeded add-on %+v %v", c, err)
	}
	conn, err := st.Connections().GetByName(t.Context(), tenant.ID, "corp-saml")
	if err != nil || conn.Strategy != "samlp" || conn.Extra["thumbprints"] == nil {
		t.Fatalf("seeded samlp connection %+v %v", conn, err)
	}
	if err := Apply(t.Context(), st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal("reapply", err)
	}
	bad, err := Parse([]byte(fmt.Sprintf(`tenants: [{name: acme, clients: [{client_id: x, app_type: regular_web, client_secret: %s, addons: {aws: {}}}]}]`, secrets.RandomString(40))))
	if err == nil {
		err = Apply(t.Context(), memory.New(), bad, fixedNow, testWrapper(t))
	}
	if err == nil || !strings.Contains(err.Error(), "addons") {
		t.Fatalf("unsupported add-on: %v", err)
	}
}
