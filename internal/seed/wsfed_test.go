package seed

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// TestSeedWSFed is Plan 37b: the seed carries the wsfed add-on,
// client_aliases, form_template and adfs connections.
func TestSeedWSFed(t *testing.T) {
	st := memory.New()
	defer st.Close()
	block, _ := pem.Decode([]byte(seedCertPEM(t)))
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}
	md := `<EntityDescriptor entityID="http://adfs.example/adfs/services/trust" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><RoleDescriptor xsi:type="fed:SecurityTokenServiceType" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` +
		base64.StdEncoding.EncodeToString(block.Bytes) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor><fed:PassiveRequestorEndpoint><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>https://adfs.example/adfs/ls/</Address></EndpointReference></fed:PassiveRequestorEndpoint></RoleDescriptor></EntityDescriptor>`
	raw := fmt.Sprintf(`tenants:
 - name: acme
   clients:
    - client_id: rp
      app_type: regular_web
      client_secret: %s
      callbacks: [https://rp.example/]
      client_aliases: [urn:rp:portal]
      form_template: "<form></form>"
      addons:
       wsfed: {}
   connections:
    - name: corp-adfs
      strategy: adfs
      enabled_clients: [rp]
      options: {fedMetadataXml: '%s'}
`, secrets.RandomString(40), md)
	f, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(t.Context(), st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tenant, _ := st.Tenants().GetByName(t.Context(), "acme")
	c, err := st.Clients().Get(t.Context(), tenant.ID, "rp")
	if err != nil || c.Addons == nil || c.Addons.WSFed == nil || strings.Join(c.ClientAliases, ",") != "urn:rp:portal" || c.FormTemplate != "<form></form>" {
		t.Fatalf("seeded client %+v %v", c, err)
	}
	conn, err := st.Connections().GetByName(t.Context(), tenant.ID, "corp-adfs")
	if err != nil || conn.Strategy != "adfs" || conn.Extra["thumbprints"] == nil || conn.Extra["signInEndpoint"] != "https://adfs.example/adfs/ls/" {
		t.Fatalf("seeded adfs connection %+v %v", conn, err)
	}
	if err := Apply(t.Context(), st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal("reapply", err)
	}
	bad, err := Parse([]byte(fmt.Sprintf(`tenants: [{name: acme, clients: [{client_id: x, app_type: regular_web, client_secret: %s, client_aliases: ["", ""]}]}]`, secrets.RandomString(40))))
	if err == nil {
		err = Apply(t.Context(), memory.New(), bad, fixedNow, testWrapper(t))
	}
	if err == nil || !strings.Contains(err.Error(), "client_aliases") {
		t.Fatalf("invalid client_aliases: %v", err)
	}
}
