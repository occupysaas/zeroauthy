package samlcore

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestParseWSFedMetadata(t *testing.T) {
	a := newIdentity(t, "sts-a", time.Now().Add(24*time.Hour))
	b := newIdentity(t, "sts-b", time.Now().Add(24*time.Hour))
	raw := []byte(serialize(t, BuildWSFedMetadata("http://adfs.example.test/adfs/services/trust", "https://adfs.example.test/adfs/ls/", a.cert2())))
	md, err := ParseWSFedMetadata(raw)
	if err != nil {
		t.Fatal(err)
	}
	if md.EntityID != "http://adfs.example.test/adfs/services/trust" || md.PassiveEndpoint != "https://adfs.example.test/adfs/ls/" ||
		len(md.SigningCerts) != 1 || !md.SigningCerts[0].Equal(a.cert) {
		t.Fatalf("metadata %+v", md)
	}
	// ADFS: a signed document with a SAML IdP role too; the STS role's
	// signing keys come first, encryption keys are ignored.
	enc := base64.StdEncoding.EncodeToString(b.cert.Raw)
	sig := base64.StdEncoding.EncodeToString(a.cert.Raw)
	adfs := `<EntityDescriptor ID="_x" entityID="http://adfs.example.test/adfs/services/trust" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
		`<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706">` +
		`<KeyDescriptor use="encryption"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + enc + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + sig + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<fed:PassiveRequestorEndpoint><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>https://adfs.example.test/adfs/ls/</Address></EndpointReference></fed:PassiveRequestorEndpoint>` +
		`</RoleDescriptor>` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://adfs.example.test/adfs/ls/"/></IDPSSODescriptor>` +
		`</EntityDescriptor>`
	md, err = ParseWSFedMetadata([]byte(adfs))
	if err != nil || len(md.SigningCerts) != 1 || !md.SigningCerts[0].Equal(a.cert) || md.PassiveEndpoint != "https://adfs.example.test/adfs/ls/" {
		t.Fatalf("ADFS metadata %+v %v", md, err)
	}
	for name, bad := range map[string]string{
		"no STS role":  `<EntityDescriptor entityID="x" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor/></EntityDescriptor>`,
		"not metadata": `<a/>`,
		"no endpoint":  `<EntityDescriptor entityID="x" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><RoleDescriptor xsi:type="fed:SecurityTokenServiceType" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + sig + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor></RoleDescriptor></EntityDescriptor>`,
	} {
		if _, err := ParseWSFedMetadata([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
