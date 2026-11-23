package rules

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func adfsMetadata(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}
	return `<EntityDescriptor entityID="http://adfs.example.test/adfs/services/trust" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
		`<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706">` +
		`<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(block.Bytes) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<fed:PassiveRequestorEndpoint><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>https://adfs.example.test/adfs/ls/</Address></EndpointReference></fed:PassiveRequestorEndpoint>` +
		`</RoleDescriptor></EntityDescriptor>`
}

func TestParseADFS(t *testing.T) {
	md := adfsMetadata(t, samlCert(t))
	s, errs := Parse(Input{Strategy: ADFS, Name: "corp-adfs", RootAttributes: SyncOnFirstLogin, Options: map[string]any{
		"fedMetadataXml": md, "thumbprints": []any{"ignored"}, "signInEndpoint": "https://ignored.example.test/",
		"user_id_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "should_trust_email_verified_connection": "always_set_emails_as_verified",
		"domain_aliases": []any{"corp.example.test"}, "upstream_params": map[string]any{"x": map[string]any{"value": "y"}}, "tenant_domain": "corp.example.test",
		"icon_url": "https://corp.example.test/icon.png", "non_persistent_attrs": []any{"groups"},
	}})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	a := s.ADFS
	if a == nil || a.SignInEndpoint != "https://adfs.example.test/adfs/ls/" || len(a.Thumbprints) != 1 || len(a.Thumbprints[0]) != 40 ||
		len(a.Thumbprints384) != 1 || len(a.Thumbprints384[0]) != 96 || a.UserIDAttribute != "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" ||
		!a.TrustEmailVerified || s.ProfileSync != SyncOnFirstLogin || strings.Join(s.DomainAliases, ",") != "corp.example.test" || !IsEnterprise(ADFS) {
		t.Fatalf("settings %+v %+v", s, a)
	}
	if a.EntityID != "" {
		t.Fatal("entityId default is applied with the tenant name, not here")
	}
	// adfs_server: the Management API fetched the metadata and wrote the
	// derived endpoint and thumbprints into the options.
	s, errs = Parse(Input{Strategy: ADFS, Name: "corp-adfs", Options: map[string]any{"adfs_server": "adfs.example.test",
		"signInEndpoint": "https://adfs.example.test/adfs/ls/", "thumbprints": []any{strings.Repeat("ab", 20)}, "prev_thumbprints": []any{strings.Repeat("cd", 20)},
		"entityId": "urn:custom"}})
	if len(errs) > 0 || s.ADFS.MetadataURL != "https://adfs.example.test/FederationMetadata/2007-06/FederationMetadata.xml" ||
		s.ADFS.SignInEndpoint != "https://adfs.example.test/adfs/ls/" || len(s.ADFS.Thumbprints) != 1 || len(s.ADFS.PrevThumbprints) != 1 || s.ADFS.EntityID != "urn:custom" {
		t.Fatalf("adfs_server: %+v %v", s.ADFS, errs)
	}
	if got := ADFSMetadataURL("https://adfs.example.test/custom/md.xml"); got != "https://adfs.example.test/custom/md.xml" {
		t.Fatalf("metadata URL kept as given: %s", got)
	}
	for name, opts := range map[string]map[string]any{
		"no source":           {},
		"both sources":        {"adfs_server": "adfs.example.test", "fedMetadataXml": md},
		"bad metadata":        {"fedMetadataXml": "<a/>"},
		"http server":         {"adfs_server": "http://adfs.example.test/md.xml"},
		"bad user id attr":    {"fedMetadataXml": md, "user_id_attribute": strings.Repeat("a", 129)},
		"bad email policy":    {"fedMetadataXml": md, "should_trust_email_verified_connection": "sometimes"},
		"bad entity id":       {"fedMetadataXml": md, "entityId": ""},
		"long entity id":      {"fedMetadataXml": md, "entityId": strings.Repeat("a", 129)},
		"server without data": {"adfs_server": "adfs.example.test"},
		"bad thumbprint":      {"adfs_server": "adfs.example.test", "signInEndpoint": "https://adfs.example.test/adfs/ls/", "thumbprints": []any{"zz"}},
		"bad domain alias":    {"fedMetadataXml": md, "domain_aliases": []any{"not a domain"}},
		"long tenant domain":  {"fedMetadataXml": md, "tenant_domain": strings.Repeat("a", 256)},
	} {
		if _, errs := Parse(Input{Strategy: ADFS, Name: "corp-adfs", Options: opts}); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	if _, errs := Parse(Input{Strategy: ADFS, Name: "a|b", Options: map[string]any{"fedMetadataXml": md}}); len(errs) == 0 {
		t.Error("name with | accepted")
	}
}
