package clientrules_test

import (
	"encoding/json"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestClientMobilePublicSchema(t *testing.T) {
	for _, raw := range []string{`{}`, `{"ios":{}}`, `{"android":{}}`, `{"ios":{"team_id":"", "app_bundle_identifier":"anything", "unknown":42}}`, `{"android":{"app_package_name":"", "sha256_cert_fingerprints":["AB"]},"future":null}`} {
		if _, err := clientrules.ParseMobile(json.RawMessage(raw)); err != nil {
			t.Errorf("valid mobile %s: %v", raw, err)
		}
	}
	for _, raw := range []string{`null`, `[]`, `{"ios":null}`, `{"ios":3}`, `{"ios":{"team_id":null}}`, `{"ios":{"app_bundle_identifier":true}}`, `{"android":[]}`, `{"android":{"app_package_name":3}}`, `{"android":{"sha256_cert_fingerprints":null}}`, `{"android":{"sha256_cert_fingerprints":[]}}`, `{"android":{"sha256_cert_fingerprints":[""]}}`, `{"android":{"sha256_cert_fingerprints":[null]}}`, `{"android":{"sha256_cert_fingerprints":[42]}}`} {
		if _, err := clientrules.ParseMobile(json.RawMessage(raw)); err == nil {
			t.Errorf("invalid mobile accepted: %s", raw)
		}
	}
}
func TestClientMobileGrantAndClones(t *testing.T) {
	mobile, err := clientrules.ParseMobile(json.RawMessage(`{"ios":{"team_id":"T","app_bundle_identifier":"app"},"android":{"sha256_cert_fingerprints":["AB"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Client{}
	spec := clientrules.Spec{AppType: "native", Mobile: mobile, GrantTypes: []string{clientrules.GrantPasskey}}
	if errs := clientrules.Normalize(&spec, false); len(errs) > 0 {
		t.Fatal(errs)
	}
	clientrules.Apply(c, &spec)
	mobile.IOS.TeamID = "changed"
	mobile.Android.SHA256CertFingerprints[0] = "changed"
	if c.Mobile.IOS.TeamID != "T" || c.Mobile.Android.SHA256CertFingerprints[0] != "AB" {
		t.Fatal("Apply retained mutable mobile input")
	}
	from := clientrules.FromClient(c)
	from.Mobile.Android.SHA256CertFingerprints[0] = "changed"
	if c.Mobile.Android.SHA256CertFingerprints[0] != "AB" {
		t.Fatal("FromClient exposed mutable storage")
	}
}
