package authz

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSAMLACSAllowed(t *testing.T) {
	c := &store.Client{Callbacks: []string{"https://sp.example.test/acs", "https://*.example.test/cb"},
		Addons: &store.ClientAddons{SAMLP: &store.SAMLAddon{Recipient: "https://sp.example.test/recipient"}}}
	for acs, want := range map[string]bool{
		"https://sp.example.test/acs": true, "https://sp.example.test/recipient": true,
		"https://sp.example.test/acs/": false, "https://sp.example.test/acs?x=1": false, "https://a.example.test/cb": false,
		"": false, "https://evil.example.test/acs": false,
	} {
		if got := SAMLACSAllowed(c, acs); got != want {
			t.Errorf("%q: %v, want %v", acs, got, want)
		}
	}
	c.Addons = nil
	if SAMLACSAllowed(c, "https://sp.example.test/acs") {
		t.Error("allowed without the add-on")
	}
}

// Actions see protocol "samlp" for SAML IdP transactions (Plan 37a).
func TestActionProtocol(t *testing.T) {
	if got := actionProtocol(flowReq{Request: Request{SAML: `{"acs":"x","aud":"y"}`}}); got != "samlp" {
		t.Fatalf("SAML transaction protocol %q", got)
	}
	if got := actionProtocol(flowReq{}); got != "oidc-basic-profile" {
		t.Fatalf("OIDC transaction protocol %q", got)
	}
}
