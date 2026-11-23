package samlidp

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func wsfedTestUser() *store.User {
	return &store.User{UserID: "auth0|u1", Email: "jdoe@example.test", Name: "J Doe", GivenName: "J", FamilyName: "Doe"}
}

func attrNames(a []samlcore.Attribute) []string {
	out := []string{}
	for _, x := range a {
		out = append(out, x.Name)
	}
	return out
}

// The WS-Fed token uses the SAML IdP mapper with the add-on defaults: the
// claim types of Auth0's WS-Fed documentation, UPN created.
func TestWSFedAssertionDefaults(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	res := tenant.Resolved{Tenant: &store.Tenant{ID: "t", Name: "t"}}
	spec, _ := wsfedAssertion(res, wsfedTestUser(), wsfedBinding{Reply: "https://rp/", Audience: "urn:rp"}, nil, "", now, now)
	if spec.NameID != "auth0|u1" || spec.Audience != "urn:rp" || !spec.NotOnOrAfter.Equal(now.Add(8*time.Hour)) {
		t.Fatalf("spec %+v", spec)
	}
	names := attrNames(spec.Attributes)
	for _, want := range []string{samlcore.ClaimNameIdentifier, samlcore.ClaimEmail, samlcore.ClaimName, samlcore.ClaimGivenName, samlcore.ClaimSurname, samlcore.ClaimUPN} {
		if !slices.Contains(names, want) {
			t.Errorf("missing claim %s in %v", want, names)
		}
	}
}

// api.samlResponse settings apply to WS-Fed tokens (W2): lifetime,
// audience, issuer, UPN and attribute overrides.
func TestWSFedAssertionEffects(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	no, n := false, 600
	se := &actionresult.SAMLEffects{LifetimeInSeconds: &n, Audience: "urn:override", Issuer: "urn:idp:custom", CreateUpnClaim: &no,
		Attributes: map[string][]string{"http://schemas.example/role": {"admin"}}, RemovedAttributes: []string{samlcore.ClaimName}}
	res := tenant.Resolved{Tenant: &store.Tenant{ID: "t", Name: "t"}}
	spec, _ := wsfedAssertion(res, wsfedTestUser(), wsfedBinding{Reply: "https://rp/", Audience: "urn:rp"}, se, "", now, now)
	names := attrNames(spec.Attributes)
	if spec.Audience != "urn:override" || spec.Issuer != "urn:idp:custom" || !spec.NotOnOrAfter.Equal(now.Add(10*time.Minute)) ||
		slices.Contains(names, samlcore.ClaimUPN) || slices.Contains(names, samlcore.ClaimName) || !slices.Contains(names, "http://schemas.example/role") {
		t.Fatalf("effects not applied: %+v", spec)
	}
}

func TestWSFedBinding(t *testing.T) {
	b := wsfedBinding{Reply: "https://rp/", Context: "c", Audience: "urn:rp"}
	enc := b.encode()
	if !authz.IsWSFedBinding(enc) || !strings.HasPrefix(enc, authz.WSFedBindingPrefix) {
		t.Fatal("binding lacks the WS-Fed prefix")
	}
	got, err := decodeWSFedBinding(enc)
	if err != nil || got != b {
		t.Fatalf("round trip %+v %v", got, err)
	}
	for _, bad := range []string{`{"reply":"x","aud":"y"}`, authz.WSFedBindingPrefix + `{}`, authz.WSFedBindingPrefix + `x`} {
		if _, err := decodeWSFedBinding(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	for in, want := range map[string]string{"rp": "urn:rp", "urn:rp": "urn:rp", "https://rp/": "https://rp/", "http://rp/": "http://rp/"} {
		if got := asResource(in); got != want {
			t.Errorf("asResource(%s)=%s", in, got)
		}
	}
}
