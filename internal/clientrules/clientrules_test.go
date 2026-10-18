package clientrules

import (
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// FromClient and Apply are inverses, so an update that changes nothing
// leaves a client as it was.
func TestFromClientApplyRoundTrip(t *testing.T) {
	skip := true
	for _, c := range []*store.Client{
		{Name: "spa", AppType: store.AppTypeSPA, TokenEndpointAuthMethod: store.AuthMethodNone,
			GrantTypes: []string{GrantAuthorizationCode}, Callbacks: []string{"https://a.test/cb"},
			RefreshToken: store.RefreshTokenPolicy{Rotating: true, Expiring: true, Leeway: 3, TokenLifetime: 100, IdleTokenLifetime: 50},
			IsFirstParty: true, RedirectionPolicy: store.RedirectionPolicyAllowAlways},
		{Name: "tp", AppType: store.AppTypeRegularWeb, TokenEndpointAuthMethod: store.AuthMethodClientSecretBasic,
			IsFirstParty: false, ThirdPartySecurityMode: store.SecurityModePermissive, IDTokenLifetime: 600,
			RedirectionPolicy: store.RedirectionPolicyOpenRedirectProtection, SkipNonVerifiableCallbackURIConfirmationPrompt: &skip,
			RequirePushedAuthorizationRequests: true},
	} {
		s := FromClient(c)
		got := &store.Client{}
		Apply(got, &s)
		if !reflect.DeepEqual(got, c) {
			t.Errorf("%s: round trip\n got %+v\nwant %+v", c.Name, got, c)
		}
	}
}

func TestNormalizeDefaultsAndRefusals(t *testing.T) {
	s := Spec{AppType: "native"}
	if errs := Normalize(&s, false); len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.TokenEndpointAuthMethod != store.AuthMethodNone || !*s.IsFirstParty || s.RedirectionPolicy != store.RedirectionPolicyAllowAlways ||
		s.RefreshToken.RotationType != NonRotating || s.RefreshToken.ExpirationType != NonExpiring {
		t.Fatalf("native defaults = %+v", s)
	}
	for name, tc := range map[string]struct {
		s    Spec
		want string
	}{
		"app type":      {Spec{AppType: "robot"}, "app_type"},
		"grant":         {Spec{AppType: "native", GrantTypes: []string{"magic"}}, "not supported"},
		"origin path":   {Spec{AppType: "spa", WebOrigins: []string{"https://a.test/x"}}, "web_origins"},
		"PAR off":       {Spec{AppType: "regular_web", RequirePushedAuthorizationRequests: true}, "pushed_authorization_requests_supported"},
		"device on spa": {Spec{AppType: "spa", GrantTypes: []string{GrantDeviceCode}}, "native"},
	} {
		errs := Normalize(&tc.s, false)
		if len(errs) == 0 || !strings.Contains(errs[0].Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, errs, tc.want)
		}
	}
	if got := DefaultGrantTypes(store.AuthMethodNone); len(got) != 2 {
		t.Errorf("public defaults = %v", got)
	}
}
