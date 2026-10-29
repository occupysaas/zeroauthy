package clientrules

import (
	"errors"
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
		{Name: "org", AppType: store.AppTypeRegularWeb, TokenEndpointAuthMethod: store.AuthMethodClientSecretPost, IsFirstParty: true,
			OrganizationUsage: store.OrgUsageRequire, OrganizationRequireBehavior: store.OrgBehaviorPreLoginPrompt,
			OrganizationDiscoveryMethods: []string{store.OrgDiscoveryEmail}},
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

// TestClientOrganizationFieldsValidation pins the observed client
// organization rules (D-0055): bad values are schema errors, the
// combination rules are ErrOrganizationRule.
func TestClientOrganizationFieldsValidation(t *testing.T) {
	usages := []string{"", store.OrgUsageDeny, store.OrgUsageAllow, store.OrgUsageRequire}
	behaviors := []string{"", store.OrgBehaviorNoPrompt, store.OrgBehaviorPreLoginPrompt, store.OrgBehaviorPostLoginPrompt}
	for _, u := range usages {
		for _, b := range behaviors {
			// pre_login_prompt is accepted with every usage (observed).
			if err := ValidateOrganizationFields(u, b, nil); err != nil {
				t.Errorf("%q/%q: %v", u, b, err)
			}
		}
		for _, m := range [][]string{{store.OrgDiscoveryEmail}, {store.OrgDiscoveryName}, {store.OrgDiscoveryEmail, store.OrgDiscoveryName}} {
			if err := ValidateOrganizationFields(u, store.OrgBehaviorPreLoginPrompt, m); err != nil {
				t.Errorf("%q with %v: %v", u, m, err)
			}
		}
	}
	for name, c := range map[string]struct {
		usage, behavior string
		methods         []string
		rule            bool
	}{
		"bad usage":                  {usage: "sometimes"},
		"bad behavior":               {behavior: "prompt"},
		"empty methods":              {behavior: store.OrgBehaviorPreLoginPrompt, methods: []string{}},
		"bad method":                 {behavior: store.OrgBehaviorPreLoginPrompt, methods: []string{"phone"}},
		"methods without a behavior": {methods: []string{store.OrgDiscoveryEmail}, rule: true},
		"methods with no_prompt":     {behavior: store.OrgBehaviorNoPrompt, methods: []string{store.OrgDiscoveryEmail}, rule: true},
		"methods with post_login":    {usage: store.OrgUsageRequire, behavior: store.OrgBehaviorPostLoginPrompt, methods: []string{store.OrgDiscoveryName}, rule: true},
	} {
		err := ValidateOrganizationFields(c.usage, c.behavior, c.methods)
		if err == nil || errors.Is(err, ErrOrganizationRule) != c.rule {
			t.Errorf("%s: err=%v, want rule=%v", name, err, c.rule)
		}
	}

	for _, g := range []string{GrantPassword, GrantPasswordRealm, GrantDeviceCode} {
		if err := CheckOrganizationGrants(store.OrgUsageRequire, []string{GrantAuthorizationCode, g}); !errors.Is(err, ErrOrganizationRule) {
			t.Errorf("require with %s: %v", g, err)
		}
		for _, u := range []string{"", store.OrgUsageDeny, store.OrgUsageAllow} {
			if err := CheckOrganizationGrants(u, []string{g}); err != nil {
				t.Errorf("%q with %s: %v", u, g, err)
			}
		}
	}
	if err := CheckOrganizationGrants(store.OrgUsageRequire, []string{GrantAuthorizationCode, GrantClientCredentials, GrantRefreshToken, GrantImplicit}); err != nil {
		t.Errorf("require with the allowed grants: %v", err)
	}

	// Normalize applies both, whoever writes the client.
	s := Spec{AppType: "regular_web", GrantTypes: []string{GrantPassword}, OrganizationUsage: store.OrgUsageRequire}
	if errs := Normalize(&s, false); len(errs) != 1 || !errors.Is(errs[0], ErrOrganizationRule) {
		t.Errorf("normalize require+password: %v", errs)
	}
	s = Spec{AppType: "regular_web", OrganizationUsage: "bogus"}
	if errs := Normalize(&s, false); len(errs) != 1 || errors.Is(errs[0], ErrOrganizationRule) {
		t.Errorf("normalize bad usage: %v", errs)
	}
}
