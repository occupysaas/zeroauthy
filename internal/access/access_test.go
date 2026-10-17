package access

import (
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func firstParty() *store.Client { return &store.Client{ClientID: "fp", IsFirstParty: true} }
func strict() *store.Client {
	return &store.Client{ClientID: "tp", ThirdPartySecurityMode: store.SecurityModeStrict, RedirectionPolicy: store.RedirectionPolicyOpenRedirectProtection}
}
func permissive() *store.Client {
	return &store.Client{ClientID: "pp", ThirdPartySecurityMode: store.SecurityModePermissive}
}
func api(mod ...func(*store.ResourceServer)) *store.ResourceServer {
	rs := &store.ResourceServer{Identifier: "https://api", SkipConsentForVerifiableFirstPartyClients: true,
		Scopes: []store.Scope{{Value: "read"}, {Value: "write"}}}
	for _, m := range mod {
		m(rs)
	}
	return rs
}
func userPolicy(p string) func(*store.ResourceServer) {
	return func(rs *store.ResourceServer) { rs.SubjectTypeAuthorization.User = p }
}
func noSkip(rs *store.ResourceServer) { rs.SkipConsentForVerifiableFirstPartyClients = false }
func grant(scopes ...string) *store.ClientGrant {
	return &store.ClientGrant{Audience: "https://api", SubjectType: store.SubjectTypeUser, Scopes: scopes}
}
func ugrant(scopes ...string) *store.UserGrant {
	return &store.UserGrant{Audience: "https://api", Scopes: scopes}
}

const web = "https://app.example/cb"

func TestDecide(t *testing.T) {
	yes := true
	tests := []struct {
		name string
		in   Input
		want Decision
	}{
		{"first-party skips consent", Input{Flow: Interactive, Client: firstParty(), API: api(), Scopes: []string{"openid", "read", "nope"}, RedirectURI: web},
			Decision{Scopes: []string{"openid", "read"}}},
		{"first-party consent when API does not skip", Input{Flow: Interactive, Client: firstParty(), API: api(noSkip), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Scopes: []string{"read"}, Consent: true}},
		{"first-party consent covered by grant", Input{Flow: Interactive, Client: firstParty(), API: api(noSkip), UserGrant: ugrant("read", "write"), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Scopes: []string{"read"}}},
		{"prompt=consent forces consent", Input{Flow: Interactive, Client: firstParty(), API: api(noSkip), UserGrant: ugrant("read"), Scopes: []string{"read"}, Prompts: []string{"consent"}, RedirectURI: web},
			Decision{Scopes: []string{"read"}, Consent: true}},
		{"first-party no audience: no consent", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid", "profile"}, RedirectURI: web},
			Decision{Scopes: []string{"openid", "profile"}}},
		{"first-party localhost: confirmation", Input{Flow: Interactive, Client: firstParty(), API: api(), Scopes: []string{"read"}, RedirectURI: "http://localhost:3000/cb"},
			Decision{Scopes: []string{"read"}, Confirmation: !firstPartyNonVerifiableConsent, Consent: firstPartyNonVerifiableConsent}},
		{"custom scheme: confirmation", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid"}, RedirectURI: "com.example.app:/cb"},
			Decision{Scopes: []string{"openid"}, Confirmation: true}},
		{"tenant skips confirmation", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid"}, RedirectURI: "http://127.0.0.1:9/cb", TenantSkipConfirmation: true},
			Decision{Scopes: []string{"openid"}}},
		{"client setting beats tenant", Input{Flow: Interactive, Client: &store.Client{IsFirstParty: true, SkipNonVerifiableCallbackURIConfirmationPrompt: &yes}, Scopes: []string{"openid"}, RedirectURI: "http://[::1]:9/cb"},
			Decision{Scopes: []string{"openid"}}},
		{"prompt=none needs confirmation", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid"}, Prompts: []string{"none"}, RedirectURI: "http://localhost/cb"},
			Decision{Err: &Error{Code: codeConfirmationRequired}}},
		{"strict needs a grant under allow_all", Input{Flow: Interactive, Client: strict(), API: api(), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeAuthorizeDenied}}},
		{"strict: grant caps scopes, OIDC dropped, consent", Input{Flow: Interactive, Client: strict(), API: api(), ClientGrant: grant("read"), Scopes: []string{"openid", "profile", "read", "write", "offline_access"}, RedirectURI: web},
			Decision{Scopes: []string{"read", "offline_access"}, Consent: true}},
		{"strict: consent covered", Input{Flow: Interactive, Client: strict(), API: api(), ClientGrant: grant("read"), UserGrant: ugrant("read", "offline_access"), Scopes: []string{"read", "offline_access"}, RedirectURI: web},
			Decision{Scopes: []string{"read", "offline_access"}}},
		{"strict: consent shown, so no confirmation", Input{Flow: Interactive, Client: strict(), API: api(), ClientGrant: grant("read"), Scopes: []string{"read"}, RedirectURI: "http://localhost/cb"},
			Decision{Scopes: []string{"read"}, Consent: true}},
		{"strict: prompt=none needs consent", Input{Flow: Interactive, Client: strict(), API: api(), ClientGrant: grant("read"), Scopes: []string{"read"}, Prompts: []string{"none"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeConsentRequired}}},
		{"strict: no audience", Input{Flow: Interactive, Client: strict(), Scopes: []string{"openid"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeStrictNoAudience}}},
		{"localhost right after login: no confirmation", Input{Flow: Interactive, Client: firstParty(), Scopes: []string{"openid"}, RedirectURI: "http://localhost/cb", ScreenShown: true},
			Decision{Scopes: []string{"openid"}}},
		{"API without skip: consent even right after login", Input{Flow: Interactive, Client: firstParty(), API: api(noSkip), Scopes: []string{"read"}, RedirectURI: "http://localhost/cb", ScreenShown: true},
			Decision{Scopes: []string{"read"}, Consent: true}},
		{"permissive follows allow_all", Input{Flow: Interactive, Client: permissive(), API: api(), Scopes: []string{"openid", "read"}, RedirectURI: web},
			permissiveAllowAll()},
		{"permissive no audience asks consent", Input{Flow: Interactive, Client: permissive(), Scopes: []string{"openid", "profile"}, RedirectURI: web},
			Decision{Scopes: []string{"openid", "profile"}, Consent: consentWithoutAudience}},
		{"deny_all at authorize", Input{Flow: Interactive, Client: firstParty(), API: api(userPolicy(store.PolicyDenyAll)), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeAuthorizeDenied}}},
		{"require_client_grant without grant", Input{Flow: Interactive, Client: firstParty(), API: api(userPolicy(store.PolicyRequireClientGrant)), Scopes: []string{"read"}, RedirectURI: web},
			Decision{Err: &Error{Code: codeAuthorizeDenied}}},
		{"require_client_grant caps scopes", Input{Flow: Interactive, Client: firstParty(), API: api(userPolicy(store.PolicyRequireClientGrant)), ClientGrant: grant("write"), Scopes: []string{"read", "write"}, RedirectURI: web},
			Decision{Scopes: []string{"write"}}},
		{"password: third-party refused", Input{Flow: Password, Client: permissive(), API: api(), Scopes: []string{"read"}},
			Decision{Err: &Error{Code: "unauthorized_client"}}},
		{"password: deny_all", Input{Flow: Password, Client: firstParty(), API: api(userPolicy(store.PolicyDenyAll)), Scopes: []string{"read"}},
			Decision{Err: &Error{Code: codeTokenDenied}}},
		{"password: no consent or confirmation", Input{Flow: Password, Client: firstParty(), API: api(noSkip), Scopes: []string{"read"}, RedirectURI: "http://localhost/cb"},
			Decision{Scopes: []string{"read"}}},
		{"refresh: grant withdrawn", Input{Flow: Refresh, Client: strict(), API: api(), Scopes: []string{"read"}},
			Decision{Err: &Error{Code: codeTokenDenied}}},
		{"refresh: grant narrowed", Input{Flow: Refresh, Client: strict(), API: api(), ClientGrant: grant("read"), Scopes: []string{"read", "write"}},
			Decision{Scopes: []string{"read"}}},
		{"client credentials: deny_all", Input{Flow: ClientCredentials, Client: firstParty(), API: api(func(rs *store.ResourceServer) { rs.SubjectTypeAuthorization.Client = store.PolicyDenyAll }), ClientGrant: &store.ClientGrant{SubjectType: store.SubjectTypeClient}},
			Decision{Err: &Error{Code: "access_denied"}}},
		{"client credentials: no grant", Input{Flow: ClientCredentials, Client: firstParty(), API: api()},
			Decision{Err: &Error{Code: "access_denied", Description: "client is not authorized for this audience"}}},
		{"client credentials: stored allow_all still needs a grant", Input{Flow: ClientCredentials, Client: firstParty(), API: api(func(rs *store.ResourceServer) { rs.SubjectTypeAuthorization.Client = store.PolicyAllowAll })},
			Decision{Err: &Error{Code: "access_denied", Description: "client is not authorized for this audience"}}},
		{"client credentials: allowed", Input{Flow: ClientCredentials, Client: strict(), API: api(), ClientGrant: &store.ClientGrant{SubjectType: store.SubjectTypeClient}},
			Decision{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(tt.in)
			if tt.want.Err != nil {
				if got.Err == nil || got.Err.Code != tt.want.Err.Code {
					t.Fatalf("Err = %+v, want code %q", got.Err, tt.want.Err.Code)
				}
				if tt.want.Err.Description != "" && got.Err.Description != tt.want.Err.Description {
					t.Fatalf("Description = %q, want %q", got.Err.Description, tt.want.Err.Description)
				}
				return
			}
			if got.Err != nil {
				t.Fatalf("unexpected error %+v", got.Err)
			}
			if !slices.Equal(got.Scopes, tt.want.Scopes) || got.Consent != tt.want.Consent || got.Confirmation != tt.want.Confirmation {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// permissiveAllowAll is the expected decision for a permissive client under
// allow_all with no grant (O8).
func permissiveAllowAll() Decision {
	if !permissiveFollowsPolicy {
		return Decision{Err: &Error{Code: codeAuthorizeDenied}}
	}
	return Decision{Scopes: []string{"openid", "read"}, Consent: true}
}

func TestNonVerifiable(t *testing.T) {
	for uri, want := range map[string]bool{
		"https://app.example/cb": false, "http://app.example/cb": false,
		"http://localhost:3000/": true, "https://localhost/cb": true, "http://LOCALHOST/cb": true,
		"http://127.0.0.1:8/cb": true, "http://[::1]:8/cb": true,
		"com.example.app:/oauth2redirect": true, "myapp://cb": true, "::bad": true,
	} {
		if got := NonVerifiable(uri); got != want {
			t.Errorf("NonVerifiable(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestConnectionUsable(t *testing.T) {
	conn := &store.Connection{EnabledClients: []string{"fp"}}
	domain := &store.Connection{IsDomainConnection: true}
	if !ConnectionUsable(firstParty(), conn) || ConnectionUsable(firstParty(), domain) {
		t.Error("first-party clients use enabled connections only")
	}
	if ConnectionUsable(strict(), conn) || !ConnectionUsable(strict(), domain) {
		t.Error("third-party clients use domain connections only")
	}
}

func TestShowErrorPage(t *testing.T) {
	if !ShowErrorPage(strict()) || !ShowErrorPage(permissive()) || ShowErrorPage(firstParty()) {
		t.Error("open_redirect_protection (and an unset third-party policy) shows errors as a page; first-party unset redirects")
	}
	open := strict()
	open.RedirectionPolicy = store.RedirectionPolicyAllowAlways
	if ShowErrorPage(open) {
		t.Error("allow_always redirects")
	}
	odd := strict()
	odd.RedirectionPolicy = "something_new"
	if !ShowErrorPage(odd) {
		t.Error("an unknown policy on a third-party client fails closed")
	}
	oddFP := firstParty()
	oddFP.RedirectionPolicy = "something_new"
	if ShowErrorPage(oddFP) {
		t.Error("an unknown policy on a first-party client redirects")
	}
}

func TestGrantScopes(t *testing.T) {
	got := GrantScopes([]string{"read"}, []string{"write", "read"})
	want := []string{"write", "read"}
	if mergeGrantScopes {
		want = []string{"read", "write"}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("GrantScopes = %v, want %v", got, want)
	}
}

func TestDecideDeviceFirstPartySkipAPI(t *testing.T) {
	d := Decide(Input{Flow: Device, Client: firstParty(), API: api(), Scopes: []string{"openid", "read"}})
	if d.Err != nil || d.Consent || d.Confirmation || !slices.Equal(d.Scopes, []string{"openid", "read"}) {
		t.Fatalf("got %+v", d)
	}
}

func TestDecideDeviceFirstPartyNoSkipAPI(t *testing.T) {
	d := Decide(Input{Flow: Device, Client: firstParty(), API: api(noSkip), Scopes: []string{"read"}})
	if d.Err != nil || !d.Consent || d.Confirmation {
		t.Fatalf("got %+v", d)
	}
}

func TestDecideDeviceGrantCovers(t *testing.T) {
	d := Decide(Input{Flow: Device, Client: firstParty(), API: api(noSkip), UserGrant: ugrant("read", "offline_access"), Scopes: []string{"read", "offline_access"}})
	if d.Err != nil || d.Consent || d.Confirmation {
		t.Fatalf("got %+v", d)
	}
}

func TestDecideDeviceNoAudienceFirstParty(t *testing.T) {
	d := Decide(Input{Flow: Device, Client: firstParty(), Scopes: []string{"openid", "profile"}})
	if d.Err != nil || d.Consent || d.Confirmation {
		t.Fatalf("got %+v", d)
	}
}

// The device confirmation screen replaces the confirmation, and prompt=none
// does not apply to the device flow.
func TestDecideDeviceNeverConfirmation(t *testing.T) {
	for _, in := range []Input{
		{Flow: Device, Client: firstParty(), Scopes: []string{"openid"}},
		{Flow: Device, Client: firstParty(), API: api(), Scopes: []string{"read"}},
		{Flow: Device, Client: firstParty(), API: api(noSkip), Scopes: []string{"read"}, Prompts: []string{"none"}},
	} {
		d := Decide(in)
		if d.Err != nil || d.Confirmation {
			t.Fatalf("Decide(%+v) = %+v", in, d)
		}
	}
}

func TestDecideDeviceDenyAll(t *testing.T) {
	d := Decide(Input{Flow: Device, Client: firstParty(), API: api(userPolicy(store.PolicyDenyAll)), Scopes: []string{"read"}})
	if d.Err == nil || d.Err.Code != "invalid_request" {
		t.Fatalf("got %+v", d)
	}
}
