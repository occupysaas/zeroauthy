package claims

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"reflect"
	"testing"
	"time"
)

func TestScopeClaims(t *testing.T) {
	u := &store.User{UserID: "oidc|local", Name: "Root", PhoneNumber: "+15555550100", PhoneVerified: false, UpdatedAt: time.Unix(1700000000, 0)}
	profile := map[string]any{"name": "Untrusted override", "middle_name": "Middle", "preferred_username": "login", "profile": "https://profile.example/", "website": "https://website.example/", "gender": "unspecified", "birthdate": "2000-01-01", "zoneinfo": "UTC", "locale": "en", "address": map[string]any{"locality": "Town", "country": "GB"}, "app_metadata": map[string]any{"role": "admin"}, "phone_number_verified": true}
	got := Select(u, profile, []string{"openid", "profile", "phone", "address"}, nil, "id_token")
	for k, v := range map[string]any{"sub": "oidc|local", "name": "Root", "middle_name": "Middle", "preferred_username": "login", "profile": "https://profile.example/", "website": "https://website.example/", "gender": "unspecified", "birthdate": "2000-01-01", "zoneinfo": "UTC", "locale": "en", "phone_number": "+15555550100", "phone_number_verified": false, "address": map[string]any{"locality": "Town", "country": "GB"}} {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("%s=%v, want %v", k, got[k], v)
		}
	}
	if _, ok := got["app_metadata"]; ok {
		t.Fatal("metadata leaked")
	}
	missing := Select(&store.User{UserID: "u"}, nil, []string{"profile", "phone", "address"}, nil, "userinfo")
	if !reflect.DeepEqual(missing, map[string]any{"sub": "u"}) {
		t.Fatalf("absent attributes: %v", missing)
	}
	// Mutating a response must not change identity storage.
	got["address"].(map[string]any)["country"] = "changed"
	if profile["address"].(map[string]any)["country"] != "GB" {
		t.Fatal("address aliases storage")
	}
}

func TestClaimsNoConsentWidening(t *testing.T) {
	u := &store.User{UserID: "u", Email: "private@example.test", PhoneNumber: "+15555550100", UserMetadata: map[string]any{"private": "value"}}
	req, err := ParseRequest(`{"id_token":{"email":{"essential":true},"phone_number":null,"app_metadata":null,"user_metadata":null},"userinfo":{"email":null}}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"id_token", "userinfo"} {
		if got := Select(u, nil, []string{"openid"}, req, target); !reflect.DeepEqual(got, map[string]any{"sub": "u"}) {
			t.Fatalf("%s widened consent: %v", target, got)
		}
		if got := Select(u, nil, []string{"openid", "email"}, req, target); got["email"] != "private@example.test" || got["phone_number"] != nil || got["user_metadata"] != nil {
			t.Fatalf("%s selection: %v", target, got)
		}
	}
}

func TestPrimaryIdentityProfile(t *testing.T) {
	u := &store.User{UserID: "oidc|primary", Identities: []store.Identity{{Provider: "oidc", UserID: "primary", ProviderData: map[string]any{"locale": "en"}}, {Provider: "oidc", UserID: "linked", ProfileData: map[string]any{"email": "linked@example.test"}, ProviderData: map[string]any{"locale": "private"}}}}
	if got := ForUser(u, []string{"profile"}); got["locale"] != "en" {
		t.Fatalf("primary profile: %v", got)
	}
	u.Identities = u.Identities[1:]
	if got := ForUser(u, []string{"profile"}); got["locale"] != nil {
		t.Fatal("linked identity leaked")
	}
}

func TestDatabasePrimaryStandardProfile(t *testing.T) {
	u := &store.User{UserID: "auth0|primary", Identities: []store.Identity{{Provider: "auth0", UserID: "primary", ProviderData: map[string]any{"locale": "en", "address": map[string]any{"country": "US"}, "private": "secret"}}, {Provider: "oidc", UserID: "secondary", ProfileData: map[string]any{"email": "linked@example.test"}, ProviderData: map[string]any{"locale": "linked"}}}}
	got := ForUser(u, []string{"openid", "profile", "address"})
	if got["locale"] != "en" || got["address"] == nil || got["private"] != nil {
		t.Fatal("primary standard profile was not selected safely", got)
	}
}
