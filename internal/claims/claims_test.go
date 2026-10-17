package claims

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestForUser(t *testing.T) {
	u := &store.User{
		UserID: "auth0|1", Email: "alice@example.com", EmailVerified: true,
		Name: "Alice", Nickname: "ally", Picture: "https://img.test/a.png",
		UpdatedAt: time.Unix(1700000000, 0),
	}
	cases := []struct {
		scopes []string
		want   map[string]any
	}{
		{[]string{"openid"}, map[string]any{"sub": "auth0|1"}},
		{[]string{"openid", "email"}, map[string]any{"sub": "auth0|1", "email": "alice@example.com", "email_verified": true}},
		{[]string{"openid", "profile"}, map[string]any{
			"sub": "auth0|1", "name": "Alice", "nickname": "ally", "picture": "https://img.test/a.png", "updated_at": int64(1700000000),
		}},
	}
	for _, tc := range cases {
		if diff := cmp.Diff(tc.want, ForUser(u, tc.scopes)); diff != "" {
			t.Errorf("scopes %v (-want +got):\n%s", tc.scopes, diff)
		}
	}
}

func TestForUserFallbacks(t *testing.T) {
	got := ForUser(&store.User{UserID: "auth0|2", Email: "bob@example.com"}, []string{"profile"})
	if got["name"] != "bob@example.com" || got["nickname"] != "bob" {
		t.Fatalf("fallbacks = %v", got)
	}
	if _, ok := got["picture"]; ok {
		t.Fatal("empty picture must be omitted")
	}
}

// OIDF oidcc-scope-profile: stored given_name and family_name are profile
// scope claims (OpenID Connect Core §5.4; Auth0 lists both under profile).
func TestForUserProfileNames(t *testing.T) {
	u := &store.User{UserID: "auth0|3", Email: "c@example.com", GivenName: "Carol", FamilyName: "Jones"}
	got := ForUser(u, []string{"openid", "profile"})
	if got["given_name"] != "Carol" || got["family_name"] != "Jones" {
		t.Fatalf("profile claims = %v, want given_name and family_name", got)
	}
	if got := ForUser(u, []string{"openid"}); got["given_name"] != nil || got["family_name"] != nil {
		t.Fatalf("openid-only claims = %v, want no names", got)
	}
	if got := ForUser(&store.User{UserID: "auth0|4"}, []string{"profile"}); got["given_name"] != nil || got["family_name"] != nil {
		t.Fatalf("empty names must be omitted: %v", got)
	}
}
