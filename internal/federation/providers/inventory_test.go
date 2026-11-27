package providers

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type inventoryRow struct {
	AuthorizationURL string            `json:"authorization_url"`
	TokenURL         string            `json:"token_url"`
	ProfileURL       string            `json:"profile_url"`
	TokenAuth        string            `json:"token_auth"`
	PKCE             string            `json:"pkce"`
	BaseScopes       []string          `json:"base_scopes"`
	ScopeFlags       map[string]string `json:"scope_flags"`
	FreeformScopes   bool              `json:"freeform_scopes"`
	UserID           string            `json:"user_id"`
	EmailVerified    string            `json:"email_verified"`
	DefaultFlags     []string          `json:"default_flags"`
}

func inventory(t *testing.T) map[string]inventoryRow {
	t.Helper()
	b, err := os.ReadFile("../inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Social struct {
			Strategies map[string]inventoryRow `json:"strategies"`
		} `json:"social_descriptors"`
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	return inv.Social.Strategies
}

// TestDescriptorsMatchInventory keeps each descriptor equal to the frozen
// contract (Task 1): endpoints, client authentication, PKCE, scopes, user ID
// and email rule. Inventory URLs that describe computed endpoints (a
// placeholder or prose) are checked by the hook tests instead.
func TestDescriptorsMatchInventory(t *testing.T) {
	inv := inventory(t)
	for _, d := range All() {
		row, ok := inv[d.Strategy]
		if !ok {
			t.Fatalf("%s: not in the inventory", d.Strategy)
		}
		literal := func(s string) bool { return strings.HasPrefix(s, "https://") && !strings.Contains(s, "<") && !strings.Contains(s, " ") }
		for name, pair := range map[string][2]string{
			"authorization_url": {row.AuthorizationURL, d.AuthorizationURL},
			"token_url":         {row.TokenURL, d.TokenURL},
			"profile_url":       {strings.TrimPrefix(row.ProfileURL, "POST "), d.ProfileURL},
		} {
			if literal(pair[0]) && pair[0] != pair[1] {
				t.Errorf("%s %s: descriptor %q, inventory %q", d.Strategy, name, pair[1], pair[0])
			}
		}
		if row.TokenAuth != d.TokenAuth || row.PKCE != d.PKCE || row.FreeformScopes != d.FreeformScopes {
			t.Errorf("%s: token_auth/pkce/freeform %s %s %v, inventory %s %s %v", d.Strategy, d.TokenAuth, d.PKCE, d.FreeformScopes, row.TokenAuth, row.PKCE, row.FreeformScopes)
		}
		if !slices.Equal(row.BaseScopes, d.BaseScopes) {
			t.Errorf("%s: base scopes %v, inventory %v", d.Strategy, d.BaseScopes, row.BaseScopes)
		}
		flags := map[string]string{}
		var defaults []string
		for _, f := range d.Flags {
			flags[f.Option] = strings.Join(f.Scopes, " ")
			if f.Default {
				defaults = append(defaults, f.Option)
			}
		}
		if !reflect.DeepEqual(flags, row.ScopeFlags) && !(len(flags) == 0 && len(row.ScopeFlags) == 0) {
			t.Errorf("%s: flags %v, inventory %v", d.Strategy, flags, row.ScopeFlags)
		}
		slices.Sort(defaults)
		slices.Sort(row.DefaultFlags)
		if !slices.Equal(defaults, row.DefaultFlags) {
			t.Errorf("%s: default flags %v, inventory %v", d.Strategy, defaults, row.DefaultFlags)
		}
		if row.UserID != d.Profile.UserID {
			t.Errorf("%s: user id %q, inventory %q", d.Strategy, d.Profile.UserID, row.UserID)
		}
		want := row.EmailVerified
		got := d.EmailVerified.Rule
		if d.EmailVerified.Rule == EmailField {
			got = "field:" + d.EmailVerified.Path
		}
		if got != want {
			t.Errorf("%s: email_verified %q, inventory %q", d.Strategy, got, want)
		}
	}
}
