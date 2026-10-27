package connrules

import "testing"

// The browser/SDK wire field must survive the connrules database-option gate
// before the strategy-specific Microsoft validation can apply.
func TestMicrosoftPersonalStrategyVersionThroughConnectionRules(t *testing.T) {
	base := `{"name":"personal","strategy":"windowslive","options":{"client_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","client_secret":"fixture-secret","strategy_version":2}}`
	s := decode(t, base)
	CreateDefaults(s)
	if errs := NormalizeAPI(s); len(errs) != 0 {
		t.Fatalf("valid personal v2 wire options rejected: %v", errs)
	}
	for _, strategy := range []string{"waad", "google-oauth2", "oauth2", "oidc"} {
		s := decode(t, base)
		s.Strategy = strategy
		CreateDefaults(s)
		if errs := NormalizeAPI(s); len(errs) == 0 {
			t.Fatalf("%s accepted personal-only strategy_version", strategy)
		}
	}
	for _, key := range []string{"mfa", "precedence", "non_persistent_attrs"} {
		s := decode(t, base)
		s.Options.Extra[key] = true
		if errs := NormalizeAPI(s); len(errs) == 0 {
			t.Fatalf("personal accepted database option %s", key)
		}
	}
}
