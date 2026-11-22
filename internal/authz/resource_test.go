package authz

import (
	"testing"
)

func TestResourceProfileCompatibility(t *testing.T) {
	f := newFixture(t)
	f.tenant.SettingsExtra = map[string]any{"resource_parameter_profile": "compatibility"}
	for _, tc := range []struct {
		resources       []string
		aud, want, code string
	}{
		{[]string{"https://api.acme.test"}, "", "https://api.acme.test", ""},
		{[]string{"https://api.acme.test"}, "https://api.acme.test", "https://api.acme.test", ""},
		{[]string{"https://api.acme.test"}, "different", "", "invalid_request"},
		{[]string{"https://api.acme.test", "https://api.acme.test"}, "", "", "invalid_target"},
	} {
		q := goodQuery()
		q["resource"] = tc.resources
		if tc.aud != "" {
			q.Set("audience", tc.aud)
		}
		req := ParseRequest(q)
		_, err, _ := ValidateRequest(t.Context(), f.st, f.tenant, &req)
		if tc.code != "" {
			if err == nil || err.Code != tc.code {
				t.Fatalf("resources=%v err=%v want=%s", tc.resources, err, tc.code)
			}
		} else if err != nil || req.Audience != tc.want {
			t.Fatalf("resources=%v audience=%s err=%v", tc.resources, req.Audience, err)
		}
	}
}
func TestResourceProfileAudience(t *testing.T) {
	f := newFixture(t)
	q := goodQuery()
	q["resource"] = []string{"ignored-one", "ignored-two"}
	req := ParseRequest(q)
	_, err, _ := ValidateRequest(t.Context(), f.st, f.tenant, &req)
	if err != nil || req.Audience != "" {
		t.Fatalf("default resource profile: %s %v", req.Audience, err)
	}
}
func TestRedirectURIOptionalSwitch(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		callbacks       []string
		optional, valid bool
	}{
		{[]string{"https://app.acme.test/callback"}, false, false},
		{[]string{"https://app.acme.test/callback"}, true, true},
		{[]string{"https://app.acme.test/callback", "https://other.example/cb"}, true, false},
		{[]string{"https://*.example.test/cb"}, true, false},
	} {
		c, err := f.st.Clients().Get(t.Context(), f.tenant.ID, "spa")
		if err != nil {
			t.Fatal(err)
		}
		c.Callbacks = tc.callbacks
		if err := f.st.Clients().Update(t.Context(), c); err != nil {
			t.Fatal(err)
		}
		req := ParseRequest(with(goodQuery(), "redirect_uri", ""))
		req.OptionalRedirectURI = tc.optional
		_, failure, redirectable := ValidateRequest(t.Context(), f.st, f.tenant, &req)
		if (failure == nil) != tc.valid {
			t.Fatalf("callbacks=%v optional=%v failure=%v", tc.callbacks, tc.optional, failure)
		}
		if failure != nil && redirectable {
			t.Fatal("unsafe redirect for missing callback")
		}
		if tc.valid && req.RedirectURI != tc.callbacks[0] {
			t.Fatal("sole callback not selected")
		}
	}
}
