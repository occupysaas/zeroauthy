package federation

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestMicrosoftIdentityLifecycle(t *testing.T) {
	e := newIdentityEnv(t, "")
	const tid = "11111111-2222-3333-4444-555555555555"
	const oid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	cases := []struct {
		strategy, name, sub, id string
		extra                   map[string]any
	}{
		{"windowslive", "personal", "Subject", "windowslive|Subject", nil},
		{"windowslive", "personal", "subject", "windowslive|subject", nil},
		{"waad", "single", oid, "waad|single|" + oid, map[string]any{"tenant_domain": tid}},
		{"waad", "orgs", tid + ":" + oid, "waad|orgs|" + tid + ":" + oid, map[string]any{"useCommonEndpoint": true}},
		{"waad", "orgs", "22222222-2222-3333-4444-555555555555:" + oid, "waad|orgs|22222222-2222-3333-4444-555555555555:" + oid, map[string]any{"useCommonEndpoint": true}},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		c := &store.Connection{TenantID: "ten", ID: tc.name, Name: tc.name, Strategy: tc.strategy, Extra: tc.extra}
		if !seen[c.ID] {
			if err := e.st.Connections().Create(e.ctx, c); err != nil {
				t.Fatal(err)
			}
			seen[c.ID] = true
		}
		r := result(tc.sub, func(p *Profile) { p.EmailVerified = boolp(false) })
		u, err := e.login(c, r)
		if err != nil {
			t.Fatal(err)
		}
		if u.UserID != tc.id || u.EmailVerified {
			t.Fatalf("user %+v", u)
		}
		r.Profile.Email = strp("changed@example.com")
		again, err := e.login(c, r)
		if err != nil || again.UserID != u.UserID || again.Email != *r.Profile.Email {
			t.Fatalf("repeat %+v %v", again, err)
		}
	}
	g, err := e.login(e.conn, result("Subject", nil))
	if err != nil || g.UserID != "google-oauth2|Subject" {
		t.Fatalf("Google %+v %v", g, err)
	}
}
