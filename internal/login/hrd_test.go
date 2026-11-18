package login

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/url"
	"strings"
	"testing"
)

func TestIdentifierHRDRedirect(t *testing.T) {
	for _, tc := range []struct {
		email                  string
		enabled, active, route bool
	}{{"a@corp.example", true, true, true}, {"a@unknown.example", true, true, false}, {"a@corp.example", false, true, false}, {"a@corp.example", true, false, false}} {
		t.Run(tc.email+map[bool]string{true: " enabled", false: " disabled"}[tc.enabled], func(t *testing.T) {
			s := newSocialEnv(t)
			enableIdentifier(t, s.env)
			c, e := s.st.Connections().Get(context.Background(), s.tenant.ID, "con_corp")
			if e != nil {
				t.Fatal(e)
			}
			c.Extra["domain_aliases"] = []any{"corp.example"}
			if !tc.enabled {
				c.EnabledClients = []string{"social-only"}
			}
			if !tc.active {
				c.Extra["__zeroauthy"] = map[string]any{"authentication": map[string]any{"active": false}}
			}
			if e := s.st.Connections().Update(context.Background(), c); e != nil {
				t.Fatal(e)
			}
			if !tc.active {
				spec := connrules.FromConnection(c)
				spec.Authentication = map[string]any{"active": false}
				connrules.Apply(spec, c)
				if e := s.st.Connections().Update(context.Background(), c); e != nil {
					t.Fatal(e)
				}
			}
			s.h.Store = discoveryNoUsers{s.st}
			b := s.browser("acme.example.test")
			page, state, csrf := b.begin(t)
			r := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "username": {tc.email}})
			if !tc.route && r.Code != 303 {
				t.Fatal(r.Code, r.Body.String())
			}
			location := r.Header().Get("Location")
			if tc.route {
				if r.Code != 200 {
					t.Fatalf("HRD must end the POST navigation with a handoff page: status %d", r.Code)
				}
				location = providerURL(t, r)
			}
			u, e := url.Parse(location)
			if e != nil {
				t.Fatal(e)
			}
			if tc.route {
				if u.Host == "" || u.Query().Get("login_hint") != tc.email {
					t.Fatal(u)
				}
			} else if !strings.HasPrefix(u.Path, "/u/login/password") {
				t.Fatal(u)
			}
		})
	}
}

var _ store.Store = discoveryNoUsers{}

func TestHRDCandidatesOrganization(t *testing.T) {
	for _, linked := range []bool{false, true} {
		s := newSocialEnv(t)
		enableIdentifier(t, s.env)
		org, _, _ := organizationFixture(t, s.env, store.OrgBehaviorNoPrompt, false, false)
		ctx := context.Background()
		c, e := s.st.Connections().Get(ctx, s.tenant.ID, "con_corp")
		if e != nil {
			t.Fatal(e)
		}
		c.Extra["domain_aliases"] = []any{"corp.example"}
		if e := s.st.Connections().Update(ctx, c); e != nil {
			t.Fatal(e)
		}
		if linked {
			if e := s.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: s.tenant.ID, OrganizationID: org.ID, ConnectionID: c.ID}, true); e != nil {
				t.Fatal(e)
			}
		}
		b := s.browser("acme.example.test")
		page, state, csrf := b.begin(t, "organization", org.ID)
		r := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "username": {"a@corp.example"}})
		location := r.Header().Get("Location")
		if linked {
			if r.Code != 200 {
				t.Fatalf("HRD must end the POST navigation with a handoff page: status %d", r.Code)
			}
			location = providerURL(t, r)
		}
		u, e := url.Parse(location)
		if e != nil || !linked && r.Code != 303 {
			t.Fatal(r.Code, e)
		}
		if (u.Host != "") != linked {
			t.Fatal(u, linked)
		}
	}
}
