package passkey

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestAssociationFiles(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	tn, _ := s.Store.Tenants().Get(ctx, "tenant")
	c := &store.Client{TenantID: "tenant", ClientID: "native", IsFirstParty: true, GrantTypes: []string{clientrules.GrantPasskey}, Mobile: &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "TEAMID", AppBundleIdentifier: "com.example.app"}, Android: &store.ClientMobileAndroid{AppPackageName: "com.example.app", SHA256CertFingerprints: []string{strings.Repeat("AB:", 31) + "AB", "unusable"}}}}
	must(t, s.Store.Clients().Create(ctx, c))
	third := *c
	third.ClientID = "third-party"
	third.IsFirstParty = false
	must(t, s.Store.Clients().Create(ctx, &third))
	noGrant := *c
	noGrant.ClientID = "no-grant"
	noGrant.GrantTypes = nil
	must(t, s.Store.Clients().Create(ctx, &noGrant))
	must(t, s.Store.CustomDomains().Create(ctx, &store.CustomDomain{TenantID: "tenant", ID: "cd", Domain: "custom.example.test", Status: "ready"}))
	must(t, s.Store.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "custom.example.test", TenantID: "tenant", DomainID: "cd", Kind: store.HostPublic, Active: true}))
	must(t, s.Store.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "alias.example.test", TenantID: "tenant", Kind: store.HostOperator, Active: true}))
	for _, host := range []string{"custom.example.test", "alias.example.test", "login.example.test"} {
		for _, path := range []string{"/.well-known/apple-app-site-association", "/.well-known/assetlinks.json"} {
			r := httptest.NewRequest("GET", "https://"+host+path, nil)
			r = r.WithContext(tenant.WithResolved(ctx, tenant.Resolved{Tenant: tn, Host: host}))
			w := httptest.NewRecorder()
			s.WellKnown(w, r)
			if host == "login.example.test" {
				if w.Code != 404 {
					t.Fatalf("canonical %d", w.Code)
				}
				continue
			}
			if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "max-age=300" || w.Header().Get("Location") != "" {
				t.Fatalf("%s %s %d %v", host, path, w.Code, w.Header())
			}
			if strings.Contains(w.Body.String(), "unusable") {
				t.Fatal("invalid fingerprint trusted")
			}
			if strings.Contains(path, "apple") {
				var b map[string]map[string][]string
				must(t, json.Unmarshal(w.Body.Bytes(), &b))
				if got := b["webcredentials"]["apps"]; len(got) != 1 || got[0] != "TEAMID.com.example.app" {
					t.Fatal(b)
				}
			}
		}
	}
	c.Mobile.IOS.TeamID = "bad.team"
	c.Mobile.Android.AppPackageName = ""
	must(t, s.Store.Clients().Update(ctx, c))
	for _, path := range []string{"/.well-known/apple-app-site-association", "/.well-known/assetlinks.json"} {
		r := httptest.NewRequest("GET", "https://alias.example.test"+path, nil)
		r = r.WithContext(tenant.WithResolved(ctx, tenant.Resolved{Tenant: tn, Host: "alias.example.test"}))
		w := httptest.NewRecorder()
		s.WellKnown(w, r)
		if w.Code != 404 {
			t.Fatalf("unusable identity %d %s", w.Code, w.Body)
		}
	}
}
