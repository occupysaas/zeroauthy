package tenantsetup

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestManagementAPINameUpgrade(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	tn := &store.Tenant{ID: "ten_a", Name: "acme", Domains: []string{"acme.test"}}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	rs, err := ManagementAPI(ctx, st, tn, "example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	rs.Name = "zeroauthy Management API"
	rs.TokenLifetime, rs.TokenLifetimeForWeb, rs.AllowOfflineAccess = 321, 654, true
	rs.SubjectTypeAuthorization = store.SubjectTypeAuthorization{User: store.PolicyAllowAll, Client: store.PolicyDenyAll}
	if err := st.ResourceServers().Update(ctx, rs); err != nil {
		t.Fatal(err)
	}
	ordinary := &store.ResourceServer{TenantID: tn.ID, ID: "rs_other", Identifier: "https://other.test", Name: "zeroauthy Management API", SigningAlg: "RS256", TokenLifetime: 123, CreatedAt: now}
	if err := st.ResourceServers().Create(ctx, ordinary); err != nil {
		t.Fatal(err)
	}
	stale, err := st.ResourceServers().Get(ctx, tn.ID, rs.ID)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := st.ResourceServers().Get(ctx, tn.ID, rs.ID)
	if err != nil {
		t.Fatal(err)
	}
	latest.TokenLifetime = 777 // an overlapping settings update after another request took its snapshot
	if err := st.ResourceServers().Update(ctx, latest); err != nil {
		t.Fatal(err)
	}
	before := rs
	if err := UpgradeManagementAPIName(ctx, st, tn, "example.test"); err != nil {
		t.Fatal(err)
	}
	after, err := st.ResourceServers().Get(ctx, tn.ID, rs.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Name != "Auth0 Management API" || after.Identifier != before.Identifier || after.TokenLifetime != 777 || after.TokenLifetimeForWeb != 654 || !after.AllowOfflineAccess || after.SubjectTypeAuthorization != before.SubjectTypeAuthorization || after.SigningAlg != before.SigningAlg || after.IsSystem != before.IsSystem || len(after.Scopes) != len(before.Scopes) || stale.TokenLifetime != 321 {
		t.Fatalf("upgrade changed more than name: %+v", after)
	}
	if err := UpgradeManagementAPIName(ctx, st, tn, "example.test"); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := st.ResourceServers().Get(ctx, tn.ID, ordinary.ID)
	if unchanged.Name != ordinary.Name || unchanged.TokenLifetime != ordinary.TokenLifetime {
		t.Fatalf("ordinary API was modified: %+v", unchanged)
	}
	sys := &store.Tenant{ID: "ten_sys", Name: "system", Reserved: true}
	if err := UpgradeManagementAPIName(ctx, st, sys, "example.test"); err != nil {
		t.Fatalf("reserved tenant: %v", err)
	}
}

func TestRBACManagementUpgrade(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	tn := &store.Tenant{ID: "old", Name: "old", Domains: []string{"old.test"}}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	api, err := ManagementAPI(ctx, st, tn, "example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	api.Scopes = []store.Scope{{Value: "read:users", Description: "retained"}}
	api.TokenLifetime = 321
	if err := st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	grant := &store.ClientGrant{TenantID: tn.ID, ID: "restricted", ClientID: "client", Audience: api.Identifier, SubjectType: store.SubjectTypeClient, Scopes: []string{"read:users"}}
	if err := st.ClientGrants().Create(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if err := UpgradeManagementAPIScopes(ctx, st, tn, "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := UpgradeManagementAPIScopes(ctx, st, tn, "example.test"); err != nil {
		t.Fatal(err)
	}
	got, err := st.ResourceServers().Get(ctx, tn.ID, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenLifetime != 321 || got.Scopes[0].Description != "retained" || len(got.Scopes) != len(ManagementAPIScopes) {
		t.Fatalf("upgrade changed settings or duplicated scopes: %+v", got)
	}
	for _, required := range []string{"read:roles", "create:roles", "update:roles", "delete:roles", "read:role_members", "create:role_members", "delete:role_members"} {
		found := false
		for _, s := range got.Scopes {
			if s.Value == required {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s", required)
		}
	}
	actual, err := st.ClientGrants().Find(ctx, tn.ID, grant.ClientID, grant.Audience, store.SubjectTypeClient)
	if err != nil {
		t.Fatal(err)
	}
	if len(actual.Scopes) != 1 || actual.Scopes[0] != "read:users" {
		t.Fatalf("grant expanded: %+v", actual)
	}
	missing := &store.Tenant{ID: "missing", Name: "missing", Domains: []string{"missing.test"}}
	if err := UpgradeManagementAPIScopes(ctx, st, missing, "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := UpgradeManagementAPIScopes(ctx, st, &store.Tenant{Reserved: true}, "example.test"); err != nil {
		t.Fatal(err)
	}
}

func TestActionsScopesUpgrade(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	tn := &store.Tenant{ID: "old", Name: "old", Domains: []string{"old.test"}}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	api, err := ManagementAPI(ctx, st, tn, "example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	api.Scopes = []store.Scope{{Value: "read:users", Description: "retained"}}
	api.TokenLifetime = 321
	if err := st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	grant := &store.ClientGrant{TenantID: tn.ID, ID: "restricted", ClientID: "client", Audience: api.Identifier, SubjectType: store.SubjectTypeClient, Scopes: []string{"read:users"}}
	if err := st.ClientGrants().Create(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if err := UpgradeManagementAPIScopes(ctx, st, tn, "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := UpgradeManagementAPIScopes(ctx, st, tn, "example.test"); err != nil {
		t.Fatal(err)
	}
	got, err := st.ResourceServers().Get(ctx, tn.ID, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenLifetime != 321 || got.Scopes[0].Description != "retained" || len(got.Scopes) != len(ManagementAPIScopes) {
		t.Fatalf("upgrade changed settings or duplicated scopes: %+v", got)
	}
	for _, required := range []string{"read:actions", "create:actions", "update:actions", "delete:actions", "read:roles", "create:roles", "update:roles", "delete:roles", "read:role_members", "create:role_members", "delete:role_members"} {
		found := false
		for _, s := range got.Scopes {
			if s.Value == required {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s", required)
		}
	}
	actual, err := st.ClientGrants().Find(ctx, tn.ID, grant.ClientID, grant.Audience, store.SubjectTypeClient)
	if err != nil {
		t.Fatal(err)
	}
	if len(actual.Scopes) != 1 || actual.Scopes[0] != "read:users" {
		t.Fatalf("grant expanded: %+v", actual)
	}
	missing := &store.Tenant{ID: "missing", Name: "missing", Domains: []string{"missing.test"}}
	if err := UpgradeManagementAPIScopes(ctx, st, missing, "example.test"); err != nil {
		t.Fatal(err)
	}
	if err := UpgradeManagementAPIScopes(ctx, st, &store.Tenant{Reserved: true}, "example.test"); err != nil {
		t.Fatal(err)
	}
}
