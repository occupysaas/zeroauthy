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
