package tenantsetup

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// TestMyOrgAPIScopes: the Phase A and Phase B scopes (D-0221), unique.
func TestMyOrgAPIScopes(t *testing.T) {
	if len(MyOrgAPIScopes) != 30 {
		t.Fatalf("%d scopes, want 30", len(MyOrgAPIScopes))
	}
	seen := map[string]bool{}
	for _, s := range MyOrgAPIScopes {
		if seen[s.Value] || !strings.Contains(s.Value, ":my_org:") || s.Description == "" {
			t.Errorf("scope %+v", s)
		}
		seen[s.Value] = true
	}
	for _, want := range []string{"update:my_org:domains", "update:my_org:identity_providers_detach", "delete:my_org:identity_providers_scim_tokens"} {
		if !seen[want] {
			t.Errorf("missing %s", want)
		}
	}
}

// TestUpgradeMyOrgAPIScopes: an API activated with Phase A's scopes gains
// Phase B's at startup, once, keeping its other settings; tenants without
// the API are untouched.
func TestUpgradeMyOrgAPIScopes(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	tn := &store.Tenant{ID: "t1", Name: "t1", Domains: []string{"t1.test"}, CanonicalHost: "t1.test"}
	none := &store.Tenant{ID: "t2", Name: "t2", Domains: []string{"t2.test"}, CanonicalHost: "t2.test"}
	for _, x := range []*store.Tenant{tn, none} {
		if err := st.Tenants().Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	api, err := MyOrgAPI(ctx, st, tn, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	api.Scopes = append([]store.Scope(nil), MyOrgAPIScopes[:12]...)
	api.Scopes[0].Description = "retained"
	if err := st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		for _, x := range []*store.Tenant{tn, none} {
			if err := UpgradeMyOrgAPIScopes(ctx, st, x); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, err := st.ResourceServers().Get(ctx, tn.ID, api.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Scopes) != len(MyOrgAPIScopes) || got.Scopes[0].Description != "retained" || got.TokenLifetime != MyOrgTokenLifetime {
		t.Fatalf("upgraded API %+v", got)
	}
	if _, err := st.ResourceServers().GetByIdentifier(ctx, none.ID, tenant.MyOrgIdentifier(none)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant without the API: %v", err)
	}
}
