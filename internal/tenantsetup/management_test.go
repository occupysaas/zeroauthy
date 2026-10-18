package tenantsetup

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestManagementAPI(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	tn, err := UpsertTenant(ctx, st, "acme", now, func(*store.Tenant) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ManagementAPI(ctx, st, tn, "example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Identifier != "https://acme.example.com/api/v2/" || rs.Name != ManagementAPIName || !rs.IsSystem {
		t.Fatalf("resource server = %+v", rs)
	}
	if rs.SubjectTypeAuthorization.Client != store.PolicyRequireClientGrant {
		t.Errorf("client policy = %q", rs.SubjectTypeAuthorization.Client)
	}
	var values []string
	for _, s := range rs.Scopes {
		values = append(values, s.Value)
		if s.Description == "" {
			t.Errorf("scope %q has no description", s.Value)
		}
	}
	for _, want := range []string{"read:clients", "create:clients", "update:clients", "delete:clients",
		"read:client_keys", "create:client_keys", "update:client_keys", "delete:client_keys"} {
		if !slices.Contains(values, want) {
			t.Errorf("scope %q missing from %v", want, values)
		}
	}
	stored, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, rs.Identifier)
	if err != nil || stored.ID != rs.ID || !stored.IsSystem {
		t.Fatalf("stored = %+v, %v", stored, err)
	}

	// Idempotent: same ID, scopes repaired.
	stored.Scopes = nil
	stored.IsSystem = false
	if err := st.ResourceServers().Update(ctx, stored); err != nil {
		t.Fatal(err)
	}
	again, err := ManagementAPI(ctx, st, tn, "example.com", now.Add(time.Hour))
	if err != nil || again.ID != rs.ID || !again.IsSystem || len(again.Scopes) != len(rs.Scopes) || !again.CreatedAt.Equal(now) {
		t.Fatalf("again = %+v, %v", again, err)
	}

	// Nor does the system tenant.
	if _, err := ManagementAPI(ctx, st, &store.Tenant{ID: "sys", Name: "system", Reserved: true}, "example.com", now); err == nil {
		t.Error("system tenant: err nil")
	}
	// A tenant with no host has no Management API.
	if _, err := ManagementAPI(ctx, st, tn, "", now); err == nil {
		t.Error("no host: err nil")
	}
}
