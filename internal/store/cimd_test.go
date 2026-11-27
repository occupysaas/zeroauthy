package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// A third-party client without its own grant uses the default grant; its
// own grant wins; first-party clients never use defaults (LR41b-4).
func TestFindEffectiveClientGrant(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	const aud = "https://api.example/"
	third := &store.Client{TenantID: "t", ClientID: "tpc_a", ThirdPartySecurityMode: store.SecurityModeStrict}
	first := &store.Client{TenantID: "t", ClientID: "app", IsFirstParty: true}
	if _, err := store.FindEffectiveClientGrant(ctx, st, third, aud, store.SubjectTypeUser); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no grants: %v", err)
	}
	def := &store.ClientGrant{TenantID: "t", ID: "cgr_default", Audience: aud, SubjectType: store.SubjectTypeUser, Scopes: []string{"read"}, DefaultFor: store.GrantDefaultForThirdParty, OrganizationUsage: "deny"}
	if err := st.ClientGrants().Create(ctx, def); err != nil {
		t.Fatal(err)
	}
	if g, err := store.FindEffectiveClientGrant(ctx, st, third, aud, store.SubjectTypeUser); err != nil || g.ID != def.ID {
		t.Fatalf("third party: %+v %v", g, err)
	}
	if _, err := store.FindEffectiveClientGrant(ctx, st, third, aud, store.SubjectTypeClient); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other subject type: %v", err)
	}
	if _, err := store.FindEffectiveClientGrant(ctx, st, first, aud, store.SubjectTypeUser); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("first party used the default: %v", err)
	}
	own := &store.ClientGrant{TenantID: "t", ID: "cgr_own", ClientID: "tpc_a", Audience: aud, SubjectType: store.SubjectTypeUser, Scopes: []string{}, OrganizationUsage: "deny"}
	if err := st.ClientGrants().Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	if g, err := store.FindEffectiveClientGrant(ctx, st, third, aud, store.SubjectTypeUser); err != nil || g.ID != own.ID {
		t.Fatalf("own grant must win: %+v %v", g, err)
	}
}
