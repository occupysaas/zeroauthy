package seed

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestRefreshTokensIISeedOnline(t *testing.T) {
	f, err := Parse([]byte(`tenants:
 - name: online-seed
   domains: [online.example.test]
   resource_servers:
    - identifier: https://online.example.test/api
      allow_online_access: true
      allow_online_access_with_ephemeral_sessions: true
      proof_of_possession: {mechanism: dpop, required: true, required_for: public_clients}
`))
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	if err := Apply(t.Context(), st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, err := st.Tenants().GetByName(t.Context(), "online-seed")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := st.ResourceServers().GetByIdentifier(t.Context(), tn.ID, "https://online.example.test/api")
	if err != nil {
		t.Fatal(err)
	}
	if !rs.AllowOnlineAccess || !rs.AllowOnlineAccessWithEphemeralSessions || rs.ProofOfPossession.RequiredFor != "public_clients" {
		t.Fatal("seed online policy lost")
	}
	// Seed apply is full replacement: an explicitly disabled setting must persist.
	f.Tenants[0].ResourceServers[0].AllowOnlineAccess = false
	f.Tenants[0].ResourceServers[0].AllowOnlineAccessWithEphemeralSessions = false
	f.Tenants[0].ResourceServers[0].ProofOfPossession = nil
	if err := ValidateFile(f); err != nil {
		t.Fatal(err)
	}
	if err := Apply(t.Context(), st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	rs, err = st.ResourceServers().GetByIdentifier(t.Context(), tn.ID, "https://online.example.test/api")
	if err != nil {
		t.Fatal(err)
	}
	if rs.AllowOnlineAccess || rs.AllowOnlineAccessWithEphemeralSessions || rs.ProofOfPossession != nil {
		t.Fatal("seed replacement retained disabled online policy")
	}
}

type refreshIILegacySeedStore struct{ store.Store }

func (refreshIILegacySeedStore) CheckRefreshTokensIISupport(context.Context) error {
	return store.ErrRefreshTokensIIUnavailable
}

func TestRefreshTokensIISeedRejectsUnavailableOnline(t *testing.T) {
	f, err := Parse([]byte(`tenants:
 - name: online-seed
   domains: [online.example.test]
   resource_servers:
    - identifier: https://online.example.test/api
      allow_online_access: true
`))
	if err != nil {
		t.Fatal(err)
	}
	st := refreshIILegacySeedStore{memory.New()}
	if err := Apply(t.Context(), st, f, fixedNow, nil); err == nil {
		t.Fatal("unsupported online seed accepted")
	}
	tenants, err := st.Tenants().List(t.Context())
	if err != nil || len(tenants) != 0 {
		t.Fatal("unsupported seed wrote tenant")
	}
}
