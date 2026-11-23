package seed

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// A seeded ad connection (Plan 38a) gets its provisioning ticket where it
// is created; a re-apply keeps the ticket and the connector-managed options
// the connector registered.
func TestSeedADConnection(t *testing.T) {
	st := memory.New()
	raw := `
tenants:
 - name: acme
   connections:
    - name: corp-ad
      strategy: ad
      options: {tenant_domain: corp.example, kerberos: true, ips: ["10.0.0.0/8"], certs: ["seed-sent"], signInEndpoint: "https://seed.example/wsfed"}
`
	f, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	w := testWrapper(t)
	if err := Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	conn, err := st.Connections().GetByName(ctx, tn.ID, "corp-ad")
	if err != nil || conn.Strategy != "ad" || conn.Extra["certs"] != nil || conn.Extra["signInEndpoint"] != nil || conn.Extra["kerberos"] != true {
		t.Fatalf("seeded ad connection %+v %v", conn, err)
	}
	repo, _ := store.ADHub(ctx, st)
	first, err := repo.GetADProvisioning(ctx, tn.ID, conn.ID)
	if err != nil {
		t.Fatalf("no ticket: %v", err)
	}
	conn.Extra["signInEndpoint"] = "http://connector.corp:4000/wsfed"
	if err := st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal("reapply", err)
	}
	again, _ := st.Connections().GetByName(ctx, tn.ID, "corp-ad")
	if again.Extra["signInEndpoint"] != "http://connector.corp:4000/wsfed" {
		t.Fatalf("re-apply lost the connector's options: %v", again.Extra)
	}
	if p, _ := repo.GetADProvisioning(ctx, tn.ID, conn.ID); p.TicketHash != first.TicketHash {
		t.Fatal("re-apply replaced the ticket")
	}
}
