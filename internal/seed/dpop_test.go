package seed

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
	"time"
)

func TestDPoPSeed(t *testing.T) {
	f, e := Parse([]byte(`tenants:
  - name: proof
    domains: [proof.example]
    clients:
      - client_id: app
        name: app
        app_type: spa
        require_proof_of_possession: true
    resource_servers:
      - identifier: https://api.example
        proof_of_possession:
          mechanism: dpop
          required: true
          required_for: public_clients
`))
	if e != nil {
		t.Fatal(e)
	}
	st := memory.New()
	if e = Apply(context.Background(), st, f, time.Now, nil); e != nil {
		t.Fatal(e)
	}
	tn, _ := st.Tenants().GetByName(context.Background(), "proof")
	c, e := st.Clients().Get(context.Background(), tn.ID, "app")
	if e != nil || !c.RequireProofOfPossession {
		t.Fatal("client policy lost")
	}
	rs, e := st.ResourceServers().GetByIdentifier(context.Background(), tn.ID, "https://api.example")
	if e != nil || rs.ProofOfPossession == nil || !rs.ProofOfPossession.Required {
		t.Fatal("API policy lost")
	}
}
