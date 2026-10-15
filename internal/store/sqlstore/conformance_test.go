package sqlstore

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

// hybrid serves the aggregates implemented so far from SQL and the rest from
// memory. Task 5 replaces it with the full driver.
type hybrid struct {
	*memory.Store
	s *Store
}

func (h hybrid) Tenants() store.Tenants                 { return h.s.Tenants() }
func (h hybrid) Clients() store.Clients                 { return h.s.Clients() }
func (h hybrid) ResourceServers() store.ResourceServers { return h.s.ResourceServers() }
func (h hybrid) ClientGrants() store.ClientGrants       { return h.s.ClientGrants() }
func (h hybrid) SigningKeys() store.SigningKeys         { return h.s.SigningKeys() }
func (h hybrid) Connections() store.Connections         { return h.s.Connections() }

func TestConformance(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.RunSuites(t, func(t *testing.T) store.Store {
				return hybrid{Store: memory.New(), s: fresh(t)}
			}, "Tenants", "Clients", "ResourceServers", "ClientGrants", "SigningKeys", "Connections")
		})
	}
}
