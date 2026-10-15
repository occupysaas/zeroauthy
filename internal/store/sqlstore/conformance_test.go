package sqlstore

import (
	"context"
	"reflect"
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
func (h hybrid) Users() store.Users                     { return h.s.Users() }
func (h hybrid) Sessions() store.Sessions               { return h.s.Sessions() }
func (h hybrid) AuthTransactions() store.AuthTransactions {
	return h.s.AuthTransactions()
}

func TestConformance(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.RunSuites(t, func(t *testing.T) store.Store {
				return hybrid{Store: memory.New(), s: fresh(t)}
			}, "Tenants", "Clients", "ResourceServers", "ClientGrants", "SigningKeys", "Connections",
				"Users", "Sessions", "AuthTransactions")
		})
	}
}

// MySQL reports changed rows unless clientFoundRows is set; an Update that
// writes identical values must still succeed.
func TestUsersUpdateUnchangedTwice(t *testing.T) {
	ctx := context.Background()
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			u := &store.User{TenantID: "ten_a", UserID: "auth0|u1", Email: "a@example.test",
				Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "u1"}}}
			if err := s.Users().Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			for i := range 2 {
				if err := s.Users().Update(ctx, u); err != nil {
					t.Fatalf("Update #%d: %v", i+1, err)
				}
			}
			got, err := s.Users().Get(ctx, u.TenantID, u.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, u) {
				t.Fatalf("got %+v, want %+v", got, u)
			}
		})
	}
}
