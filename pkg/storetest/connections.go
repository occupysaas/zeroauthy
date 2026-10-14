package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newConnection(tenantID, id, name string) *store.Connection {
	return &store.Connection{
		TenantID:         tenantID,
		ID:               id,
		Name:             name,
		Strategy:         store.StrategyDatabase,
		EnabledClients:   []string{"c1", "c2"},
		DisableSignup:    true,
		RequiresUsername: true,
		PasswordPolicy:   store.PasswordPolicy{MinLength: 10, RequireCharacterClasses: 3},
		CreatedAt:        ts(0),
	}
}

func testConnections(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newConnection("ten_a", "con1", "Database")
		mustNoErr(t, s.Connections().Create(ctx, want))
		got, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		got, err = s.Connections().GetByName(ctx, "ten_a", "Database")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.EnabledClients = []string{"c3"}
		want.Name = "Renamed"
		mustNoErr(t, s.Connections().Update(ctx, want))
		_, err = s.Connections().GetByName(ctx, "ten_a", "Database")
		mustErrIs(t, err, store.ErrNotFound)
		got, err = s.Connections().GetByName(ctx, "ten_a", "Renamed")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		mustErrIs(t, s.Connections().Update(ctx, newConnection("ten_a", "missing", "x")), store.ErrNotFound)
		_, err = s.Connections().Get(ctx, "ten_b", "con1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("NameUniquePerTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_a", "con1", "Database")))
		mustErrIs(t, s.Connections().Create(ctx, newConnection("ten_a", "con2", "Database")), store.ErrConflict)
		mustErrIs(t, s.Connections().Create(ctx, newConnection("ten_a", "con1", "Other")), store.ErrConflict)
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_b", "con1", "Database")))
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_a", "con3", "Third")))
		mustErrIs(t, s.Connections().Update(ctx, newConnection("ten_a", "con3", "Database")), store.ErrConflict)
	})

	t.Run("ListOrderedByName", func(t *testing.T) {
		s := open(t, newStore)
		for _, n := range []string{"b", "c", "a"} {
			mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_a", "con-"+n, n)))
		}
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_b", "x", "zz")))
		got, err := s.Connections().List(ctx, "ten_a")
		mustNoErr(t, err)
		var names []string
		for _, c := range got {
			names = append(names, c.Name)
		}
		mustEqual(t, names, []string{"a", "b", "c"})
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newConnection("ten_a", "con1", "Database")
		mustNoErr(t, s.Connections().Create(ctx, in))
		in.EnabledClients[0] = "mutated"
		got, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		got.EnabledClients[1] = "mutated-too"
		again, _ := s.Connections().Get(ctx, "ten_a", "con1")
		mustEqual(t, again.EnabledClients, []string{"c1", "c2"})
	})
}
