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
		PasswordOptions: store.PasswordOptions{
			Complexity: store.PasswordComplexity{
				MinLength:            10,
				CharacterTypes:       []string{"uppercase", "lowercase", "number", "special"},
				CharacterTypeRule:    store.CharacterTypeRuleThreeOfFour,
				IdenticalCharacters:  store.PasswordBlock,
				SequentialCharacters: store.PasswordAllow,
				MaxLengthExceeded:    store.MaxLengthTruncate,
				MinCharacterClasses:  2,
			},
			History:     store.PasswordHistory{Active: true, Size: 5},
			Dictionary:  store.PasswordDictionary{Active: true, Default: store.DictionaryEn10k, Custom: []string{"acme", "Pa55word"}},
			ProfileData: store.PasswordProfileData{Active: true, BlockedFields: []string{"name", "user_metadata.first"}},
		},
		BruteForceProtection: true,
		UsernameMin:          3,
		UsernameMax:          40,
		Origin:               store.OriginAPI,
		Extra:                map[string]any{"display_name": "Db", "nested": map[string]any{"list": []any{"a", map[string]any{"b": true}}, "n": float64(7)}},
		CreatedAt:            ts(0),

		EnabledDatabaseCustomization: true,
		ImportMode:                   true,
		CustomScripts:                map[string]string{store.ScriptLogin: "function login(e, p, cb) { cb(null, null) }"},
		ConfigurationSealed:          []byte{0x01, 0x02, 0xff},
		SetUserRootAttributes:        store.RootAttributesOnFirstLogin,
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

	t.Run("IsDomainConnection", func(t *testing.T) {
		s := open(t, newStore)
		want := newConnection("ten_a", "con1", "Database")
		want.IsDomainConnection = true
		mustNoErr(t, s.Connections().Create(ctx, want))
		got, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		got, err = s.Connections().GetByName(ctx, "ten_a", "Database")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		list, total, err := s.Connections().List(ctx, "ten_a", store.ConnectionFilter{}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, list, []*store.Connection{want})
		mustEqual(t, total, 1)
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

	t.Run("Settings", func(t *testing.T) { testConnectionSettings(t, newStore) })
	t.Run("List", func(t *testing.T) { testConnectionList(t, newStore) })
	t.Run("Delete", func(t *testing.T) { testConnectionDelete(t, newStore) })

	t.Run("PlainConnectionHasNoScripts", func(t *testing.T) {
		s := open(t, newStore)
		c := newConnection("ten_a", "con1", "Database")
		c.EnabledDatabaseCustomization, c.ImportMode = false, false
		c.CustomScripts, c.ConfigurationSealed, c.SetUserRootAttributes = nil, nil, ""
		mustNoErr(t, s.Connections().Create(ctx, c))
		got, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		mustEqual(t, got, c)
	})

	t.Run("ScriptsAndSealedConfigAreCopied", func(t *testing.T) {
		s := open(t, newStore)
		in := newConnection("ten_a", "con1", "Database")
		mustNoErr(t, s.Connections().Create(ctx, in))
		in.CustomScripts[store.ScriptLogin] = "mutated"
		in.ConfigurationSealed[0] = 0x99
		got, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		got.CustomScripts[store.ScriptLogin] = "mutated-too"
		got.ConfigurationSealed[0] = 0x98
		again, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		mustEqual(t, again.CustomScripts, map[string]string{store.ScriptLogin: "function login(e, p, cb) { cb(null, null) }"})
		mustEqual(t, again.ConfigurationSealed, []byte{0x01, 0x02, 0xff})
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
