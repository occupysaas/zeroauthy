package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testConnectionSettings pins the settings Plan 15 adds to a connection:
// password options, brute force protection, username limits, origin and the
// free-form extra options.
func testConnectionSettings(t *testing.T, newStore Factory) {
	ctx := context.Background()

	roundTrip := func(t *testing.T, s store.Store, want *store.Connection) {
		t.Helper()
		got, err := s.Connections().Get(ctx, want.TenantID, want.ID)
		mustNoErr(t, err)
		mustEqual(t, got, want)
		got, err = s.Connections().GetByName(ctx, want.TenantID, want.Name)
		mustNoErr(t, err)
		mustEqual(t, got, want)
	}

	t.Run("ZeroValuesStayZero", func(t *testing.T) {
		s := open(t, newStore)
		c := &store.Connection{TenantID: "ten_a", ID: "con1", Name: "Bare", Strategy: store.StrategyDatabase, CreatedAt: ts(0)}
		mustNoErr(t, s.Connections().Create(ctx, c))
		roundTrip(t, s, c)
		got, _ := s.Connections().Get(ctx, "ten_a", "con1")
		mustEqual(t, got.Extra == nil, true)
		mustEqual(t, got.PasswordOptions.Complexity.CharacterTypes == nil, true)
		mustEqual(t, got.PasswordOptions.Dictionary.Custom == nil, true)
		mustEqual(t, got.PasswordOptions.ProfileData.BlockedFields == nil, true)
	})

	t.Run("EmptyListsStayEmpty", func(t *testing.T) {
		s := open(t, newStore)
		c := newConnection("ten_a", "con1", "Db")
		c.PasswordOptions.Complexity.CharacterTypes = []string{}
		c.PasswordOptions.Dictionary.Custom = nil
		c.PasswordOptions.ProfileData.BlockedFields = []string{}
		c.Extra = map[string]any{}
		mustNoErr(t, s.Connections().Create(ctx, c))
		roundTrip(t, s, c)
	})

	t.Run("UpdateReplacesSettings", func(t *testing.T) {
		s := open(t, newStore)
		c := newConnection("ten_a", "con1", "Db")
		mustNoErr(t, s.Connections().Create(ctx, c))
		c.PasswordOptions = store.PasswordOptions{Complexity: store.PasswordComplexity{MinLength: 15, CharacterTypeRule: store.CharacterTypeRuleAll}}
		c.BruteForceProtection = false
		c.UsernameMin, c.UsernameMax = 1, 128
		c.Origin = ""
		c.Extra = nil
		mustNoErr(t, s.Connections().Update(ctx, c))
		roundTrip(t, s, c)
		c.PasswordOptions.History = store.PasswordHistory{Active: true, Size: 24}
		c.Origin = store.OriginAPI
		c.Extra = map[string]any{"k": "v"}
		mustNoErr(t, s.Connections().Update(ctx, c))
		roundTrip(t, s, c)
	})

	// Complexity.MinCharacterClasses keeps the seed's old
	// require_character_classes of 1 and 2, which Auth0's model has no
	// words for ("at least N of the four kinds").
	t.Run("MinCharacterClassesRoundTrip", func(t *testing.T) {
		s := open(t, newStore)
		for i, n := range []int{0, 1, 2} {
			c := newConnection("ten_a", "con"+string(rune('a'+i)), "Db"+string(rune('a'+i)))
			c.PasswordOptions.Complexity.MinCharacterClasses = n
			mustNoErr(t, s.Connections().Create(ctx, c))
			roundTrip(t, s, c)
		}
	})

	t.Run("ExtraKeepsNestedJSON", func(t *testing.T) {
		s := open(t, newStore)
		c := newConnection("ten_a", "con1", "Db")
		c.Extra = map[string]any{
			"s": "text", "n": float64(1.5), "i": float64(3), "b": false, "z": nil,
			"obj":  map[string]any{"deep": map[string]any{"list": []any{float64(1), "two", map[string]any{"three": []any{}}}}},
			"list": []any{map[string]any{"a": "b"}, []any{"x", "y"}},
			"é":    "ü",
		}
		mustNoErr(t, s.Connections().Create(ctx, c))
		roundTrip(t, s, c)
	})

	t.Run("ExtraIsCopied", func(t *testing.T) {
		s := open(t, newStore)
		c := newConnection("ten_a", "con1", "Db")
		c.Extra = map[string]any{"obj": map[string]any{"list": []any{"a"}}}
		mustNoErr(t, s.Connections().Create(ctx, c))
		c.Extra["obj"].(map[string]any)["list"].([]any)[0] = "mutated"
		got, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		mustEqual(t, got.Extra, map[string]any{"obj": map[string]any{"list": []any{"a"}}})
		got.Extra["obj"].(map[string]any)["list"].([]any)[0] = "mutated-too"
		got.PasswordOptions.Dictionary.Custom[0] = "mutated-too"
		got.PasswordOptions.Complexity.CharacterTypes[0] = "mutated-too"
		got.PasswordOptions.ProfileData.BlockedFields[0] = "mutated-too"
		again, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustNoErr(t, err)
		mustEqual(t, again.Extra, map[string]any{"obj": map[string]any{"list": []any{"a"}}})
		mustEqual(t, again.PasswordOptions.Dictionary.Custom, []string{"acme", "Pa55word"})
		mustEqual(t, again.PasswordOptions.Complexity.CharacterTypes[0], "uppercase")
		mustEqual(t, again.PasswordOptions.ProfileData.BlockedFields[0], "name")
	})
}

// testConnectionList pins Connections.List: case-insensitive name order,
// the Name and Strategies filters, paging, totals and tenant isolation.
func testConnectionList(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)

	type spec struct{ id, name, strategy string }
	// Names that order differently by byte and by case-insensitive
	// comparison; "alpha" and "Alpha" tie, so the ID decides.
	for _, sp := range []spec{
		{"con3", "Charlie", "sms"}, {"con2", "Alpha", "auth0"}, {"con5", "delta", "auth0"},
		{"con1", "alpha", "auth0"}, {"con4", "beta", "google-oauth2"},
	} {
		c := newConnection("ten_a", sp.id, sp.name)
		c.Strategy = sp.strategy
		mustNoErr(t, s.Connections().Create(ctx, c))
	}
	mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_b", "con9", "aaa")))

	list := func(f store.ConnectionFilter, p store.Page) ([]string, int) {
		t.Helper()
		got, total, err := s.Connections().List(ctx, "ten_a", f, p)
		mustNoErr(t, err)
		ids := []string{}
		for _, c := range got {
			ids = append(ids, c.ID)
		}
		return ids, total
	}
	check := func(name string, f store.ConnectionFilter, p store.Page, wantIDs []string, wantTotal int) {
		t.Run(name, func(t *testing.T) {
			ids, total := list(f, p)
			mustEqual(t, ids, wantIDs)
			mustEqual(t, total, wantTotal)
		})
	}
	all := []string{"con1", "con2", "con4", "con3", "con5"}
	check("All", store.ConnectionFilter{}, store.Page{}, all, 5)
	check("NameExact", store.ConnectionFilter{Name: "alpha"}, store.Page{}, []string{"con1"}, 1)
	check("NameIsCaseSensitive", store.ConnectionFilter{Name: "ALPHA"}, store.Page{}, []string{}, 0)
	check("NameOtherTenant", store.ConnectionFilter{Name: "aaa"}, store.Page{}, []string{}, 0)
	check("OneStrategy", store.ConnectionFilter{Strategies: []string{"auth0"}}, store.Page{}, []string{"con1", "con2", "con5"}, 3)
	check("StrategiesAnyOf", store.ConnectionFilter{Strategies: []string{"sms", "google-oauth2"}}, store.Page{}, []string{"con4", "con3"}, 2)
	check("UnknownStrategy", store.ConnectionFilter{Strategies: []string{"nope"}}, store.Page{}, []string{}, 0)
	check("NameAndStrategies", store.ConnectionFilter{Name: "Alpha", Strategies: []string{"auth0", "sms"}}, store.Page{}, []string{"con2"}, 1)
	check("NameAndWrongStrategy", store.ConnectionFilter{Name: "Alpha", Strategies: []string{"sms"}}, store.Page{}, []string{}, 0)
	check("FirstPage", store.ConnectionFilter{}, store.Page{Limit: 2}, all[:2], 5)
	check("MiddlePage", store.ConnectionFilter{}, store.Page{Offset: 2, Limit: 2}, all[2:4], 5)
	check("LastPartialPage", store.ConnectionFilter{}, store.Page{Offset: 4, Limit: 2}, all[4:], 5)
	check("PastTheEnd", store.ConnectionFilter{}, store.Page{Offset: 9, Limit: 2}, []string{}, 5)
	check("OffsetWithoutLimit", store.ConnectionFilter{}, store.Page{Offset: 3}, all[3:], 5)
	check("FilteredPage", store.ConnectionFilter{Strategies: []string{"auth0"}}, store.Page{Offset: 1, Limit: 1}, []string{"con2"}, 3)

	t.Run("OtherTenant", func(t *testing.T) {
		got, total, err := s.Connections().List(ctx, "ten_b", store.ConnectionFilter{}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, total, 1)
		mustEqual(t, got[0].ID, "con9")
	})

	t.Run("ReturnsFullConnections", func(t *testing.T) {
		got, _, err := s.Connections().List(ctx, "ten_a", store.ConnectionFilter{Name: "Alpha"}, store.Page{})
		mustNoErr(t, err)
		want := newConnection("ten_a", "con2", "Alpha")
		mustEqual(t, got, []*store.Connection{want})
	})
}
