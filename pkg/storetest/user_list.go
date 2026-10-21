package storetest

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The user-list suites run one table of query trees against a fixed set of
// twelve users in ten_a (and one decoy in ten_b). Every driver must return
// the same users for every tree: that is what keeps memory, SQLite,
// PostgreSQL, MySQL and plugins in agreement on search.

const day = 24 * time.Hour

// listUser is one fixture row: the user and how often it logs in.
type listUser struct {
	u         *store.User
	logins    int
	lastLogin time.Duration // offset of the last login from ts(0)
	ip        string
}

func listFixtures() []listUser {
	db := func(id string) []store.Identity {
		return []store.Identity{{Connection: "Database", Provider: store.StrategyDatabase, UserID: id, PasswordHash: "$argon2id$h-" + id}}
	}
	mk := func(i int, email string, verified bool, username, name, nick, given, family, phone string, phoneVerified bool,
		app, user map[string]any) *store.User {
		id := "u" + string(rune('0'+i/10)) + string(rune('0'+i%10))
		return &store.User{
			TenantID: "ten_a", UserID: "auth0|" + id, Email: email, EmailVerified: verified, Username: username,
			Name: name, Nickname: nick, GivenName: given, FamilyName: family, PhoneNumber: phone, PhoneVerified: phoneVerified,
			Picture: "https://img.test/" + id + ".png", Identities: db(id), AppMetadata: app, UserMetadata: user,
			CreatedAt: ts(time.Duration(i) * day), UpdatedAt: ts(time.Duration(40-i) * day),
		}
	}
	m := func(kv ...any) map[string]any {
		out := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	u01 := mk(1, "alice@example.com", true, "alice", "Alice Smith", "alice", "Alice", "Smith", "+15550001", true,
		m("plan", "pro", "x", 1), m("color", "red"))
	u02 := mk(2, "bob@example.com", false, "bob", "Bob Jones", "bob", "Bob", "Jones", "", false,
		m("plan", "PRO", "x", []any{1.0}), m("color", "blue"))
	u02.Blocked = true
	u03 := mk(3, "carol@test.org", true, "", "Carol", "carol", "", "", "+15550003", false,
		m("plan", []any{"basic", "pro"}, "x", true), nil)
	u04 := mk(4, "dave@test.org", false, "dave", "dave@test.org", "dave", "Dave", "", "", false,
		m("plan", 2, "x", []any{true}), m("tier", "2")) // an int, as a caller may store it
	u05 := mk(5, "erin@example.com", true, "erin_x", "Erin", "erin", "Erin", "Stone", "+15550005", true,
		m("plan", true), map[string]any{})
	u06 := mk(6, "frank@example.com", false, "", "100% Frank", "frank", "Frank", "", "", false,
		m("plan", nil), m("color", "Red"))
	u07 := mk(7, "grace@example.com", true, "grace", "Grace Hopper", "grace", "Grace", "Hopper", "", false,
		m("plan", m("name", "pro")), nil)
	u07.Identities = append(u07.Identities, store.Identity{Connection: "google-oauth2", Provider: "google-oauth2", UserID: "g-777"})
	u08 := mk(8, "heidi@example.com", true, "", "Heidi", "heidi", "Émilie", "Klum", "", false,
		m("plan", []any{[]any{"pro"}}), m("nested", m("k", "v", "n", 5.0)))
	u09 := mk(9, "ivan@example.com", false, "ivan", "Ivan", "ivan", "", "Petrov", "+15550009", true,
		m("plan", "pro", "nums", []any{5.0, 6.0}), m("lst", []string{"a", "b"}))
	u10 := mk(10, "judy@example.com", true, "", "Judy*Star", "judy", "Judy", "", "", false, nil, nil)
	u11 := mk(11, "mallory@example.com", false, "mallory", "Mallory", "mallory", "", "", "", false,
		m("plan", []any{"PRO"}, "flags", []any{true}), nil)
	u11.Identities = []store.Identity{{Connection: "Other", Provider: store.StrategyDatabase, UserID: "u11"}}
	u12 := mk(12, "", false, "trent", "trent", "trent", "", "", "+15550012", false, m("count", 2.0), nil)
	return []listUser{
		{u01, 3, 30 * day, "10.0.0.1"},
		{u02, 1, 31 * day, "10.0.0.2"},
		{u03, 0, 0, ""},
		{u04, 5, 32 * day, "192.168.1.4"},
		{u05, 2, 32 * day, "10.0.0.5"},
		{u06, 0, 0, ""},
		{u07, 10, 29 * day, "10.0.0.7"},
		{u08, 1, 28 * day, "10.0.0.8"},
		{u09, 3, 33 * day, "10.0.0.9"},
		{u10, 0, 0, ""},
		{u11, 2, 27 * day, "10.1.0.11"},
		{u12, 0, 0, ""},
	}
}

// seedList creates the fixtures, their logins and a decoy in ten_b.
func seedList(t *testing.T, s store.Store) {
	t.Helper()
	ctx := context.Background()
	for _, f := range listFixtures() {
		mustNoErr(t, s.Users().Create(ctx, f.u))
		for i := range f.logins {
			at := ts(f.lastLogin - time.Duration(f.logins-1-i)*time.Hour)
			mustNoErr(t, s.Users().RecordLogin(ctx, "ten_a", f.u.UserID, at, f.ip))
		}
	}
	decoy := newUser("ten_b", "u01", "alice@example.com", "alice")
	decoy.AppMetadata = map[string]any{"plan": "pro"}
	mustNoErr(t, s.Users().Create(ctx, decoy))
	mustNoErr(t, s.Users().RecordLogin(ctx, "ten_b", decoy.UserID, ts(40*day), "10.9.9.9"))
}

// Query tree builders.
func qStr(field, v string) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryTerm, Field: field, Kind: store.KindString, Value: v}
}
func qBool(field string, v bool) *store.UserQuery {
	s := "false"
	if v {
		s = "true"
	}
	return &store.UserQuery{Op: store.QueryTerm, Field: field, Kind: store.KindBool, Value: s}
}
func qNum(field, v string) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryTerm, Field: field, Kind: store.KindNumber, Value: v}
}
func qDate(field, v string) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryTerm, Field: field, Kind: store.KindDate, Value: v}
}
func qWild(field, glob string) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryWildcard, Field: field, Kind: store.KindString, Value: glob}
}
func qExists(field string) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryExists, Field: field}
}

// qRange builds a range; "*" is an open end. Brackets: "[]", "{}", "[}", "{]".
func qRange(field string, kind store.ValueKind, br, lo, hi string) *store.UserQuery {
	q := &store.UserQuery{Op: store.QueryRange, Field: field, Kind: kind, LoIncl: br[0] == '[', HiIncl: br[1] == ']'}
	if lo != "*" {
		q.Lo = &lo
	}
	if hi != "*" {
		q.Hi = &hi
	}
	return q
}
func qAnd(k ...*store.UserQuery) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryAnd, Kids: k}
}
func qOr(k ...*store.UserQuery) *store.UserQuery { return &store.UserQuery{Op: store.QueryOr, Kids: k} }
func qNot(k *store.UserQuery) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryNot, Kids: []*store.UserQuery{k}}
}

// ids expands "01 02" into auth0|u01, auth0|u02.
func ids(s string) []string {
	out := []string{}
	for f := range strings.FieldsSeq(s) {
		out = append(out, "auth0|u"+f)
	}
	return out
}

func userIDsOf(us []*store.User) []string {
	out := []string{}
	for _, u := range us {
		out = append(out, u.UserID)
	}
	return out
}

const allTwelve = "01 02 03 04 05 06 07 08 09 10 11 12"

// listCase is one query and the users it must match, in user_id order.
type listCase struct {
	name string
	q    *store.UserQuery
	want string
}

func userListCases() []listCase {
	return []listCase{
		{"Nil", nil, allTwelve},
		{"All", &store.UserQuery{Op: store.QueryAll}, allTwelve},
		// Root string terms: whole value, case-insensitive.
		{"EmailCaseInsensitive", qStr("email", "ALICE@Example.com"), "01"},
		{"EmailIsExact", qStr("email", "alice"), ""},
		{"NameWholeValue", qStr("name", "alice SMITH"), "01"},
		{"NamePartIsNoMatch", qStr("name", "alice"), ""},
		{"GivenNameUnicodeFold", qStr("given_name", "émilie"), "08"},
		{"GivenNameAccentMatters", qStr("given_name", "emilie"), ""},
		{"FamilyName", qStr("family_name", "JONES"), "02"},
		{"Nickname", qStr("nickname", "Carol"), "03"},
		{"Username", qStr("username", "ERIN_X"), "05"},
		{"PhoneNumber", qStr("phone_number", "+15550001"), "01"},
		{"UserIDCaseInsensitive", qStr("user_id", "AUTH0|U07"), "07"},
		{"UserIDRangeExclusiveInclusive", qRange("user_id", store.KindString, "{]", "auth0|u03", "auth0|u06"), "04 05 06"},
		{"UserIDRangeFoldsCase", qRange("user_id", store.KindString, "[}", "AUTH0|U03", "auth0|U05"), "03 04"},
		{"UserIDRangeOpenEnd", qRange("user_id", store.KindString, "{}", "auth0|u10", "*"), "11 12"},
		{"UserIDRangeOpenStart", qRange("user_id", store.KindString, "{]", "*", "auth0|u02"), "01 02"},
		{"UserIDRangeWithConnection", qAnd(qRange("user_id", store.KindString, "{}", "auth0|u06", "*"), qStr("identities.connection", "Database")), "07 08 09 10 12"},
		{"LastIP", qStr("last_ip", "10.0.0.5"), "05"},
		// Booleans and numbers.
		{"EmailVerifiedFalse", qBool("email_verified", false), "02 04 06 09 11 12"},
		{"PhoneVerified", qBool("phone_verified", true), "01 05 09"},
		{"BlockedTrue", qBool("blocked", true), "02"},
		{"BlockedFalse", qBool("blocked", false), "01 03 04 05 06 07 08 09 10 11 12"},
		{"LoginsCount", qNum("logins_count", "3"), "01 09"},
		{"LoginsCountZero", qNum("logins_count", "0"), "03 06 10 12"},
		{"LoginsCountFraction", qNum("logins_count", "2.5"), ""},
		// Identities: any identity matches.
		{"IdentityConnection", qStr("identities.connection", "google-oauth2"), "07"},
		{"IdentityConnectionCase", qStr("identities.connection", "DATABASE"), "01 02 03 04 05 06 07 08 09 10 12"},
		{"IdentityProvider", qStr("identities.provider", "google-oauth2"), "07"},
		{"IdentityUserID", qStr("identities.user_id", "G-777"), "07"},
		// Wildcards: globs on root string fields, % and _ are literal.
		{"WildSuffix", qWild("email", "*@TEST.org"), "03 04"},
		{"WildPrefix", qWild("email", "a*"), "01"},
		{"WildBoth", qWild("name", "*o*"), "02 03 04 07 11"},
		{"WildBareNeedsValue", qWild("email", "*"), "01 02 03 04 05 06 07 08 09 10 11"},
		{"WildLastIP", qWild("last_ip", "*"), "01 02 04 05 07 08 09 11"},
		{"WildPercentLiteral", qWild("name", "100%*"), "06"},
		{"WildPercentNotAny", qWild("name", "%*"), ""},
		{"WildUnderscoreNotAny", qWild("username", "e_in*"), ""},
		{"WildUnderscoreLiteral", qWild("username", "erin_*"), "05"},
		{"WildEscapedStar", qWild("name", `judy\**`), "10"},
		{"WildEscapedStarExact", qWild("name", `judy\*`), ""},
		// Ranges: numbers as numbers, dates as instants.
		{"LoginsClosed", qRange("logins_count", store.KindNumber, "[]", "2", "5"), "01 04 05 09 11"},
		{"LoginsLeftOpen", qRange("logins_count", store.KindNumber, "{]", "2", "5"), "01 04 09"},
		{"LoginsAtLeast", qRange("logins_count", store.KindNumber, "[]", "5", "*"), "04 07"},
		{"LoginsBelow", qRange("logins_count", store.KindNumber, "[}", "*", "2"), "02 03 06 08 10 12"},
		{"LoginsFractionBounds", qRange("logins_count", store.KindNumber, "[]", "1.5", "2.5"), "05 11"},
		{"CreatedDays", qRange("created_at", store.KindDate, "[]", "2026-01-05", "2026-01-07"), "03 04"},
		{"CreatedAfterInstant", qRange("created_at", store.KindDate, "{]", "2026-01-10T03:04:05Z", "*"), "09 10 11 12"},
		{"CreatedFromInstant", qRange("created_at", store.KindDate, "[]", "2026-01-10T03:04:05Z", "*"), "08 09 10 11 12"},
		{"LastLoginFrom", qRange("last_login", store.KindDate, "[]", "2026-02-01", "*"), "01 02 04 05 09"},
		{"LastLoginBeforeExcl", qRange("last_login", store.KindDate, "[}", "*", "2026-01-31T03:04:05Z"), "08 11"},
		{"LastLoginBeforeIncl", qRange("last_login", store.KindDate, "[]", "*", "2026-01-31T03:04:05Z"), "07 08 11"},
		{"UpdatedDay", qRange("updated_at", store.KindDate, "[]", "2026-02-08", "2026-02-09"), "03"},
		{"CreatedTermDay", qDate("created_at", "2026-01-05"), "03"},
		{"CreatedTermInstant", qDate("created_at", "2026-01-06T04:04:05+01:00"), "04"},
		// Exists.
		{"ExistsGivenName", qExists("given_name"), "01 02 04 05 06 07 08 10"},
		{"ExistsUsername", qExists("username"), "01 02 04 05 07 09 11 12"},
		{"ExistsLastLogin", qExists("last_login"), "01 02 04 05 07 08 09 11"},
		{"ExistsNestedMeta", qExists("user_metadata.nested.k"), "08"},
		{"ExistsIdentityUserID", qExists("identities.user_id"), allTwelve},
		// Not is plain negation; absent fields never match a term.
		{"NotBlocked", qNot(qBool("blocked", true)), "01 03 04 05 06 07 08 09 10 11 12"},
		{"NotExistsFamilyName", qNot(qExists("family_name")), "03 04 06 10 11 12"},
		{"NotFamilyNameIncludesAbsent", qNot(qStr("family_name", "smith")), "02 03 04 05 06 07 08 09 10 11 12"},
		{"NotFamilyNameWithExists", qAnd(qExists("family_name"), qNot(qStr("family_name", "smith"))), "02 05 07 08 09"},
		// Boolean structure.
		{"Or", qOr(qStr("nickname", "bob"), qStr("nickname", "carol")), "02 03"},
		{"And", qAnd(qWild("email", "*@example.com"), qRange("logins_count", store.KindNumber, "[]", "3", "*")), "01 07 09"},
		{"Nested", qAnd(
			qOr(qWild("email", "*@test.org"), qBool("blocked", true), qStr("user_metadata.color", "red")),
			qNot(qOr(qStr("nickname", "dave"), qRange("logins_count", store.KindNumber, "[]", "3", "*")))), "02 03"},
		{"DoubleNot", qNot(qNot(qStr("nickname", "judy"))), "10"},
		// Metadata: case-sensitive, typed, arrays, nested keys.
		{"MetaString", qStr("user_metadata.color", "red"), "01"},
		{"MetaStringCase", qStr("user_metadata.color", "RED"), ""},
		{"MetaArrayString", qStr("user_metadata.lst", "b"), "09"},
		{"MetaArrayNumber", qNum("app_metadata.nums", "5"), "09"},
		{"MetaArrayNumberNotString", qStr("app_metadata.nums", "5"), ""},
		{"MetaNested", qStr("user_metadata.nested.k", "v"), "08"},
		{"MetaNestedNumber", qNum("user_metadata.nested.n", "5"), "08"},
		{"MetaStringNotNumber", qStr("user_metadata.tier", "2"), "04"},
		{"MetaNumberNotString", qNum("user_metadata.tier", "2"), ""},
		{"MetaFloatEqualsInt", qNum("app_metadata.count", "2"), "12"},
		{"MetaArrayBool", qBool("app_metadata.flags", true), "11"},
	}
}

func testUserList(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	seedList(t, s)

	t.Run("Queries", func(t *testing.T) {
		for _, c := range userListCases() {
			t.Run(c.name, func(t *testing.T) {
				got, total, err := s.Users().List(ctx, "ten_a", c.q, store.UserSort{Field: "user_id"}, store.Page{})
				mustNoErr(t, err)
				mustEqual(t, userIDsOf(got), ids(c.want))
				mustEqual(t, total, len(ids(c.want)))
			})
		}
	})

	t.Run("DefaultOrder", func(t *testing.T) {
		got, total, err := s.Users().List(ctx, "ten_a", nil, store.UserSort{}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, userIDsOf(got), ids("09 04 05 02 01 07 08 11 03 06 10 12"))
		mustEqual(t, total, 12)
	})

	t.Run("LastLoginAscending", func(t *testing.T) {
		got, _, err := s.Users().List(ctx, "ten_a", nil, store.UserSort{Field: "last_login"}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, userIDsOf(got), ids("03 06 10 12 11 08 07 01 02 04 05 09"))
	})

	t.Run("NameBothWays", func(t *testing.T) {
		got, _, err := s.Users().List(ctx, "ten_a", nil, store.UserSort{Field: "name"}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, userIDsOf(got), ids("06 01 02 03 04 05 07 08 09 10 11 12"))
		got, _, err = s.Users().List(ctx, "ten_a", nil, store.UserSort{Field: "name", Desc: true}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, userIDsOf(got), ids("12 11 10 09 08 07 05 04 03 02 01 06"))
	})

	t.Run("TiesBreakOnUserID", func(t *testing.T) {
		got, _, err := s.Users().List(ctx, "ten_a", nil, store.UserSort{Field: "email_verified"}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, userIDsOf(got), ids("02 04 06 09 11 12 01 03 05 07 08 10"))
		got, _, err = s.Users().List(ctx, "ten_a", nil, store.UserSort{Field: "email_verified", Desc: true}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, userIDsOf(got), ids("01 03 05 07 08 10 02 04 06 09 11 12"))
	})

	// Every sortable field, both ways, against a reference order: users
	// without the value first ascending and last descending, strings
	// case-insensitive, ties on user_id ascending.
	t.Run("EverySortField", func(t *testing.T) {
		var fixtures []*store.User
		for _, f := range listFixtures() {
			u, err := s.Users().Get(ctx, "ten_a", f.u.UserID)
			mustNoErr(t, err)
			fixtures = append(fixtures, u)
		}
		for _, field := range sortFields {
			for _, desc := range []bool{false, true} {
				want := slices.Clone(fixtures)
				slices.SortStableFunc(want, func(a, b *store.User) int { return refCompare(a, b, field, desc) })
				got, total, err := s.Users().List(ctx, "ten_a", nil, store.UserSort{Field: field, Desc: desc}, store.Page{})
				mustNoErr(t, err)
				if diff := cmpIDs(userIDsOf(got), userIDsOf(want)); diff != "" {
					t.Errorf("sort %s desc=%v: %s", field, desc, diff)
				}
				mustEqual(t, total, 12)
			}
		}
	})

	t.Run("Paging", func(t *testing.T) {
		got, total, err := s.Users().List(ctx, "ten_a", nil, store.UserSort{}, store.Page{Offset: 2, Limit: 3})
		mustNoErr(t, err)
		mustEqual(t, userIDsOf(got), ids("05 02 01"))
		mustEqual(t, total, 12)

		q := qWild("email", "*@example.com")
		got, total, err = s.Users().List(ctx, "ten_a", q, store.UserSort{Field: "user_id", Desc: true}, store.Page{Offset: 1, Limit: 2})
		mustNoErr(t, err)
		mustEqual(t, userIDsOf(got), ids("10 09"))
		mustEqual(t, total, 9)

		got, total, err = s.Users().List(ctx, "ten_a", q, store.UserSort{}, store.Page{Offset: 50, Limit: 2})
		mustNoErr(t, err)
		mustEqual(t, len(got), 0)
		mustEqual(t, total, 9)
	})

	t.Run("FullUsers", func(t *testing.T) {
		got, _, err := s.Users().List(ctx, "ten_a", qStr("nickname", "alice"), store.UserSort{}, store.Page{})
		mustNoErr(t, err)
		want, err := s.Users().Get(ctx, "ten_a", "auth0|u01")
		mustNoErr(t, err)
		mustEqual(t, got, []*store.User{want})
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		got, total, err := s.Users().List(ctx, "ten_b", nil, store.UserSort{}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, userIDsOf(got), ids("01"))
		mustEqual(t, total, 1)
		got, _, err = s.Users().List(ctx, "ten_b", qStr("app_metadata.plan", "pro"), store.UserSort{}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, got[0].TenantID, "ten_b")
		got, total, err = s.Users().List(ctx, "ten_c", nil, store.UserSort{}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, len(got), 0)
		mustEqual(t, total, 0)
	})

	t.Run("BadTrees", func(t *testing.T) {
		bad := map[string]*store.UserQuery{
			"UnknownField":       qStr("bogus_field", "x"),
			"BareMetadata":       qStr("app_metadata", "x"),
			"EmptyMetadataKey":   qStr("app_metadata.", "x"),
			"EmptyMetadataPart":  qStr("user_metadata.a..b", "x"),
			"QuoteInMetadataKey": qStr(`app_metadata.a"b`, "x"),
			"UnknownIdentity":    qStr("identities.bogus", "x"),
			"WildcardOnMetadata": qWild("app_metadata.plan", "p*"),
			"WildcardOnBool":     qWild("blocked", "t*"),
			"RangeOnString":      qRange("email", store.KindString, "[]", "a", "b"),
			"RangeOnMetadata":    qRange("app_metadata.n", store.KindNumber, "[]", "1", "2"),
			"KindMismatch":       qNum("email", "1"),
			"BadNumber":          qNum("logins_count", "abc"),
			"BadBool":            &store.UserQuery{Op: store.QueryTerm, Field: "blocked", Kind: store.KindBool, Value: "maybe"},
			"BadDate":            qDate("created_at", "yesterday"),
			"DateOnMetadata":     qDate("app_metadata.when", "2026-01-01"),
			"NotWithoutKid":      {Op: store.QueryNot},
			"AndWithoutKids":     {Op: store.QueryAnd},
			"NilKid":             qOr(qStr("email", "x"), nil),
			"UnknownOp":          {Op: store.QueryOp(99)},
		}
		for name, q := range bad {
			t.Run(name, func(t *testing.T) {
				if _, _, err := s.Users().List(ctx, "ten_a", q, store.UserSort{}, store.Page{}); err == nil {
					t.Fatal("List accepted a bad tree")
				}
			})
		}
		if _, _, err := s.Users().List(ctx, "ten_a", nil, store.UserSort{Field: "app_metadata.plan"}, store.Page{}); err == nil {
			t.Fatal("List accepted an unknown sort field")
		}
	})
}

// testUserQueryMetadataTypes pins Review Focus 1: app_metadata.plan:pro
// matches the string "pro" and arrays holding it, and nothing else: not
// "PRO", the number 2, true, null, an object, a nested array or an absent
// key. Typed terms match only values of their kind.
func testUserQueryMetadataTypes(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	seedList(t, s)
	for _, c := range []listCase{
		{"StringPro", qStr("app_metadata.plan", "pro"), "01 03 09"},
		{"StringPRO", qStr("app_metadata.plan", "PRO"), "02 11"},
		{"NotStringPro", qNot(qStr("app_metadata.plan", "pro")), "02 04 05 06 07 08 10 11 12"},
		{"Number2", qNum("app_metadata.plan", "2"), "04"},
		{"Number2Point0", qNum("app_metadata.plan", "2.0"), "04"},
		{"String2", qStr("app_metadata.plan", "2"), ""},
		{"BoolTrue", qBool("app_metadata.plan", true), "05"},
		{"StringTrue", qStr("app_metadata.plan", "true"), ""},
		{"BoolFalse", qBool("app_metadata.plan", false), ""},
		{"StringNull", qStr("app_metadata.plan", "null"), ""},
		{"ObjectKey", qStr("app_metadata.plan.name", "pro"), "07"},
		{"Exists", qExists("app_metadata.plan"), "01 02 03 04 05 07 08 09 11"},
		{"NotExists", qNot(qExists("app_metadata.plan")), "06 10 12"},
		// Booleans and numbers never cross: true is not 1, in a scalar or an array.
		{"BoolTrueNotNumberOne", qBool("app_metadata.x", true), "03 04"},
		{"NumberOneNotBoolTrue", qNum("app_metadata.x", "1"), "01 02"},
		{"BoolFalseNotNumberZero", qBool("app_metadata.x", false), ""},
		{"NumberZeroNotBoolFalse", qNum("app_metadata.x", "0"), ""},
		{"StringOneNotNumber", qStr("app_metadata.x", "1"), ""},
		{"StringTrueNotBool", qStr("app_metadata.x", "true"), ""},
		{"OtherTenantUnseen", qAnd(qStr("app_metadata.plan", "pro"), qStr("email", "alice@example.com")), "01"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, total, err := s.Users().List(ctx, "ten_a", c.q, store.UserSort{Field: "user_id"}, store.Page{})
			mustNoErr(t, err)
			mustEqual(t, userIDsOf(got), ids(c.want))
			mustEqual(t, total, len(ids(c.want)))
		})
	}
}

var sortFields = []string{"user_id", "email", "email_verified", "name", "given_name", "family_name", "nickname", "username",
	"phone_number", "phone_verified", "blocked", "created_at", "updated_at", "last_login", "logins_count", "last_ip"}

// refCompare is the reference order the sort tests check drivers against,
// written independently of any driver.
func refCompare(a, b *store.User, field string, desc bool) int {
	str := map[string]func(*store.User) string{
		"user_id": func(u *store.User) string { return u.UserID }, "email": func(u *store.User) string { return u.Email },
		"name": func(u *store.User) string { return u.Name }, "given_name": func(u *store.User) string { return u.GivenName },
		"family_name": func(u *store.User) string { return u.FamilyName }, "nickname": func(u *store.User) string { return u.Nickname },
		"username": func(u *store.User) string { return u.Username }, "phone_number": func(u *store.User) string { return u.PhoneNumber },
		"last_ip": func(u *store.User) string { return u.LastIP },
	}
	b2i := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	var c int
	switch field {
	case "email_verified":
		c = cmp.Compare(b2i(a.EmailVerified), b2i(b.EmailVerified))
	case "phone_verified":
		c = cmp.Compare(b2i(a.PhoneVerified), b2i(b.PhoneVerified))
	case "blocked":
		c = cmp.Compare(b2i(a.Blocked), b2i(b.Blocked))
	case "logins_count":
		c = cmp.Compare(a.LoginsCount, b.LoginsCount)
	case "created_at":
		c = a.CreatedAt.Compare(b.CreatedAt)
	case "updated_at":
		c = a.UpdatedAt.Compare(b.UpdatedAt)
	case "last_login":
		switch {
		case a.LastLogin == nil && b.LastLogin == nil:
		case a.LastLogin == nil:
			c = -1
		case b.LastLogin == nil:
			c = 1
		default:
			c = a.LastLogin.Compare(*b.LastLogin)
		}
	default:
		c = strings.Compare(strings.ToLower(str[field](a)), strings.ToLower(str[field](b)))
	}
	if desc {
		c = -c
	}
	return cmp.Or(c, strings.Compare(a.UserID, b.UserID))
}

func cmpIDs(got, want []string) string {
	if slices.Equal(got, want) {
		return ""
	}
	return "got " + strings.Join(got, ",") + " want " + strings.Join(want, ",")
}
