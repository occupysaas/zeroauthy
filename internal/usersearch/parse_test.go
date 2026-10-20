package usersearch

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Compact constructors for expected trees.
func term(f, v string) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryTerm, Field: f, Kind: store.KindString, Value: v}
}
func termK(f string, k store.ValueKind, v string) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryTerm, Field: f, Kind: k, Value: v}
}
func wild(f, v string) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryWildcard, Field: f, Kind: store.KindString, Value: v}
}
func exists(f string) *store.UserQuery { return &store.UserQuery{Op: store.QueryExists, Field: f} }
func and(k ...*store.UserQuery) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryAnd, Kids: k}
}
func or(k ...*store.UserQuery) *store.UserQuery { return &store.UserQuery{Op: store.QueryOr, Kids: k} }
func not(k *store.UserQuery) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryNot, Kids: []*store.UserQuery{k}}
}
func str(s string) *string { return &s }
func rng(f string, k store.ValueKind, lo, hi *string, li, hiIncl bool) *store.UserQuery {
	return &store.UserQuery{Op: store.QueryRange, Field: f, Kind: k, Lo: lo, Hi: hi, LoIncl: li, HiIncl: hiIncl}
}
func bare(t string) *store.UserQuery {
	return or(term("name", t), term("given_name", t), term("family_name", t), term("nickname", t),
		wild("email", t+"@*"), wild("email", "*@"+t))
}
func bareLit(t string) *store.UserQuery {
	e := strings.ReplaceAll(t, "*", `\*`)
	return or(term("name", t), term("given_name", t), term("family_name", t), term("nickname", t),
		wild("email", e+"@*"), wild("email", "*@"+e))
}
func notRoot(f string, q *store.UserQuery) *store.UserQuery { return and(exists(f), not(q)) }

func TestParseTrees(t *testing.T) {
	num, boolK, date := store.KindNumber, store.KindBool, store.KindDate
	cases := []struct {
		name, q string
		want    *store.UserQuery
	}{
		// Auth0's documented examples.
		{"name exact", `name:"jane smith"`, term("name", "jane smith")},
		{"email", `email:"john@example.com"`, term("email", "john@example.com")},
		{"user_id escaped pipe", `user_id:auth0\|abc`, term("user_id", "auth0|abc")},
		{"user_id quoted", `user_id:"auth0|abc"`, term("user_id", "auth0|abc")},
		{"and", `name:"jane smith" AND email_verified:true`, and(term("name", "jane smith"), termK("email_verified", boolK, "true"))},
		{"or", `name:a OR name:b`, or(term("name", "a"), term("name", "b"))},
		{"juxtaposition is or", `name:a name:b`, or(term("name", "a"), term("name", "b"))},
		{"not root string", `NOT family_name:x`, notRoot("family_name", term("family_name", "x"))},
		{"dash not", `-family_name:x`, notRoot("family_name", term("family_name", "x"))},
		{"bang not", `!given_name:x`, notRoot("given_name", term("given_name", "x"))},
		{"not on bool is plain", `NOT blocked:true`, not(termK("blocked", boolK, "true"))},
		{"not on number is plain", `NOT logins_count:5`, not(termK("logins_count", num, "5"))},
		{"not on metadata is plain", `NOT app_metadata.k:x`, not(term("app_metadata.k", "x"))},
		{"not on identities plain", `NOT identities.connection:x`, not(term("identities.connection", "x"))},
		{"not wildcard root", `NOT email:*@x.com`, notRoot("email", wild("email", "*@x.com"))},
		{"not group value", `NOT name:(a OR b)`, notRoot("name", or(term("name", "a"), term("name", "b")))},
		{"not parens plain", `NOT (name:a OR nickname:b)`, not(or(term("name", "a"), term("nickname", "b")))},
		{"group value", `email:(a@x.com OR b@x.com)`, or(term("email", "a@x.com"), term("email", "b@x.com"))},
		{"group", `(name:a OR name:b) AND blocked:false`, and(or(term("name", "a"), term("name", "b")), termK("blocked", boolK, "false"))},
		{"double not", `NOT NOT name:a`, not(notRoot("name", term("name", "a")))},
		{"exists", `_exists_:phone_number`, exists("phone_number")},
		{"exists metadata", `_exists_:app_metadata.plan`, exists("app_metadata.plan")},
		{"all", `*`, &store.UserQuery{Op: store.QueryAll}},
		{"email star is exists", `email:*`, exists("email")},
		{"leading star", `name:*obs`, wild("name", "*obs")},
		{"trailing star", `email:o*`, wild("email", "o*")},
		{"quoted star literal", `email:"obs*"`, term("email", "obs*")},
		{"escaped star literal in wildcard", `name:a\*b*`, wild("name", `a\*b*`)},
		{"escaped star alone is a term", `name:a\*b`, term("name", "a*b")},
		{"identities", `identities.connection:"Username-Password-Authentication"`, term("identities.connection", "Username-Password-Authentication")},
		{"last_ip star", `last_ip:*`, exists("last_ip")},
		{"case of root value kept", `email:OBS@Example.com`, term("email", "OBS@Example.com")},
		// Bare terms.
		{"bare", `alice`, bare("alice")},
		{"bare email", `alice+x@example.com`, bare("alice+x@example.com")},
		{"bare trailing space", "alice ", bare("alice")},
		{"bare quoted phrase", `"bea obs"`, bare("bea obs")},
		{"bare quoted star literal", `"a*"`, bareLit("a*")},
		{"bare star glob", `ali*`, or(wild("name", "ali*"), wild("given_name", "ali*"), wild("family_name", "ali*"),
			wild("nickname", "ali*"), wild("email", "ali*@*"), wild("email", "*@ali*"))},
		{"bare escaped star", `a\*`, bareLit("a*")},
		{"two bare words", `alice bob`, or(bare("alice"), bare("bob"))},
		{"bare not", `NOT alice`, not(bare("alice"))},
		{"bare then field", `alice AND blocked:true`, and(bare("alice"), termK("blocked", boolK, "true"))},
		// Typed values.
		{"logins_count term", `logins_count:5`, termK("logins_count", num, "5")},
		{"logins_count abc is 0", `logins_count:abc`, termK("logins_count", num, "0")},
		{"bool maybe is false", `email_verified:maybe`, termK("email_verified", boolK, "false")},
		{"bool True", `blocked:TRUE`, termK("blocked", boolK, "true")},
		{"date term", `created_at:2026-10-19`, termK("created_at", date, "2026-10-19")},
		{"datetime term", `last_login:2026-10-19T21:22:30`, termK("last_login", date, "2026-10-19T21:22:30")},
		// Metadata literals.
		{"meta string", `app_metadata.plan:pro`, term("app_metadata.plan", "pro")},
		{"meta quoted number is string", `app_metadata.tier:"2"`, term("app_metadata.tier", "2")},
		{"meta number", `app_metadata.tier:2`, termK("app_metadata.tier", num, "2")},
		{"meta decimal", `user_metadata.n:-2.5e3`, termK("user_metadata.n", num, "-2.5e3")},
		{"meta bool", `user_metadata.ok:true`, termK("user_metadata.ok", boolK, "true")},
		{"meta quoted bool is string", `user_metadata.ok:"true"`, term("user_metadata.ok", "true")},
		{"meta TRUE is string", `user_metadata.ok:TRUE`, term("user_metadata.ok", "TRUE")},
		{"meta nested", `app_metadata.obj.k:v`, term("app_metadata.obj.k", "v")},
		{"meta quoted star literal", `user_metadata.c:"a*"`, term("user_metadata.c", "a*")},
		{"meta nan is string", `user_metadata.c:NaN`, term("user_metadata.c", "NaN")},
		// Ranges.
		{"incl range", `logins_count:[1 TO 5]`, rng("logins_count", num, str("1"), str("5"), true, true)},
		{"excl range", `logins_count:{1 TO 5}`, rng("logins_count", num, str("1"), str("5"), false, false)},
		{"mixed range", `logins_count:{1 TO 5]`, rng("logins_count", num, str("1"), str("5"), false, true)},
		{"mixed range 2", `logins_count:[1 TO 5}`, rng("logins_count", num, str("1"), str("5"), true, false)},
		{"open hi", `logins_count:[1 TO *]`, rng("logins_count", num, str("1"), nil, true, true)},
		{"open lo", `created_at:[* TO 2026-10-19]`, rng("created_at", date, nil, str("2026-10-19"), true, true)},
		{"date range", `last_login:[2026-01-01 TO 2026-10-19T21:22:30]`, rng("last_login", date, str("2026-01-01"), str("2026-10-19T21:22:30"), true, true)},
		{"gt", `logins_count:>5`, rng("logins_count", num, str("5"), nil, false, false)},
		{"gte", `logins_count:>=5`, rng("logins_count", num, str("5"), nil, true, false)},
		{"lt", `updated_at:<2026-10-19`, rng("updated_at", date, nil, str("2026-10-19"), false, false)},
		{"lte", `updated_at:<=2026-10-19`, rng("updated_at", date, nil, str("2026-10-19"), false, true)},
		{"range in group", `logins_count:([1 TO 2] OR 9)`, or(rng("logins_count", num, str("1"), str("2"), true, true), termK("logins_count", num, "9"))},
		// Whitespace and parentheses.
		{"tabs and newlines", "name:a\tAND\nname:b", and(term("name", "a"), term("name", "b"))},
		{"adjacent parens", `(name:a)(name:b)`, or(term("name", "a"), term("name", "b"))},
		{"nested", `((name:a))`, term("name", "a")},
		{"escaped quote", `name:"a \"b\" c"`, term("name", `a "b" c`)},
		{"escaped backslash", `name:"a\\b"`, term("name", `a\b`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.q)
			if err != nil {
				t.Fatalf("Parse(%q): %v", c.q, err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("Parse(%q)\n got %s\nwant %s", c.q, dump(got), dump(c.want))
			}
		})
	}
}

func TestPrecedence(t *testing.T) {
	got, err := Parse(`name:a OR name:b AND name:c`)
	if err != nil {
		t.Fatal(err)
	}
	want := or(term("name", "a"), and(term("name", "b"), term("name", "c")))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %s", dump(got))
	}
	got, _ = Parse(`NOT blocked:true AND name:c`)
	want = and(not(termK("blocked", store.KindBool, "true")), term("name", "c"))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("not binds tighter than and: got %s", dump(got))
	}
	got, _ = Parse(`name:a AND name:b OR name:c AND name:d`)
	want = or(and(term("name", "a"), term("name", "b")), and(term("name", "c"), term("name", "d")))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %s", dump(got))
	}
	got, _ = Parse(`name:a OR name:b OR name:c`)
	if !reflect.DeepEqual(got, or(term("name", "a"), term("name", "b"), term("name", "c"))) {
		t.Errorf("or chain: got %s", dump(got))
	}
}

func TestEmptyIsNil(t *testing.T) {
	for _, q := range []string{"", " ", "\t\n "} {
		got, err := Parse(q)
		if got != nil || err != nil {
			t.Errorf("Parse(%q) = %v, %v; want nil, nil", q, got, err)
		}
	}
}

func TestParseErrors(t *testing.T) {
	const undefined = "invalid query: undefined"
	cases := []struct{ q, msg string }{
		{`bogus_field:x`, "invalid query: field 'bogus_field' is not searchable"},
		{`NOT bogus_field:x`, "invalid query: field 'bogus_field' is not searchable"},
		{`bogus_field:(a OR b)`, "invalid query: field 'bogus_field' is not searchable"},
		{`_exists_:bogus`, "invalid query: field 'bogus' is not searchable"},
		{`identities.nope:x`, "invalid query: field 'identities.nope' is not searchable"},
		{`app_metadata.:x`, "invalid query: field 'app_metadata.' is not searchable"},
		{`user_metadata.color:o*`, "invalid query: operator 'wildcard' is not supported on field 'user_metadata.color'"},
		{`user_metadata.color:*`, "invalid query: operator 'wildcard' is not supported on field 'user_metadata.color'"},
		{`app_metadata.tier:[1 TO 5]`, "invalid query: operator 'greater or equal' is not supported on field 'app_metadata.tier'"},
		{`app_metadata.tier:{1 TO 5]`, "invalid query: operator 'greater' is not supported on field 'app_metadata.tier'"},
		{`app_metadata.tier:>5`, "invalid query: operator 'greater' is not supported on field 'app_metadata.tier'"},
		{`app_metadata.tier:>=5`, "invalid query: operator 'greater or equal' is not supported on field 'app_metadata.tier'"},
		{`app_metadata.tier:<5`, "invalid query: operator 'less' is not supported on field 'app_metadata.tier'"},
		{`app_metadata.tier:<=5`, "invalid query: operator 'less or equal' is not supported on field 'app_metadata.tier'"},
		{`app_metadata.tier:[* TO 5]`, "invalid query: operator 'less or equal' is not supported on field 'app_metadata.tier'"},
		{`email:[a TO b]`, "invalid query: operator 'greater or equal' is not supported on field 'email'"},
		{`blocked:[1 TO 2]`, "invalid query: operator 'greater or equal' is not supported on field 'blocked'"},
		{`logins_count:5*`, "invalid query: operator 'wildcard' is not supported on field 'logins_count'"},
		{`identities.connection:db*`, "invalid query: operator 'wildcard' is not supported on field 'identities.connection'"},
		{`app_metadata:pro`, "invalid query: operator 'equals' requires a key on field 'app_metadata'"},
		{`user_metadata:"pro"`, "invalid query: operator 'equals' requires a key on field 'user_metadata'"},
		{`_exists_:app_metadata`, "invalid query: operator 'exists' requires a key on field 'app_metadata'"},
		{`AND`, "invalid query: 'AND' requires at least one operand on each side"},
		{`AND name:a`, "invalid query: 'AND' requires at least one operand on each side"},
		{`name:a AND`, "invalid query: 'AND' requires at least one operand on each side"},
		{`(name:a AND)`, "invalid query: 'AND' requires at least one operand on each side"},
		{`name:"abc`, undefined},
		{`"abc`, undefined},
		{`name:a"b`, undefined},
		{`(name:a`, undefined},
		{`name:a)`, undefined},
		{`)`, undefined},
		{`()`, undefined},
		{`(`, undefined},
		{`email:`, undefined},
		{`email: x`, undefined},
		{`email:)`, undefined},
		{`name:()`, undefined},
		{`name:(a OR`, undefined},
		{`OR`, undefined},
		{`OR name:a`, undefined},
		{`name:a OR`, undefined},
		{`NOT`, undefined},
		{`name:a NOT`, undefined},
		{`-`, undefined},
		{`!`, undefined},
		{`- name:a`, undefined},
		{`logins_count:[1 TO`, undefined},
		{`logins_count:[1 5]`, undefined},
		{`logins_count:[1 TO 5`, undefined},
		{`logins_count:>`, undefined},
		{`created_at:notadate`, undefined},
		{`created_at:[a TO b]`, undefined},
		{`_exists_:`, undefined},
		{`_exists_:a*`, undefined},
		{strings.Repeat("(", 5000) + "name:a" + strings.Repeat(")", 5000), undefined},
		{strings.Repeat("NOT ", 5000) + "name:a", undefined},
	}
	for _, c := range cases {
		t.Run(c.q[:min(len(c.q), 40)], func(t *testing.T) {
			got, err := Parse(c.q)
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("Parse(%q) = %s, %v; want an *Error", c.q, dump(got), err)
			}
			if e.Message != c.msg || e.Code != "" {
				t.Errorf("Parse(%q) error = %q (code %q); want %q", c.q, e.Message, e.Code, c.msg)
			}
		})
	}
}

func TestParseSort(t *testing.T) {
	ok := []struct {
		s    string
		want store.UserSort
	}{
		{"created_at:1", store.UserSort{Field: "created_at"}},
		{"created_at:-1", store.UserSort{Field: "created_at", Desc: true}},
		{"email:1", store.UserSort{Field: "email"}},
		{"logins_count:-1", store.UserSort{Field: "logins_count", Desc: true}},
		{"last_login:1", store.UserSort{Field: "last_login"}},
		{"bogus:1", store.UserSort{}},
		{"app_metadata.plan:1", store.UserSort{}},
		{"identities.connection:-1", store.UserSort{}},
		{"", store.UserSort{}},
	}
	for _, c := range ok {
		got, err := ParseSort(c.s)
		if err != nil || got != c.want {
			t.Errorf("ParseSort(%q) = %+v, %v; want %+v", c.s, got, err, c.want)
		}
	}
	for _, s := range []string{"created_at", "created_at:2", "created_at:0", ":1", "created_at:1 ", " created_at:1", "a b:1", "created_at:+1", "created_at:1\n", "created_at:-1:1", "ü:1"} {
		_, err := ParseSort(s)
		var e *Error
		if !errors.As(err, &e) {
			t.Errorf("ParseSort(%q) err = %v; want *Error", s, err)
			continue
		}
		want := `Query validation error: 'String does not match pattern ^(([a-zA-Z0-9_\\.]+))\:(1|-1)$: ` + s +
			`' on property sort (Field to sort by. Use <code>field:order</code> where order is <code>1</code> for ascending and <code>-1</code> for descending. e.g. <code>created_at:1</code>).`
		if e.Message != want || e.Code != "invalid_query_string" {
			t.Errorf("ParseSort(%q) = %q, %q", s, e.Message, e.Code)
		}
	}
}

func TestFields(t *testing.T) {
	if f := Fields["logins_count"]; f.Kind != store.KindNumber || !f.Sortable || f.Prefix {
		t.Errorf("logins_count = %+v", f)
	}
	if f := Fields["app_metadata"]; !f.Prefix || f.Sortable {
		t.Errorf("app_metadata = %+v", f)
	}
	if f := Fields["identities.provider"]; f.Sortable {
		t.Errorf("identities.provider sortable")
	}
	if Fields["created_at"].Kind != store.KindDate || Fields["blocked"].Kind != store.KindBool {
		t.Error("kinds")
	}
}

func dump(q *store.UserQuery) string {
	if q == nil {
		return "<nil>"
	}
	var b strings.Builder
	var rec func(*store.UserQuery)
	rec = func(q *store.UserQuery) {
		switch q.Op {
		case store.QueryAll:
			b.WriteString("ALL")
		case store.QueryAnd, store.QueryOr, store.QueryNot:
			b.WriteString([]string{"", "AND", "OR", "NOT"}[q.Op] + "(")
			for i, k := range q.Kids {
				if i > 0 {
					b.WriteString(", ")
				}
				rec(k)
			}
			b.WriteString(")")
		case store.QueryTerm:
			b.WriteString(q.Field + "=" + q.Value + "/" + string(rune('0'+q.Kind)))
		case store.QueryWildcard:
			b.WriteString(q.Field + "~" + q.Value)
		case store.QueryExists:
			b.WriteString("EXISTS " + q.Field)
		case store.QueryRange:
			p := func(s *string) string {
				if s == nil {
					return "*"
				}
				return *s
			}
			b.WriteString(q.Field + " in " + p(q.Lo) + ".." + p(q.Hi))
		}
	}
	rec(q)
	return b.String()
}
