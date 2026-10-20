package store

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// QueryOp is the operator of a UserQuery node.
type QueryOp int

const (
	// QueryAll matches every user.
	QueryAll QueryOp = iota
	// QueryAnd matches when every kid matches.
	QueryAnd
	// QueryOr matches when any kid matches.
	QueryOr
	// QueryNot matches when its single kid does not.
	QueryNot
	// QueryTerm matches a field equal to Value.
	QueryTerm
	// QueryWildcard matches a root string field against the glob Value.
	QueryWildcard
	// QueryRange matches a number or date field between Lo and Hi.
	QueryRange
	// QueryExists matches when Field is present and not null.
	QueryExists
)

// ValueKind is the type of a term's or range's value.
type ValueKind int

const (
	KindString ValueKind = iota
	KindBool             // Value "true" or "false"
	KindNumber           // a decimal number
	KindDate             // RFC 3339, or YYYY-MM-DD (midnight UTC)
)

// UserQuery is a user search as a tree, already rewritten from Auth0's query
// syntax by the caller (internal/usersearch). Drivers evaluate the tree only;
// they know nothing of the syntax.
//
// Fields are Auth0's names: the root fields user_id, email, email_verified,
// name, given_name, family_name, nickname, username, phone_number,
// phone_verified, blocked, created_at, updated_at, last_login, logins_count
// and last_ip; identities.connection, identities.provider and
// identities.user_id; and app_metadata.<path> and user_metadata.<path>, with
// dots between nested keys. Any other field is an error. Root fields have
// fixed kinds: the *_verified fields and blocked are KindBool, logins_count
// KindNumber, the dates KindDate, and the rest KindString.
//
// Semantics (D-0043):
//   - Terms and wildcards on root string fields and on identities.* compare
//     case-insensitively; on metadata paths case-sensitively, and only values
//     of the term's Kind match (the number 2 is not the string "2").
//   - A metadata term matches a scalar equal to the value, or an array that
//     contains it as an element. It never looks inside nested arrays or
//     objects; the path itself does not step through arrays.
//   - Wildcards are for root string fields and ranges for logins_count and
//     the dates; the parser refuses others, and drivers return an error.
//     In a glob, * matches any run of characters and \* is a literal star.
//   - Exists is true when the field is present and not null. Root string
//     fields are present when non-empty, last_login when set; the bool
//     fields, logins_count, created_at and updated_at are always present.
//     identities.<f> is present when any identity has a non-empty <f>.
//   - Not is plain negation. An absent field never matches a term, wildcard
//     or range (the parser adds Exists where Auth0 excludes absent fields).
//   - identities.* matches if any identity matches.
//   - Ranges compare numbers as numbers and dates as instants, at
//     microsecond precision. A date term YYYY-MM-DD matches that UTC day; an
//     RFC 3339 term matches the instant.
type UserQuery struct {
	Op     QueryOp
	Kids   []*UserQuery // And, Or (one or more); Not (exactly one)
	Field  string
	Kind   ValueKind
	Value  string  // Term; Wildcard: a glob, `*` anywhere, `\*` a literal star
	Lo, Hi *string // Range; nil = open
	// LoIncl and HiIncl make the bounds inclusive.
	LoIncl, HiIncl bool
}

// UserSort orders a user list by a root field. The zero value is Auth0's
// default order: last_login descending, users who never logged in last. An
// explicit sort puts users without the value first ascending and last
// descending; strings compare case-insensitively. Ties break on user_id
// ascending (byte order).
type UserSort struct {
	Field string
	Desc  bool
}

// FieldClass says where a query field lives.
type FieldClass int

const (
	FieldRoot     FieldClass = iota // a column of the user
	FieldIdentity                   // identities.<Name>, any identity
	FieldMetadata                   // <Name>.<Path...>, Name app_metadata or user_metadata
)

// UserField is a parsed query field.
type UserField struct {
	Class FieldClass
	Name  string    // root field name; identity sub-field; "app_metadata" or "user_metadata"
	Path  []string  // metadata keys, outermost first
	Kind  ValueKind // root and identity fields
}

var rootFieldKinds = map[string]ValueKind{
	"user_id": KindString, "email": KindString, "name": KindString, "given_name": KindString,
	"family_name": KindString, "nickname": KindString, "username": KindString, "phone_number": KindString,
	"last_ip": KindString, "email_verified": KindBool, "phone_verified": KindBool, "blocked": KindBool,
	"logins_count": KindNumber, "created_at": KindDate, "updated_at": KindDate, "last_login": KindDate,
}

// ParseUserField classifies a query field, or returns an error for a field
// that is not searchable. Metadata keys must be non-empty and free of '"',
// '\' and control characters, so every driver can address them.
func ParseUserField(field string) (UserField, error) {
	if k, ok := rootFieldKinds[field]; ok {
		return UserField{Class: FieldRoot, Name: field, Kind: k}, nil
	}
	if sub, ok := strings.CutPrefix(field, "identities."); ok {
		switch sub {
		case "connection", "provider", "user_id":
			return UserField{Class: FieldIdentity, Name: sub, Kind: KindString}, nil
		}
		return UserField{}, fmt.Errorf("store: field %q is not searchable", field)
	}
	for _, m := range []string{"app_metadata", "user_metadata"} {
		rest, ok := strings.CutPrefix(field, m+".")
		if !ok {
			continue
		}
		path := strings.Split(rest, ".")
		for _, p := range path {
			if p == "" || strings.ContainsFunc(p, func(r rune) bool { return r == '"' || r == '\\' || r < 0x20 || r == 0x7f }) {
				return UserField{}, fmt.Errorf("store: field %q is not searchable", field)
			}
		}
		return UserField{Class: FieldMetadata, Name: m, Path: path}, nil
	}
	return UserField{}, fmt.Errorf("store: field %q is not searchable", field)
}

// Validate checks the whole tree: operators, fields, kinds and values. A nil
// tree is valid and matches every user.
func (q *UserQuery) Validate() error {
	if q == nil {
		return nil
	}
	_, err := compileQuery(q)
	return err
}

// Validate checks that s names a root field (or is zero).
func (s UserSort) Validate() error {
	if s.Field == "" {
		return nil
	}
	if _, ok := rootFieldKinds[s.Field]; !ok {
		return fmt.Errorf("store: cannot sort users by %q", s.Field)
	}
	return nil
}

// Effective returns the sort to apply: the zero value becomes last_login
// descending.
func (s UserSort) Effective() UserSort {
	if s.Field == "" {
		return UserSort{Field: "last_login", Desc: true}
	}
	return s
}

// IntBounds returns the inclusive integer bounds a number or date leaf
// selects: logins_count as a count, dates as Unix microseconds. A range or
// term on logins_count with fractional bounds is narrowed to the integers it
// covers; a fractional term gives an empty interval (lo > hi). A date term
// YYYY-MM-DD covers its UTC day.
func (q *UserQuery) IntBounds() (lo, hi int64, err error) {
	f, err := ParseUserField(q.Field)
	if err != nil {
		return 0, 0, err
	}
	if f.Class != FieldRoot || (f.Kind != KindNumber && f.Kind != KindDate) {
		return 0, 0, fmt.Errorf("store: %q has no numeric bounds", q.Field)
	}
	parse := func(v string) (val float64, dayLen int64, err error) {
		if f.Kind == KindNumber {
			n, err := ParseQueryNumber(v)
			return n, 0, err
		}
		m, isDay, err := ParseQueryDate(v)
		if isDay {
			return float64(m), int64(day / time.Microsecond), err
		}
		return float64(m), 1, err
	}
	switch q.Op {
	case QueryTerm:
		v, dl, err := parse(q.Value)
		if err != nil {
			return 0, 0, err
		}
		if f.Kind == KindDate {
			return int64(v), int64(v) + dl - 1, nil
		}
		if v != math.Trunc(v) {
			return 1, 0, nil
		}
		return clampInt(v), clampInt(v), nil
	case QueryRange:
		lo, hi = math.MinInt64, math.MaxInt64
		if q.Lo != nil {
			v, _, err := parse(*q.Lo)
			if err != nil {
				return 0, 0, err
			}
			switch c := math.Ceil(v); {
			case q.LoIncl || c != v:
				lo = clampInt(c)
			default:
				lo = clampInt(v + 1)
			}
		}
		if q.Hi != nil {
			v, _, err := parse(*q.Hi)
			if err != nil {
				return 0, 0, err
			}
			switch fl := math.Floor(v); {
			case q.HiIncl || fl != v:
				hi = clampInt(fl)
			default:
				hi = clampInt(v - 1)
			}
		}
		return lo, hi, nil
	}
	return 0, 0, fmt.Errorf("store: operator %d has no bounds", q.Op)
}

const day = 24 * time.Hour

func clampInt(v float64) int64 {
	switch {
	case v >= math.MaxInt64:
		return math.MaxInt64
	case v <= math.MinInt64:
		return math.MinInt64
	}
	return int64(v)
}

// ParseQueryNumber parses a decimal number value; NaN and infinities are
// refused.
func ParseQueryNumber(v string) (float64, error) {
	n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, fmt.Errorf("store: %q is not a number", v)
	}
	return n, nil
}

// ParseQueryDate parses a date value as Unix microseconds. YYYY-MM-DD is
// midnight UTC (isDay true); otherwise RFC 3339, or RFC 3339 without a zone
// (taken as UTC).
func ParseQueryDate(v string) (micros int64, isDay bool, err error) {
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		return t.UnixMicro(), true, nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UnixMicro(), false, nil
		}
	}
	return 0, false, fmt.Errorf("store: %q is not a date", v)
}

// GlobPieces splits a wildcard glob into its literal pieces: the glob
// matches a value that is pieces[0], any run, pieces[1], …, any run,
// pieces[n-1]. `\*` is a literal star; any other backslash is literal.
func GlobPieces(glob string) []string {
	var pieces []string
	var cur strings.Builder
	for i := 0; i < len(glob); i++ {
		switch {
		case glob[i] == '\\' && i+1 < len(glob) && glob[i+1] == '*':
			cur.WriteByte('*')
			i++
		case glob[i] == '*':
			pieces = append(pieces, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(glob[i])
		}
	}
	return append(pieces, cur.String())
}

// MetadataJSON is the JSON literal a metadata term compares against: a
// string, a number or true/false, by Kind.
func (q *UserQuery) MetadataJSON() (string, error) {
	v, err := q.metadataValue()
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func (q *UserQuery) metadataValue() (any, error) {
	switch q.Kind {
	case KindString:
		return q.Value, nil
	case KindBool:
		return parseQueryBool(q.Value)
	case KindNumber:
		return ParseQueryNumber(q.Value)
	}
	return nil, fmt.Errorf("store: kind %d is not valid on %q", q.Kind, q.Field)
}

func parseQueryBool(v string) (bool, error) {
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("store: %q is not true or false", v)
}

// ---- in-memory evaluation ----

// UserMatcher evaluates a validated query tree against users. Memory and
// tests use it; SQL drivers translate the same tree.
type UserMatcher struct{ root *node }

type node struct {
	q     *UserQuery
	f     UserField
	kids  []*node
	lo    int64 // number and date leaves
	hi    int64
	lower string   // string terms, lowercased
	glob  []string // wildcard pieces, lowercased
	meta  any      // metadata term value: string, bool or float64
}

// NewUserMatcher validates q and prepares it; a nil q matches everyone.
func NewUserMatcher(q *UserQuery) (*UserMatcher, error) {
	if q == nil {
		return &UserMatcher{}, nil
	}
	n, err := compileQuery(q)
	if err != nil {
		return nil, err
	}
	return &UserMatcher{root: n}, nil
}

func compileQuery(q *UserQuery) (*node, error) {
	if q == nil {
		return nil, errors.New("store: nil query node")
	}
	n := &node{q: q}
	switch q.Op {
	case QueryAll:
		return n, nil
	case QueryAnd, QueryOr, QueryNot:
		if len(q.Kids) == 0 || (q.Op == QueryNot && len(q.Kids) != 1) {
			return nil, fmt.Errorf("store: operator %d with %d operands", q.Op, len(q.Kids))
		}
		for _, k := range q.Kids {
			c, err := compileQuery(k)
			if err != nil {
				return nil, err
			}
			n.kids = append(n.kids, c)
		}
		return n, nil
	case QueryTerm, QueryWildcard, QueryRange, QueryExists:
	default:
		return nil, fmt.Errorf("store: unknown query operator %d", q.Op)
	}
	f, err := ParseUserField(q.Field)
	if err != nil {
		return nil, err
	}
	n.f = f
	if q.Op == QueryExists {
		return n, nil
	}
	if f.Class == FieldMetadata {
		if q.Op != QueryTerm {
			return nil, fmt.Errorf("store: operator %d is not supported on %q", q.Op, q.Field)
		}
		n.meta, err = q.metadataValue()
		return n, err
	}
	if q.Kind != f.Kind {
		return nil, fmt.Errorf("store: kind %d is not valid on %q", q.Kind, q.Field)
	}
	switch q.Op {
	case QueryWildcard:
		if f.Class != FieldRoot || f.Kind != KindString {
			return nil, fmt.Errorf("store: wildcard is not supported on %q", q.Field)
		}
		for _, p := range GlobPieces(q.Value) {
			n.glob = append(n.glob, strings.ToLower(p))
		}
	case QueryRange:
		if f.Kind != KindNumber && f.Kind != KindDate {
			return nil, fmt.Errorf("store: range is not supported on %q", q.Field)
		}
		n.lo, n.hi, err = q.IntBounds()
	case QueryTerm:
		switch f.Kind {
		case KindString:
			n.lower = strings.ToLower(q.Value)
		case KindBool:
			_, err = parseQueryBool(q.Value)
		default:
			n.lo, n.hi, err = q.IntBounds()
		}
	}
	return n, err
}

// Match reports whether u matches.
func (m *UserMatcher) Match(u *User) bool {
	if m.root == nil {
		return true
	}
	var md map[string]any // normalized metadata, decoded on first use
	return m.root.match(u, &md)
}

func (n *node) match(u *User, md *map[string]any) bool {
	switch n.q.Op {
	case QueryAll:
		return true
	case QueryAnd:
		for _, k := range n.kids {
			if !k.match(u, md) {
				return false
			}
		}
		return true
	case QueryOr:
		for _, k := range n.kids {
			if k.match(u, md) {
				return true
			}
		}
		return false
	case QueryNot:
		return !n.kids[0].match(u, md)
	}
	switch n.f.Class {
	case FieldIdentity:
		for _, id := range u.Identities {
			v := map[string]string{"connection": id.Connection, "provider": id.Provider, "user_id": id.UserID}[n.f.Name]
			if v != "" && (n.q.Op == QueryExists || strings.ToLower(v) == n.lower) {
				return true
			}
		}
		return false
	case FieldMetadata:
		if *md == nil {
			*md = normalizeMetadata(u)
		}
		v, ok := lookupPath((*md)[n.f.Name], n.f.Path)
		if !ok || v == nil {
			return false
		}
		if n.q.Op == QueryExists {
			return true
		}
		if arr, isArr := v.([]any); isArr {
			for _, e := range arr {
				if e == n.meta {
					return true
				}
			}
			return false
		}
		return v == n.meta
	}
	switch n.f.Kind {
	case KindString:
		v := rootString(u, n.f.Name)
		switch {
		case v == "":
			return false
		case n.q.Op == QueryExists:
			return true
		case n.q.Op == QueryWildcard:
			return globMatch(strings.ToLower(v), n.glob)
		}
		return strings.ToLower(v) == n.lower
	case KindBool:
		if n.q.Op == QueryExists {
			return true
		}
		return strconv.FormatBool(rootBool(u, n.f.Name)) == n.q.Value
	}
	v, ok := rootInt(u, n.f.Name)
	if !ok {
		return false
	}
	if n.q.Op == QueryExists {
		return true
	}
	return n.lo <= v && v <= n.hi
}

func rootString(u *User, name string) string {
	switch name {
	case "user_id":
		return u.UserID
	case "email":
		return u.Email
	case "name":
		return u.Name
	case "given_name":
		return u.GivenName
	case "family_name":
		return u.FamilyName
	case "nickname":
		return u.Nickname
	case "username":
		return u.Username
	case "phone_number":
		return u.PhoneNumber
	case "last_ip":
		return u.LastIP
	}
	return ""
}

func rootBool(u *User, name string) bool {
	switch name {
	case "email_verified":
		return u.EmailVerified
	case "phone_verified":
		return u.PhoneVerified
	case "blocked":
		return u.Blocked
	}
	return false
}

// rootInt returns logins_count, or a date as Unix microseconds; ok is false
// for a last_login that was never set.
func rootInt(u *User, name string) (int64, bool) {
	switch name {
	case "logins_count":
		return int64(u.LoginsCount), true
	case "created_at":
		return u.CreatedAt.UnixMicro(), true
	case "updated_at":
		return u.UpdatedAt.UnixMicro(), true
	case "last_login":
		if u.LastLogin == nil {
			return 0, false
		}
		return u.LastLogin.UnixMicro(), true
	}
	return 0, false
}

func globMatch(v string, pieces []string) bool {
	if len(pieces) == 1 {
		return v == pieces[0]
	}
	first, last := pieces[0], pieces[len(pieces)-1]
	if len(v) < len(first)+len(last) || !strings.HasPrefix(v, first) || !strings.HasSuffix(v, last) {
		return false
	}
	mid := v[len(first) : len(v)-len(last)]
	for _, p := range pieces[1 : len(pieces)-1] {
		i := strings.Index(mid, p)
		if i < 0 {
			return false
		}
		mid = mid[i+len(p):]
	}
	return true
}

// normalizeMetadata round-trips the user's metadata through JSON, as SQL
// drivers store it: numbers become float64 and slices []any.
func normalizeMetadata(u *User) map[string]any {
	out := map[string]any{"app_metadata": nil, "user_metadata": nil}
	for k, m := range map[string]map[string]any{"app_metadata": u.AppMetadata, "user_metadata": u.UserMetadata} {
		if m == nil {
			continue
		}
		b, err := json.Marshal(m)
		if err != nil {
			continue
		}
		var v any
		if json.Unmarshal(b, &v) == nil {
			out[k] = v
		}
	}
	return out
}

func lookupPath(v any, path []string) (any, bool) {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = m[k]; !ok {
			return nil, false
		}
	}
	return v, true
}

// CompareUsers orders a and b by s (see UserSort). Memory and tests use it.
func CompareUsers(a, b *User, s UserSort) int {
	s = s.Effective()
	var c int
	switch kind := rootFieldKinds[s.Field]; kind {
	case KindString:
		c = strings.Compare(strings.ToLower(rootString(a, s.Field)), strings.ToLower(rootString(b, s.Field)))
	case KindBool:
		ab, bb := rootBool(a, s.Field), rootBool(b, s.Field)
		c = cmp.Compare(boolInt(ab), boolInt(bb))
	default:
		av, aok := rootInt(a, s.Field)
		bv, bok := rootInt(b, s.Field)
		c = cmp.Or(cmp.Compare(boolInt(aok), boolInt(bok)), cmp.Compare(av, bv))
	}
	if s.Desc {
		c = -c
	}
	return cmp.Or(c, strings.Compare(a.UserID, b.UserID))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
