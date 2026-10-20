package usersearch

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

const maxDepth = 64

var (
	errUndefined = &Error{Message: "invalid query: undefined"}
	errAnd       = &Error{Message: "invalid query: 'AND' requires at least one operand on each side"}
	numberRe     = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
	rangeFields  = map[string]bool{"logins_count": true, "created_at": true, "updated_at": true, "last_login": true}
)

func queryErr(format string, args ...any) *Error {
	return &Error{Message: "invalid query: " + fmt.Sprintf(format, args...)}
}

// Parse parses an Auth0 v3 query. An empty or blank q gives nil, which
// matches every user. Every error is an *Error.
//
// Rewrites (D-0043):
//   - A bare term t is Or(name:t, given_name:t, family_name:t, nickname:t,
//     email:t@*, email:*@t). An unescaped * in a bare term is a wildcard
//     in all six (so ali* finds alice, ali@example.com and so on); a
//     quoted or \* star is literal and is escaped in the two email globs.
//     A bare * alone is every user.
//   - Juxtaposition is Or; precedence is NOT, then AND, then Or.
//   - NOT on a root string field also requires the field to be present.
//   - Metadata terms take their kind from the literal.
func Parse(q string) (*store.UserQuery, error) {
	// No driver can store NUL or invalid UTF-8 (Postgres refuses both), so
	// no user can match them; refuse them before they reach one.
	if !utf8.ValidString(q) || strings.ContainsRune(q, 0) {
		return nil, errUndefined
	}
	p := &parser{s: scanner{r: []rune(q)}}
	p.s.skipSpace()
	if p.s.eof() {
		return nil, nil
	}
	tree, err := p.or("", 0)
	if err != nil {
		return nil, err
	}
	p.s.skipSpace()
	if !p.s.eof() { // a stray ')'
		return nil, errUndefined
	}
	return tree, nil
}

type parser struct{ s scanner }

// or parses juxtaposed and OR-joined operands. field is the field of an
// enclosing group value, or "".
func (p *parser) or(field string, depth int) (*store.UserQuery, error) {
	if depth > maxDepth {
		return nil, errUndefined
	}
	var kids []*store.UserQuery
	for {
		k, err := p.and(field, depth)
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
		p.s.skipSpace()
		if p.s.eof() || p.s.peek() == ')' {
			break
		}
		if p.s.keyword("OR") {
			p.s.skipSpace()
			if p.s.eof() || p.s.peek() == ')' {
				return nil, errUndefined
			}
		}
	}
	return join(store.QueryOr, kids), nil
}

func (p *parser) and(field string, depth int) (*store.UserQuery, error) {
	kids := []*store.UserQuery{}
	k, err := p.not(field, depth)
	if err != nil {
		return nil, err
	}
	kids = append(kids, k)
	for {
		p.s.skipSpace()
		if !p.s.keyword("AND") {
			break
		}
		p.s.skipSpace()
		if p.s.eof() || p.s.peek() == ')' {
			return nil, errAnd
		}
		k, err := p.not(field, depth)
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	return join(store.QueryAnd, kids), nil
}

func join(op store.QueryOp, kids []*store.UserQuery) *store.UserQuery {
	if len(kids) == 1 {
		return kids[0]
	}
	return &store.UserQuery{Op: op, Kids: kids}
}

func (p *parser) not(field string, depth int) (*store.UserQuery, error) {
	p.s.skipSpace()
	if p.s.eof() {
		return nil, errUndefined
	}
	if p.s.keyword("AND") {
		return nil, errAnd
	}
	if p.s.keyword("OR") {
		return nil, errUndefined
	}
	neg := p.s.keyword("NOT")
	if !neg && (p.s.peek() == '-' || p.s.peek() == '!') {
		neg = true
		p.s.pos++
		if p.s.atBoundary() { // a lone - or !
			return nil, errUndefined
		}
	}
	if !neg {
		return p.primary(field, depth)
	}
	if depth > maxDepth {
		return nil, errUndefined
	}
	p.s.skipSpace()
	if p.s.eof() || p.s.peek() == ')' {
		return nil, errUndefined
	}
	k, err := p.not(field, depth+1)
	if err != nil {
		return nil, err
	}
	return negate(k), nil
}

// negate is NOT, which on root string fields also excludes users without the
// field (Auth0 does not return them).
func negate(k *store.UserQuery) *store.UserQuery {
	not := &store.UserQuery{Op: store.QueryNot, Kids: []*store.UserQuery{k}}
	if f := rootStringField(k); f != "" {
		return &store.UserQuery{Op: store.QueryAnd, Kids: []*store.UserQuery{{Op: store.QueryExists, Field: f}, not}}
	}
	return not
}

// rootStringField returns the field when every leaf under q is a term or
// wildcard on one root string field, else "".
func rootStringField(q *store.UserQuery) string {
	switch q.Op {
	case store.QueryTerm, store.QueryWildcard:
		if f, err := store.ParseUserField(q.Field); err == nil && f.Class == store.FieldRoot && f.Kind == store.KindString {
			return q.Field
		}
	case store.QueryAnd, store.QueryOr:
		name := ""
		for _, k := range q.Kids {
			n := rootStringField(k)
			if n == "" || (name != "" && n != name) {
				return ""
			}
			name = n
		}
		return name
	}
	return ""
}

func (p *parser) primary(field string, depth int) (*store.UserQuery, error) {
	s := &p.s
	switch s.peek() {
	case ')':
		return nil, errUndefined
	case '(':
		s.pos++
		inner, err := p.or(field, depth+1)
		if err != nil {
			return nil, err
		}
		s.skipSpace()
		if s.peek() != ')' || s.eof() {
			return nil, errUndefined
		}
		s.pos++
		return inner, nil
	}
	if field != "" { // inside field:( ... )
		return p.fieldValue(field, depth)
	}
	if name, after, ok := s.fieldPrefix(); ok {
		s.pos = after
		return p.fieldClause(name, depth)
	}
	v, ok := s.value()
	if !ok {
		return nil, errUndefined
	}
	return bareTerm(v), nil
}

func escapeStars(s string) string { return strings.ReplaceAll(s, "*", `\*`) }

func bareTerm(v val) *store.UserQuery {
	if v.text == "*" {
		return &store.UserQuery{Op: store.QueryAll}
	}
	glob := v.text
	if !v.wild {
		glob = escapeStars(v.plain)
	}
	var kids []*store.UserQuery
	for _, f := range []string{"name", "given_name", "family_name", "nickname"} {
		if v.wild {
			kids = append(kids, &store.UserQuery{Op: store.QueryWildcard, Field: f, Value: glob})
		} else {
			kids = append(kids, &store.UserQuery{Op: store.QueryTerm, Field: f, Value: v.plain})
		}
	}
	kids = append(kids,
		&store.UserQuery{Op: store.QueryWildcard, Field: "email", Value: glob + "@*"},
		&store.UserQuery{Op: store.QueryWildcard, Field: "email", Value: "*@" + glob})
	return &store.UserQuery{Op: store.QueryOr, Kids: kids}
}

// checkField reports a field that is not searchable. app_metadata and
// user_metadata without a key pass here and fail where the operator is known.
func checkField(name string) error {
	if name == "app_metadata" || name == "user_metadata" {
		return nil
	}
	if _, err := store.ParseUserField(name); err != nil {
		return queryErr("field '%s' is not searchable", name)
	}
	return nil
}

// fieldClause parses what follows "field:".
func (p *parser) fieldClause(name string, depth int) (*store.UserQuery, error) {
	s := &p.s
	if name == "_exists_" {
		v, ok := s.value()
		if !ok || v.wild {
			return nil, errUndefined
		}
		if err := checkField(v.plain); err != nil {
			return nil, err
		}
		return leafExists(v.plain)
	}
	if err := checkField(name); err != nil {
		return nil, err
	}
	if s.peek() != '(' && s.atBoundary() {
		return nil, errUndefined // empty value
	}
	if s.peek() == '(' {
		s.pos++
		inner, err := p.or(name, depth+1)
		if err != nil {
			return nil, err
		}
		s.skipSpace()
		if s.peek() != ')' || s.eof() {
			return nil, errUndefined
		}
		s.pos++
		return inner, nil
	}
	return p.fieldValue(name, depth)
}

// fieldValue parses one value for field: a range, a comparison, a quoted
// string or a bare word.
func (p *parser) fieldValue(name string, depth int) (*store.UserQuery, error) {
	s := &p.s
	switch s.peek() {
	case '[', '{':
		return p.rangeValue(name)
	case '>', '<':
		op := string(s.peek())
		s.pos++
		if s.peek() == '=' {
			op += "="
			s.pos++
		}
		v, ok := s.value()
		if !ok {
			return nil, errUndefined
		}
		q := &store.UserQuery{Op: store.QueryRange}
		bound := &v.plain
		if op[0] == '>' {
			q.Lo, q.LoIncl = bound, len(op) == 2
		} else {
			q.Hi, q.HiIncl = bound, len(op) == 2
		}
		return leafRange(name, q, map[string]string{">": "greater", ">=": "greater or equal", "<": "less", "<=": "less or equal"}[op])
	}
	v, ok := s.value()
	if !ok {
		return nil, errUndefined
	}
	return leafTerm(name, v)
}

func (p *parser) rangeValue(name string) (*store.UserQuery, error) {
	s := &p.s
	open := s.peek()
	s.pos++
	save := s.stop
	s.stop = "]}"
	defer func() { s.stop = save }()
	bound := func() (*string, bool) {
		s.skipSpace()
		v, ok := s.value()
		if !ok {
			return nil, false
		}
		if !v.quoted && v.text == "*" {
			return nil, true
		}
		return &v.plain, true
	}
	lo, ok := bound()
	if !ok {
		return nil, errUndefined
	}
	s.skipSpace()
	if !s.keyword("TO") {
		return nil, errUndefined
	}
	hi, ok := bound()
	if !ok {
		return nil, errUndefined
	}
	s.skipSpace()
	closer := s.peek()
	if s.eof() || (closer != ']' && closer != '}') {
		return nil, errUndefined
	}
	s.pos++
	q := &store.UserQuery{Op: store.QueryRange, Lo: lo, Hi: hi, LoIncl: open == '[', HiIncl: closer == ']'}
	opName := "greater"
	switch {
	case lo != nil && q.LoIncl:
		opName = "greater or equal"
	case lo == nil && hi != nil && q.HiIncl:
		opName = "less or equal"
	case lo == nil && hi != nil:
		opName = "less"
	case lo == nil && q.LoIncl:
		opName = "greater or equal"
	}
	return leafRange(name, q, opName)
}

func keyRequired(name, op string) *Error {
	return queryErr("operator '%s' requires a key on field '%s'", op, name)
}

func notSupported(name, op string) *Error {
	return queryErr("operator '%s' is not supported on field '%s'", op, name)
}

func leafExists(name string) (*store.UserQuery, error) {
	if name == "app_metadata" || name == "user_metadata" {
		return nil, keyRequired(name, "exists")
	}
	return &store.UserQuery{Op: store.QueryExists, Field: name}, nil
}

func leafRange(name string, q *store.UserQuery, op string) (*store.UserQuery, error) {
	if name == "app_metadata" || name == "user_metadata" {
		return nil, keyRequired(name, op)
	}
	f, _ := store.ParseUserField(name)
	if !rangeFields[name] {
		return nil, notSupported(name, op)
	}
	q.Field, q.Kind = name, f.Kind
	for _, b := range []**string{&q.Lo, &q.Hi} {
		if *b == nil {
			continue
		}
		v, err := coerce(f.Kind, **b)
		if err != nil {
			return nil, err
		}
		*b = &v
	}
	return q, nil
}

// coerce makes a literal fit a root field's kind: a number that is not one is
// 0 and a bool that is not true is false (as Auth0 does); a bad date is a
// syntax error.
func coerce(kind store.ValueKind, v string) (string, error) {
	switch kind {
	case store.KindBool:
		if strings.EqualFold(v, "true") {
			return "true", nil
		}
		return "false", nil
	case store.KindNumber:
		if _, err := store.ParseQueryNumber(v); err != nil {
			return "0", nil
		}
		return v, nil
	case store.KindDate:
		if _, _, err := store.ParseQueryDate(v); err != nil {
			return "", errUndefined
		}
	}
	return v, nil
}

func leafTerm(name string, v val) (*store.UserQuery, error) {
	if name == "app_metadata" || name == "user_metadata" {
		op := "equals"
		if v.wild {
			op = "wildcard"
		}
		return nil, keyRequired(name, op)
	}
	f, _ := store.ParseUserField(name)
	if f.Class == store.FieldMetadata {
		if v.wild {
			return nil, notSupported(name, "wildcard")
		}
		q := &store.UserQuery{Op: store.QueryTerm, Field: name, Kind: store.KindString, Value: v.plain}
		if !v.quoted {
			switch {
			case v.plain == "true" || v.plain == "false":
				q.Kind = store.KindBool
			case numberRe.MatchString(v.plain):
				q.Kind = store.KindNumber
			}
		}
		return q, nil
	}
	if v.wild {
		if v.text == "*" {
			return &store.UserQuery{Op: store.QueryExists, Field: name}, nil
		}
		if f.Class != store.FieldRoot || f.Kind != store.KindString {
			return nil, notSupported(name, "wildcard")
		}
		return &store.UserQuery{Op: store.QueryWildcard, Field: name, Kind: store.KindString, Value: v.text}, nil
	}
	val, err := coerce(f.Kind, v.plain)
	if err != nil {
		return nil, err
	}
	return &store.UserQuery{Op: store.QueryTerm, Field: name, Kind: f.Kind, Value: val}, nil
}
