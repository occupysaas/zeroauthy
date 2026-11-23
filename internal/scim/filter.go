// Package scim is the inbound SCIM 2.0 service provider of enterprise
// connections (Plan 37c, D-0150): RFC 7644 Users and Groups at
// /scim/v2/connections/{connection_id}, authorized by the connection's
// SCIM tokens.
package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Schema URNs (RFC 7643).
const (
	CoreUser        = "urn:ietf:params:scim:schemas:core:2.0:User"
	CoreGroup       = "urn:ietf:params:scim:schemas:core:2.0:Group"
	EnterpriseUser  = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	ListResponseURN = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	PatchOpURN      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ErrorURN        = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// Limits on untrusted filters and paths.
const (
	maxFilterBytes = 1024
	maxPathBytes   = 256
	maxDepth       = 16
)

// errInvalid is a filter or path the server cannot accept (scimType
// invalidFilter or invalidPath).
var errInvalid = errors.New("scim: invalid expression")

// Op is a filter operator. Only eq, and, or are supported (Auth0's
// documented operators).
type Op int

// Filter operators.
const (
	OpEq Op = iota
	OpAnd
	OpOr
)

// Filter is a parsed RFC 7644 §3.4.2.2 filter. A comparison has Path and
// Value (string, bool, float64 or nil); and/or have Left and Right.
type Filter struct {
	Op          Op
	Path        string
	Value       any
	Left, Right *Filter
	attr        Path // parsed Path of a top-level comparison
}

// Attr returns the parsed attribute path of a comparison.
func (f *Filter) Attr() Path { return f.attr }

func formatValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(t)
		return strings.TrimSuffix(b.String(), "\n")
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	}
	return fmt.Sprint(v)
}

// String is a canonical, fully parenthesized form.
func (f *Filter) String() string {
	switch f.Op {
	case OpAnd:
		return "(" + f.Left.String() + " and " + f.Right.String() + ")"
	case OpOr:
		return "(" + f.Left.String() + " or " + f.Right.String() + ")"
	}
	return "(" + f.Path + " eq " + formatValue(f.Value) + ")"
}

// Path is a SCIM attribute path: [URN ":"] Attr ["[" filter "]"] ["." Sub].
// URN is empty for the core schema of the resource.
type Path struct {
	URN, Attr string
	Filter    *Filter // a value filter: one comparison on a sub-attribute
	Sub       string
}

// String renders the path; the core schema URN is left out.
func (p Path) String() string {
	var b strings.Builder
	if p.URN != "" {
		b.WriteString(p.URN + ":")
	}
	b.WriteString(p.Attr)
	if p.Filter != nil {
		b.WriteString("[" + p.Filter.Path + " eq " + formatValue(p.Filter.Value) + "]")
	}
	if p.Sub != "" {
		b.WriteString("." + p.Sub)
	}
	return b.String()
}

func nameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '$'
}

func validName(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z' || s[0] == '$') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !nameChar(s[i]) {
			return false
		}
	}
	return true
}

// ParsePath parses an attribute path as used in mappings, PATCH paths and
// filters.
func ParsePath(s string) (Path, error) {
	if s == "" || len(s) > maxPathBytes || !utf8.ValidString(s) {
		return Path{}, errInvalid
	}
	var p Path
	rest := s
	if strings.HasPrefix(strings.ToLower(rest), "urn:") {
		// The URN ends at the last ':' before the attribute (and before any
		// value filter).
		head := rest
		if i := strings.IndexByte(head, '['); i >= 0 {
			head = head[:i]
		}
		i := strings.LastIndexByte(head, ':')
		if i <= len("urn:") {
			return Path{}, errInvalid
		}
		urn := rest[:i]
		rest = rest[i+1:]
		switch {
		case strings.EqualFold(urn, CoreUser), strings.EqualFold(urn, CoreGroup):
		case strings.EqualFold(urn, EnterpriseUser):
			p.URN = EnterpriseUser
		default:
			return Path{}, errInvalid
		}
	}
	attr := rest
	if i := strings.IndexAny(rest, "[."); i >= 0 {
		attr, rest = rest[:i], rest[i:]
	} else {
		rest = ""
	}
	if !validName(attr) {
		return Path{}, errInvalid
	}
	p.Attr = attr
	if strings.HasPrefix(rest, "[") {
		end := closingBracket(rest)
		if end < 0 {
			return Path{}, errInvalid
		}
		inner, err := parseExpr(rest[1:end], 1)
		if err != nil || inner.Op != OpEq || strings.ContainsAny(inner.Path, ".[") {
			return Path{}, errInvalid
		}
		p.Filter = &Filter{Op: OpEq, Path: inner.Path, Value: inner.Value}
		rest = rest[end+1:]
	}
	if rest != "" {
		if rest[0] != '.' || !validName(rest[1:]) {
			return Path{}, errInvalid
		}
		p.Sub = rest[1:]
	}
	return p, nil
}

// closingBracket returns the index of the ']' closing s[0]=='[', skipping
// quoted strings, or -1.
func closingBracket(s string) int {
	inQuote := false
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case inQuote && c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case !inQuote && c == ']':
			return i
		}
	}
	return -1
}

// ParseFilter parses a filter: comparisons with eq, combined with and/or
// and parentheses.
func ParseFilter(s string) (*Filter, error) {
	if strings.TrimSpace(s) == "" || len(s) > maxFilterBytes || !utf8.ValidString(s) {
		return nil, errInvalid
	}
	return parseExpr(s, 0)
}

type lexer struct {
	s   string
	pos int
}

func (l *lexer) skip() {
	for l.pos < len(l.s) && (l.s[l.pos] == ' ' || l.s[l.pos] == '\t') {
		l.pos++
	}
}

// word reads a keyword or an attribute path (with any bracketed value
// filter) up to whitespace or a parenthesis.
func (l *lexer) word() string {
	l.skip()
	start := l.pos
	for l.pos < len(l.s) {
		c := l.s[l.pos]
		if c == '[' {
			end := closingBracket(l.s[l.pos:])
			if end < 0 {
				l.pos = len(l.s)
				return l.s[start:]
			}
			l.pos += end + 1
			continue
		}
		if c == ' ' || c == '\t' || c == '(' || c == ')' {
			break
		}
		l.pos++
	}
	return l.s[start:l.pos]
}

func (l *lexer) peek() byte {
	l.skip()
	if l.pos >= len(l.s) {
		return 0
	}
	return l.s[l.pos]
}

func (l *lexer) value() (any, error) {
	l.skip()
	if l.pos >= len(l.s) {
		return nil, errInvalid
	}
	if l.s[l.pos] == '"' {
		end := -1
		for i := l.pos + 1; i < len(l.s); i++ {
			if l.s[i] == '\\' {
				i++
				continue
			}
			if l.s[i] == '"' {
				end = i
				break
			}
		}
		if end < 0 {
			return nil, errInvalid
		}
		var v string
		if err := json.Unmarshal([]byte(l.s[l.pos:end+1]), &v); err != nil {
			return nil, errInvalid
		}
		l.pos = end + 1
		return v, nil
	}
	w := l.word()
	switch strings.ToLower(w) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null":
		return nil, nil
	}
	f, err := strconv.ParseFloat(w, 64)
	if err != nil {
		return nil, errInvalid
	}
	return f, nil
}

func parseExpr(s string, depth int) (*Filter, error) {
	l := &lexer{s: s}
	f, err := l.or(depth)
	if err != nil {
		return nil, err
	}
	if l.peek() != 0 {
		return nil, errInvalid
	}
	return f, nil
}

func (l *lexer) keyword(kw string) bool {
	save := l.pos
	if strings.EqualFold(l.word(), kw) {
		return true
	}
	l.pos = save
	return false
}

func (l *lexer) or(depth int) (*Filter, error) {
	left, err := l.and(depth)
	if err != nil {
		return nil, err
	}
	for l.keyword("or") {
		right, err := l.and(depth)
		if err != nil {
			return nil, err
		}
		left = &Filter{Op: OpOr, Left: left, Right: right}
	}
	return left, nil
}

func (l *lexer) and(depth int) (*Filter, error) {
	left, err := l.factor(depth)
	if err != nil {
		return nil, err
	}
	for l.keyword("and") {
		right, err := l.factor(depth)
		if err != nil {
			return nil, err
		}
		left = &Filter{Op: OpAnd, Left: left, Right: right}
	}
	return left, nil
}

func (l *lexer) factor(depth int) (*Filter, error) {
	if depth > maxDepth {
		return nil, errInvalid
	}
	if l.peek() == '(' {
		l.pos++
		f, err := l.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if l.peek() != ')' {
			return nil, errInvalid
		}
		l.pos++
		return f, nil
	}
	path := l.word()
	if strings.EqualFold(path, "not") || path == "" {
		return nil, errInvalid
	}
	attr, err := ParsePath(path)
	if err != nil {
		return nil, err
	}
	if !l.keyword("eq") {
		return nil, errInvalid
	}
	v, err := l.value()
	if err != nil {
		return nil, err
	}
	return &Filter{Op: OpEq, Path: path, Value: v, attr: attr}, nil
}
