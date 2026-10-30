package orgsearch

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type parser struct {
	s, mode  string
	i, count int
}

func Parse(s, mode string) (store.OrganizationQuery, error) {
	if mode == "" {
		mode = "lucene"
	}
	if len(s) > 4000 || utf8.RuneCountInString(s) > 1000 || !utf8.ValidString(s) || mode != "lucene" && mode != "scim" {
		return store.OrganizationQuery{}, store.ErrInvalid
	}
	p := parser{s: s, mode: mode}
	p.space()
	if p.i == len(s) {
		return store.OrganizationQuery{}, nil
	}
	q, e := p.expr(1, 1)
	p.space()
	if e != nil || p.i != len(s) || Validate(q) != nil {
		return store.OrganizationQuery{}, store.ErrInvalid
	}
	normalizeDates(&q)
	return q, nil
}
func (p *parser) space() {
	for p.i < len(p.s) && strings.ContainsRune(" \t\r\n", rune(p.s[p.i])) {
		p.i++
	}
}
func (p *parser) word(w string) bool {
	p.space()
	end := p.i + len(w)
	if end > len(p.s) || p.s[p.i:end] != w || end < len(p.s) && !strings.ContainsRune(" \t\r\n()", rune(p.s[end])) {
		return false
	}
	p.i = end
	return true
}
func (p *parser) expr(min, depth int) (store.OrganizationQuery, error) {
	if depth > 16 {
		return store.OrganizationQuery{}, store.ErrInvalid
	}
	p.space()
	var a store.OrganizationQuery
	var e error
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		a, e = p.expr(1, depth+1)
		p.space()
		if e != nil || p.i >= len(p.s) || p.s[p.i] != ')' {
			return a, store.ErrInvalid
		}
		p.i++
	} else {
		a, e = p.leaf()
		if e != nil {
			return a, e
		}
	}
	for {
		old := p.i
		op := ""
		prec := 0
		and, or := "AND", "OR"
		if p.mode == "scim" {
			and, or = "and", "or"
		}
		if p.word(and) {
			op = "and"
			prec = 2
		} else if p.word(or) {
			op = "or"
			prec = 1
		}
		if prec < min || prec == 0 {
			p.i = old
			break
		}
		b, e := p.expr(prec+1, depth)
		if e != nil {
			return a, e
		}
		left := a
		a = store.OrganizationQuery{Op: op, Left: &left, Right: &b}
	}
	return a, nil
}
func (p *parser) leaf() (store.OrganizationQuery, error) {
	p.space()
	start := p.i
	for p.i < len(p.s) && !strings.ContainsRune(": \t\n\r()", rune(p.s[p.i])) {
		p.i++
	}
	q := store.OrganizationQuery{Field: p.s[start:p.i]}
	if !validField(q.Field) {
		return q, store.ErrInvalid
	}
	p.space()
	p.count++
	if p.count > 5 {
		return q, store.ErrInvalid
	}
	if p.mode == "scim" {
		for _, op := range []string{"eq", "ne", "sw", "ew", "co", "pr", "gt", "ge", "lt", "le"} {
			if p.word(op) {
				q.Op = op
				break
			}
		}
		if q.Op == "" {
			return q, store.ErrInvalid
		}
		if q.Op == "pr" {
			return q, nil
		}
		v, _, e := p.value()
		q.Value = v
		return q, e
	}
	if p.i >= len(p.s) || p.s[p.i] != ':' {
		return q, store.ErrInvalid
	}
	p.i++
	p.space()
	q.Op = "eq"
	if p.i < len(p.s) && (p.s[p.i] == '[' || p.s[p.i] == '{') {
		q.Op = "range"
		q.LowerExclusive = p.s[p.i] == '{'
		p.i++
		start = p.i
		for p.i < len(p.s) && p.s[p.i] != ']' && p.s[p.i] != '}' {
			p.i++
		}
		if p.i == len(p.s) {
			return q, store.ErrInvalid
		}
		q.UpperExclusive = p.s[p.i] == '}'
		parts := strings.Split(p.s[start:p.i], " TO ")
		p.i++
		if len(parts) != 2 {
			return q, store.ErrInvalid
		}
		q.Value = strings.Trim(strings.TrimSpace(parts[0]), `"`)
		q.Upper = strings.Trim(strings.TrimSpace(parts[1]), `"`)
		if q.Value == "*" {
			q.Value = ""
		}
		if q.Upper == "*" {
			q.Upper = ""
		}
		return q, nil
	}
	v, stars, e := p.value()
	if e != nil {
		return q, e
	}
	q.Value = v
	if len(stars) > 0 {
		if len(stars) == 1 && stars[0] == len(v)-1 {
			q.Op = "sw"
			q.Value = v[:len(v)-1]
		} else if len(stars) == 1 && stars[0] == 0 {
			q.Op = "ew"
			q.Value = v[1:]
		} else if len(stars) == 2 && stars[0] == 0 && stars[1] == len(v)-1 {
			q.Op = "co"
			q.Value = v[1 : len(v)-1]
		} else {
			return q, store.ErrInvalid
		}
		if q.Value == "" {
			return q, store.ErrInvalid
		}
	}
	return q, nil
}
func (p *parser) value() (string, []int, error) {
	p.space()
	if p.i >= len(p.s) {
		return "", nil, store.ErrInvalid
	}
	if p.s[p.i] == '"' {
		start := p.i
		p.i++
		for p.i < len(p.s) {
			c := p.s[p.i]
			p.i++
			if c == '\\' {
				if p.i >= len(p.s) {
					break
				}
				p.i++
				continue
			}
			if c == '"' {
				v, e := strconv.Unquote(p.s[start:p.i])
				return v, nil, e
			}
		}
		return "", nil, store.ErrInvalid
	}
	var b strings.Builder
	var stars []int
	for p.i < len(p.s) && !strings.ContainsRune(" \t\r\n()", rune(p.s[p.i])) {
		c := p.s[p.i]
		p.i++
		if c == '\\' && p.mode == "lucene" {
			if p.i == len(p.s) {
				return "", nil, store.ErrInvalid
			}
			b.WriteByte(p.s[p.i])
			p.i++
			continue
		}
		if strings.ContainsRune("~?/[]{}\"", rune(c)) {
			return "", nil, store.ErrInvalid
		}
		if c == '*' {
			if p.mode != "lucene" {
				return "", nil, store.ErrInvalid
			}
			stars = append(stars, b.Len())
		}
		b.WriteByte(c)
	}
	v := b.String()
	if v == "" {
		return "", nil, store.ErrInvalid
	}
	if p.mode == "scim" {
		var n json.Number
		if json.Unmarshal([]byte(v), &n) != nil || v == "null" || v == "true" || v == "false" {
			return "", nil, store.ErrInvalid
		}
	}
	return v, stars, nil
}

func normalizeDates(q *store.OrganizationQuery) {
	if q.Left != nil {
		normalizeDates(q.Left)
	}
	if q.Right != nil {
		normalizeDates(q.Right)
	}
	if q.Field == "created_at" {
		for _, v := range []*string{&q.Value, &q.Upper} {
			if *v != "" {
				t, e := time.Parse(time.RFC3339Nano, *v)
				if e == nil {
					*v = t.UTC().Format(time.RFC3339Nano)
				}
			}
		}
	}
}
