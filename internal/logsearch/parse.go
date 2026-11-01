package logsearch

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var queryLimits = logrules.Inventory().Limits

type parser struct {
	s        string
	i, count int
}

// Parse accepts the bounded Lucene subset from the frozen log inventory.
func Parse(s string) (*store.LogQuery, error) {
	if len(s) > queryLimits["query_bytes_max"] || utf8.RuneCountInString(s) > queryLimits["query_runes_max"] || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return nil, store.ErrInvalid
	}
	p := parser{s: s}
	p.space()
	if p.i == len(s) {
		return nil, nil
	}
	q, err := p.expr(1, 0, "")
	p.space()
	if err != nil || p.i != len(s) || Validate(q) != nil {
		return nil, store.ErrInvalid
	}
	return q, nil
}
func (p *parser) space() {
	for p.i < len(p.s) && strings.ContainsRune(" \t\r\n", rune(p.s[p.i])) {
		p.i++
	}
}
func (p *parser) word(w string) bool {
	p.space()
	e := p.i + len(w)
	if e > len(p.s) || p.s[p.i:e] != w || e < len(p.s) && !strings.ContainsRune(" \t\r\n()", rune(p.s[e])) {
		return false
	}
	p.i = e
	return true
}
func (p *parser) expr(min, depth int, field string) (*store.LogQuery, error) {
	if depth > queryLimits["query_depth_max"] {
		return nil, store.ErrInvalid
	}
	p.space()
	var a *store.LogQuery
	var err error
	if p.word("NOT") {
		a, err = p.expr(3, depth+1, field)
		a = &store.LogQuery{Op: "not", Left: a}
	} else if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		a, err = p.expr(1, depth+1, field)
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			return nil, store.ErrInvalid
		}
		p.i++
	} else {
		a, err = p.leaf(depth, field)
	}
	if err != nil {
		return nil, err
	}
	for {
		old := p.i
		op, prec := "", 0
		if p.word("AND") {
			op, prec = "and", 2
		} else if p.word("OR") {
			op, prec = "or", 1
		}
		if prec < min || prec == 0 {
			p.i = old
			break
		}
		b, e := p.expr(prec+1, depth, field)
		if e != nil {
			return nil, e
		}
		a = &store.LogQuery{Op: op, Left: a, Right: b}
	}
	return a, nil
}
func (p *parser) leaf(depth int, field string) (*store.LogQuery, error) {
	p.space()
	start := p.i
	if p.i < len(p.s) && p.s[p.i] != '"' {
		for p.i < len(p.s) && !strings.ContainsRune(": \t\r\n()", rune(p.s[p.i])) {
			p.i++
		}
		if p.i < len(p.s) && p.s[p.i] == ':' {
			field = p.s[start:p.i]
			p.i++
			p.space()
			known := false
			for _, f := range logrules.Fields() {
				if f.Name == field {
					known = true
					break
				}
			}
			if !known {
				return nil, store.ErrInvalid
			}
			if p.i < len(p.s) && p.s[p.i] == '(' {
				p.i++
				q, err := p.expr(1, depth+1, field)
				p.space()
				if p.i >= len(p.s) || p.s[p.i] != ')' {
					return nil, store.ErrInvalid
				}
				p.i++
				return q, err
			}
		} else {
			p.i = start
		}
	}
	q := &store.LogQuery{Op: "eq", Field: field}
	p.count++
	if p.count > queryLimits["query_terms_max"] {
		return nil, store.ErrInvalid
	}
	if p.i < len(p.s) && (p.s[p.i] == '[' || p.s[p.i] == '{') {
		q.Op = "range"
		q.LowerExclusive = p.s[p.i] == '{'
		p.i++
		start = p.i
		for p.i < len(p.s) && p.s[p.i] != ']' && p.s[p.i] != '}' {
			p.i++
		}
		if p.i == len(p.s) {
			return nil, store.ErrInvalid
		}
		q.UpperExclusive = p.s[p.i] == '}'
		parts := strings.Split(p.s[start:p.i], " TO ")
		p.i++
		if len(parts) != 2 {
			return nil, store.ErrInvalid
		}
		q.Value = strings.Trim(strings.TrimSpace(parts[0]), `"`)
		q.Upper = strings.Trim(strings.TrimSpace(parts[1]), `"`)
		if q.Value == "*" {
			q.Value = ""
		}
		if q.Upper == "*" {
			q.Upper = ""
		}
	} else {
		v, stars, err := p.value()
		if err != nil {
			return nil, err
		}
		q.Value = v
		if len(stars) > 0 {
			if len(stars) != 1 || stars[0] != len(v)-1 || len(v) == 1 {
				return nil, store.ErrInvalid
			}
			q.Op = "sw"
			q.Value = v[:len(v)-1]
		}
	}
	if field == "date" {
		for i, v := range []*string{&q.Value, &q.Upper} {
			if *v == "" {
				continue
			}
			t, e := time.Parse("2006-01-02", *v)
			if e == nil {
				if q.Op == "range" && i == 1 && !q.UpperExclusive {
					t = t.Add(24*time.Hour - time.Nanosecond)
				}
				if q.Op == "range" && i == 0 && q.LowerExclusive {
					t = t.Add(24*time.Hour - time.Nanosecond)
				}
			} else {
				t, e = time.Parse(time.RFC3339Nano, *v)
			}
			if e != nil || store.ValidateLogTimes(t) != nil {
				return nil, store.ErrInvalid
			}
			*v = t.UTC().Format(time.RFC3339Nano)
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
				if p.i < len(p.s) {
					p.i++
				}
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
		if c == '\\' {
			if p.i == len(p.s) {
				return "", nil, store.ErrInvalid
			}
			b.WriteByte(p.s[p.i])
			p.i++
			continue
		}
		if strings.ContainsRune("~?/[]{}\":", rune(c)) {
			return "", nil, store.ErrInvalid
		}
		if c == '*' {
			stars = append(stars, b.Len())
		}
		b.WriteByte(c)
	}
	if b.Len() == 0 {
		return "", nil, store.ErrInvalid
	}
	return b.String(), stars, nil
}
