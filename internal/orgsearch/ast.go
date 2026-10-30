// Package orgsearch implements the bounded Organizations II search language.
package orgsearch

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func validField(f string) bool {
	return f == "id" || f == "name" || f == "display_name" || f == "created_at" || strings.HasPrefix(f, "metadata.") && len(f) > 9 && !strings.ContainsAny(f[9:], ".[]\x00")
}
func Validate(q store.OrganizationQuery) error {
	count := 0
	size := 0
	var walk func(store.OrganizationQuery, int) bool
	walk = func(n store.OrganizationQuery, depth int) bool {
		if depth > 16 {
			return false
		}
		size += utf8.RuneCountInString(n.Field + n.Value + n.Upper)
		if size > 1000 || !utf8.ValidString(n.Field+n.Value+n.Upper) || strings.ContainsRune(n.Field+n.Value+n.Upper, 0) {
			return false
		}
		if n.Op == "" {
			return !n.LowerExclusive && !n.UpperExclusive && depth == 1 && n.Field == "" && n.Left == nil && n.Right == nil && n.Value == "" && n.Upper == ""
		}
		if n.Op == "and" || n.Op == "or" {
			return !n.LowerExclusive && !n.UpperExclusive && n.Left != nil && n.Right != nil && n.Field == "" && n.Value == "" && n.Upper == "" && walk(*n.Left, depth+1) && walk(*n.Right, depth+1)
		}
		count++
		if count > 5 || !validField(n.Field) || n.Left != nil || n.Right != nil {
			return false
		}
		if n.Op != "range" && (n.Upper != "" || n.LowerExclusive || n.UpperExclusive) {
			return false
		}
		switch n.Op {
		case "eq", "ne", "sw", "ew", "co", "pr", "gt", "ge", "lt", "le", "range":
		default:
			return false
		}
		if n.Op == "pr" {
			return n.Value == ""
		}
		if n.Field == "id" && n.Op != "eq" && n.Op != "ne" {
			return false
		}
		if (n.Op == "co" || n.Op == "ew") && utf8.RuneCountInString(n.Value) < 3 {
			return false
		}
		if n.Field == "created_at" {
			if n.Op == "sw" || n.Op == "ew" || n.Op == "co" {
				return false
			}
			for _, v := range []string{n.Value, n.Upper} {
				if v != "" {
					if _, e := time.Parse(time.RFC3339Nano, v); e != nil {
						return false
					}
				}
			}
			return n.Op == "range" || n.Value != ""
		}
		return n.Op != "range"
	}
	if !walk(q, 1) {
		return store.ErrInvalid
	}
	return nil
}
func Page(p store.OrganizationSearchPage) (store.OrganizationSearchPage, error) {
	if p.Take == 0 {
		p.Take = 50
	}
	if p.Sort == "" {
		p.Sort = "created_at"
	}
	if p.Take < 1 || p.Take > 100 || p.Sort != "name" && p.Sort != "display_name" && p.Sort != "created_at" || p.LastID == "" && p.LastValue != "" {
		return p, store.ErrInvalid
	}
	if p.LastID != "" && p.Sort == "created_at" {
		if t, e := time.Parse(time.RFC3339Nano, p.LastValue); e != nil || t.Nanosecond()%1000 != 0 {
			return p, store.ErrInvalid
		}
	}
	return p, nil
}
func SortValue(o store.Organization, field string) string {
	switch field {
	case "name":
		return o.Name
	case "display_name":
		return o.DisplayName
	default:
		return o.CreatedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	}
}
func Compare(av, ai, bv, bi, field string) int {
	n := 0
	if field == "created_at" {
		a, _ := time.Parse(time.RFC3339Nano, av)
		b, _ := time.Parse(time.RFC3339Nano, bv)
		n = a.Compare(b)
	} else {
		n = strings.Compare(av, bv)
	}
	if n == 0 {
		n = strings.Compare(ai, bi)
	}
	return n
}
