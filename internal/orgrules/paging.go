package orgrules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Entry is one listable item with its sort key. Lists are ordered by
// (Sort, ID), reversed when descending.
type Entry[T any] struct {
	Item     T
	Sort, ID string
}

// OrderEntries sorts es by (Sort, ID), reversed when desc.
func OrderEntries[T any](es []Entry[T], desc bool) {
	slices.SortFunc(es, func(a, b Entry[T]) int { return cmpEntry(a.Sort, a.ID, b.Sort, b.ID, desc) })
}

func cmpEntry(as, ai, bs, bi string, desc bool) int {
	n := strings.Compare(as, bs)
	if n == 0 {
		n = strings.Compare(ai, bi)
	}
	if desc {
		return -n
	}
	return n
}

// PageEntries pages es, which OrderEntries already ordered. scope is bound
// into checkpoint cursors together with p.Sort. Invalid pagination or a
// foreign cursor is store.ErrInvalid.
func PageEntries[T any](es []Entry[T], p store.OrgPage, scope string, desc bool) (store.OrgResult[T], error) {
	mode, err := NormalizePage(&p)
	if err != nil {
		return store.OrgResult[T]{}, store.ErrInvalid
	}
	out := store.OrgResult[T]{Items: []T{}}
	if mode == Offset {
		out.Total = len(es)
		start := len(es)
		// Division avoids overflow for arbitrarily large page input.
		if p.Page <= len(es)/p.PerPage {
			start = p.Page * p.PerPage
		}
		for _, e := range es[start:min(len(es), start+p.PerPage)] {
			out.Items = append(out.Items, e.Item)
		}
		return out, nil
	}
	if p.From != "" {
		c, err := DecodeCursor(p.From, scope, p.Sort)
		if err != nil {
			return out, store.ErrInvalid
		}
		es = slices.DeleteFunc(slices.Clone(es), func(e Entry[T]) bool { return cmpEntry(e.Sort, e.ID, c.Key, c.ID, desc) <= 0 })
	}
	for _, e := range es[:min(len(es), p.Take)] {
		out.Items = append(out.Items, e.Item)
	}
	if len(es) > p.Take {
		last := es[p.Take-1]
		out.Next = EncodeCursor(Cursor{Scope: scope, Sort: p.Sort, Key: last.Sort, ID: last.ID})
	}
	return out, nil
}

// PageIDs pages plain IDs ordered ascending (byte order).
func PageIDs(ids []string, p store.OrgPage, scope string) (store.OrgResult[string], error) {
	slices.Sort(ids)
	es := make([]Entry[string], len(ids))
	for i, id := range ids {
		es[i] = Entry[string]{Item: id, ID: id}
	}
	return PageEntries(es, p, scope, false)
}

// nameCollation ignores case and punctuation like the reference ordering.
var nameCollation = strings.NewReplacer("-", "", "_", "")

// PageOrgs orders and pages organizations. Offset mode without a sort is
// ascending by name; checkpoint mode without a sort is creation order. The
// returned items are shallow copies: callers pass organizations they own.
func PageOrgs(orgs []*store.Organization, p store.OrgPage, scope string) (store.OrgResult[store.Organization], error) {
	field, desc, err := ParseSort(p.Sort)
	if err != nil {
		return store.OrgResult[store.Organization]{}, store.ErrInvalid
	}
	if field == "" {
		field = SortName
		if p.From != "" || p.Take > 0 {
			field = SortCreatedAt
		}
	}
	es := make([]Entry[store.Organization], len(orgs))
	for i, o := range orgs {
		e := Entry[store.Organization]{Item: *o, ID: o.ID}
		switch field {
		case SortName:
			e.Sort = nameCollation.Replace(strings.ToLower(o.Name))
		case SortDisplayName:
			e.Sort = strings.ToLower(o.DisplayName)
		default:
			e.Sort = fmt.Sprintf("%020d", o.CreatedAt.UnixNano())
		}
		es[i] = e
	}
	OrderEntries(es, desc)
	return PageEntries(es, p, scope, desc)
}

// Scope builds the cursor scope of one list.
func Scope(kind, tid string, rest ...string) string {
	return kind + "/" + tid + "/" + strings.Join(rest, "/")
}
