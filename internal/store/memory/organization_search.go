package memory

import (
	"context"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/orgsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (r organizationsII) Search(_ context.Context, tid string, q store.OrganizationQuery, p store.OrganizationSearchPage) (store.OrgResult[store.Organization], error) {
	out := store.OrgResult[store.Organization]{Items: []store.Organization{}}
	p, err := orgsearch.Page(p)
	if err != nil || orgsearch.Validate(q) != nil {
		return out, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	for k, o := range r.s.orgs {
		if k.tenant == tid && orgsearch.Match(q, *o) && (p.LastID == "" || orgsearch.Compare(orgsearch.SortValue(*o, p.Sort), o.ID, p.LastValue, p.LastID, p.Sort) > 0) {
			out.Items = append(out.Items, *cloneOrg(o))
		}
	}
	slices.SortFunc(out.Items, func(a, b store.Organization) int {
		return orgsearch.Compare(orgsearch.SortValue(a, p.Sort), a.ID, orgsearch.SortValue(b, p.Sort), b.ID, p.Sort)
	})
	if len(out.Items) > p.Take {
		out.Items = out.Items[:p.Take]
		out.Next = out.Items[p.Take-1].ID
	}
	return out, nil
}
