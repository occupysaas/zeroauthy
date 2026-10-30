package sqlstore

import (
	"context"
	"strconv"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (r organizationsII) Search(ctx context.Context, tid string, q store.OrganizationQuery, p store.OrganizationSearchPage) (store.OrgResult[store.Organization], error) {
	out := store.OrgResult[store.Organization]{Items: []store.Organization{}}
	p, err := orgsearch.Page(p)
	if err != nil {
		return out, err
	}
	where, args, err := orgsearch.SQL(q, r.s.d.name)
	if err != nil {
		return out, err
	}
	args = append([]any{tid}, args...)
	query := `SELECT ` + orgCols + ` FROM organizations WHERE tenant_id=? AND (` + where + `)`
	field := p.Sort
	if field != "created_at" {
		field += r.s.d.byteOrder
	}
	if p.LastID != "" {
		var v any = p.LastValue
		if p.Sort == "created_at" {
			t, _ := time.Parse(time.RFC3339Nano, p.LastValue)
			v = t.UnixMicro()
		}
		query += ` AND (` + field + `>? OR (` + field + `=? AND id` + r.s.d.byteOrder + `>?))`
		args = append(args, v, v, p.LastID)
	}
	query += ` ORDER BY ` + field + `, id` + r.s.d.byteOrder + ` LIMIT ` + strconv.Itoa(p.Take+1)
	orgs, err := (organizations{r.s}).queryOrgs(ctx, query, args...)
	if err != nil {
		return out, err
	}
	if len(orgs) > p.Take {
		orgs = orgs[:p.Take]
		out.Next = orgs[p.Take-1].ID
	}
	for _, o := range orgs {
		out.Items = append(out.Items, *o)
	}
	return out, nil
}
