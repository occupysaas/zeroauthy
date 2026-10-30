package grpcstore

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/orgsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

func queryToPB(q store.OrganizationQuery) *storev1.OrganizationQueryMsg {
	out := &storev1.OrganizationQueryMsg{Op: q.Op, Field: q.Field, Value: q.Value, Upper: q.Upper, LowerExclusive: q.LowerExclusive, UpperExclusive: q.UpperExclusive}
	if q.Left != nil {
		out.Left = queryToPB(*q.Left)
	}
	if q.Right != nil {
		out.Right = queryToPB(*q.Right)
	}
	return out
}
func queryFromPB(q *storev1.OrganizationQueryMsg, depth int, count *int) (store.OrganizationQuery, error) {
	if q == nil || depth > 16 {
		return store.OrganizationQuery{}, store.ErrInvalid
	}
	*count++
	if *count > 9 {
		return store.OrganizationQuery{}, store.ErrInvalid
	}
	out := store.OrganizationQuery{Op: q.Op, Field: q.Field, Value: q.Value, Upper: q.Upper, LowerExclusive: q.LowerExclusive, UpperExclusive: q.UpperExclusive}
	if q.Left != nil {
		v, e := queryFromPB(q.Left, depth+1, count)
		if e != nil {
			return out, e
		}
		out.Left = &v
	}
	if q.Right != nil {
		v, e := queryFromPB(q.Right, depth+1, count)
		if e != nil {
			return out, e
		}
		out.Right = &v
	}
	return out, nil
}
func (o clientOrganizationsII) Search(ctx context.Context, tid string, q store.OrganizationQuery, p store.OrganizationSearchPage) (store.OrgResult[store.Organization], error) {
	out := store.OrgResult[store.Organization]{Items: []store.Organization{}}
	p, err := orgsearch.Page(p)
	if err != nil || orgsearch.Validate(q) != nil {
		return out, store.ErrInvalid
	}
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, SearchQuery: queryToPB(q), SearchPage: &storev1.OrganizationSearchPageMsg{Take: int64(p.Take), Sort: p.Sort, LastValue: p.LastValue, LastId: p.LastID}}, o.c.rpc.OrganizationsIISearch)
	if err != nil {
		return out, err
	}
	for _, pb := range v.Organizations {
		x := orgFromPB(pb)
		if x == nil {
			return out, store.ErrInvalid
		}
		out.Items = append(out.Items, *x)
	}
	out.Next = v.Next
	return out, nil
}
func (s *Server) OrganizationsIISearch(ctx context.Context, in *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(in.TxId, out, func(o store.OrganizationsII) error {
		count := 0
		q, e := queryFromPB(in.SearchQuery, 1, &count)
		if e != nil || orgsearch.Validate(q) != nil {
			return store.ErrInvalid
		}
		pb := in.SearchPage
		if pb == nil || pb.Take < 0 || pb.Take > 100 {
			return store.ErrInvalid
		}
		p := store.OrganizationSearchPage{Take: int(pb.Take), Sort: pb.Sort, LastValue: pb.LastValue, LastID: pb.LastId}
		p, e = orgsearch.Page(p)
		if e != nil {
			return e
		}
		v, e := o.Search(ctx, in.TenantId, q, p)
		if e != nil {
			return e
		}
		for _, x := range v.Items {
			out.Organizations = append(out.Organizations, orgToPB(&x))
		}
		out.Next = v.Next
		return nil
	}), nil
}
