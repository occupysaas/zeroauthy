package grpcstore

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Missing additive RPCs are capability errors, never an empty registry. Other
// transport errors retain context cancellation and the original gRPC status.
func capabilityError(err, unavailable error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("%w: %w", unavailable, err)
	}
	return err
}

// This read-only protocol probe prevents older servers silently dropping new
// canonical/origin fields on existing write RPCs. Do not cache failed probes.
func (c *Client) requireCustomDomains(ctx context.Context) error {
	r, e := c.rpc.CustomDomainsSupported(ctx, &storev1.CustomDomainCapabilitiesRequest{TxId: c.txID})
	return do("CustomDomainsSupported", r, capabilityError(e, store.ErrCustomDomainRepositoryUnavailable))
}
func (s *Server) CustomDomainsSupported(ctx context.Context, q *storev1.CustomDomainCapabilitiesRequest) (*storev1.Result, error) {
	// Both calls are read-only, need no fabricated tenant, and surface drivers
	// that expose the new protocol while retaining unavailable backing stubs.
	return exec(s, q.TxId, func(st store.Store) error {
		if _, err := st.CustomDomains().ListDue(ctx, 1); err != nil {
			return err
		}
		_, err := st.TLSAssets().ListExpired(ctx, 1)
		return err
	}), nil
}

type clientCustomDomains struct{ c *Client }
type clientTLSAssets struct{ c *Client }

func (c *Client) CustomDomains() store.CustomDomains { return clientCustomDomains{c} }
func (c *Client) TLSAssets() store.TLSAssets         { return clientTLSAssets{c} }
func (a clientCustomDomains) Delete(ctx context.Context, tenant, id string, expected int64) error {
	r, e := a.c.rpc.CustomDomainsDelete(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, TenantId: tenant, Id: id, ExpectedRevision: expected})
	return do("CustomDomainsDelete", r, capabilityError(e, store.ErrCustomDomainRepositoryUnavailable))
}
func (s *Server) CustomDomainsDelete(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	return &storev1.CustomDomainResult{Error: errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.CustomDomains().Delete(ctx, q.TenantId, q.Id, q.ExpectedRevision)
	}))}, nil
}
func (a clientCustomDomains) DeleteHost(ctx context.Context, host, tenant, domain string) error {
	r, e := a.c.rpc.CustomDomainsDeleteHost(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, Host: host, TenantId: tenant, DomainId: domain})
	return do("CustomDomainsDeleteHost", r, capabilityError(e, store.ErrCustomDomainRepositoryUnavailable))
}
func (s *Server) CustomDomainsDeleteHost(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	return &storev1.CustomDomainResult{Error: errToPB(s.with(q.TxId, func(st store.Store) error { return st.CustomDomains().DeleteHost(ctx, q.Host, q.TenantId, q.DomainId) }))}, nil
}
func (a clientCustomDomains) SetDefault(ctx context.Context, tenant, domain string) error {
	r, e := a.c.rpc.CustomDomainsSetDefault(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, TenantId: tenant, DomainId: domain})
	return do("CustomDomainsSetDefault", r, capabilityError(e, store.ErrCustomDomainRepositoryUnavailable))
}
func (s *Server) CustomDomainsSetDefault(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	return &storev1.CustomDomainResult{Error: errToPB(s.with(q.TxId, func(st store.Store) error { return st.CustomDomains().SetDefault(ctx, q.TenantId, q.DomainId) }))}, nil
}
func (a clientTLSAssets) Delete(ctx context.Context, key string, expected int64) error {
	r, e := a.c.rpc.TLSAssetsDelete(ctx, &storev1.TLSAssetRequest{TxId: a.c.txID, Key: key, ExpectedRevision: expected})
	return do("TLSAssetsDelete", r, capabilityError(e, store.ErrTLSAssetRepositoryUnavailable))
}
func (s *Server) TLSAssetsDelete(ctx context.Context, q *storev1.TLSAssetRequest) (*storev1.TLSAssetResult, error) {
	return &storev1.TLSAssetResult{Error: errToPB(s.with(q.TxId, func(st store.Store) error { return st.TLSAssets().Delete(ctx, q.Key, q.ExpectedRevision) }))}, nil
}
func (a clientCustomDomains) Get(ctx context.Context, tenant, id string) (*store.CustomDomain, error) {
	r, e := a.c.rpc.CustomDomainsGet(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, TenantId: tenant, Id: id})
	return decOne("CustomDomainsGet", capabilityError(e, store.ErrCustomDomainRepositoryUnavailable), r.GetError(), r.GetValue(), customDomainFromPB)
}
func (s *Server) CustomDomainsGet(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	v, e, err := one(s, q.TxId, func(st store.Store) (*store.CustomDomain, error) {
		return st.CustomDomains().Get(ctx, q.TenantId, q.Id)
	}, customDomainToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.CustomDomainResult{Error: e, Value: v}, nil
}
func (a clientCustomDomains) List(ctx context.Context, tenant string) ([]*store.CustomDomain, error) {
	r, e := a.c.rpc.CustomDomainsList(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, TenantId: tenant})
	return decList("CustomDomainsList", capabilityError(e, store.ErrCustomDomainRepositoryUnavailable), r.GetError(), r.GetValues(), customDomainFromPB)
}
func (s *Server) CustomDomainsList(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	v, e, err := many(s, q.TxId, func(st store.Store) ([]*store.CustomDomain, error) { return st.CustomDomains().List(ctx, q.TenantId) }, customDomainToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.CustomDomainResult{Error: e, Values: v}, nil
}
func (a clientCustomDomains) ListDue(ctx context.Context, limit int) ([]*store.CustomDomain, error) {
	r, e := a.c.rpc.CustomDomainsListDue(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, Limit: int64(limit)})
	return decList("CustomDomainsListDue", capabilityError(e, store.ErrCustomDomainRepositoryUnavailable), r.GetError(), r.GetValues(), customDomainFromPB)
}
func (s *Server) CustomDomainsListDue(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	v, e, err := many(s, q.TxId, func(st store.Store) ([]*store.CustomDomain, error) {
		return st.CustomDomains().ListDue(ctx, int(q.Limit))
	}, customDomainToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.CustomDomainResult{Error: e, Values: v}, nil
}
func (a clientCustomDomains) GetHost(ctx context.Context, host string) (*store.HostBinding, error) {
	r, e := a.c.rpc.CustomDomainsGetHost(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, Host: host})
	return decOne("CustomDomainsGetHost", capabilityError(e, store.ErrCustomDomainRepositoryUnavailable), r.GetError(), r.GetBinding(), hostBindingFromPB)
}
func (s *Server) CustomDomainsGetHost(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	v, e, err := one(s, q.TxId, func(st store.Store) (*store.HostBinding, error) { return st.CustomDomains().GetHost(ctx, q.Host) }, hostBindingToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.CustomDomainResult{Error: e, Binding: v}, nil
}
func (a clientTLSAssets) Get(ctx context.Context, key string) (*store.TLSAsset, error) {
	r, e := a.c.rpc.TLSAssetsGet(ctx, &storev1.TLSAssetRequest{TxId: a.c.txID, Key: key})
	return decOne("TLSAssetsGet", capabilityError(e, store.ErrTLSAssetRepositoryUnavailable), r.GetError(), r.GetValue(), tlsAssetFromPB)
}
func (s *Server) TLSAssetsGet(ctx context.Context, q *storev1.TLSAssetRequest) (*storev1.TLSAssetResult, error) {
	v, e, err := one(s, q.TxId, func(st store.Store) (*store.TLSAsset, error) { return st.TLSAssets().Get(ctx, q.Key) }, tlsAssetToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.TLSAssetResult{Error: e, Value: v}, nil
}
func (a clientTLSAssets) ListExpired(ctx context.Context, limit int) ([]*store.TLSAsset, error) {
	r, e := a.c.rpc.TLSAssetsListExpired(ctx, &storev1.TLSAssetRequest{TxId: a.c.txID, Limit: int64(limit)})
	return decList("TLSAssetsListExpired", capabilityError(e, store.ErrTLSAssetRepositoryUnavailable), r.GetError(), r.GetValues(), tlsAssetFromPB)
}
func (s *Server) TLSAssetsListExpired(ctx context.Context, q *storev1.TLSAssetRequest) (*storev1.TLSAssetResult, error) {
	v, e, err := many(s, q.TxId, func(st store.Store) ([]*store.TLSAsset, error) { return st.TLSAssets().ListExpired(ctx, int(q.Limit)) }, tlsAssetToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.TLSAssetResult{Error: e, Values: v}, nil
}
func (a clientCustomDomains) Create(ctx context.Context, row *store.CustomDomain) error {
	pb, e := customDomainToPB(row)
	if e != nil {
		return e
	}
	r, e := a.c.rpc.CustomDomainsCreate(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, Value: pb})
	if e = do("CustomDomainsCreate", r, capabilityError(e, store.ErrCustomDomainRepositoryUnavailable)); e != nil {
		return e
	}
	if row != nil {
		row.Revision = r.GetValue().GetRevision()
	}
	return nil
}
func (s *Server) CustomDomainsCreate(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	row, e := customDomainFromPB(q.Value)
	if e != nil || row == nil {
		return &storev1.CustomDomainResult{Error: errToPB(store.ErrInvalid)}, nil
	}
	e = s.with(q.TxId, func(st store.Store) error { return st.CustomDomains().Create(ctx, row) })
	if e != nil {
		return &storev1.CustomDomainResult{Error: errToPB(e)}, nil
	}
	pb, err := customDomainToPB(row)
	if err != nil {
		return nil, encodeFault(err)
	}
	return &storev1.CustomDomainResult{Value: pb}, nil
}
func (a clientCustomDomains) Update(ctx context.Context, row *store.CustomDomain, expected int64) error {
	pb, e := customDomainToPB(row)
	if e != nil {
		return e
	}
	r, e := a.c.rpc.CustomDomainsUpdate(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, Value: pb, ExpectedRevision: expected})
	if e = do("CustomDomainsUpdate", r, capabilityError(e, store.ErrCustomDomainRepositoryUnavailable)); e != nil {
		return e
	}
	if row != nil {
		row.Revision = r.GetValue().GetRevision()
	}
	return nil
}
func (s *Server) CustomDomainsUpdate(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	row, e := customDomainFromPB(q.Value)
	if e != nil || row == nil {
		return &storev1.CustomDomainResult{Error: errToPB(store.ErrInvalid)}, nil
	}
	e = s.with(q.TxId, func(st store.Store) error { return st.CustomDomains().Update(ctx, row, q.ExpectedRevision) })
	if e != nil {
		return &storev1.CustomDomainResult{Error: errToPB(e)}, nil
	}
	pb, err := customDomainToPB(row)
	if err != nil {
		return nil, encodeFault(err)
	}
	return &storev1.CustomDomainResult{Value: pb}, nil
}
func (a clientTLSAssets) Put(ctx context.Context, row *store.TLSAsset, expected int64) error {
	pb, e := tlsAssetToPB(row)
	if e != nil {
		return e
	}
	r, e := a.c.rpc.TLSAssetsPut(ctx, &storev1.TLSAssetRequest{TxId: a.c.txID, Value: pb, ExpectedRevision: expected})
	if e = do("TLSAssetsPut", r, capabilityError(e, store.ErrTLSAssetRepositoryUnavailable)); e != nil {
		return e
	}
	if row != nil {
		row.Revision = r.GetValue().GetRevision()
	}
	return nil
}
func (s *Server) TLSAssetsPut(ctx context.Context, q *storev1.TLSAssetRequest) (*storev1.TLSAssetResult, error) {
	row, e := tlsAssetFromPB(q.Value)
	if e != nil || row == nil {
		return &storev1.TLSAssetResult{Error: errToPB(store.ErrInvalid)}, nil
	}
	e = s.with(q.TxId, func(st store.Store) error { return st.TLSAssets().Put(ctx, row, q.ExpectedRevision) })
	if e != nil {
		return &storev1.TLSAssetResult{Error: errToPB(e)}, nil
	}
	pb, err := tlsAssetToPB(row)
	if err != nil {
		return nil, encodeFault(err)
	}
	return &storev1.TLSAssetResult{Value: pb}, nil
}

func (a clientCustomDomains) PutHost(ctx context.Context, row *store.HostBinding) error {
	pb, e := hostBindingToPB(row)
	if e != nil {
		return e
	}
	r, e := a.c.rpc.CustomDomainsPutHost(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, Binding: pb})
	return do("CustomDomainsPutHost", r, capabilityError(e, store.ErrCustomDomainRepositoryUnavailable))
}
func (s *Server) CustomDomainsPutHost(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	row, e := hostBindingFromPB(q.Binding)
	if e != nil || row == nil {
		return &storev1.CustomDomainResult{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.CustomDomainResult{Error: errToPB(s.with(q.TxId, func(st store.Store) error { return st.CustomDomains().PutHost(ctx, row) }))}, nil
}
func (a clientCustomDomains) GetDefault(ctx context.Context, tenant string) (string, error) {
	r, e := a.c.rpc.CustomDomainsGetDefault(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, TenantId: tenant})
	if e = do("CustomDomainsGetDefault", r, capabilityError(e, store.ErrCustomDomainRepositoryUnavailable)); e != nil {
		return "", e
	}
	return r.DefaultId, nil
}
func (s *Server) CustomDomainsGetDefault(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	r := &storev1.CustomDomainResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) (e error) {
		r.DefaultId, e = st.CustomDomains().GetDefault(ctx, q.TenantId)
		return e
	}))
	return r, nil
}
func (a clientCustomDomains) AdmitAttempt(ctx context.Context, tenant, domain string) (time.Duration, error) {
	r, e := a.c.rpc.CustomDomainsAdmitAttempt(ctx, &storev1.CustomDomainRequest{TxId: a.c.txID, TenantId: tenant, DomainId: domain})
	if e = do("CustomDomainsAdmitAttempt", r, capabilityError(e, store.ErrCustomDomainRepositoryUnavailable)); e != nil {
		return 0, e
	}
	if e := r.RetryAfter.CheckValid(); e != nil {
		return 0, e
	}
	return r.RetryAfter.AsDuration(), nil
}
func (s *Server) CustomDomainsAdmitAttempt(ctx context.Context, q *storev1.CustomDomainRequest) (*storev1.CustomDomainResult, error) {
	r := &storev1.CustomDomainResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		d, e := st.CustomDomains().AdmitAttempt(ctx, q.TenantId, q.DomainId)
		r.RetryAfter = durationpb.New(d)
		return e
	}))
	return r, nil
}
func (a clientTLSAssets) ClaimLease(ctx context.Context, key, owner string, duration time.Duration) (*store.TLSLease, error) {
	r, e := a.c.rpc.TLSAssetsClaimLease(ctx, &storev1.TLSAssetRequest{TxId: a.c.txID, Key: key, Owner: owner, Duration: durationpb.New(duration)})
	return decOne("TLSAssetsClaimLease", capabilityError(e, store.ErrTLSAssetRepositoryUnavailable), r.GetError(), r.GetLease(), tlsLeaseFromPB)
}
func (s *Server) TLSAssetsClaimLease(ctx context.Context, q *storev1.TLSAssetRequest) (*storev1.TLSAssetResult, error) {
	if e := q.Duration.CheckValid(); e != nil {
		return &storev1.TLSAssetResult{Error: errToPB(store.ErrInvalid)}, nil
	}
	v, err, encErr := one(s, q.TxId, func(st store.Store) (*store.TLSLease, error) {
		return st.TLSAssets().ClaimLease(ctx, q.Key, q.Owner, q.Duration.AsDuration())
	}, tlsLeaseToPB)
	if encErr != nil {
		return nil, encErr
	}
	return &storev1.TLSAssetResult{Error: err, Lease: v}, nil
}
func (a clientTLSAssets) RenewLease(ctx context.Context, lease store.TLSLease, duration time.Duration) (*store.TLSLease, error) {
	pb, e := tlsLeaseToPB(&lease)
	if e != nil {
		return nil, e
	}
	r, e := a.c.rpc.TLSAssetsRenewLease(ctx, &storev1.TLSAssetRequest{TxId: a.c.txID, Lease: pb, Duration: durationpb.New(duration)})
	return decOne("TLSAssetsRenewLease", capabilityError(e, store.ErrTLSAssetRepositoryUnavailable), r.GetError(), r.GetLease(), tlsLeaseFromPB)
}
func (s *Server) TLSAssetsRenewLease(ctx context.Context, q *storev1.TLSAssetRequest) (*storev1.TLSAssetResult, error) {
	if e := q.Duration.CheckValid(); e != nil {
		return &storev1.TLSAssetResult{Error: errToPB(store.ErrInvalid)}, nil
	}
	lease, e := tlsLeaseFromPB(q.Lease)
	if e != nil || lease == nil {
		return &storev1.TLSAssetResult{Error: errToPB(store.ErrInvalid)}, nil
	}
	v, err, encErr := one(s, q.TxId, func(st store.Store) (*store.TLSLease, error) {
		return st.TLSAssets().RenewLease(ctx, *lease, q.Duration.AsDuration())
	}, tlsLeaseToPB)
	if encErr != nil {
		return nil, encErr
	}
	return &storev1.TLSAssetResult{Error: err, Lease: v}, nil
}
func (a clientTLSAssets) CheckLease(ctx context.Context, lease store.TLSLease) error {
	pb, e := tlsLeaseToPB(&lease)
	if e != nil {
		return e
	}
	r, e := a.c.rpc.TLSAssetsCheckLease(ctx, &storev1.TLSAssetRequest{TxId: a.c.txID, Lease: pb})
	return do("TLSAssetsCheckLease", r, capabilityError(e, store.ErrTLSAssetRepositoryUnavailable))
}
func (s *Server) TLSAssetsCheckLease(ctx context.Context, q *storev1.TLSAssetRequest) (*storev1.TLSAssetResult, error) {
	lease, e := tlsLeaseFromPB(q.Lease)
	if e != nil || lease == nil {
		return &storev1.TLSAssetResult{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.TLSAssetResult{Error: errToPB(s.with(q.TxId, func(st store.Store) error { return st.TLSAssets().CheckLease(ctx, *lease) }))}, nil
}
func (a clientTLSAssets) ReleaseLease(ctx context.Context, lease store.TLSLease) error {
	pb, e := tlsLeaseToPB(&lease)
	if e != nil {
		return e
	}
	r, e := a.c.rpc.TLSAssetsReleaseLease(ctx, &storev1.TLSAssetRequest{TxId: a.c.txID, Lease: pb})
	return do("TLSAssetsReleaseLease", r, capabilityError(e, store.ErrTLSAssetRepositoryUnavailable))
}
func (s *Server) TLSAssetsReleaseLease(ctx context.Context, q *storev1.TLSAssetRequest) (*storev1.TLSAssetResult, error) {
	lease, e := tlsLeaseFromPB(q.Lease)
	if e != nil || lease == nil {
		return &storev1.TLSAssetResult{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.TLSAssetResult{Error: errToPB(s.with(q.TxId, func(st store.Store) error { return st.TLSAssets().ReleaseLease(ctx, *lease) }))}, nil
}
