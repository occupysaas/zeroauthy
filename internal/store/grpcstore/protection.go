package grpcstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"time"
)

type clientProtection struct{ c *Client }

func (c *Client) Protection() store.Protection { return clientProtection{c} }
func protectionKeyToPB(k store.ProtectionKey) *storev1.ProtectionKey {
	return &storev1.ProtectionKey{TenantId: k.TenantID, Kind: k.Kind, ConnectionId: k.ConnectionID, Identifier: k.Identifier, Ip: k.IP}
}
func protectionKeyFromPB(k *storev1.ProtectionKey) store.ProtectionKey {
	return store.ProtectionKey{TenantID: k.GetTenantId(), Kind: k.GetKind(), ConnectionID: k.GetConnectionId(), Identifier: k.GetIdentifier(), IP: k.GetIp()}
}
func protectionFilterToPB(f store.ProtectionFilter) *storev1.ProtectionKey {
	return &storev1.ProtectionKey{Kind: f.Kind, ConnectionId: f.ConnectionID, Identifier: f.Identifier, Ip: f.IP}
}
func protectionFilterFromPB(f *storev1.ProtectionKey) store.ProtectionFilter {
	return store.ProtectionFilter{Kind: f.GetKind(), ConnectionID: f.GetConnectionId(), Identifier: f.GetIdentifier(), IP: f.GetIp()}
}
func protectionRPCError(op string, r *storev1.ProtectionResult, e error) error {
	if e != nil {
		return rpcErr(op, tooOld(e))
	}
	return errFromPB(r.GetError())
}
func (a clientProtection) Reserve(ctx context.Context, ls []store.ProtectionLimit, now time.Time) (store.ProtectionAdmission, error) {
	q := &storev1.ProtectionRequest{TxId: a.c.txID, Now: tsToPB(now)}
	for _, l := range ls {
		q.Limits = append(q.Limits, &storev1.ProtectionLimit{Key: protectionKeyToPB(l.Key), Algorithm: l.Algorithm, Capacity: int64(l.Capacity), Window: durationpb.New(l.Window), Refill: durationpb.New(l.Refill), Lockout: durationpb.New(l.Lockout)})
	}
	r, e := a.c.rpc.ProtectionReserve(ctx, q)
	if e = protectionRPCError("ProtectionReserve", r, e); e != nil {
		return store.ProtectionAdmission{}, e
	}
	return store.ProtectionAdmission{Allowed: r.Allowed, Receipt: store.ProtectionReceipt{TenantID: r.TenantId, ID: r.ReceiptId}, RetryAt: tsFromPB(r.RetryAt)}, nil
}
func (a clientProtection) Complete(ctx context.Context, receipt store.ProtectionReceipt, outcome string, now time.Time) error {
	r, e := a.c.rpc.ProtectionComplete(ctx, &storev1.ProtectionRequest{TxId: a.c.txID, TenantId: receipt.TenantID, ReceiptId: receipt.ID, Outcome: outcome, Now: tsToPB(now)})
	return protectionRPCError("ProtectionComplete", r, e)
}
func (a clientProtection) Blocks(ctx context.Context, tenant string, f store.ProtectionFilter, now time.Time) ([]store.ProtectionBlock, error) {
	r, e := a.c.rpc.ProtectionBlocks(ctx, &storev1.ProtectionRequest{TxId: a.c.txID, TenantId: tenant, Filter: protectionFilterToPB(f), Now: tsToPB(now)})
	if e = protectionRPCError("ProtectionBlocks", r, e); e != nil {
		return nil, e
	}
	out := []store.ProtectionBlock{}
	for _, b := range r.Blocks {
		out = append(out, store.ProtectionBlock{Key: protectionKeyFromPB(b.Key), BlockedUntil: tsFromPB(b.BlockedUntil)})
	}
	return out, nil
}
func (a clientProtection) Clear(ctx context.Context, tenant string, f store.ProtectionFilter) error {
	r, e := a.c.rpc.ProtectionClear(ctx, &storev1.ProtectionRequest{TxId: a.c.txID, TenantId: tenant, Filter: protectionFilterToPB(f)})
	return protectionRPCError("ProtectionClear", r, e)
}
func (a clientProtection) UseProof(ctx context.Context, hash string, now, expires time.Time) (bool, error) {
	r, e := a.c.rpc.ProtectionUseProof(ctx, &storev1.ProtectionRequest{TxId: a.c.txID, ProofHash: hash, Now: tsToPB(now), ExpiresAt: tsToPB(expires)})
	if e = protectionRPCError("ProtectionUseProof", r, e); e != nil {
		return false, e
	}
	return r.Allowed, nil
}
func (a clientProtection) RecordRisk(ctx context.Context, tenant, id, ip string, now time.Time) error {
	r, e := a.c.rpc.ProtectionRecordRisk(ctx, &storev1.ProtectionRequest{TxId: a.c.txID, TenantId: tenant, AttemptId: id, Ip: ip, Now: tsToPB(now)})
	return protectionRPCError("ProtectionRecordRisk", r, e)
}
func (a clientProtection) RiskCount(ctx context.Context, tenant, ip string, now time.Time) (int, error) {
	r, e := a.c.rpc.ProtectionRiskCount(ctx, &storev1.ProtectionRequest{TxId: a.c.txID, TenantId: tenant, Ip: ip, Now: tsToPB(now)})
	if e = protectionRPCError("ProtectionRiskCount", r, e); e != nil {
		return 0, e
	}
	return int(r.Count), nil
}
func (a clientProtection) Sweep(ctx context.Context, now time.Time, limit int) (int, error) {
	r, e := a.c.rpc.ProtectionSweep(ctx, &storev1.ProtectionRequest{TxId: a.c.txID, Now: tsToPB(now), Limit: int64(limit)})
	if e = protectionRPCError("ProtectionSweep", r, e); e != nil {
		return 0, e
	}
	return int(r.Count), nil
}

func (s *Server) ProtectionReserve(ctx context.Context, q *storev1.ProtectionRequest) (*storev1.ProtectionResult, error) {
	r := &storev1.ProtectionResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		p := st.Protection()
		var ls []store.ProtectionLimit
		for _, l := range q.Limits {
			if e := l.Window.CheckValid(); e != nil {
				return store.ErrInvalid
			}
			if e := l.Refill.CheckValid(); e != nil {
				return store.ErrInvalid
			}
			if e := l.Lockout.CheckValid(); e != nil {
				return store.ErrInvalid
			}
			ls = append(ls, store.ProtectionLimit{Key: protectionKeyFromPB(l.Key), Algorithm: l.Algorithm, Capacity: int(l.Capacity), Window: l.Window.AsDuration(), Refill: l.Refill.AsDuration(), Lockout: l.Lockout.AsDuration()})
		}
		a, e := p.Reserve(ctx, ls, tsFromPB(q.Now))
		r.Allowed = a.Allowed
		r.TenantId = a.Receipt.TenantID
		r.ReceiptId = a.Receipt.ID
		r.RetryAt = tsToPB(a.RetryAt)
		return e
	}))
	return r, nil
}

func (s *Server) ProtectionComplete(ctx context.Context, q *storev1.ProtectionRequest) (*storev1.ProtectionResult, error) {
	r := &storev1.ProtectionResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		p := st.Protection()
		return p.Complete(ctx, store.ProtectionReceipt{TenantID: q.TenantId, ID: q.ReceiptId}, q.Outcome, tsFromPB(q.Now))
	}))
	return r, nil
}

func (s *Server) ProtectionBlocks(ctx context.Context, q *storev1.ProtectionRequest) (*storev1.ProtectionResult, error) {
	r := &storev1.ProtectionResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		p := st.Protection()
		bs, e := p.Blocks(ctx, q.TenantId, protectionFilterFromPB(q.Filter), tsFromPB(q.Now))
		for _, b := range bs {
			r.Blocks = append(r.Blocks, &storev1.ProtectionBlock{Key: protectionKeyToPB(b.Key), BlockedUntil: tsToPB(b.BlockedUntil)})
		}
		return e
	}))
	return r, nil
}

func (s *Server) ProtectionClear(ctx context.Context, q *storev1.ProtectionRequest) (*storev1.ProtectionResult, error) {
	r := &storev1.ProtectionResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		p := st.Protection()
		return p.Clear(ctx, q.TenantId, protectionFilterFromPB(q.Filter))
	}))
	return r, nil
}

func (s *Server) ProtectionUseProof(ctx context.Context, q *storev1.ProtectionRequest) (*storev1.ProtectionResult, error) {
	r := &storev1.ProtectionResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		p := st.Protection()
		var e error
		r.Allowed, e = p.UseProof(ctx, q.ProofHash, tsFromPB(q.Now), tsFromPB(q.ExpiresAt))
		return e
	}))
	return r, nil
}

func (s *Server) ProtectionRecordRisk(ctx context.Context, q *storev1.ProtectionRequest) (*storev1.ProtectionResult, error) {
	r := &storev1.ProtectionResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		p := st.Protection()
		return p.RecordRisk(ctx, q.TenantId, q.AttemptId, q.Ip, tsFromPB(q.Now))
	}))
	return r, nil
}

func (s *Server) ProtectionRiskCount(ctx context.Context, q *storev1.ProtectionRequest) (*storev1.ProtectionResult, error) {
	r := &storev1.ProtectionResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		p := st.Protection()
		n, e := p.RiskCount(ctx, q.TenantId, q.Ip, tsFromPB(q.Now))
		r.Count = int64(n)
		return e
	}))
	return r, nil
}

func (s *Server) ProtectionSweep(ctx context.Context, q *storev1.ProtectionRequest) (*storev1.ProtectionResult, error) {
	r := &storev1.ProtectionResult{}
	r.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		p := st.Protection()
		n, e := p.Sweep(ctx, tsFromPB(q.Now), int(q.Limit))
		r.Count = int64(n)
		return e
	}))
	return r, nil
}
