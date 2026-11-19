package grpcstore

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	pb "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

type clientDPoP struct{ c *Client }
type clientTokenQuotas struct{ c *Client }

func (c *Client) DPoP() store.DPoP               { return clientDPoP{c} }
func (c *Client) TokenQuotas() store.TokenQuotas { return clientTokenQuotas{c} }
func (r clientDPoP) UseProof(ctx context.Context, tid, origin, jkt, jti string, at, expires time.Time) error {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return err
	}
	res, err := r.c.rpc.DPoPUseProof(ctx, &pb.DPoPProofRequest{TxId: r.c.txID, TenantId: tid, Origin: origin, Jkt: jkt, Jti: jti, Now: tsToPB(at), ExpiresAt: tsToPB(expires)})
	return r.c.refreshResult("DPoPUseProof", res, err)
}

func (s *Server) DPoPUseProof(ctx context.Context, q *pb.DPoPProofRequest) (*pb.Result, error) {
	return withRefreshII(s, ctx, q, (*Server).dPoPUseProof)
}

func (s *Server) dPoPUseProof(ctx context.Context, q *pb.DPoPProofRequest) (*pb.Result, error) {
	if err := checkTS(q.Now, q.ExpiresAt); err != nil {
		return &pb.Result{Error: errToPB(err)}, nil
	}
	return exec(s, q.TxId, func(st store.Store) error {
		return st.DPoP().UseProof(ctx, q.TenantId, q.Origin, q.Jkt, q.Jti, tsFromPB(q.Now), tsFromPB(q.ExpiresAt))
	}), nil
}

func (r clientDPoP) PurgeBefore(ctx context.Context, before time.Time, limit int) (int, error) {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return 0, err
	}
	res, err := r.c.rpc.DPoPPurgeBefore(ctx, &pb.RefreshIIPurgeRequest{TxId: r.c.txID, Before: tsToPB(before), Limit: int64(limit)})
	if err = r.c.refreshResult("DPoPPurgeBefore", res, err); err != nil {
		return 0, err
	}
	return int(res.Count), nil
}

func (s *Server) DPoPPurgeBefore(ctx context.Context, q *pb.RefreshIIPurgeRequest) (*pb.CountResult, error) {
	return withRefreshII(s, ctx, q, (*Server).dPoPPurgeBefore)
}

func (s *Server) dPoPPurgeBefore(ctx context.Context, q *pb.RefreshIIPurgeRequest) (*pb.CountResult, error) {
	if err := checkTS(q.Before); err != nil {
		return &pb.CountResult{Error: errToPB(err)}, nil
	}
	return count(s, q.TxId, func(st store.Store) (int, error) { return st.DPoP().PurgeBefore(ctx, tsFromPB(q.Before), int(q.Limit)) }), nil
}

func (r clientTokenQuotas) PurgeBefore(ctx context.Context, before time.Time, limit int) (int, error) {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return 0, err
	}
	res, err := r.c.rpc.TokenQuotasPurgeBefore(ctx, &pb.RefreshIIPurgeRequest{TxId: r.c.txID, Before: tsToPB(before), Limit: int64(limit)})
	if err = r.c.refreshResult("TokenQuotasPurgeBefore", res, err); err != nil {
		return 0, err
	}
	return int(res.Count), nil
}

func (s *Server) TokenQuotasPurgeBefore(ctx context.Context, q *pb.RefreshIIPurgeRequest) (*pb.CountResult, error) {
	return withRefreshII(s, ctx, q, (*Server).tokenQuotasPurgeBefore)
}

func (s *Server) tokenQuotasPurgeBefore(ctx context.Context, q *pb.RefreshIIPurgeRequest) (*pb.CountResult, error) {
	if err := checkTS(q.Before); err != nil {
		return &pb.CountResult{Error: errToPB(err)}, nil
	}
	return count(s, q.TxId, func(st store.Store) (int, error) {
		return st.TokenQuotas().PurgeBefore(ctx, tsFromPB(q.Before), int(q.Limit))
	}), nil
}

func subjectToPB(s store.QuotaSubject) *pb.QuotaSubjectMsg {
	return &pb.QuotaSubjectMsg{Kind: s.Kind, Id: s.ID, Quota: quotaToPB(&s.Quota)}
}

func subjectFromPB(s *pb.QuotaSubjectMsg) (store.QuotaSubject, error) {
	q := quotaFromPB(s.GetQuota())
	if q == nil {
		return store.QuotaSubject{}, store.ErrInvalid
	}
	return store.QuotaSubject{Kind: s.Kind, ID: s.Id, Quota: *q}, nil
}

func (r clientTokenQuotas) Consume(ctx context.Context, tid string, subjects []store.QuotaSubject, now time.Time) ([]store.QuotaState, error) {
	return r.query(ctx, tid, subjects, now, true)
}

func (r clientTokenQuotas) Peek(ctx context.Context, tid string, subjects []store.QuotaSubject, now time.Time) ([]store.QuotaState, error) {
	return r.query(ctx, tid, subjects, now, false)
}

func (r clientTokenQuotas) query(ctx context.Context, tid string, subjects []store.QuotaSubject, now time.Time, consume bool) ([]store.QuotaState, error) {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return nil, err
	}
	q := &pb.QuotaRequest{TxId: r.c.txID, TenantId: tid, Now: tsToPB(now)}
	for _, subject := range subjects {
		q.Subjects = append(q.Subjects, subjectToPB(subject))
	}
	call := r.c.rpc.TokenQuotasPeek
	if consume {
		call = r.c.rpc.TokenQuotasConsume
	}
	res, err := call(ctx, q)
	if err = r.c.refreshResult("TokenQuotas", res, err); err != nil {
		return nil, err
	}
	states := make([]store.QuotaState, 0, len(res.States))
	for _, v := range res.States {
		subject, err := subjectFromPB(v.GetSubject())
		if err != nil {
			return nil, err
		}
		st := store.QuotaState{Subject: subject, Exceeded: v.Exceeded}
		for _, b := range v.Buckets {
			if b == nil {
				return nil, store.ErrInvalid
			}
			if err := checkTS(b.ResetAt); err != nil {
				return nil, err
			}
			bucket := store.QuotaBucket{Name: b.Name, Limit: int(b.Limit), Remaining: int(b.Remaining), Reset: tsFromPB(b.ResetAt)}
			for _, pct := range b.CrossedThresholds {
				bucket.CrossedThresholds = append(bucket.CrossedThresholds, int(pct))
			}
			st.Buckets = append(st.Buckets, bucket)
		}
		states = append(states, st)
	}
	return states, nil
}

func (s *Server) TokenQuotasConsume(ctx context.Context, q *pb.QuotaRequest) (*pb.QuotaResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).tokenQuotasConsumeRPC)
}

func (s *Server) tokenQuotasConsumeRPC(ctx context.Context, q *pb.QuotaRequest) (*pb.QuotaResponse, error) {
	return s.quotaQuery(ctx, q, true)
}

func (s *Server) TokenQuotasPeek(ctx context.Context, q *pb.QuotaRequest) (*pb.QuotaResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).tokenQuotasPeekRPC)
}

func (s *Server) tokenQuotasPeekRPC(ctx context.Context, q *pb.QuotaRequest) (*pb.QuotaResponse, error) {
	return s.quotaQuery(ctx, q, false)
}

func (s *Server) quotaQuery(ctx context.Context, q *pb.QuotaRequest, consume bool) (*pb.QuotaResponse, error) {
	out := &pb.QuotaResponse{}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		if err := checkTS(q.Now); err != nil {
			return err
		}
		var subjects []store.QuotaSubject
		for _, s := range q.Subjects {
			subject, err := subjectFromPB(s)
			if err != nil {
				return err
			}
			subjects = append(subjects, subject)
		}
		repo := st.TokenQuotas()
		query := repo.Peek
		if consume {
			query = repo.Consume
		}
		states, err := query(ctx, q.TenantId, subjects, tsFromPB(q.Now))
		if err != nil {
			return err
		}
		for _, s := range states {
			v := &pb.QuotaStateMsg{Subject: subjectToPB(s.Subject), Exceeded: s.Exceeded}
			for _, b := range s.Buckets {
				bucket := &pb.QuotaBucketMsg{Name: b.Name, Limit: int64(b.Limit), Remaining: int64(b.Remaining), ResetAt: tsToPB(b.Reset)}
				for _, pct := range b.CrossedThresholds {
					bucket.CrossedThresholds = append(bucket.CrossedThresholds, int32(pct))
				}
				v.Buckets = append(v.Buckets, bucket)
			}
			out.States = append(out.States, v)
		}
		return nil
	}))
	return out, nil
}
