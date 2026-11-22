package grpcstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CheckSAMLSupport reports whether the plugin implements saml.v1 (Plan 37a).
// A definite answer is cached; transient probe errors are retried.
func (c *Client) CheckSAMLSupport(ctx context.Context) error {
	switch c.samlCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrSAMLUnavailable
	}
	result, err := c.rpc.SAMLCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("saml.v1 capability", capabilityError(err, store.ErrSAMLUnavailable))
	} else {
		err = errFromPB(result.GetError())
		if err == nil && result.GetVersion() < 1 {
			err = store.ErrSAMLUnavailable
		}
	}
	if errors.Is(err, store.ErrSAMLUnavailable) {
		c.samlCap.v.Store(2)
	} else if err == nil {
		c.samlCap.v.CompareAndSwap(0, 1)
	}
	if c.samlCap.v.Load() == 2 {
		return store.ErrSAMLUnavailable
	}
	return err
}

// SAMLCapabilities answers saml.v1 for the backing store.
func (s *Server) SAMLCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if _, explicit := s.st.(store.SAMLSupporter); !explicit {
		_, sessions := s.st.Sessions().(store.SAMLSessionRecorder)
		_, replay := s.st.(store.SAMLReplayStore)
		if !sessions || !replay {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
	}
	if err := store.CheckSAMLSupport(ctx, s.st); err != nil {
		if errors.Is(err, store.ErrSAMLUnavailable) {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
		return nil, status.Error(codes.Unavailable, "saml.v1 backing store probe failed")
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

// RecordSAMLParticipant implements store.SAMLSessionRecorder over gRPC.
func (a clientSessions) RecordSAMLParticipant(ctx context.Context, tid, id string, p store.SAMLParticipant) error {
	if err := a.c.CheckSAMLSupport(ctx); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	result, err := a.c.rpc.SAMLSessionParticipant(ctx, &storev1.SAMLParticipantWrite{TxId: a.c.txID, TenantId: tid, Id: id, Participant: raw})
	return do("SAMLSessionParticipant", result, err)
}

// SAMLSessionParticipant serves RecordSAMLParticipant.
func (s *Server) SAMLSessionParticipant(ctx context.Context, q *storev1.SAMLParticipantWrite) (*storev1.Result, error) {
	var p store.SAMLParticipant
	if err := json.Unmarshal(q.Participant, &p); err != nil {
		return &storev1.Result{Error: errToPB(store.ErrInvalid)}, nil
	}
	return exec(s, q.TxId, func(st store.Store) error {
		repo, ok := st.Sessions().(store.SAMLSessionRecorder)
		if !ok {
			return store.ErrSAMLUnavailable
		}
		return repo.RecordSAMLParticipant(ctx, q.TenantId, q.Id, p)
	}), nil
}

// UseSAMLAssertion implements store.SAMLReplayStore over gRPC.
func (c *Client) UseSAMLAssertion(ctx context.Context, tid, connection, id string, exp, now time.Time) error {
	if err := c.CheckSAMLSupport(ctx); err != nil {
		return err
	}
	r, err := c.rpc.SAMLReplayUse(ctx, &storev1.GlobalRevocationJTIRequest{TxId: c.txID, TenantId: tid, ConnectionId: connection, Jti: id, ExpiresAt: tsToPB(exp), Now: tsToPB(now)})
	return do("SAMLReplayUse", r, err)
}

// PurgeSAMLAssertions implements store.SAMLReplayStore over gRPC.
func (c *Client) PurgeSAMLAssertions(ctx context.Context, before time.Time, limit int) (int, error) {
	if err := c.CheckSAMLSupport(ctx); err != nil {
		return 0, err
	}
	r, err := c.rpc.SAMLReplayPurge(ctx, &storev1.ClientCredentialsPurgeRequest{TxId: c.txID, Before: tsToPB(before), Limit: int64(limit)})
	if err != nil {
		return 0, rpcErr("SAMLReplayPurge", err)
	}
	return int(r.GetCount()), errFromPB(r.GetError())
}

// SAMLReplayUse serves UseSAMLAssertion.
func (s *Server) SAMLReplayUse(ctx context.Context, q *storev1.GlobalRevocationJTIRequest) (*storev1.Result, error) {
	return exec(s, q.TxId, func(st store.Store) error {
		repo, ok := st.(store.SAMLReplayStore)
		if !ok {
			return store.ErrSAMLUnavailable
		}
		if err := checkTS(q.ExpiresAt, q.Now); err != nil {
			return err
		}
		return repo.UseSAMLAssertion(ctx, q.TenantId, q.ConnectionId, q.Jti, tsFromPB(q.ExpiresAt), tsFromPB(q.Now))
	}), nil
}

// SAMLReplayPurge serves PurgeSAMLAssertions.
func (s *Server) SAMLReplayPurge(ctx context.Context, q *storev1.ClientCredentialsPurgeRequest) (*storev1.CountResult, error) {
	out := &storev1.CountResult{}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		repo, ok := st.(store.SAMLReplayStore)
		if !ok {
			return store.ErrSAMLUnavailable
		}
		n, err := repo.PurgeSAMLAssertions(ctx, tsFromPB(q.Before), int(q.Limit))
		out.Count = int64(n)
		return err
	}))
	return out, nil
}
