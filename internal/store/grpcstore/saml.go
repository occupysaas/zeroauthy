package grpcstore

import (
	"context"
	"encoding/json"
	"errors"

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
		if _, ok := s.st.Sessions().(store.SAMLSessionRecorder); !ok {
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
