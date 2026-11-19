package grpcstore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	pb "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

type refreshProbeServer struct {
	*Server
	probes    atomic.Int32
	rotations atomic.Int32
	failure   codes.Code
}

func (s *refreshProbeServer) RefreshTokensIICapabilities(ctx context.Context, q *pb.PingRequest) (*pb.EventsCapabilitiesResult, error) {
	s.probes.Add(1)
	if s.failure != codes.OK {
		return nil, status.Error(s.failure, "probe")
	}
	return &pb.EventsCapabilitiesResult{Version: 1}, nil
}

func (s *refreshProbeServer) RefreshTokensRotate(context.Context, *pb.RefreshTokensRotateRequest) (*pb.Result, error) {
	s.rotations.Add(1)
	return &pb.Result{}, nil
}

func TestRefreshIIOldPlugin(t *testing.T) {
	ctx := context.Background()
	srv := &refreshProbeServer{Server: NewServer(memory.New()), failure: codes.Unimplemented}
	c := serveWith(t, srv)
	defer c.Close()
	now := time.Now()
	if err := c.RefreshTokens().Rotate(ctx, "t", "first", &store.RefreshToken{}, now, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.RefreshTokens().Rotate(ctx, "t", "first", &store.RefreshToken{DPoPJKT: "jkt"}, now, time.Second); !errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
		t.Fatalf("bound rotation=%v", err)
	}
	if err := c.AuthCodes().Create(ctx, &store.AuthCode{TenantID: "t", CodeHash: "h", DPoPJKT: "key"}); !errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
		t.Fatalf("bound code write=%v", err)
	}
	if err := c.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c", RequireProofOfPossession: true}); !errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
		t.Fatalf("proof requirement write=%v", err)
	}
	if err := c.WithTx(ctx, func(tx store.Store) error {
		return tx.DPoP().UseProof(ctx, "t", "origin", "key", "id", now, now.Add(time.Minute))
	}); !errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
		t.Fatalf("proof claim=%v", err)
	}
	if srv.probes.Load() != 1 || srv.rotations.Load() != 1 {
		t.Fatalf("probes=%d legacy rotations=%d", srv.probes.Load(), srv.rotations.Load())
	}
}

func TestRefreshIITransportFailure(t *testing.T) {
	srv := &refreshProbeServer{Server: NewServer(memory.New()), failure: codes.Unavailable}
	c := serveWith(t, srv)
	defer c.Close()
	for range 2 {
		err := c.RefreshTokens().Rotate(context.Background(), "t", "first", &store.RefreshToken{}, time.Now(), 0)
		if status.Code(err) != codes.Unavailable || errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
			t.Fatalf("temporary failure=%v", err)
		}
	}
	if srv.probes.Load() != 2 || srv.rotations.Load() != 0 {
		t.Fatalf("probes=%d legacy rotations=%d", srv.probes.Load(), srv.rotations.Load())
	}
}

func TestRefreshIINilConversion(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx := context.Background()
	if err := c.RefreshTokens().ConvertNonRotating(ctx, "t", "id", nil); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("nil successor: %v", err)
	}
	if err := c.RefreshTokens().ConvertRotating(ctx, "t", "missing", nil, time.Now(), 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing presentation: %v", err)
	}
}

type replacedRefreshPlugin struct{ *refreshProbeServer }

func (s *replacedRefreshPlugin) RefreshTokensIIWrite(context.Context, *pb.RefreshIIWrite) (*pb.Result, error) {
	return nil, status.Error(codes.Unimplemented, "versioned writes unavailable")
}
func TestRefreshIICapabilityDisappears(t *testing.T) {
	backing := memory.New()
	srv := &replacedRefreshPlugin{&refreshProbeServer{Server: NewServer(backing)}}
	c := serveWith(t, srv)
	defer c.Close()
	ctx := context.Background()
	if err := c.CheckRefreshTokensIISupport(ctx); err != nil {
		t.Fatal(err)
	}
	err := c.AuthCodes().Create(ctx, &store.AuthCode{TenantID: "t", CodeHash: "h", DPoPJKT: "key"})
	if !errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
		t.Fatalf("write=%v", err)
	}
	if _, err := backing.AuthCodes().Get(ctx, "t", "h"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old write route accepted a bound code: %v", err)
	}
	if err := c.CheckRefreshTokensIISupport(ctx); !errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
		t.Fatalf("latched=%v", err)
	}
}
