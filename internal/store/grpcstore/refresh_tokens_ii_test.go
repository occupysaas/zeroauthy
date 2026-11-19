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
	if err := c.CheckRefreshTokensIISupport(ctx); !errors.Is(err, store.ErrRefreshTokensIISupportLost) || errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
		t.Fatalf("latched=%v", err)
	}
}

// This binary serves the earlier protocol over retained rows. Its legacy
// methods can read or consume the data, but cannot return binding fields.
type retainedLegacyPlugin struct {
	pb.UnimplementedStoreServiceServer
	legacy *Server
	calls  atomic.Int32
}

func (p *retainedLegacyPlugin) AuthCodesConsume(ctx context.Context, q *pb.ConsumeRequest) (*pb.AuthCodeResult, error) {
	p.calls.Add(1)
	r, err := p.legacy.AuthCodesConsume(ctx, q)
	if r.GetValue() != nil {
		r.Value.DpopJkt = ""
	}
	return r, err
}
func (p *retainedLegacyPlugin) RefreshTokensGetByTokenHash(ctx context.Context, q *pb.ScopedKey) (*pb.RefreshTokenResult, error) {
	p.calls.Add(1)
	r, err := p.legacy.RefreshTokensGetByTokenHash(ctx, q)
	if r.GetValue() != nil {
		r.Value.DpopJkt = ""
		r.Value.Access = ""
	}
	return r, err
}
func (p *retainedLegacyPlugin) ClientsGet(ctx context.Context, q *pb.ScopedKey) (*pb.ClientResult, error) {
	p.calls.Add(1)
	r, err := p.legacy.ClientsGet(ctx, q)
	if r.GetValue() != nil {
		r.Value.RequireProofOfPossession = false
	}
	return r, err
}
func (p *retainedLegacyPlugin) ResourceServersGetByIdentifier(ctx context.Context, q *pb.ScopedKey) (*pb.ResourceServerResult, error) {
	p.calls.Add(1)
	r, err := p.legacy.ResourceServersGetByIdentifier(ctx, q)
	if r.GetValue() != nil {
		r.Value.ProofOfPossession = nil
	}
	return r, err
}
func (p *retainedLegacyPlugin) AuthTransactionsGet(ctx context.Context, q *pb.ScopedKey) (*pb.AuthTransactionResult, error) {
	p.calls.Add(1)
	r, err := p.legacy.AuthTransactionsGet(ctx, q)
	if r.GetValue() != nil {
		r.Value.DpopJkt = ""
	}
	return r, err
}
func (p *retainedLegacyPlugin) RefreshTokensRotate(ctx context.Context, q *pb.RefreshTokensRotateRequest) (*pb.Result, error) {
	p.calls.Add(1)
	return p.legacy.RefreshTokensRotate(ctx, q)
}
func (p *retainedLegacyPlugin) BeginTx(ctx context.Context, q *pb.BeginTxRequest) (*pb.BeginTxResponse, error) {
	return p.legacy.BeginTx(ctx, q)
}
func (p *retainedLegacyPlugin) Rollback(ctx context.Context, q *pb.EndTxRequest) (*pb.Result, error) {
	return p.legacy.Rollback(ctx, q)
}
func (p *retainedLegacyPlugin) Commit(ctx context.Context, q *pb.EndTxRequest) (*pb.Result, error) {
	return p.legacy.Commit(ctx, q)
}

func TestRefreshIIRetainedDataAfterReplacement(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	for _, operation := range []string{"consume", "token", "client", "api", "auth-transaction", "transaction"} {
		t.Run(operation, func(t *testing.T) {
			backing := memory.New()
			srv := NewServer(backing)
			t.Cleanup(srv.Close)
			c := serveWith(t, srv)
			if err := c.AuthCodes().Create(ctx, &store.AuthCode{TenantID: "t", CodeHash: "hash", DPoPJKT: "retained"}); err != nil {
				t.Fatal(err)
			}
			if err := c.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: "t", ID: "id", FamilyID: "family", TokenHash: "hash", Access: "online", DPoPJKT: "retained"}); err != nil {
				t.Fatal(err)
			}
			if err := c.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "app", RequireProofOfPossession: true}); err != nil {
				t.Fatal(err)
			}
			if err := c.AuthTransactions().Create(ctx, &store.AuthTransaction{TenantID: "t", ID: "flow", DPoPJKT: "retained"}); err != nil {
				t.Fatal(err)
			}
			if err := c.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: "t", ID: "api", Identifier: "https://api.example.test", ProofOfPossession: &store.ProofOfPossession{Mechanism: "dpop", Required: true}}); err != nil {
				t.Fatal(err)
			}
			old := &retainedLegacyPlugin{legacy: srv}
			// Switch the RPC destination while retaining the original negotiated client.
			c.rpc = serveWith(t, old).rpc
			var err error
			switch operation {
			case "consume":
				_, err = c.AuthCodes().Consume(ctx, "t", "hash", now)
			case "token":
				_, err = c.RefreshTokens().GetByTokenHash(ctx, "t", "hash")
			case "client":
				_, err = c.Clients().Get(ctx, "t", "app")
			case "api":
				_, err = c.ResourceServers().GetByIdentifier(ctx, "t", "https://api.example.test")
			case "auth-transaction":
				_, err = c.AuthTransactions().Get(ctx, "t", "flow")
			case "transaction":
				err = c.WithTx(ctx, func(tx store.Store) error { _, e := tx.AuthCodes().Consume(ctx, "t", "hash", now); return e })
			}
			if !errors.Is(err, store.ErrRefreshTokensIIUnavailable) || !errors.Is(err, store.ErrRefreshTokensIISupportLost) {
				t.Errorf("first retained operation=%v", err)
			}
			err = c.RefreshTokens().Rotate(ctx, "t", "id", &store.RefreshToken{TenantID: "t", ID: "next", FamilyID: "family", TokenHash: "next"}, now, 0)
			if !errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
				t.Errorf("rotation after downgrade=%v", err)
			}
			// Restore a capable peer. Loss remains latched on the original
			// client and on any subsequent transaction view until reconnect.
			c.rpc = serveWith(t, srv).rpc
			if e := c.WithTx(ctx, func(tx store.Store) error { return store.CheckRefreshTokensIISupport(ctx, tx) }); !errors.Is(e, store.ErrRefreshTokensIISupportLost) || errors.Is(e, store.ErrRefreshTokensIIUnavailable) {
				t.Fatalf("downgraded transaction probe=%v", e)
			}
			if n := old.calls.Load(); n != 0 {
				t.Errorf("reached %d legacy operations", n)
			}
			code, e := backing.AuthCodes().Get(ctx, "t", "hash")
			if e != nil || code.UsedAt != nil || code.DPoPJKT != "retained" {
				t.Fatal("retained code changed")
			}
			token, e := backing.RefreshTokens().Get(ctx, "t", "id")
			if e != nil || token.RotatedAt != nil || token.RevokedAt != nil || token.DPoPJKT != "retained" || token.Access != "online" {
				t.Fatal("retained family changed")
			}
		})
	}
}

type changingRefreshBackend struct {
	store.Store
	probe   func() error
	txProbe func() error
}

func (s changingRefreshBackend) CheckRefreshTokensIISupport(context.Context) error { return s.probe() }
func (s changingRefreshBackend) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(changingRefreshBackend{tx, s.txProbe, s.txProbe}) })
}
func TestRefreshIIReceivingStore(t *testing.T) {
	ctx := t.Context()
	for _, op := range []string{"code", "rotate", "check-rotation", "tx-check-rotation", "tx-code", "tx-only", "transient"} {
		t.Run(op, func(t *testing.T) {
			backing := memory.New()
			var declined atomic.Bool
			refusal := func() error {
				if !declined.Load() {
					return nil
				}
				if op == "transient" {
					return status.Error(codes.Unavailable, "backend unavailable")
				}
				return store.ErrRefreshTokensIIUnavailable
			}
			srvBase := changingRefreshBackend{backing, refusal, refusal}
			if op == "tx-only" || op == "tx-check-rotation" {
				srvBase.probe = func() error { return nil }
			}
			if op == "tx-code" {
				srvBase.txProbe = func() error { return nil }
			}
			srv := NewServer(srvBase)
			t.Cleanup(srv.Close)
			c := serveWith(t, srv)
			if err := c.CheckRefreshTokensIISupport(ctx); err != nil {
				t.Fatal(err)
			}
			if err := backing.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: "t", ID: "old", TokenHash: "old", FamilyID: "f", Rotating: true}); err != nil {
				t.Fatal(err)
			}
			declined.Store(true)
			create := func(st store.Store) error {
				return st.AuthCodes().Create(ctx, &store.AuthCode{TenantID: "t", CodeHash: "attempt", DPoPJKT: "jkt"})
			}
			var err error
			switch op {
			case "check-rotation":
				err = c.RefreshTokens().CheckRotation(ctx, "t", "old", time.Now(), time.Second)
			case "tx-check-rotation":
				err = c.WithTx(ctx, func(tx store.Store) error {
					return tx.RefreshTokens().CheckRotation(ctx, "t", "old", time.Now(), time.Second)
				})
			case "rotate":
				err = c.RefreshTokens().Rotate(ctx, "t", "old", &store.RefreshToken{TenantID: "t", ID: "next", TokenHash: "next", FamilyID: "f", Rotating: true}, time.Now(), 0)
			case "tx-code", "tx-only":
				err = c.WithTx(ctx, create)
			default:
				err = create(c)
			}
			if op == "transient" {
				if status.Code(err) != codes.Unavailable || errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
					t.Errorf("transient=%v", err)
				}
			} else if !errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
				t.Errorf("declining backing store returned %v", err)
			}
			if _, e := backing.AuthCodes().Get(ctx, "t", "attempt"); !errors.Is(e, store.ErrNotFound) {
				t.Errorf("backing store wrote bound code: %v", e)
			}
			old, e := backing.RefreshTokens().Get(ctx, "t", "old")
			if e != nil || old.RotatedAt != nil {
				t.Error("backing store rotated old token")
			}
			if op == "transient" {
				declined.Store(false)
				if e := create(c); e != nil {
					t.Fatalf("retry=%v", e)
				}
			}
		})
	}
}

func TestRefreshIIInitiallyLegacyReadAndConsume(t *testing.T) {
	ctx := t.Context()
	backing := memory.New()
	if err := backing.AuthCodes().Create(ctx, &store.AuthCode{TenantID: "t", CodeHash: "code"}); err != nil {
		t.Fatal(err)
	}
	if err := backing.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "app"}); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(backing)
	t.Cleanup(srv.Close)
	old := &retainedLegacyPlugin{legacy: srv}
	c := serveWith(t, old)
	if _, err := c.Clients().Get(ctx, "t", "app"); err != nil {
		t.Fatal(err)
	}
	if err := c.WithTx(ctx, func(tx store.Store) error { _, e := tx.AuthCodes().Consume(ctx, "t", "code", time.Now()); return e }); err != nil {
		t.Fatal(err)
	}
	if old.calls.Load() != 2 {
		t.Fatalf("legacy operations=%d", old.calls.Load())
	}
	code, err := backing.AuthCodes().Get(ctx, "t", "code")
	if err != nil || code.UsedAt == nil {
		t.Fatal("legacy consumption was lost")
	}
}
