package grpcstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// A panic inside fn rolls the remote transaction back and is re-raised.
func TestClientWithTxPanicRollsBack(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic swallowed")
			}
		}()
		_ = c.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, &store.Tenant{ID: "p", Name: "p"}); err != nil {
				return err
			}
			panic("boom")
		})
	}()
	if _, err := c.Tenants().Get(ctx, "p"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write after panic: %v", err)
	}
	// The server-side transaction was released: another WithTx proceeds.
	if err := c.WithTx(ctx, func(store.Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// Cancelling ctx inside fn still rolls back (Rollback uses WithoutCancel).
func TestClientWithTxCancelledContext(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	err := c.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Tenants().Create(ctx, &store.Tenant{ID: "c", Name: "c"}); err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.Tenants().Get(context.Background(), "c"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write after cancel: %v", err)
	}
}

// Transport failures are errors, not domain errors.
func TestClientTransportErrorIsNotADomainError(t *testing.T) {
	c := inProcess(t)
	c.Close()
	_, err := c.Tenants().Get(context.Background(), "x")
	assertTransportErr(t, err)
	assertTransportErr(t, c.Tenants().Create(context.Background(), &store.Tenant{ID: "x", Name: "x"}))
}

func assertTransportErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("no error, want a transport error")
	}
	for _, s := range []error{store.ErrNotFound, store.ErrConflict, store.ErrAlreadyUsed} {
		if errors.Is(err, s) {
			t.Fatalf("err = %v matches %v", err, s)
		}
	}
	var se interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &se) {
		t.Fatalf("err = %v carries no gRPC status", err)
	}
}

// Context errors surface as context errors, keeping the gRPC status.
func TestClientContextErrors(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.Tenants().Create(ctx, &store.Tenant{ID: "x", Name: "x"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	var se interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &se) {
		t.Fatal("status dropped from chain")
	}
	dctx, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dcancel()
	err = c.WithTx(dctx, func(store.Store) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &se) {
		t.Fatalf("deadline: %v", err)
	}
}

// fakeRPC fails Commit and records Rollback.
type fakeRPC struct {
	storev1.StoreServiceClient
	commitErr  error
	commitPB   *storev1.Error
	rolledBack int
}

func (f *fakeRPC) BeginTx(context.Context, *storev1.BeginTxRequest, ...grpc.CallOption) (*storev1.BeginTxResponse, error) {
	return &storev1.BeginTxResponse{TxId: "t"}, nil
}

func (f *fakeRPC) Commit(context.Context, *storev1.EndTxRequest, ...grpc.CallOption) (*storev1.Result, error) {
	return &storev1.Result{Error: f.commitPB}, f.commitErr
}

func (f *fakeRPC) Rollback(context.Context, *storev1.EndTxRequest, ...grpc.CallOption) (*storev1.Result, error) {
	f.rolledBack++
	return &storev1.Result{}, errors.New("rollback failed")
}

// A failed Commit still sends a best-effort Rollback and returns the Commit error.
func TestClientFailedCommitRollsBack(t *testing.T) {
	for name, f := range map[string]*fakeRPC{
		"transport": {commitErr: status.Error(codes.Unavailable, "gone")},
		"domain":    {commitPB: &storev1.Error{Kind: storev1.Error_KIND_CONFLICT, Message: "open nested transaction"}},
	} {
		c := &Client{rpc: f}
		err := c.WithTx(context.Background(), func(store.Store) error { return nil })
		if err == nil || f.rolledBack != 1 {
			t.Fatalf("%s: err = %v, rollbacks = %d", name, err, f.rolledBack)
		}
		if strings.Contains(err.Error(), "rollback failed") {
			t.Fatalf("%s: rollback error leaked: %v", name, err)
		}
	}
}
