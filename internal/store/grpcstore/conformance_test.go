package grpcstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"net"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

var _ store.Store = (*Client)(nil)

// serve serves backing over bufconn and returns a client. Closing the client
// tears down the connection, the server, and backing.
func serve(t *testing.T, backing store.Store) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	srv := NewServer(backing)
	storev1.RegisterStoreServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return NewClient(conn, func() error {
		err := conn.Close()
		srv.Close()
		gs.Stop()
		if cerr := backing.Close(); err == nil {
			err = cerr
		}
		return err
	})
}

// inProcess serves a fresh memory store over bufconn.
func inProcess(t *testing.T) *Client { return serve(t, memory.New()) }

// inProcessSQLite serves a fresh, migrated SQLite store over bufconn, so the
// held transactions run against real savepoints.
func inProcessSQLite(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	st, err := sqlstore.Open(ctx, "sqlite://"+filepath.Join(t.TempDir(), "z.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		t.Fatal(err)
	}
	return serve(t, st)
}

// actionsPending names the Actions suite as skipped until the gRPC protocol
// carries the repository (Plan 27 Task 5); the stubs fail closed, not succeed.
var actionsPending = map[string]string{"Actions": "gRPC Actions repository lands in Plan 27 Task 5"}

func TestConformance(t *testing.T) {
	storetest.RunExcept(t, func(t *testing.T) store.Store { return inProcess(t) }, actionsPending)
}

func TestConformanceSQLite(t *testing.T) {
	storetest.RunExcept(t, func(t *testing.T) store.Store { return inProcessSQLite(t) }, actionsPending)
}

// These assertions run against SQL savepoints behind real gRPC transaction
// handles. A callback failure must undo rotation, revocation and custom writes.
func TestSigningLifecycleSQLiteRollback(t *testing.T) {
	ctx := context.Background()
	st := inProcessSQLite(t)
	defer st.Close()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "rollback", Name: "rollback"}); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st.SigningKeys(), w)
	if err = km.Ensure(ctx, "rollback"); err != nil {
		t.Fatal(err)
	}
	before, err := st.SigningKeys().List(ctx, "rollback")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	aborted := errors.New("injected rollback")
	err = st.WithTx(ctx, func(tx store.Store) error {
		m := keys.NewManager(tx.SigningKeys(), w)
		if _, err := m.RotateWithResult(ctx, "rollback"); err != nil {
			return err
		}
		if _, err := m.Revoke(ctx, "rollback", before[0].KID); err != nil {
			return err
		}
		if err := tx.CustomSigningKeys().Replace(ctx, &store.CustomSigningKeySet{TenantID: "rollback", JWKS: json.RawMessage(`{"keys":[{"kid":"custom-rollback","kty":"RSA","n":"abc","e":"AQAB"}]}`)}); err != nil {
			return err
		}
		return aborted
	})
	if !errors.Is(err, aborted) {
		t.Fatalf("callback error=%v", err)
	}
	after, err := st.SigningKeys().List(ctx, "rollback")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot, actual) {
		t.Fatal("aborted gRPC SQL transaction leaked managed key state")
	}
	if _, err = st.CustomSigningKeys().Get(ctx, "rollback"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("aborted custom set=%v", err)
	}
	if _, err = km.RotateWithResult(ctx, "rollback"); err != nil {
		t.Fatalf("rotation after rollback=%v", err)
	}
}
