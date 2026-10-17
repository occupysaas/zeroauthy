package grpcstore

import (
	"context"
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

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return inProcess(t) })
}

func TestConformanceSQLite(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return inProcessSQLite(t) })
}
