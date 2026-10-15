package storeplugin

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/zeroauthy/zeroauthy/internal/store/grpcstore"
	"github.com/zeroauthy/zeroauthy/pkg/store"
)

type panicStore struct {
	store.Store
	panicNext bool
}

func (p *panicStore) Ping(context.Context) error {
	if p.panicNext {
		p.panicNext = false
		panic("boom")
	}
	return nil
}

// A panic in one handler fails that request with an error; the server keeps
// serving.
func TestServerSurvivesHandlerPanic(t *testing.T) {
	ps := &panicStore{panicNext: true}
	srv := grpc.NewServer(serverOptions()...)
	gs := grpcstore.NewServer(ps)
	registerStore(srv, gs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	defer srv.Stop()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := grpcstore.NewClient(conn, func() error { return conn.Close() })
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err == nil {
		t.Fatal("panicking request succeeded")
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("server did not survive the panic: %v", err)
	}
}
