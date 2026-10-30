package grpcstore

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Replace the actual TCP server while retaining the same client connection.
// A successful II negotiation must not survive a replacement by a v1-only
// plugin; upgrading the replacement must recover without constructing a client.
func TestOrganizationsIIActualServerReplacement(t *testing.T) {
	backing := memory.New()
	address := "127.0.0.1:0"
	var server *grpc.Server
	start := func(version int32, missing bool) {
		t.Helper()
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		address = listener.Addr().String()
		plugin := &iiCapabilityPlugin{Server: NewServer(backing), missing: missing}
		plugin.version.Store(version)
		t.Cleanup(func() { plugin.Close() })
		server = grpc.NewServer()
		storev1.RegisterStoreServiceServer(server, plugin)
		current := server
		go current.Serve(listener)
	}
	start(1, false)
	defer func() { server.Stop() }()
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(conn, conn.Close)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ready := func() {
		t.Helper()
		for {
			conn.ResetConnectBackoff()
			if err := client.Ping(ctx); err == nil {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("replacement transport never recovered")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	ready()
	orgSeed(t, client)
	org := &store.Organization{TenantID: "t", ID: "org_abcdefghijklmnop", Name: "replacement"}
	if err := client.Organizations().Create(ctx, org, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.CheckOrganizationsIISupport(ctx); err != nil {
		t.Fatal(err)
	}
	server.Stop()
	start(0, true)
	ready()
	if _, err := client.Organizations().Get(ctx, "t", org.ID); err != nil {
		t.Fatalf("Plan29 after replacement: %v", err)
	}
	active := *org
	active.IsAppEntitlementActive = true
	if err := client.Organizations().Update(ctx, &active); !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
		t.Fatalf("active II write on replacement: %v", err)
	}
	got, err := backing.Organizations().Get(ctx, "t", org.ID)
	if err != nil || got.IsAppEntitlementActive {
		t.Fatalf("unsupported write persisted: %v", err)
	}
	server.Stop()
	start(1, false)
	ready()
	if err := client.CheckOrganizationsIISupport(ctx); err != nil {
		t.Fatalf("upgrade recovery: %v", err)
	}
	if err := client.Organizations().Update(ctx, &active); err != nil {
		t.Fatal(err)
	}
	got, err = backing.Organizations().Get(ctx, "t", org.ID)
	if err != nil || !got.IsAppEntitlementActive {
		t.Fatalf("recovered write missing: %v", err)
	}
}
