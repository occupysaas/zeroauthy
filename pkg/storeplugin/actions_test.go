package storeplugin

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store/grpcstore"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type capabilityTwoServer struct{ *grpcstore.Server }

func (capabilityTwoServer) ActionsCapabilities(context.Context, *storev1.PingRequest) (*storev1.ActionsCapabilitiesResult, error) {
	return &storev1.ActionsCapabilitiesResult{Version: 2}, nil
}

// Hiding ActionsSupporter in the SDK wrapper bypasses the app's startup admission.
func TestActionsOpenedCapabilityAdmission(t *testing.T) {
	backing := memory.New()
	defer backing.Close()
	srv := grpc.NewServer()
	storev1.RegisterStoreServiceServer(srv, capabilityTwoServer{grpcstore.NewServer(backing)})
	lis := bufconn.Listen(1 << 20)
	go srv.Serve(lis)
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///buf", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var s store.Store = &opened{Store: grpcstore.NewClient(conn, nil)}
	capable, ok := s.(store.ActionsSupporter)
	if !ok {
		t.Fatal("opened plugin hides Actions capability admission from startup")
	}
	if err = capable.CheckActionsSupport(context.Background()); !errors.Is(err, store.ErrActionsUnavailable) || !strings.Contains(err.Error(), "capability 3") {
		t.Fatalf("old plugin startup admission: %v", err)
	}
}
