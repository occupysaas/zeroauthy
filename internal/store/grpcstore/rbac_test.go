package grpcstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestRBACPluginRoundTrip(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	if err := c.CheckRBACSupport(context.Background()); err != nil {
		t.Fatal(err)
	}
	storetest.RunSuites(t, func(t *testing.T) store.Store { return inProcess(t) }, "RBAC")
}

type oldRBACPlugin struct{ *Server }

func (oldRBACPlugin) RBACCapabilities(context.Context, *storev1.PingRequest) (*storev1.RBACCapabilitiesResult, error) {
	return nil, status.Error(codes.Unimplemented, "pre-RBAC plugin")
}
func TestRBACOldPlugin(t *testing.T) {
	c := serveWith(t, oldRBACPlugin{NewServer(memory.New())})
	defer c.Close()
	if err := c.CheckRBACSupport(context.Background()); !errors.Is(err, store.ErrRBACUnavailable) {
		t.Fatalf("capability: %v", err)
	}
	err := c.ResourceServers().Create(context.Background(), &store.ResourceServer{TenantID: "t", ID: "a", Identifier: "https://api.test", EnforcePolicies: true})
	if !errors.Is(err, store.ErrRBACUnavailable) {
		t.Fatalf("setting silently downgraded: %v", err)
	}
}
