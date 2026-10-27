package grpcstore

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This server exposes all Plan 24 RPCs and intentionally lacks only Plan 25.
type plan24Plugin struct{ *Server }

func (p plan24Plugin) MicrosoftFederationSupported(context.Context, *storev1.MicrosoftFederationCapabilitiesRequest) (*storev1.Result, error) {
	return nil, status.Error(codes.Unimplemented, "old plugin")
}

type noMicrosoftStore struct{ store.Store }
type flakyMicrosoftStore struct {
	store.Store
	fail   bool
	probes int
}

func (s *flakyMicrosoftStore) MicrosoftFederationSupported(context.Context) error {
	s.probes++
	if s.fail {
		return store.ErrConflict
	}
	return nil
}

func TestMicrosoftFederationCapability(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"plan24", "unsupported backing", "supported", "transient"} {
		t.Run(kind, func(t *testing.T) {
			backing := memory.New()
			defer backing.Close()
			var c *Client
			flaky := &flakyMicrosoftStore{Store: backing, fail: true}
			switch kind {
			case "plan24":
				c = serveWith(t, plan24Plugin{NewServer(backing)})
			case "unsupported backing":
				c = serve(t, noMicrosoftStore{backing})
			case "transient":
				c = serve(t, flaky)
			default:
				c = serve(t, backing)
			}
			defer c.Close()
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			want := store.ErrFederationUnavailable
			if kind == "transient" {
				want = store.ErrConflict
			}
			if kind == "supported" {
				want = nil
			}
			check := func(err error) {
				t.Helper()
				if !errors.Is(err, want) {
					t.Fatalf("got %v want %v", err, want)
				}
			}
			check(c.MicrosoftFederationSupported(ctx))
			if kind == "unsupported backing" {
				pb, _ := connectionToPB(&store.Connection{TenantID: "t", ID: "raw-ms", Name: "raw", Strategy: "windowslive"})
				r, err := c.rpc.ConnectionsCreate(ctx, &storev1.ConnectionWrite{Value: pb})
				if err != nil {
					t.Fatal(err)
				}
				check(errFromPB(r.Error))
				userPB, _ := userToPB(&store.User{TenantID: "t", UserID: "windowslive|raw", Identities: []store.Identity{{Connection: "raw", Provider: "windowslive", UserID: "raw"}}})
				r, err = c.rpc.UsersCreate(ctx, &storev1.UserWrite{Value: userPB})
				if err != nil {
					t.Fatal(err)
				}
				check(errFromPB(r.Error))
			}

			// Non-Microsoft federation remains usable on an empty predecessor store.
			if err := c.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "g", Name: "google", Strategy: "google-oauth2"}); err != nil {
				t.Fatal(err)
			}
			calls := []func() error{
				func() error {
					return c.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "ms", Name: "personal", Strategy: "windowslive"})
				},
				func() error {
					return c.Connections().Update(ctx, &store.Connection{TenantID: "t", ID: "g", Name: "google", Strategy: "windowslive"})
				},
				func() error {
					return c.Users().Create(ctx, &store.User{TenantID: "t", UserID: "windowslive|s", Identities: []store.Identity{{Connection: "personal", Provider: "windowslive", UserID: "s"}}})
				},
			}
			for _, call := range calls {
				check(call())
			}
			if want != nil {
				if _, err := backing.Connections().Get(ctx, "t", "ms"); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("wrote connection: %v", err)
				}
				if _, err := backing.Users().Get(ctx, "t", "windowslive|s"); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("wrote user: %v", err)
				}
			}
			if kind == "transient" {
				flaky.fail = false
				if err := c.MicrosoftFederationSupported(ctx); err != nil || flaky.probes < 2 {
					t.Fatalf("recovery: %v probes %d", err, flaky.probes)
				}
			}
		})
	}
}
func TestMicrosoftFederationCapabilityTransaction(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	if err := c.WithTx(ctx, func(tx store.Store) error {
		// A probe must route through the held transaction. Probing the outer
		// memory backing store would deadlock behind this transaction's lock.
		return tx.(store.MicrosoftFederationSupporter).MicrosoftFederationSupported(ctx)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMicrosoftFederationCapabilityGuardsIdentityWrites(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"plan24", "unsupported backing"} {
		t.Run(kind, func(t *testing.T) {
			backing := memory.New()
			defer backing.Close()
			if err := backing.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			if err := backing.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "ms", Name: "personal", Strategy: "windowslive"}); err != nil {
				t.Fatal(err)
			}
			var c *Client
			if kind == "plan24" {
				c = serveWith(t, plan24Plugin{NewServer(backing)})
			} else {
				c = serve(t, noMicrosoftStore{backing})
			}
			defer c.Close()
			key := store.FederatedIdentityKey{TenantID: "t", ConnectionID: "ms", Subject: "s"}
			for name, call := range map[string]func() error{
				"identity put":    func() error { return c.Federation().PutIdentity(ctx, key, "owner") },
				"identity delete": func() error { return c.Federation().DeleteIdentity(ctx, key, "owner") },
				"tokens put":      func() error { return c.Federation().PutTokens(ctx, key, []byte("sealed")) },
				"tokens delete":   func() error { return c.Federation().DeleteTokens(ctx, key) },
				"attempt": func() error {
					return c.Federation().CreateAttempt(ctx, &store.FederationAttempt{TenantID: "t", StateHash: "s", ConnectionID: "ms", TransactionID: "tx"})
				},
			} {
				if err := call(); !errors.Is(err, store.ErrFederationUnavailable) {
					t.Errorf("%s: %v", name, err)
				}
			}
			if _, err := backing.Federation().GetTokens(ctx, key); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("tokens mutation %v", err)
			}
		})
	}
}
