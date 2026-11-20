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

// prePlan39cPlugin is a plugin binary built before the GitHub capability RPC.
type prePlan39cPlugin struct{ *Server }

func (prePlan39cPlugin) GitHubFederationSupported(context.Context, *storev1.GitHubFederationCapabilitiesRequest) (*storev1.Result, error) {
	return nil, status.Error(codes.Unimplemented, "old plugin")
}

// noGitHubStore hides every optional capability of its backing store,
// GitHubFederationSupporter included.
type noGitHubStore struct{ store.Store }

func TestGRPCGitHubCapabilityOldPlugin(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"old binary", "unsupported backing", "supported"} {
		t.Run(kind, func(t *testing.T) {
			backing := memory.New()
			defer backing.Close()
			var c *Client
			switch kind {
			case "old binary":
				c = serveWith(t, prePlan39cPlugin{NewServer(backing)})
			case "unsupported backing":
				c = serve(t, noGitHubStore{backing})
			default:
				c = serve(t, backing)
			}
			defer c.Close()
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			var want error = store.ErrFederationUnavailable
			if kind == "supported" {
				want = nil
			}
			check := func(name string, err error) {
				t.Helper()
				if !errors.Is(err, want) {
					t.Fatalf("%s: got %v want %v", name, err, want)
				}
			}
			check("probe", c.GitHubFederationSupported(ctx))

			// Other social connections stay usable on a predecessor plugin.
			if err := c.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "g", Name: "google", Strategy: "google-oauth2"}); err != nil {
				t.Fatal(err)
			}
			if kind == "unsupported backing" {
				// The plugin server gates raw RPCs too, not only the client.
				pb, _ := connectionToPB(&store.Connection{TenantID: "t", ID: "raw-gh", Name: "raw", Strategy: "github"})
				r, err := c.rpc.ConnectionsCreate(ctx, &storev1.ConnectionWrite{Value: pb})
				if err != nil {
					t.Fatal(err)
				}
				check("raw connection", errFromPB(r.Error))
				userPB, _ := userToPB(&store.User{TenantID: "t", UserID: "github|7", Identities: []store.Identity{{Connection: "raw", Provider: "github", UserID: "7"}}})
				r, err = c.rpc.UsersCreate(ctx, &storev1.UserWrite{Value: userPB})
				if err != nil {
					t.Fatal(err)
				}
				check("raw user", errFromPB(r.Error))
			}
			check("connection create", c.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "gh", Name: "gh", Strategy: "github"}))
			check("connection update", c.Connections().Update(ctx, &store.Connection{TenantID: "t", ID: "g", Name: "google", Strategy: "github"}))
			check("user create", c.Users().Create(ctx, &store.User{TenantID: "t", UserID: "github|42", Identities: []store.Identity{{Connection: "gh", Provider: "github", UserID: "42"}}}))
			if want == nil {
				u, err := c.Users().FindByIdentity(ctx, "t", "gh", "42")
				if err != nil || u.UserID != "github|42" {
					t.Fatalf("indexed %+v %v", u, err)
				}
				return
			}
			if _, err := backing.Connections().Get(ctx, "t", "gh"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("wrote connection: %v", err)
			}
			if g, err := backing.Connections().Get(ctx, "t", "g"); err != nil || g.Strategy != "google-oauth2" {
				t.Fatalf("updated connection: %+v %v", g, err)
			}
			if _, err := backing.Users().Get(ctx, "t", "github|42"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("wrote user: %v", err)
			}
		})
	}
}

func TestGRPCGitHubCapabilityGuardsIdentityWrites(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"old binary", "unsupported backing"} {
		t.Run(kind, func(t *testing.T) {
			backing := memory.New()
			defer backing.Close()
			if err := backing.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			if err := backing.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "gh", Name: "gh", Strategy: "github"}); err != nil {
				t.Fatal(err)
			}
			var c *Client
			if kind == "old binary" {
				c = serveWith(t, prePlan39cPlugin{NewServer(backing)})
			} else {
				c = serve(t, noGitHubStore{backing})
			}
			defer c.Close()
			key := store.FederatedIdentityKey{TenantID: "t", ConnectionID: "gh", Subject: "42"}
			for name, call := range map[string]func() error{
				"identity put":    func() error { return c.Federation().PutIdentity(ctx, key, "owner") },
				"identity delete": func() error { return c.Federation().DeleteIdentity(ctx, key, "owner") },
				"tokens put":      func() error { return c.Federation().PutTokens(ctx, key, []byte("sealed")) },
				"tokens delete":   func() error { return c.Federation().DeleteTokens(ctx, key) },
				"attempt": func() error {
					return c.Federation().CreateAttempt(ctx, &store.FederationAttempt{TenantID: "t", StateHash: "s", ConnectionID: "gh", TransactionID: "tx"})
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

func TestGRPCGitHubCapabilityTransaction(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	if err := c.WithTx(ctx, func(tx store.Store) error {
		return tx.(store.GitHubFederationSupporter).GitHubFederationSupported(ctx)
	}); err != nil {
		t.Fatal(err)
	}
}
