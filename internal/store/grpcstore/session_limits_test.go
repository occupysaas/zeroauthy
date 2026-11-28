package grpcstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	pb "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestSessionLimits round-trips Plan 40's SetLimits through the plugin over
// the memory and SQLite backends.
func TestSessionLimits(t *testing.T) {
	for name, c := range map[string]*Client{"memory": inProcess(t), "sqlite": inProcessSQLite(t)} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			s := &store.LoginSession{TenantID: "t", ID: "s1", TokenHash: "h1", UserID: "auth0|u", Connection: "db", AuthenticatedAt: now,
				ExpiresAt: now.Add(72 * time.Hour), IdleExpiresAt: now.Add(24 * time.Hour), CreatedAt: now, UpdatedAt: now, LastInteractedAt: now, CookieMode: "persistent"}
			if err := c.Sessions().Create(ctx, s); err != nil {
				t.Fatal(err)
			}
			got, err := store.SetSessionLimits(ctx, c, "t", "s1", now.Add(time.Hour), now.Add(30*time.Minute), "non-persistent")
			if err != nil {
				t.Fatal(err)
			}
			if !got.ExpiresAt.Equal(now.Add(time.Hour)) || !got.IdleExpiresAt.Equal(now.Add(30*time.Minute)) || got.CookieMode != "non-persistent" {
				t.Fatalf("session %+v", got)
			}
			if _, err := store.SetSessionLimits(ctx, c, "t", "missing", now, now, ""); err == nil {
				t.Fatal("missing session updated")
			}
		})
	}
}

func TestSessionClaims(t *testing.T) {
	for name, c := range map[string]*Client{"memory": inProcess(t), "sqlite": inProcessSQLite(t)} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			if err := c.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "s", TokenHash: "hash", UserinfoClaims: map[string]string{"a": `{"initial":true}`}}); err != nil {
				t.Fatal(err)
			}
			for _, client := range []string{"a", "b"} {
				if _, err := store.SetSessionClaims(ctx, c, "t", "s", client, `{"urn:test":true}`); err != nil {
					t.Fatal(err)
				}
			}
			s, err := c.Sessions().Get(ctx, "t", "s")
			if err != nil || len(s.UserinfoClaims) != 2 || s.UserinfoClaims["a"] != `{"urn:test":true}` {
				t.Fatalf("%+v %v", s, err)
			}
			if _, err := store.SetSessionClaims(ctx, c, "other", "s", "a", `{}`); err == nil {
				t.Fatal("cross tenant write")
			}
		})
	}
}

type oldClaimsServer struct{ *Server }

func (s oldClaimsServer) SessionsSetClaims(context.Context, *pb.SessionClaimsRequest) (*pb.SessionResult, error) {
	return nil, status.Error(codes.Unimplemented, "old plugin")
}
func TestOldRemotePluginEmptyClaims(t *testing.T) {
	st := memory.New()
	_ = st.Tenants().Create(t.Context(), &store.Tenant{ID: "t", Name: "t"})
	_ = st.Sessions().Create(t.Context(), &store.LoginSession{TenantID: "t", ID: "s", TokenHash: "h"})
	c := serveWith(t, oldClaimsServer{NewServer(st)})
	if _, err := store.SetSessionClaims(t.Context(), c, "t", "s", "app", `{}`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetSessionClaims(t.Context(), c, "t", "s", "app", `{"urn:claim":true}`); err == nil {
		t.Fatal("real unsupported write accepted")
	}
}
