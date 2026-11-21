package logout

import (
	"context"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Emulate the tenant policy lock contract enforced by SQL stores. A competing
// tenant-first revocation must never meet a session-first termination.
type orderedStore struct {
	store.Store
	tenantLocked *bool
}

func (s orderedStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { locked := false; return fn(orderedStore{tx, &locked}) })
}
func (s orderedStore) Tenants() store.Tenants {
	return orderedTenants{s.Store.Tenants(), s.tenantLocked}
}
func (s orderedStore) Sessions() store.Sessions {
	return orderedSessions{s.Store.Sessions(), s.tenantLocked}
}

type orderedTenants struct {
	store.Tenants
	locked *bool
}

func (s orderedTenants) Get(ctx context.Context, id string) (*store.Tenant, error) {
	if s.locked != nil {
		*s.locked = true
	}
	return s.Tenants.Get(ctx, id)
}

type orderedSessions struct {
	store.Sessions
	locked *bool
}

func (s orderedSessions) GetForUpdate(ctx context.Context, tid, id string) (*store.LoginSession, error) {
	if s.locked == nil || !*s.locked {
		return nil, fmt.Errorf("session lock precedes tenant policy lock")
	}
	return s.Sessions.GetForUpdate(ctx, tid, id)
}
func (s orderedSessions) ListExpired(ctx context.Context, before time.Time, limit int) ([]*store.LoginSession, error) {
	return s.Sessions.(store.SessionExpiryLister).ListExpired(ctx, before, limit)
}
func TestTerminationTenantLockOrder(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(fmt.Sprint(expiry), func(t *testing.T) {
			s := queuedService(t)
			s.Store = orderedStore{Store: s.Store}
			ended := &store.LoginSession{TenantID: "t", ID: "sid", TokenHash: secrets.HashToken("test-cookie"), Origin: "https://tenant.example", UserID: "u", ExpiresAt: s.now(), IdleExpiresAt: s.now()}
			if err := s.Store.Sessions().Create(t.Context(), ended); err != nil {
				t.Fatal(err)
			}
			if expiry {
				if _, err := s.SweepExpired(t.Context(), s.now(), 100); err != nil {
					t.Fatal(err)
				}
			} else {
				m := &session.Manager{Store: s.Store, Now: s.Now, OnEnd: func(context.Context, store.Store, *store.LoginSession) error { return nil }}
				req := httptest.NewRequest("POST", "https://tenant.example/oidc/logout", nil)
				req.AddCookie(&http.Cookie{Name: session.CookieName, Value: "test-cookie"})
				tn, err := s.Store.Tenants().Get(t.Context(), "t")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := m.End(t.Context(), httptest.NewRecorder(), req, tn); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
