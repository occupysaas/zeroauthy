package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type originReadStore struct {
	store.Store
	requests *originReadRequests
}

func (s originReadStore) PushedAuthRequests() store.PushedAuthRequests { return s.requests }

type originReadRequests struct {
	store.PushedAuthRequests
	consumes int
}

func (p *originReadRequests) Get(context.Context, string, string) (*store.PushedAuthRequest, error) {
	return nil, errors.New("temporary read failure")
}
func (p *originReadRequests) Consume(ctx context.Context, tid string, hash string, now time.Time) (*store.PushedAuthRequest, error) {
	p.consumes++
	return p.PushedAuthRequests.Consume(ctx, tid, hash, now)
}
func TestPushedOriginReadFailureDoesNotConsume(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	repo := &originReadRequests{PushedAuthRequests: e.st.PushedAuthRequests()}
	e.h.Store = originReadStore{Store: e.st, requests: repo}
	ctx := tenant.WithResolved(context.Background(), tenant.Resolved{Tenant: e.tenant, Host: "alias.acme.test"})
	_, err := e.h.resolvePushed(ctx, e.tenant, parQuery("par-web", uri))
	if repo.consumes != 0 {
		t.Fatalf("origin read failure consumed PAR %d times", repo.consumes)
	}
	if err == nil || err.Code != "server_error" {
		t.Fatal("read failure unexpectedly succeeded")
	}
}
