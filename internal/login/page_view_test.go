package login

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// writeCountingStore counts writes to the stores a login page view touches.
type writeCountingStore struct {
	store.Store
	writes atomic.Int64
}

func (s *writeCountingStore) AuthTransactions() store.AuthTransactions {
	return &writeCountingTxns{AuthTransactions: s.Store.AuthTransactions(), n: &s.writes}
}

func (s *writeCountingStore) MFA() store.MFA {
	return &writeCountingMFA{MFA: s.Store.MFA(), n: &s.writes}
}

type writeCountingTxns struct {
	store.AuthTransactions
	n *atomic.Int64
}

func (s *writeCountingTxns) CompareAndSwapHosted(ctx context.Context, tid, id string, rev int64, next store.HostedLoginState, now time.Time) error {
	s.n.Add(1)
	return s.AuthTransactions.CompareAndSwapHosted(ctx, tid, id, rev, next, now)
}

func (s *writeCountingTxns) Create(ctx context.Context, t *store.AuthTransaction) error {
	s.n.Add(1)
	return s.AuthTransactions.Create(ctx, t)
}

func (s *writeCountingTxns) Delete(ctx context.Context, tid, id string) error {
	s.n.Add(1)
	return s.AuthTransactions.Delete(ctx, tid, id)
}

type writeCountingMFA struct {
	store.MFA
	n *atomic.Int64
}

func (s *writeCountingMFA) CreateChallenge(ctx context.Context, c *store.MFAChallenge) error {
	s.n.Add(1)
	return s.MFA.CreateChallenge(ctx, c)
}

// A login page view whose stored state is unchanged writes nothing.
func TestLoginPageViewNoWrite(t *testing.T) {
	st := &writeCountingStore{Store: memory.New()}
	e := newEnvWithStore(t, st)
	b := e.browser("acme.example.test")
	_, state, _ := b.begin(t)
	view := func() int64 {
		before := st.writes.Load()
		if rec := b.do(t, "GET", "/u/login?"+url.Values{"state": {state}}.Encode(), nil); rec.Code != 200 {
			t.Fatalf("login page = %d %s", rec.Code, rec.Body)
		}
		return st.writes.Load() - before
	}
	view()
	if n := view(); n != 0 {
		t.Fatalf("second login page view made %d writes, want 0", n)
	}
}
