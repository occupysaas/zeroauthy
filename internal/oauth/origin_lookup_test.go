package oauth

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
	codes *originReadCodes
}

func (s originReadStore) AuthCodes() store.AuthCodes { return s.codes }

type originReadCodes struct {
	store.AuthCodes
	consumes   int
	readOrigin string
}

func (c *originReadCodes) Get(ctx context.Context, tid, hash string) (*store.AuthCode, error) {
	if c.readOrigin != "" {
		ac, err := c.AuthCodes.Get(ctx, tid, hash)
		if err == nil {
			ac.Origin = c.readOrigin
		}
		return ac, err
	}
	return nil, errors.New("temporary read failure")
}
func (c *originReadCodes) Consume(ctx context.Context, tid string, hash string, now time.Time) (*store.AuthCode, error) {
	c.consumes++
	return c.AuthCodes.Consume(ctx, tid, hash, now)
}

func TestAuthorizationCodeOriginReadFailureDoesNotConsume(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "code-spa", "https://app.acme.test/cb", "", []string{"openid"}, pkceChallenge)
	repo := &originReadCodes{AuthCodes: f.st.AuthCodes()}
	f.h.Store = originReadStore{Store: f.st, codes: repo}
	tid := f.tenantID(t, "acme")
	tn, err := f.st.Tenants().Get(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.st.Clients().Get(context.Background(), tid, "code-spa")
	if err != nil {
		t.Fatal(err)
	}
	_, oerr := f.h.authorizationCode(context.Background(), tenant.Resolved{Tenant: tn, Host: "alias.acme.test"}, c, codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier))
	if repo.consumes != 0 {
		t.Fatalf("origin read failure consumed code %d times", repo.consumes)
	}
	if oerr == nil || oerr.Code != "server_error" {
		t.Fatal("read failure unexpectedly succeeded")
	}
}

func TestAuthorizationCodeRechecksConsumedOrigin(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "code-spa", "https://app.acme.test/cb", "", []string{"openid"}, pkceChallenge)
	// Simulate a stale lookup from a store transport: the consumed row remains
	// canonical even though the preliminary lookup claimed this alias.
	repo := &originReadCodes{AuthCodes: f.st.AuthCodes(), readOrigin: "https://alias.acme.test"}
	f.h.Store = originReadStore{Store: f.st, codes: repo}
	tid := f.tenantID(t, "acme")
	tn, err := f.st.Tenants().Get(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.st.Clients().Get(context.Background(), tid, "code-spa")
	if err != nil {
		t.Fatal(err)
	}
	response, oerr := f.h.authorizationCode(context.Background(), tenant.Resolved{Tenant: tn, Host: "alias.acme.test"}, c, codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier))
	if response != nil || oerr == nil || oerr.Code != "invalid_grant" {
		t.Fatalf("foreign consumed origin issued response=%v err=%v", response, oerr)
	}
}
