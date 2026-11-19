package federation

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type githubProbeStore struct {
	store.Store
	err error
}

func (s githubProbeStore) GitHubFederationSupported(context.Context) error { return s.err }

func TestRequireGitHubFederation(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	if err := RequireGitHubFederation(ctx, predecessorStore{st}); !errors.Is(err, store.ErrFederationUnavailable) {
		t.Fatalf("missing capability: %v", err)
	}
	transient := errors.New("probe interrupted")
	if err := RequireGitHubFederation(ctx, githubProbeStore{st, transient}); !errors.Is(err, transient) {
		t.Fatalf("transient: %v", err)
	}
	if err := RequireGitHubFederation(ctx, st); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubIdentityResolve(t *testing.T) {
	e := newIdentityEnv(t, "")
	c := &store.Connection{TenantID: "ten", ID: "con_gh", Name: "gh", Strategy: "github"}
	if err := e.st.Connections().Create(e.ctx, c); err != nil {
		t.Fatal(err)
	}
	// A store without the capability refuses the login and writes nothing.
	if _, err := e.svc.ResolveIdentity(e.ctx, predecessorStore{e.st}, c, result("42", nil)); !errors.Is(err, store.ErrFederationUnavailable) {
		t.Fatalf("unsupported login: %v", err)
	}
	if _, n, err := e.st.Users().List(e.ctx, "ten", nil, store.UserSort{}, store.Page{}); err != nil || n != 0 {
		t.Fatalf("unsupported login wrote %d users: %v", n, err)
	}
	u, err := e.svc.ResolveIdentity(e.ctx, e.st, c, result("9007199254740993", nil))
	if err != nil {
		t.Fatal(err)
	}
	if u.UserID != "github|9007199254740993" || len(u.Identities) != 1 || u.Identities[0].UserID != "9007199254740993" || u.Identities[0].Provider != "github" {
		t.Fatalf("user %+v", u)
	}
	if got, err := e.st.Users().FindByIdentity(e.ctx, "ten", "con_gh", "9007199254740993"); err != nil || got.UserID != u.UserID {
		t.Fatalf("index %+v %v", got, err)
	}
}
