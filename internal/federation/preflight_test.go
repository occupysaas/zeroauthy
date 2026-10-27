package federation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type predecessorStore struct{ store.Store }
type probeStore struct {
	store.Store
	err   error
	calls int
}

func (s *probeStore) MicrosoftFederationSupported(context.Context) error { s.calls++; return s.err }

type legacyUsers struct {
	store.Users
	users []*store.User
	pages int
}

func (u *legacyUsers) List(_ context.Context, tenant string, _ *store.UserQuery, _ store.UserSort, p store.Page) ([]*store.User, int, error) {
	u.pages++
	var all []*store.User
	for _, v := range u.users {
		if v.TenantID == tenant {
			all = append(all, v)
		}
	}
	end := min(p.Offset+p.Limit, len(all))
	if p.Offset >= len(all) {
		return nil, len(all), nil
	}
	return all[p.Offset:end], len(all), nil
}

type legacyStore struct {
	store.Store
	users *legacyUsers
}

func (s legacyStore) Users() store.Users                                 { return s.users }
func (s legacyStore) MicrosoftFederationSupported(context.Context) error { return nil }

func TestMicrosoftFederationCapability(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := RequireMicrosoftFederation(ctx, predecessorStore{st}); !errors.Is(err, store.ErrFederationUnavailable) {
		t.Fatalf("missing capability: %v", err)
	}
	transient := errors.New("probe interrupted")
	p := &probeStore{Store: st, err: transient}
	if err := RequireMicrosoftFederation(ctx, p); !errors.Is(err, transient) {
		t.Fatalf("transient: %v", err)
	}
	p.err = nil
	if err := RequireMicrosoftFederation(ctx, p); err != nil || p.calls != 2 {
		t.Fatalf("recovery %v calls %d", err, p.calls)
	}
	p.err = transient
	if err := RequireMicrosoftFederation(ctx, p); !errors.Is(err, transient) {
		t.Fatalf("cached success: %v", err)
	}
	if err := RequireMicrosoftFederation(ctx, st); err != nil {
		t.Fatal(err)
	}
}
func TestMicrosoftIdentityPreflight(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"none", "valid", "unknown", "malformed", "missing", "mismatch", "unsupported connection", "unsupported identity"} {
		t.Run(kind, func(t *testing.T) {
			st := memory.New()
			defer st.Close()
			// The Microsoft row lives beyond both the first tenant and user page.
			for _, name := range []string{"a", "z"} {
				if err := st.Tenants().Create(ctx, &store.Tenant{ID: name, Name: name}); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 101; i++ {
				if err := st.Connections().Create(ctx, &store.Connection{TenantID: "z", ID: fmt.Sprint("g", i), Name: fmt.Sprint("g", i), Strategy: "google-oauth2"}); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "none" && kind != "unsupported identity" {
				if err := st.Connections().Create(ctx, &store.Connection{TenantID: "z", ID: "ms", Name: "zzz", Strategy: "windowslive"}); err != nil {
					t.Fatal(err)
				}
			}
			users := &legacyUsers{Users: st.Users()}
			for i := 0; i < 101; i++ {
				users.users = append(users.users, &store.User{TenantID: "z", UserID: fmt.Sprint("auth0|", i)})
			}
			if kind != "none" && kind != "unsupported connection" {
				id := store.Identity{Connection: "zzz", Provider: "windowslive", UserID: "secret-subject\nprivate"}
				if kind == "unknown" {
					id.Connection = "absent"
				}
				if kind == "malformed" {
					id.UserID = ""
				}
				u := &store.User{TenantID: "z", UserID: "windowslive|secret", Identities: []store.Identity{id}}
				users.users = append(users.users, u)
				if kind == "valid" || kind == "mismatch" {
					owner := u.UserID
					if kind == "mismatch" {
						owner = "auth0|other"
					}
					if err := st.Users().Create(ctx, &store.User{TenantID: "z", UserID: owner, Identities: []store.Identity{id}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			var target store.Store = legacyStore{st, users}
			if strings.HasPrefix(kind, "unsupported") || kind == "none" {
				target = predecessorStore{target}
			}
			err := PreflightMicrosoftIdentities(ctx, target)
			if kind == "none" || kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid ownership")
			} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsanitized: %v", err)
			}
			if users.pages < 2 && !strings.HasPrefix(kind, "unsupported") {
				t.Fatalf("not paginated: %d", users.pages)
			}
			// Preflight must never repair missing ownership.
			if kind == "missing" {
				if _, e := st.Users().FindByIdentity(ctx, "z", "ms", "secret-subject\nprivate"); !errors.Is(e, store.ErrNotFound) {
					t.Fatalf("preflight wrote: %v", e)
				}
			}
		})
	}
}

func TestMicrosoftIdentityCapabilityDenial(t *testing.T) {
	e := newIdentityEnv(t, "")
	c := &store.Connection{TenantID: "ten", ID: "ms", Name: "personal", Strategy: "windowslive"}
	if err := e.st.Connections().Create(e.ctx, c); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.ResolveIdentity(e.ctx, predecessorStore{e.st}, c, result("Sub", nil))
	if !errors.Is(err, store.ErrFederationUnavailable) {
		t.Fatalf("unsupported login: %v", err)
	}
	_, n, err := e.st.Users().List(e.ctx, "ten", nil, store.UserSort{}, store.Page{})
	if err != nil || n != 0 {
		t.Fatalf("unsupported login wrote %d users: %v", n, err)
	}
}
