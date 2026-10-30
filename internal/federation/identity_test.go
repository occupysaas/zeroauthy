package federation

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }

type identityEnv struct {
	st   *memory.Store
	svc  *Service
	conn *store.Connection
	ctx  context.Context
}

func newIdentityEnv(t *testing.T, sync string) *identityEnv {
	t.Helper()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	e := &identityEnv{st: memory.New(), svc: &Service{Wrapper: w, Now: func() time.Time { return fixedTime }}, ctx: context.Background()}
	if err := e.st.Tenants().Create(e.ctx, &store.Tenant{ID: "ten", Name: "ten"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*store.Connection{
		{TenantID: "ten", ID: "con_db", Name: "Database", Strategy: store.StrategyDatabase},
		{TenantID: "ten", ID: "con_g", Name: "google", Strategy: StrategyGoogle, SetUserRootAttributes: sync, FederationRevision: 1,
			Extra: map[string]any{"client_id": "c"}, FederationSecretsSealed: []byte("x")},
		{TenantID: "ten", ID: "con_g2", Name: "google2", Strategy: StrategyGoogle, FederationRevision: 1, Extra: map[string]any{"client_id": "c2"}, FederationSecretsSealed: []byte("x")},
	} {
		if err := e.st.Connections().Create(e.ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	e.conn, _ = e.st.Connections().Get(e.ctx, "ten", "con_g")
	return e
}

func result(sub string, p func(*Profile)) ProviderResult {
	r := ProviderResult{Profile: Profile{Subject: sub, Email: strp("a@example.com"), EmailVerified: boolp(true), Name: strp("Alice")},
		Tokens: TokenSet{AccessToken: "at-1", RefreshToken: "rt-1", TokenType: "Bearer", ExpiresAt: fixedTime.Add(time.Hour)}}
	if p != nil {
		p(&r.Profile)
	}
	return r
}

func (e *identityEnv) login(conn *store.Connection, r ProviderResult) (*store.User, error) {
	var u *store.User
	err := e.st.WithTx(e.ctx, func(tx store.Store) error {
		var err error
		u, err = e.svc.ResolveIdentity(e.ctx, tx, conn, r)
		return err
	})
	return u, err
}

func (e *identityEnv) tokens(t *testing.T, conn, sub string) TokenSet {
	t.Helper()
	k := store.FederatedIdentityKey{TenantID: "ten", ConnectionID: conn, Subject: sub}
	sealed, err := e.st.Federation().GetTokens(e.ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := OpenTokens(e.svc.Wrapper, k, sealed)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestFederatedIdentityLifecycle(t *testing.T) {
	t.Run("first and repeat login", func(t *testing.T) {
		e := newIdentityEnv(t, "")
		u, err := e.login(e.conn, result("Sub", nil))
		if err != nil {
			t.Fatal(err)
		}
		if u.UserID != "google-oauth2|Sub" || u.Email != "a@example.com" || !u.EmailVerified || u.Name != "Alice" ||
			len(u.Identities) != 1 || u.Identities[0].UserID != "Sub" || u.Identities[0].Provider != StrategyGoogle {
			t.Fatalf("provisioned %+v", u)
		}
		if ts := e.tokens(t, "con_g", "Sub"); ts.AccessToken != "at-1" || ts.RefreshToken != "rt-1" {
			t.Fatalf("tokens %+v", ts)
		}
		r := result("Sub", func(p *Profile) { p.Name = strp("Alice B") })
		r.Tokens = TokenSet{AccessToken: "at-2", TokenType: "Bearer"}
		again, err := e.login(e.conn, r)
		if err != nil || again.UserID != u.UserID || again.Name != "Alice B" {
			t.Fatalf("repeat %+v %v", again, err)
		}
		if ts := e.tokens(t, "con_g", "Sub"); ts.AccessToken != "at-2" || ts.RefreshToken != "rt-1" {
			t.Fatalf("omitted refresh not preserved: %+v", ts)
		}
		// A missing field never erases the stored value.
		again, _ = e.login(e.conn, result("Sub", func(p *Profile) { p.Name = nil }))
		if again.Name != "Alice B" {
			t.Fatalf("absent name erased: %q", again.Name)
		}
	})
	t.Run("same email distinct subjects and no auto link", func(t *testing.T) {
		e := newIdentityEnv(t, "")
		if err := e.st.Users().Create(e.ctx, &store.User{TenantID: "ten", UserID: "auth0|db", Email: "a@example.com", EmailVerified: true,
			Identities: []store.Identity{{Connection: "Database", Provider: store.StrategyDatabase, UserID: "db"}}}); err != nil {
			t.Fatal(err)
		}
		a, err1 := e.login(e.conn, result("one", nil))
		b, err2 := e.login(e.conn, result("two", nil))
		if err1 != nil || err2 != nil || a.UserID == b.UserID || a.UserID == "auth0|db" || b.UserID == "auth0|db" {
			t.Fatalf("%v %v %v %v", a, b, err1, err2)
		}
	})
	t.Run("concurrent provisioning", func(t *testing.T) {
		e := newIdentityEnv(t, "")
		var wg sync.WaitGroup
		ids := make([]string, 8)
		errs := make([]error, 8)
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				u, err := e.login(e.conn, result("race", nil))
				if errors.Is(err, store.ErrConflict) {
					u, err = e.login(e.conn, result("race", nil)) // the caller's single retry
				}
				if u != nil {
					ids[i] = u.UserID
				}
				errs[i] = err
			}()
		}
		wg.Wait()
		for i := range 8 {
			if errs[i] != nil || ids[i] != "google-oauth2|race" {
				t.Fatalf("login %d: %v %v", i, ids[i], errs[i])
			}
		}
		all, n, _ := e.st.Users().List(e.ctx, "ten", nil, store.UserSort{Field: "user_id"}, store.Page{})
		if n != 1 {
			t.Fatalf("%d users: %v", n, all)
		}
	})
	t.Run("imported linked identity syncs only its profile data", func(t *testing.T) {
		e := newIdentityEnv(t, "")
		if err := e.st.Users().Create(e.ctx, &store.User{TenantID: "ten", UserID: "auth0|imp", Email: "root@example.com", Name: "Root",
			Identities: []store.Identity{{Connection: "Database", Provider: store.StrategyDatabase, UserID: "imp"},
				{Connection: "google", Provider: StrategyGoogle, UserID: "Linked", ProfileData: map[string]any{"email": "old@example.com"}}}}); err != nil {
			t.Fatal(err)
		}
		u, err := e.login(e.conn, result("Linked", func(p *Profile) { p.Email = strp("new@example.com") }))
		if err != nil || u.UserID != "auth0|imp" || u.Email != "root@example.com" || u.Name != "Root" {
			t.Fatalf("%+v %v", u, err)
		}
		if pd := u.Identities[1].ProfileData; pd["email"] != "new@example.com" || pd["email_verified"] != true {
			t.Fatalf("profile data %v", pd)
		}
	})
	t.Run("public id collision fails closed", func(t *testing.T) {
		e := newIdentityEnv(t, "")
		if _, err := e.login(e.conn, result("Same", nil)); err != nil {
			t.Fatal(err)
		}
		other, _ := e.st.Connections().Get(e.ctx, "ten", "con_g2")
		if _, err := e.login(other, result("Same", nil)); !errors.Is(err, ErrIdentityConflict) {
			t.Fatalf("collision %v", err)
		}
	})
	t.Run("blocked user", func(t *testing.T) {
		e := newIdentityEnv(t, "")
		u, _ := e.login(e.conn, result("B", nil))
		u.Blocked = true
		if err := e.st.Users().Update(e.ctx, u); err != nil {
			t.Fatal(err)
		}
		r := result("B", nil)
		r.Tokens.AccessToken = "at-blocked"
		if _, err := e.login(e.conn, r); !errors.Is(err, ErrUserBlocked) {
			t.Fatalf("blocked %v", err)
		}
		if ts := e.tokens(t, "con_g", "B"); ts.AccessToken != "at-1" {
			t.Fatal("failed login updated tokens")
		}
	})
	for _, mode := range []string{"on_first_login", "never_on_login"} {
		t.Run(mode, func(t *testing.T) {
			e := newIdentityEnv(t, mode)
			if _, err := e.login(e.conn, result("S", nil)); err != nil {
				t.Fatal(err)
			}
			u, err := e.login(e.conn, result("S", func(p *Profile) { p.Name = strp("Changed"); p.Email = strp("c@example.com") }))
			if err != nil || u.Name != "Alice" || u.Email != "a@example.com" {
				t.Fatalf("%s synced: %+v %v", mode, u, err)
			}
		})
	}
	t.Run("changed email resets verification", func(t *testing.T) {
		e := newIdentityEnv(t, "")
		u, _ := e.login(e.conn, result("V", nil))
		version := u.Version
		u, err := e.login(e.conn, result("V", func(p *Profile) { p.Email = strp("moved@example.com"); p.EmailVerified = nil }))
		if err != nil || u.Email != "moved@example.com" || u.EmailVerified || u.Version == version {
			t.Fatalf("%+v %v", u, err)
		}
		u, _ = e.login(e.conn, result("V", func(p *Profile) { p.Email = strp("moved@example.com"); p.EmailVerified = boolp(true) }))
		if !u.EmailVerified {
			t.Fatal("explicit verification ignored")
		}
	})
	t.Run("metadata only at creation", func(t *testing.T) {
		e := newIdentityEnv(t, "")
		u, _ := e.login(e.conn, result("M", func(p *Profile) { p.UserMetadata = map[string]any{"theme": "dark"} }))
		if u.UserMetadata["theme"] != "dark" {
			t.Fatalf("metadata %v", u.UserMetadata)
		}
		u.UserMetadata["theme"] = "operator"
		_ = e.st.Users().Update(e.ctx, u)
		u, _ = e.login(e.conn, result("M", func(p *Profile) { p.UserMetadata = map[string]any{"theme": "light"} }))
		if u.UserMetadata["theme"] != "operator" {
			t.Fatalf("operator metadata overwritten: %v", u.UserMetadata)
		}
	})
}

func TestInvitationIdentityProvisioningProvenance(t *testing.T) {
	e := newIdentityEnv(t, "")
	called := 0
	for _, wantCreated := range []bool{true, false} {
		err := e.st.WithTx(e.ctx, func(tx store.Store) error {
			_, created, err := e.svc.resolveIdentity(e.ctx, tx, e.conn, result("Invited", nil), func() error { called++; return nil })
			if err == nil && created != wantCreated {
				t.Fatalf("created=%v want=%v", created, wantCreated)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if called != 1 {
		t.Fatalf("beforeProvision calls=%d", called)
	}
}
