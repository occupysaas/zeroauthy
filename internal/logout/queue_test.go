package logout

import (
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func queuedService(t *testing.T) *Service {
	st := memory.New()
	t.Cleanup(func() { _ = st.Close() })
	wrapper, _ := keys.NewLocalWrapper([]byte(secrets.RandomString(32)))
	if err := st.Tenants().Create(t.Context(), &store.Tenant{ID: "t", Name: "tenant", CanonicalHost: "tenant.example", Domains: []string{"tenant.example"}}); err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st.SigningKeys(), wrapper)
	if err := km.Ensure(t.Context(), "t"); err != nil {
		t.Fatal(err)
	}
	return &Service{Store: st, Wrapper: wrapper, Keys: km, Now: func() time.Time { return time.Unix(1800000000, 0).UTC() }}
}
func TestFanOutOncePerClient(t *testing.T) {
	s := queuedService(t)
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Store.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: id, OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://" + id + ".example/logout"}}}); err != nil {
			t.Fatal(err)
		}
	}
	session := &store.LoginSession{TenantID: "t", ID: "session", UserID: "u", ClientIDs: []string{"a", "b", "a", "c"}}
	if err := s.Store.WithTx(t.Context(), func(tx store.Store) error {
		return s.WithStore(tx).SessionsEnded(t.Context(), "t", []*store.LoginSession{session, session}, RPLogout)
	}); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.Store.Actions().ClaimJobs(t.Context(), s.now(), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 3 {
		t.Fatalf("jobs=%d want 3", len(jobs))
	}
	seen := map[string]bool{}
	for _, job := range jobs {
		if job.Trigger != JobKind {
			t.Fatal("wrong job kind")
		}
		payload, err := s.open(&job)
		if err != nil {
			t.Fatal(err)
		}
		if seen[payload.ClientID] {
			t.Fatal("duplicate client delivery")
		}
		seen[payload.ClientID] = true
		if payload.Session.ID != "session" || payload.Issuer != "https://tenant.example/" || payload.Initiator != RPLogout {
			t.Fatal("wrong session delivery snapshot")
		}
	}
}
func TestInitiatorSubscription(t *testing.T) {
	for _, tc := range []struct {
		settings *store.OIDCLogout
		why      Initiator
		want     bool
	}{
		{nil, RPLogout, false},
		{&store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}}, RPLogout, true},
		{&store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}}, PasswordChanged, false},
		{&store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}, InitiatorsMode: "all"}, PasswordChanged, true},
		{&store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}, InitiatorsMode: "custom", Initiators: []string{"rp-logout", "idp-logout", "session-revoked"}}, SessionRevoked, true},
	} {
		if got := subscribed(tc.settings, tc.why); got != tc.want {
			t.Fatalf("subscription %s got=%v want=%v", tc.why, got, tc.want)
		}
	}
}
func TestQueueRollback(t *testing.T) {
	s := queuedService(t)
	if err := s.Store.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}}}); err != nil {
		t.Fatal(err)
	}
	session := &store.LoginSession{TenantID: "t", ID: "session", UserID: "u", ClientIDs: []string{"rp"}}
	err := s.Store.WithTx(t.Context(), func(tx store.Store) error {
		if err := s.WithStore(tx).SessionsEnded(t.Context(), "t", []*store.LoginSession{session}, RPLogout); err != nil {
			return err
		}
		return store.ErrConflict
	})
	if err != store.ErrConflict {
		t.Fatal(err)
	}
	jobs, err := s.Store.Actions().ClaimJobs(t.Context(), s.now(), time.Minute, 10)
	if err != nil || len(jobs) != 0 {
		t.Fatal("rolled-back notification survived")
	}
}

func TestQueueAfterAccountDeletion(t *testing.T) {
	s := queuedService(t)
	if err := s.Store.Users().Create(t.Context(), &store.User{TenantID: "t", UserID: "auth0|user", Identities: []store.Identity{{Provider: "auth0", UserID: "user", Connection: "DB"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}, InitiatorsMode: "all"}}); err != nil {
		t.Fatal(err)
	}
	session := &store.LoginSession{TenantID: "t", ID: "session", UserID: "auth0|user", ClientIDs: []string{"rp"}}
	if err := s.Store.WithTx(t.Context(), func(tx store.Store) error {
		if err := tx.Users().Delete(t.Context(), "t", "auth0|user"); err != nil {
			return err
		}
		return s.WithStore(tx).SessionsEnded(t.Context(), "t", []*store.LoginSession{session}, AccountDeleted)
	}); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.Store.Actions().ClaimJobs(t.Context(), s.now(), time.Minute, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal("account-deletion notification depended on a live user")
	}
}

func TestOrganizationReceiverBinding(t *testing.T) {
	s := queuedService(t)
	if err := s.Store.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://{organization_name}.rp.example/{organization_id}/logout"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Organizations().Create(t.Context(), &store.Organization{TenantID: "t", ID: "org_0123456789abcdef", Name: "acme"}, nil); err != nil {
		t.Fatal(err)
	}
	session := &store.LoginSession{TenantID: "t", ID: "sid", UserID: "u", ClientIDs: []string{"rp"}, ClientOrganizations: map[string]string{"rp": "org_0123456789abcdef"}}
	if err := s.SessionsEnded(t.Context(), "t", []*store.LoginSession{session}, RPLogout); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.Store.Actions().ClaimJobs(t.Context(), s.now(), time.Minute, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs %v %v", jobs, err)
	}
	p, err := s.open(&jobs[0])
	if err != nil {
		t.Fatal(err)
	}
	if p.URL != "https://acme.rp.example/org_0123456789abcdef/logout" {
		t.Fatalf("unbound receiver %q", p.URL)
	}
}

func TestLogoutUnblocked(t *testing.T) {
	s := queuedService(t)
	var calls atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); <-r.Context().Done() }))
	defer receiver.Close()
	s.HTTP = receiver.Client()
	s.AllowPrivateNetworks = true
	if err := s.Store.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{receiver.URL}}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- s.SessionsEnded(t.Context(), "t", []*store.LoginSession{{TenantID: "t", ID: "sid", UserID: "u", ClientIDs: []string{"rp"}}}, RPLogout)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("local logout waited for receiver")
	}
	if calls.Load() != 0 {
		t.Fatal("logout performed network delivery synchronously")
	}
}

func TestRetiredIssuerDoesNotBlockLocalRevocation(t *testing.T) {
	for _, subscribe := range []bool{false, true} {
		t.Run(fmt.Sprint(subscribe), func(t *testing.T) {
			s := queuedService(t)
			if subscribe {
				if err := s.Store.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}, InitiatorsMode: "all"}}); err != nil {
					t.Fatal(err)
				}
			}
			for _, id := range []string{"retired", "active"} {
				origin := "https://tenant.example"
				if id == "retired" {
					origin = "https://retired.example"
				}
				if err := s.Store.Sessions().Create(t.Context(), &store.LoginSession{TenantID: "t", ID: id, TokenHash: id, UserID: "u", Origin: origin, ClientIDs: []string{"rp"}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Store.WithTx(t.Context(), func(tx store.Store) error {
				return s.WithStore(tx).EndUserSessions(t.Context(), "t", "u", SessionRevoked)
			}); err != nil {
				t.Fatalf("retired issuer blocked local revocation: %v", err)
			}
			live, err := s.Store.Sessions().ListByUser(t.Context(), "t", "u")
			if err != nil || len(live) != 0 {
				t.Fatal("local sessions survived")
			}
			jobs, err := s.Store.Actions().ClaimJobs(t.Context(), s.now(), time.Minute, 10)
			want := 0
			if subscribe {
				want = 1
			}
			if err != nil || len(jobs) != want {
				t.Fatalf("jobs=%d want=%d err=%v", len(jobs), want, err)
			}
		})
	}
}
func TestReceiverRefusesPortQualifiedTenant(t *testing.T) {
	s := queuedService(t)
	if err := s.Store.Tenants().Create(t.Context(), &store.Tenant{ID: "other", Name: "other", CanonicalHost: "other.example:8443", Domains: []string{"other.example:8443"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.receiverAllowed(t.Context(), "https://other.example:8443/logout"); err == nil {
		t.Fatal("tenant receiver accepted")
	}
}
