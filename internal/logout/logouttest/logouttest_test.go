package logouttest_test

import (
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"github.com/zeroauthy/zeroauthy/internal/logout/logouttest"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// TestOpenMatchesSealing keeps the helper's envelope label and payload shape
// in step with the real queue.
func TestOpenMatchesSealing(t *testing.T) {
	st := memory.New()
	t.Cleanup(func() { _ = st.Close() })
	wrapper, _ := keys.NewLocalWrapper([]byte(secrets.RandomString(32)))
	now := time.Unix(1800000000, 0).UTC()
	if err := st.Tenants().Create(t.Context(), &store.Tenant{ID: "t", Name: "t", CanonicalHost: "tenant.example", Domains: []string{"tenant.example"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}, InitiatorsMode: "all"}}); err != nil {
		t.Fatal(err)
	}
	svc := &logout.Service{Store: st, Wrapper: wrapper, Now: func() time.Time { return now }}
	session := &store.LoginSession{TenantID: "t", ID: "sid", UserID: "u", ClientIDs: []string{"rp"}}
	if err := svc.SessionsEnded(t.Context(), "t", []*store.LoginSession{session}, logout.AccountDeleted); err != nil {
		t.Fatal(err)
	}
	jobs, err := st.Actions().ClaimJobs(t.Context(), now, time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	got := logouttest.RequireInitiator(t, wrapper, jobs, 1, logout.AccountDeleted)
	if got[0].ClientID != "rp" || got[0].SessionID != "sid" {
		t.Fatalf("decoded %+v", got[0])
	}
}
