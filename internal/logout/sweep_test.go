package logout

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExpiredSessionsEnqueue(t *testing.T) {
	s := queuedService(t)
	if err := s.Store.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}, InitiatorsMode: "all"}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"expired", "live"} {
		expiry := s.now().Add(time.Hour)
		if id == "expired" {
			expiry = s.now()
		}
		if err := s.Store.Sessions().Create(t.Context(), &store.LoginSession{TenantID: "t", ID: id, TokenHash: id, UserID: "u", ClientIDs: []string{"rp"}, ExpiresAt: expiry, IdleExpiresAt: expiry}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.SweepExpired(t.Context(), s.now(), 100)
	if err != nil || n != 1 {
		t.Fatalf("swept=%d err=%v", n, err)
	}
	if _, err := s.Store.Sessions().Get(t.Context(), "t", "live"); err != nil {
		t.Fatal("live session removed")
	}
	jobs, err := s.Store.Actions().ClaimJobs(t.Context(), s.now(), time.Minute, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal("expiry notification missing")
	}
	content, err := s.open(&jobs[0])
	if err != nil || content.Initiator != SessionExpired {
		t.Fatal("wrong expiry initiator")
	}
	n, err = s.SweepExpired(t.Context(), s.now(), 100)
	if err != nil || n != 0 {
		t.Fatal("expiry repeated")
	}
}

func TestReturningExpiredBrowserRetainsFanoutSnapshot(t *testing.T) {
	s := queuedService(t)
	if err := s.Store.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}, InitiatorsMode: "all"}}); err != nil {
		t.Fatal(err)
	}
	expired := &store.LoginSession{TenantID: "t", ID: "sid", TokenHash: secrets.HashToken("throwaway-cookie"), UserID: "u", Origin: "https://tenant.example", ClientIDs: []string{"rp"}, ExpiresAt: s.now(), IdleExpiresAt: s.now()}
	if err := s.Store.Sessions().Create(t.Context(), expired); err != nil {
		t.Fatal(err)
	}
	m := &session.Manager{Store: s.Store, Now: s.Now, OnEnd: func(context.Context, store.Store, *store.LoginSession) error { return nil }}
	req := httptest.NewRequest("GET", "https://tenant.example/authorize", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: "throwaway-cookie"})
	tn, err := s.Store.Tenants().Get(t.Context(), "t")
	if err != nil {
		t.Fatal(err)
	}
	if current, err := m.Current(t.Context(), req, tn); err != nil || current != nil {
		t.Fatalf("expired browser authenticated: %v", err)
	}
	if _, err := s.SweepExpired(t.Context(), s.now(), 100); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.Store.Actions().ClaimJobs(t.Context(), s.now(), time.Minute, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal("returning browser lost the expiry snapshot")
	}
	content, err := s.open(&jobs[0])
	if err != nil || content.Initiator != SessionExpired {
		t.Fatal("wrong expiry event")
	}
}
