package logout

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
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
