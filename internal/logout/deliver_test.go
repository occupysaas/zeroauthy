package logout

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func deliveryJob(t *testing.T, s *Service, endpoint string) *store.ActionJob {
	if err := s.Store.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{endpoint}}}); err != nil {
		t.Fatal(err)
	}
	session := &store.LoginSession{TenantID: "t", ID: "session", UserID: "u", ClientIDs: []string{"rp"}}
	if err := s.Store.WithTx(t.Context(), func(tx store.Store) error {
		return s.WithStore(tx).SessionsEnded(t.Context(), "t", []*store.LoginSession{session}, RPLogout)
	}); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.Store.Actions().ClaimJobs(t.Context(), s.now(), time.Minute, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim count=%d err=%v", len(jobs), err)
	}
	return &jobs[0]
}
func TestDeliveryOutcomes(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{{200, "done"}, {204, "done"}, {400, "failed"}, {401, "failed"}, {302, "failed"}, {503, "pending"}} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			var calls atomic.Int32
			receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Error("wrong delivery request")
				}
				if err := r.ParseForm(); err != nil || r.Form.Get("logout_token") == "" {
					t.Error("logout token missing")
				}
				w.Header().Set("Location", "https://redirect.example/")
				w.WriteHeader(tc.status)
			}))
			defer receiver.Close()
			s := queuedService(t)
			s.HTTP = receiver.Client()
			s.AllowPrivateNetworks = true
			job := deliveryJob(t, s, receiver.URL+"/logout")
			next := s.Deliver(t.Context(), job)
			if next == nil || next.Status != tc.want || calls.Load() != 1 {
				t.Fatalf("status=%v calls=%d", next, calls.Load())
			}
			if strings.Contains(string(next.Sealed), "logout_token") {
				t.Fatal("token persisted unsealed")
			}
		})
	}
}
func TestDeliveryRetriesMintFreshTokens(t *testing.T) {
	tokens := []string{}
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tokens = append(tokens, r.Form.Get("logout_token"))
		if len(tokens) < 3 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer receiver.Close()
	s := queuedService(t)
	s.HTTP = receiver.Client()
	s.AllowPrivateNetworks = true
	job := deliveryJob(t, s, receiver.URL)
	for i := 0; i < 3; i++ {
		// Recreate the service around the persisted store on each delivery attempt.
		restarted := *s
		next := restarted.Deliver(t.Context(), job)
		if next == nil {
			t.Fatal("delivery cancelled")
		}
		if err := s.Store.Actions().FinishJob(t.Context(), next, job.LeaseUntil); err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			if next.Status != "done" {
				t.Fatal("successful retry not completed")
			}
			break
		}
		at := next.NextAt
		s.Now = func() time.Time { return at }
		claimed, err := s.Store.Actions().ClaimJobs(t.Context(), s.now(), time.Minute, 1)
		if err != nil || len(claimed) != 1 {
			t.Fatal("retry not durable")
		}
		job = &claimed[0]
	}
	if len(tokens) != 3 || tokens[0] == tokens[1] || tokens[1] == tokens[2] {
		t.Fatal("retry tokens not fresh")
	}
}
func TestDeliveryOutboundPolicy(t *testing.T) {
	var calls atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer receiver.Close()
	s := queuedService(t)
	s.HTTP = receiver.Client()
	job := deliveryJob(t, s, receiver.URL)
	if next := s.Deliver(t.Context(), job); next == nil || next.Status != "failed" || calls.Load() != 0 {
		t.Fatal("private address was contacted")
	}
}
func TestDeliveryNoRedirects(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer target.Close()
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer receiver.Close()
	s := queuedService(t)
	s.HTTP = receiver.Client()
	s.AllowPrivateNetworks = true
	job := deliveryJob(t, s, receiver.URL)
	if next := s.Deliver(t.Context(), job); next == nil || next.Status != "failed" || calls.Load() != 0 {
		t.Fatal("redirect followed or retried")
	}
}
func TestDeliveryDeadline(t *testing.T) {
	s := queuedService(t)
	job := deliveryJob(t, s, "https://rp.example/logout")
	at := s.now().Add(10 * time.Minute)
	s.Now = func() time.Time { return at }
	if next := s.Deliver(t.Context(), job); next == nil || next.Status != "failed" {
		t.Fatal("expired delivery retried")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if next := s.Deliver(cancelled, job); next != nil {
		t.Fatal("cancelled worker completed a lease")
	}
}
func TestDeliveryTenantHostsBlocked(t *testing.T) {
	for _, host := range []string{"tenant.example", "tenant.auth0.com"} {
		s := queuedService(t)
		s.AllowPrivateNetworks = true
		job := deliveryJob(t, s, (&url.URL{Scheme: "https", Host: host, Path: "/logout"}).String())
		if next := s.Deliver(t.Context(), job); next == nil || next.Status != "failed" {
			t.Fatalf("tenant host %s not refused", host)
		}
	}
}

func TestDeliveryTimeout(t *testing.T) {
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(6 * time.Second):
		}
	}))
	defer receiver.Close()
	s := queuedService(t)
	s.HTTP = receiver.Client()
	s.AllowPrivateNetworks = true
	job := deliveryJob(t, s, receiver.URL)
	started := time.Now()
	next := s.Deliver(t.Context(), job)
	if next == nil || next.Status != "pending" {
		t.Fatal("timeout not retried")
	}
	elapsed := time.Since(started)
	if elapsed < 4*time.Second || elapsed > 7*time.Second {
		t.Fatalf("delivery timeout=%v want about 5s", elapsed)
	}
}
