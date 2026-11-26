package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testCIBA covers Plan 41c's backchannel authentication requests: unique
// hashes, single decision, the poll rules with single redemption, the
// pending count and the sweep.
func testCIBA(t *testing.T, factory Factory) {
	s := open(t, factory)
	ctx := context.Background()
	for _, tid := range []string{"a", "b"} {
		mustNoErr(t, s.Tenants().Create(ctx, newTenant(tid)))
		mustNoErr(t, s.Clients().Create(ctx, &store.Client{TenantID: "ten_" + tid, ClientID: "app", Name: "App", AppType: store.AppTypeRegularWeb}))
	}
	// The client's channels round trip.
	ch := &store.Client{TenantID: "ten_a", ClientID: "ciba-app", Name: "CIBA", AppType: store.AppTypeRegularWeb, AsyncApprovalNotificationChannels: []string{"email", "guardian-push"}}
	mustNoErr(t, s.Clients().Create(ctx, ch))
	gotClient, err := s.Clients().Get(ctx, "ten_a", "ciba-app")
	mustNoErr(t, err)
	mustEqual(t, gotClient.AsyncApprovalNotificationChannels, ch.AsyncApprovalNotificationChannels)
	ch.AsyncApprovalNotificationChannels = nil
	mustNoErr(t, s.Clients().Update(ctx, ch))
	gotClient, _ = s.Clients().Get(ctx, "ten_a", "ciba-app")
	if gotClient.AsyncApprovalNotificationChannels != nil {
		t.Fatalf("cleared channels = %v", gotClient.AsyncApprovalNotificationChannels)
	}

	repo, err := store.CIBA(ctx, s)
	if err != nil {
		t.Fatalf("store.CIBA: %v", err)
	}
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	req := func(id string) *store.CIBARequest {
		return &store.CIBARequest{Origin: "https://ten.example", TenantID: "ten_a", IDHash: id, TicketHash: "t" + id, ClientID: "app", UserID: "auth0|u1",
			Scopes: []string{"openid", "email"}, Audience: "https://api.example/", BindingMessage: "CODE-1", Status: store.CIBAPending,
			Interval: 5, ExpiresAt: t0.Add(10 * time.Minute), CreatedAt: t0}
	}
	r := req("r1")
	mustNoErr(t, repo.CreateCIBARequest(ctx, r))
	got, err := repo.GetCIBARequest(ctx, "ten_a", "r1")
	mustNoErr(t, err)
	mustEqual(t, got, r)
	got, err = repo.GetCIBARequestByTicket(ctx, "ten_a", "tr1")
	mustNoErr(t, err)
	mustEqual(t, got, r)
	_, err = repo.GetCIBARequest(ctx, "ten_b", "r1")
	mustErrIs(t, err, store.ErrNotFound)
	dup := req("r1")
	dup.TicketHash = "other"
	mustErrIs(t, repo.CreateCIBARequest(ctx, dup), store.ErrConflict)
	dupTicket := req("r9")
	dupTicket.TicketHash = "tr1"
	mustErrIs(t, repo.CreateCIBARequest(ctx, dupTicket), store.ErrConflict)

	// Polls: pending, slow_down (interval grows), another client changes nothing.
	p, _, err := repo.PollCIBARequest(ctx, "ten_a", "r1", "app", t0.Add(time.Second))
	mustNoErr(t, err)
	mustEqual(t, p, store.CIBAPollPending)
	p, _, err = repo.PollCIBARequest(ctx, "ten_a", "r1", "app", t0.Add(3*time.Second))
	mustNoErr(t, err)
	mustEqual(t, p, store.CIBAPollSlowDown)
	got, _ = repo.GetCIBARequest(ctx, "ten_a", "r1")
	mustEqual(t, got.Interval, 10)
	_, _, err = repo.PollCIBARequest(ctx, "ten_a", "r1", "intruder", t0.Add(time.Minute))
	mustErrIs(t, err, store.ErrNotFound)
	again, _ := repo.GetCIBARequest(ctx, "ten_a", "r1")
	mustEqual(t, again, got)

	// One decision; then concurrent polls redeem once.
	dec := store.CIBADecision{Status: store.CIBAApproved, GrantedScopes: []string{"openid"}, ActionEffects: []byte{1, 2, 3}, AuthTime: t0.Add(time.Minute), MFAAt: t0.Add(time.Minute)}
	decided, err := repo.DecideCIBARequest(ctx, "ten_a", "r1", dec)
	mustNoErr(t, err)
	mustEqual(t, decided.Status, store.CIBAApproved)
	_, err = repo.DecideCIBARequest(ctx, "ten_a", "r1", store.CIBADecision{Status: store.CIBADenied})
	mustErrIs(t, err, store.ErrAlreadyUsed)
	var wg sync.WaitGroup
	var mu sync.Mutex
	approved := 0
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, rec, err := repo.PollCIBARequest(ctx, "ten_a", "r1", "app", t0.Add(2*time.Minute))
			if err == nil && p == store.CIBAPollApproved {
				mu.Lock()
				approved++
				mu.Unlock()
				if rec == nil || rec.UserID != "auth0|u1" || len(rec.GrantedScopes) != 1 || len(rec.ActionEffects) != 3 || !rec.AuthTime.Equal(t0.Add(time.Minute)) {
					t.Errorf("approved record %+v", rec)
				}
			}
		}()
	}
	wg.Wait()
	mustEqual(t, approved, 1)
	p, _, err = repo.PollCIBARequest(ctx, "ten_a", "r1", "app", t0.Add(3*time.Minute))
	mustNoErr(t, err)
	mustEqual(t, p, store.CIBAPollInvalid)

	// Denied, then expired.
	r2 := req("r2")
	mustNoErr(t, repo.CreateCIBARequest(ctx, r2))
	_, err = repo.DecideCIBARequest(ctx, "ten_a", "r2", store.CIBADecision{Status: store.CIBADenied})
	mustNoErr(t, err)
	p, _, _ = repo.PollCIBARequest(ctx, "ten_a", "r2", "app", t0.Add(time.Minute))
	mustEqual(t, p, store.CIBAPollDenied)
	r3 := req("r3")
	mustNoErr(t, repo.CreateCIBARequest(ctx, r3))
	p, _, _ = repo.PollCIBARequest(ctx, "ten_a", "r3", "app", t0.Add(10*time.Minute))
	mustEqual(t, p, store.CIBAPollExpired)

	// Pending count: r3 is pending (expired, inside the 24-hour window).
	n, err := repo.CountPendingCIBARequests(ctx, "ten_a", t0.Add(time.Hour))
	mustNoErr(t, err)
	mustEqual(t, n, 1)
	n, _ = repo.CountPendingCIBARequests(ctx, "ten_a", t0.Add(25*time.Hour))
	mustEqual(t, n, 0)
	n, _ = repo.CountPendingCIBARequests(ctx, "ten_b", t0)
	mustEqual(t, n, 0)

	// The sweep removes requests that expired by then.
	future := req("r4")
	future.ExpiresAt = t0.Add(48 * time.Hour)
	mustNoErr(t, repo.CreateCIBARequest(ctx, future))
	removed, err := repo.DeleteExpiredCIBARequests(ctx, t0.Add(time.Hour))
	mustNoErr(t, err)
	mustEqual(t, removed, 3)
	_, err = repo.GetCIBARequest(ctx, "ten_a", "r1")
	mustErrIs(t, err, store.ErrNotFound)
	_, err = repo.GetCIBARequest(ctx, "ten_a", "r4")
	mustNoErr(t, err)

	// Deleting the client removes its requests.
	mustNoErr(t, s.Clients().Delete(ctx, "ten_a", "app"))
	_, err = repo.GetCIBARequest(ctx, "ten_a", "r4")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("request survived its client: %v", err)
	}
}
