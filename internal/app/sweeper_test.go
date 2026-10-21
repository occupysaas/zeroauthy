package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestSweepRemovesExpiredRecords(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	st := memory.New()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.AuthTransactions().Create(ctx, &store.AuthTransaction{TenantID: "t", ID: "old", ExpiresAt: now.Add(-time.Minute)}))
	must(st.AuthTransactions().Create(ctx, &store.AuthTransaction{TenantID: "t", ID: "new", ExpiresAt: now.Add(time.Minute)}))
	must(st.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "old", TokenHash: "h1", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(-time.Second)}))
	must(st.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "new", TokenHash: "h2", ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour)}))
	// Codes are kept for codeRetention after expiry so late replays are
	// still recognized.
	must(st.AuthCodes().Create(ctx, &store.AuthCode{TenantID: "t", CodeHash: "recent", ExpiresAt: now.Add(-time.Hour)}))
	must(st.AuthCodes().Create(ctx, &store.AuthCode{TenantID: "t", CodeHash: "ancient", ExpiresAt: now.Add(-codeRetention - time.Minute)}))
	must(st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: "t", ID: "old", TokenHash: "r1", ExpiresAt: now.Add(-time.Second)}))
	must(st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: "t", ID: "forever", TokenHash: "r2"}))
	must(st.PasswordResetTickets().Create(ctx, &store.PasswordResetTicket{TenantID: "t", ID: "old", TokenHash: "p1", ExpiresAt: now.Add(-time.Second)}))
	must(st.PasswordResetTickets().Create(ctx, &store.PasswordResetTicket{TenantID: "t", ID: "new", TokenHash: "p2", ExpiresAt: now.Add(time.Hour)}))
	must(st.EmailVerificationTickets().Create(ctx, &store.EmailVerificationTicket{TenantID: "t", ID: "old", TokenHash: "v1", ExpiresAt: now.Add(-time.Second)}))
	must(st.EmailVerificationTickets().Create(ctx, &store.EmailVerificationTicket{TenantID: "t", ID: "new", TokenHash: "v2", ExpiresAt: now.Add(time.Hour)}))
	must(st.PushedAuthRequests().Create(ctx, &store.PushedAuthRequest{TenantID: "t", IDHash: "old", ExpiresAt: now.Add(-time.Second)}))
	must(st.PushedAuthRequests().Create(ctx, &store.PushedAuthRequest{TenantID: "t", IDHash: "new", ExpiresAt: now.Add(30 * time.Second)}))
	// Device codes are kept for deviceCodeRetention after expiry so the
	// device's next poll gets expired_token.
	must(st.DeviceCodes().Create(ctx, &store.DeviceCode{TenantID: "t", DeviceCodeHash: "recent", UserCodeHash: "ur", ExpiresAt: now.Add(-time.Hour)}))
	must(st.DeviceCodes().Create(ctx, &store.DeviceCode{TenantID: "t", DeviceCodeHash: "ancient", UserCodeHash: "ua", ExpiresAt: now.Add(-25 * time.Hour)}))
	must(st.Jobs().Create(ctx, &store.Job{TenantID: "t", ID: "old", Type: store.JobUsersExport, Status: store.JobCompleted, ExpiresAt: now.Add(-time.Second)}))
	must(st.Jobs().Create(ctx, &store.Job{TenantID: "t", ID: "new", Type: store.JobUsersExport, Status: store.JobCompleted, ExpiresAt: now.Add(time.Hour)}))

	n, err := sweep(ctx, st, now)
	if err != nil || n != 9 {
		t.Fatalf("sweep = %d, %v; want 9, nil", n, err)
	}
	if _, err := st.Jobs().Get(ctx, "t", "old"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired job kept: %v", err)
	}
	if _, err := st.Jobs().Get(ctx, "t", "new"); err != nil {
		t.Errorf("live job removed: %v", err)
	}
	if _, err := st.AuthTransactions().Get(ctx, "t", "new"); err != nil {
		t.Errorf("live transaction removed: %v", err)
	}
	if _, err := st.Sessions().GetByTokenHash(ctx, "t", "h2"); err != nil {
		t.Errorf("live session removed: %v", err)
	}
	if _, err := st.AuthCodes().Consume(ctx, "t", "recent", now); err != nil {
		t.Errorf("recently expired code removed: %v", err)
	}
	if _, err := st.AuthCodes().Consume(ctx, "t", "ancient", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ancient code kept: %v", err)
	}
	if _, err := st.EmailVerificationTickets().GetByTokenHash(ctx, "t", "v1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired verification ticket kept: %v", err)
	}
	if _, err := st.EmailVerificationTickets().GetByTokenHash(ctx, "t", "v2"); err != nil {
		t.Errorf("live verification ticket removed: %v", err)
	}
	if _, err := st.RefreshTokens().GetByTokenHash(ctx, "t", "r2"); err != nil {
		t.Errorf("non-expiring refresh token removed: %v", err)
	}
	if _, err := st.PasswordResetTickets().GetByTokenHash(ctx, "t", "p2"); err != nil {
		t.Errorf("live reset ticket removed: %v", err)
	}
	if _, err := st.PushedAuthRequests().Get(ctx, "t", "new"); err != nil {
		t.Errorf("live pushed request removed: %v", err)
	}
	if _, err := st.DeviceCodes().Get(ctx, "t", "recent"); err != nil {
		t.Errorf("recently expired device code removed: %v", err)
	}
	if _, err := st.DeviceCodes().Get(ctx, "t", "ancient"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ancient device code kept: %v", err)
	}
	if _, err := st.PasswordResetTickets().GetByTokenHash(ctx, "t", "p1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired reset ticket kept: %v", err)
	}
}
