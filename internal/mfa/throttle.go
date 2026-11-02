package mfa

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Throttle is the durable atomic subset of Plan 19's protection repository.
// Implementations must share counters across requests, service instances and
// hosted/grant entry points; process-local admission is never a fallback.
type Throttle interface {
	Reserve(context.Context, []store.ProtectionLimit, time.Time) (store.ProtectionAdmission, error)
	Complete(context.Context, store.ProtectionReceipt, string, time.Time) error
	Clear(context.Context, string, store.ProtectionFilter) error
}

func proofKey(tid, uid, factor string) store.ProtectionKey {
	return store.ProtectionKey{TenantID: tid, Kind: "mfa", ConnectionID: factor, Identifier: "mfa:" + tid + ":" + uid + ":" + factor}
}
func (s *Service) reserveProof(ctx context.Context, tid, uid, factor string) (store.ProtectionReceipt, error) {
	if s.th == nil {
		return store.ProtectionReceipt{}, store.ErrProtectionUnimplemented
	}
	a, err := s.th.Reserve(ctx, []store.ProtectionLimit{{Key: proofKey(tid, uid, factor), Algorithm: "fixed-window", Capacity: 10, Window: 15 * time.Minute}}, s.now())
	if err != nil {
		return store.ProtectionReceipt{}, err
	}
	if !a.Allowed {
		// Separate persisted single admission emits once for this blocked window,
		// including concurrent requests and independent service instances.
		key := proofKey(tid, uid, factor)
		key.Kind = "mfa-notice"
		key.IP = a.RetryAt.UTC().Format(time.RFC3339Nano)
		notice, e := s.th.Reserve(ctx, []store.ProtectionLimit{{Key: key, Algorithm: "fixed-window", Capacity: 1, Window: 15 * time.Minute}}, s.now())
		if e != nil {
			return store.ProtectionReceipt{}, e
		}
		if notice.Allowed {
			if e = s.th.Complete(ctx, notice.Receipt, "failure", s.now()); e != nil {
				return store.ProtectionReceipt{}, e
			}
			s.emit(ctx, tid, uid, "gd_otp_rate_limit_exceed")
		}
		return store.ProtectionReceipt{}, ErrThrottled
	}
	return a.Receipt, nil
}
func (s *Service) finishProof(ctx context.Context, tid, uid, factor string, r store.ProtectionReceipt, outcome string) error {
	if err := s.th.Complete(ctx, r, outcome, s.now()); err != nil {
		return err
	}
	if outcome == "success" {
		k := proofKey(tid, uid, factor)
		f := store.ProtectionFilter{Kind: k.Kind, ConnectionID: k.ConnectionID, Identifier: k.Identifier}
		if err := s.th.Clear(ctx, tid, f); err != nil {
			return err
		}
		f.Kind = "mfa-notice"
		return s.th.Clear(ctx, tid, f)
	}
	return nil
}
func (s *Service) reserveEmail(ctx context.Context, tid, uid string, now time.Time) error {
	if s.th == nil {
		return store.ErrProtectionUnimplemented
	}
	key := store.ProtectionKey{TenantID: tid, Kind: "mfa-email", Identifier: uid}
	resend := key
	resend.Kind = "mfa-email-resend"
	a, err := s.th.Reserve(ctx, []store.ProtectionLimit{{Key: key, Algorithm: "fixed-window", Capacity: 5, Window: 15 * time.Minute}, {Key: resend, Algorithm: "fixed-window", Capacity: 1, Window: 30 * time.Second}}, now)
	if err != nil {
		return err
	}
	if !a.Allowed {
		return ErrThrottled
	}
	// Sending uses the budget even if transport fails, preventing provider abuse.
	return s.th.Complete(ctx, a.Receipt, "failure", now)
}
