package identity

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := NewThrottle(3, 15*time.Minute, 10*time.Minute)
	th.Now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !th.Attempt("k") {
			t.Fatalf("blocked on attempt %d", i+1)
		}
	}
	if th.Attempt("k") {
		t.Fatal("not locked after 3 attempts")
	}
	if !th.Attempt("other") {
		t.Fatal("unrelated key locked")
	}

	now = now.Add(10*time.Minute + time.Second)
	if !th.Attempt("k") {
		t.Fatal("still locked after the lockout period")
	}

	// Attempts outside the window do not accumulate.
	th.Attempt("w")
	th.Attempt("w")
	now = now.Add(16 * time.Minute)
	if !th.Attempt("w") || !th.Attempt("w") {
		t.Fatal("old attempts counted after the window")
	}

	// Success clears the counter: the first two attempts after it pass,
	// and only the third trips the lock.
	th.Attempt("s")
	th.Attempt("s")
	th.Success("s")
	if !th.Attempt("s") || !th.Attempt("s") {
		t.Fatal("success did not reset the counter")
	}
	if !th.Attempt("s") || th.Attempt("s") {
		t.Fatal("third attempt after success should lock the key")
	}
}

func TestThrottleRefund(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := NewThrottle(3, 15*time.Minute, 10*time.Minute)
	th.Now = func() time.Time { return now }

	th.Attempt("r")
	th.Attempt("r")
	th.Refund("r")
	// Count is back to 1, so the next two attempts pass and the third
	// locks. Without the refund the second would already be blocked.
	if !th.Attempt("r") || !th.Attempt("r") {
		t.Fatal("refund did not undo an attempt")
	}
	if th.Attempt("r") {
		t.Fatal("key not locked after 3 counted attempts")
	}

	// Refund does not clear an active lockout.
	th.Refund("r")
	if th.Attempt("r") {
		t.Fatal("refund cleared an active lockout")
	}
}

func TestThrottleLockoutLongerThanWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := NewThrottle(2, 5*time.Minute, 30*time.Minute)
	th.Now = func() time.Time { return now }

	th.Attempt("k")
	if !th.Attempt("k") {
		t.Fatal("second attempt should pass and lock")
	}
	now = now.Add(6 * time.Minute) // window has expired, lockout has not
	if th.Attempt("k") {
		t.Fatal("lockout lifted early when the window expired")
	}
	now = now.Add(25 * time.Minute) // 31 minutes after the lock
	if !th.Attempt("k") {
		t.Fatal("still locked after the lockout period")
	}
}

func TestThrottleConcurrentAttempts(t *testing.T) {
	th := NewThrottle(3, time.Hour, time.Hour)

	var passed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if th.Attempt("k") {
				passed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := passed.Load(); got != 3 {
		t.Fatalf("%d of 50 concurrent attempts passed, want 3", got)
	}
}

func TestNewThrottleClampsMaxFailures(t *testing.T) {
	th := NewThrottle(0, time.Minute, time.Minute)
	if !th.Attempt("k") {
		t.Fatal("first attempt blocked")
	}
	if th.Attempt("k") {
		t.Fatal("maxFailures 0 should lock after one attempt")
	}
}

func TestNilThrottleAllows(t *testing.T) {
	var th *Throttle
	for range 100 {
		if !th.Attempt("k") {
			t.Fatal("nil throttle refused")
		}
	}
	th.Refund("k")
	th.Success("k")
}

func TestNewThrottleOrOffZero(t *testing.T) {
	if NewThrottleOrOff(0, time.Minute, time.Minute) != nil {
		t.Fatal("max 0 should be off")
	}
	if NewThrottleOrOff(3, time.Minute, time.Minute) == nil {
		t.Fatal("max 3 should be on")
	}
}

// Refunding the attempt that set a lockout undoes the lockout as well: a
// success on the last allowed try does not lock the key.
func TestThrottleRefundUndoesOwnLockout(t *testing.T) {
	th := NewThrottle(3, time.Hour, time.Hour)
	th.Attempt("k")
	th.Attempt("k")
	if !th.Attempt("k") {
		t.Fatal("third attempt refused")
	}
	th.Refund("k") // the third attempt succeeded
	if !th.Attempt("k") {
		t.Fatal("refunded attempt left the key locked")
	}
	// That attempt (count 3 again) locks; without a refund it stays locked.
	if th.Attempt("k") {
		t.Fatal("key not locked after 3 counted attempts")
	}
}
