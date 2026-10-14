package identity

import (
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := NewThrottle(3, 15*time.Minute, 10*time.Minute)
	th.Now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !th.Allowed("k") {
			t.Fatalf("blocked after %d failures", i)
		}
		th.Failure("k")
	}
	if th.Allowed("k") {
		t.Fatal("not locked after 3 failures")
	}
	if !th.Allowed("other") {
		t.Fatal("unrelated key locked")
	}

	now = now.Add(10*time.Minute + time.Second)
	if !th.Allowed("k") {
		t.Fatal("still locked after the lockout period")
	}

	// Failures outside the window do not accumulate.
	th.Failure("w")
	th.Failure("w")
	now = now.Add(16 * time.Minute)
	th.Failure("w")
	if !th.Allowed("w") {
		t.Fatal("old failures counted after the window")
	}

	// Success clears the counter.
	th.Failure("s")
	th.Failure("s")
	th.Success("s")
	th.Failure("s")
	th.Failure("s")
	if !th.Allowed("s") {
		t.Fatal("success did not reset the counter")
	}
}
