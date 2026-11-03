package logs

import (
	"context"
	"sync"
	"testing"
)

type captureRecorder struct {
	mu     sync.Mutex
	events []Event
}

func (c *captureRecorder) Record(_ context.Context, e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

// Passwordless SMS users are named by their phone number; no event may carry
// the full number (D-0060 P5: logs always masked), whichever request records
// it (hosted login, verify_redirect, a later MFA or token step).
func TestRecordEventMasksPhoneUserNames(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"+14155550123", "XXXXXXXX0123"},
		{"ada@example.test", "ada@example.test"},
		{"+1 not a number", "+1 not a number"},
		{"", ""},
	} {
		r := &captureRecorder{}
		RecordEvent(context.Background(), r, Event{TenantID: "t", Type: "s", UserName: tc.name})
		ctx := WithEvent(context.Background(), Event{UserName: tc.name})
		RecordEvent(ctx, r, Event{TenantID: "t", Type: "s"})
		if len(r.events) != 2 {
			t.Fatalf("%q: %d events", tc.name, len(r.events))
		}
		for _, e := range r.events {
			if e.UserName != tc.want {
				t.Errorf("%q: user_name = %q, want %q", tc.name, e.UserName, tc.want)
			}
		}
	}
}
