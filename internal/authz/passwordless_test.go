package authz

import (
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Documented: with connection=email|sms an existing session is not reused.
func TestPasswordlessConnectionNeedsLogin(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	h := &Handlers{Now: func() time.Time { return now }}
	for _, tc := range []struct {
		sessConn, reqConn string
		want              bool
	}{
		{"email", "email", true}, {"sms", "sms", true}, {"email", "", false}, {"sms", "", false},
		{"Username-Password-Authentication", "Username-Password-Authentication", false},
	} {
		sess := &store.LoginSession{Connection: tc.sessConn, AuthenticatedAt: now}
		if got := h.needsLogin(Request{Connection: tc.reqConn}, sess); got != tc.want {
			t.Errorf("session %q, connection %q: needsLogin = %v, want %v", tc.sessConn, tc.reqConn, got, tc.want)
		}
	}
}
