package protection_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"testing"
)

func TestCredentialOutcome(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"valid", nil, "success"}, {"blocked", identity.ErrUserBlocked, "success"},
		{"wrong", identity.ErrInvalidCredentials, "failure"}, {"change required", identity.ErrPasswordChangeRequired, "failure"},
		{"refused", &identity.UnauthorizedError{Message: "refused"}, "failure"}, {"script raised", identity.ErrScript, "failure"},
		{"unavailable", errors.Join(identity.ErrScript, identity.ErrScriptUnavailable), "refund"},
		{"cancelled", context.Canceled, "refund"}, {"deadline", context.DeadlineExceeded, "refund"}, {"store", errors.New("store failed"), "refund"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := protection.CredentialOutcome(tc.err); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
			if tc.err != nil && protection.CredentialOutcome(fmt.Errorf("wrapped: %w", tc.err)) != tc.want {
				t.Fatal("wrapped error changed outcome")
			}
		})
	}
}
