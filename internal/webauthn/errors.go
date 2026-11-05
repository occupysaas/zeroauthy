// Package webauthn verifies WebAuthn registrations and assertions (W3C
// WebAuthn Levels 2 and 3) for passkeys and WebAuthn MFA. It is pure: no
// storage, HTTP or clock beyond what callers pass in. See D-0062.
package webauthn

import (
	"errors"
	"fmt"
)

// reasons are the bounded failure codes surfaced in logs (failure_details).
var reasons = map[string]bool{
	"parse": true, "type": true, "challenge": true, "origin": true, "cross_origin": true,
	"rp_id": true, "user_present": true, "user_verified": true, "alg": true, "key": true,
	"attestation": true, "signature": true, "user_handle": true, "sign_count": true,
	"backup_eligibility": true, "backup_state": true, "too_large": true,
}

// Error is a verification failure with a bounded reason code. Detail is for
// server logs only and never echoes credential bytes.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string { return "webauthn: " + e.Code + ": " + e.Detail }

func fail(code, format string, args ...any) error {
	if !reasons[code] {
		code = "parse"
	}
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Reason returns err's bounded reason code, or "" for nil and foreign errors.
func Reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
