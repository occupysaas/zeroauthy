package phone

import (
	"context"
	"errors"
	"fmt"
)

// Message is one SMS or voice delivery. Code and Locale feed Action events
// only; they are never logged.
type Message struct {
	TenantID, To, DeliveryMethod string // DeliveryMethod: text|voice
	Type                         string // otp_verify|otp_enroll|change_password|blocked_account|password_breach|passwordless
	Body, From                   string
	Code, Locale                 string
	UserID, ClientID             string
}

type Result struct{ ProviderMessageID string }

// ErrorClass is the provider-independent failure category.
type ErrorClass string

const (
	ClassInvalidNumber       ErrorClass = "invalid_number"
	ClassUnreachable         ErrorClass = "unreachable"
	ClassRateLimited         ErrorClass = "rate_limited"
	ClassProviderAuth        ErrorClass = "provider_auth"
	ClassUnsupportedDelivery ErrorClass = "unsupported_delivery"
	ClassTransient           ErrorClass = "transient"
)

// SendError carries a class and a cause that never contains the provider's
// response body, credentials or numbers.
type SendError struct {
	Class ErrorClass
	Err   error
}

func (e *SendError) Error() string {
	if e.Err == nil {
		return string(e.Class)
	}
	return fmt.Sprintf("%s: %v", e.Class, e.Err)
}
func (e *SendError) Unwrap() error { return e.Err }

// ClassOf returns the class of err, or "" when it is not a SendError.
func ClassOf(err error) ErrorClass {
	var se *SendError
	if errors.As(err, &se) {
		return se.Class
	}
	return ""
}

type Sender interface {
	Send(ctx context.Context, m Message) (Result, error)
}
