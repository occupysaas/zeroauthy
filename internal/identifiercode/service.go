// Package identifiercode issues and consumes one-time identifier codes for
// hosted signup, hosted reset, and Management phone verification.
package identifiercode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passwordless"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

const (
	Signup = "signup"
	Reset  = "reset"
	// Verify has its own scope so a Management send cannot replace or
	// satisfy an authentication transaction's signup or reset code.
	Verify = "verify"
)

var (
	ErrCountryBlocked = errors.New("country not allowed")
	ErrSendLimit      = errors.New("phone send limit")
	ErrDelivery       = errors.New("phone delivery failed")
)

type Service struct {
	Store    store.Store
	Wrapper  keys.Wrapper
	Phone    passwordless.SMSSender
	Email    *email.Service
	Recorder logs.Recorder
	Now      func() time.Time
}

type SendInput struct {
	TenantID, ConnectionID, Identifier, Kind string
	Payload                                  string
	UserID                                   string
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s Service) Send(ctx context.Context, in SendInput) error {
	tid, conn, number, kind := in.TenantID, in.ConnectionID, in.Identifier, in.Kind
	isEmail := kind != Verify && strings.Contains(number, "@")
	normalized, err := phone.NormalizeE164(number, "")
	if isEmail {
		normalized = loginid.Normalize(number)
		err = nil
		if !loginid.ValidEmail(normalized) {
			return errors.New("invalid email")
		}
	}
	if err != nil {
		return err
	}
	tn, err := s.Store.Tenants().Get(ctx, tid)
	if err != nil {
		return err
	}
	if !isEmail && !tenantrules.PhoneSettingsOf(tn).CountryAllowed(phone.CountryCode(normalized)) {
		return ErrCountryBlocked
	}
	if !isEmail && s.Phone == nil {
		return store.ErrPhoneUnavailable
	}
	limits := []store.ProtectionLimit{{Key: store.ProtectionKey{TenantID: tid, Kind: "identifier-phone-" + kind, ConnectionID: conn, Identifier: normalized}, Algorithm: "fixed-window", Capacity: 10, Window: time.Hour}}
	if ip := logs.Enrich(ctx, logs.Event{}).IP; ip != "" {
		limits = append(limits, store.ProtectionLimit{Key: store.ProtectionKey{TenantID: tid, Kind: "identifier-phone-ip", IP: ip}, Algorithm: "fixed-window", Capacity: 50, Window: time.Hour})
	}
	a, err := s.Store.Protection().Reserve(ctx, limits, s.now())
	if err != nil {
		return err
	}
	if !a.Allowed {
		code := "limit_phone"
		if kind == Signup {
			code = "limit_signup_otp"
		}
		logs.RecordEvent(ctx, s.Recorder, logs.Event{TenantID: tid, Type: code})
		return ErrSendLimit
	}
	if err = s.Store.Protection().Complete(ctx, a.Receipt, "failure", s.now()); err != nil {
		return err
	}
	code := passwordless.NewCode(6)
	var request json.RawMessage
	if in.Payload != "" {
		sealed, e := keys.SealBound(s.Wrapper, "identifier-code/v1", []string{tid, conn, normalized, kind}, []byte(in.Payload))
		if e != nil {
			return e
		}
		request, _ = json.Marshal(sealed)
	}
	lifetime := 5 * time.Minute
	if kind == Signup {
		lifetime = time.Duration(phonerules.Limits.SignupOTPLifetimeSeconds) * time.Second
	}
	now := s.now()
	c := &store.PasswordlessCode{TenantID: tid, ConnectionID: conn, Identifier: normalized, Kind: "phone-" + kind, CodeHash: secrets.HashToken(code), Request: request, CreatedAt: now, ExpiresAt: now.Add(lifetime)}
	if err = s.Store.Phone().PutPasswordlessCode(ctx, c); err != nil {
		return err
	}
	purpose, typ := "verify", "otp_verify"
	if kind == Reset {
		purpose = "reset"
		typ = "change_password"
	}
	if isEmail {
		if s.Email == nil {
			return email.ErrServiceUnavailable
		}
		name := "verify_email_by_code"
		if kind == Reset {
			name = "reset_email_by_code"
		}
		return s.Email.SendPasswordless(ctx, email.PasswordlessEmail{TenantID: tid, To: normalized, Template: name, Code: code})
	}
	_, err = s.Phone.Send(ctx, tid, phone.Route{Purpose: purpose, ConnectionID: conn}, phone.Message{
		TenantID: tid, To: normalized, DeliveryMethod: "text", Type: typ, Code: code, UserID: in.UserID,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDelivery, err)
	}
	return nil
}

func (s Service) Consume(ctx context.Context, tid, conn, number, kind, code string) (string, error) {
	normalized, err := phone.NormalizeE164(number, "")
	if strings.Contains(number, "@") {
		normalized = loginid.Normalize(number)
		err = nil
	}
	if err != nil {
		return "", err
	}
	c, err := s.Store.Phone().ConsumePasswordlessCode(ctx, tid, conn, normalized, "phone-"+kind, secrets.HashToken(code), 3, s.now())
	if err != nil {
		return "", err
	}
	if len(c.Request) == 0 {
		return "", nil
	}
	var sealed []byte
	if err = json.Unmarshal(c.Request, &sealed); err != nil {
		return "", err
	}
	plain, err := keys.OpenBound(s.Wrapper, "identifier-code/v1", []string{tid, conn, normalized, kind}, sealed)
	return string(plain), err
}
