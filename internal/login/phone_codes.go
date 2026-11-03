package login

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passwordless"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

func (h *Handlers) sendIdentifierCode(ctx context.Context, tid, conn, number, kind, payload string) error {
	isEmail := strings.Contains(number, "@")
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
	tn, err := h.Store.Tenants().Get(ctx, tid)
	if err != nil {
		return err
	}
	if !isEmail && !tenantrules.PhoneSettingsOf(tn).CountryAllowed(phone.CountryCode(normalized)) {
		return errors.New("country not allowed")
	}
	if !isEmail && (h.MFA == nil || h.MFA.Phone == nil) {
		return store.ErrPhoneUnavailable
	}
	limits := []store.ProtectionLimit{{Key: store.ProtectionKey{TenantID: tid, Kind: "identifier-phone", Identifier: normalized}, Algorithm: "fixed-window", Capacity: 10, Window: time.Hour}}
	if ip := logs.Enrich(ctx, logs.Event{}).IP; ip != "" {
		limits = append(limits, store.ProtectionLimit{Key: store.ProtectionKey{TenantID: tid, Kind: "identifier-phone-ip", IP: ip}, Algorithm: "fixed-window", Capacity: 50, Window: time.Hour})
	}
	a, err := h.Store.Protection().Reserve(ctx, limits, h.now())
	if err != nil {
		return err
	}
	if !a.Allowed {
		code := "limit_phone"
		if kind == "signup" {
			code = "limit_signup_otp"
		}
		logs.RecordEvent(ctx, h.Recorder, logs.Event{TenantID: tid, Type: code})
		return errors.New("phone send limit")
	}
	if err = h.Store.Protection().Complete(ctx, a.Receipt, "failure", h.now()); err != nil {
		return err
	}
	code := passwordless.NewCode(6)
	var request json.RawMessage
	if payload != "" {
		sealed, e := keys.SealBound(h.Authz.Wrapper, "identifier-code/v1", []string{tid, conn, normalized, kind}, []byte(payload))
		if e != nil {
			return e
		}
		request, _ = json.Marshal(sealed)
	}
	c := &store.PasswordlessCode{TenantID: tid, ConnectionID: conn, Identifier: normalized, Kind: "phone-" + kind, CodeHash: secrets.HashToken(code), Request: request, CreatedAt: h.now(), ExpiresAt: h.now().Add(5 * time.Minute)}
	if err = h.Store.Phone().PutPasswordlessCode(ctx, c); err != nil {
		return err
	}
	purpose, typ := "verify", "otp_verify"
	if kind == "reset" {
		purpose = "reset"
		typ = "change_password"
	}
	if isEmail {
		svc := h.codeEmail()
		if svc == nil {
			return email.ErrServiceUnavailable
		}
		name := "verify_email_by_code"
		if kind == "reset" {
			name = "reset_email_by_code"
		}
		return svc.SendPasswordless(ctx, email.PasswordlessEmail{TenantID: tid, To: normalized, Template: name, Code: code})
	}
	_, err = h.MFA.Phone.Send(ctx, tid, phone.Route{Purpose: purpose, ConnectionID: conn}, phone.Message{TenantID: tid, To: normalized, DeliveryMethod: "text", Type: typ, Code: code})
	return err
}
func (h *Handlers) consumeIdentifierCode(ctx context.Context, tid, conn, number, kind, code string) (string, error) {
	normalized, err := phone.NormalizeE164(number, "")
	if strings.Contains(number, "@") {
		normalized = loginid.Normalize(number)
		err = nil
	}
	if err != nil {
		return "", err
	}
	c, err := h.Store.Phone().ConsumePasswordlessCode(ctx, tid, conn, normalized, "phone-"+kind, secrets.HashToken(code), 3, h.now())
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
	plain, err := keys.OpenBound(h.Authz.Wrapper, "identifier-code/v1", []string{tid, conn, normalized, kind}, sealed)
	return string(plain), err
}

func (h *Handlers) codeEmail() *email.Service {
	if h.Resets != nil && h.Resets.Email != nil {
		return h.Resets.Email
	}
	if h.Verification != nil {
		return h.Verification.Email
	}
	return nil
}
func (h *Handlers) codeTemplateEnabled(ctx context.Context, tid, name string) bool {
	svc := h.codeEmail()
	if svc == nil {
		return false
	}
	p, err := svc.Resolve(ctx, tid, name)
	return err == nil && p.Template != nil && p.Enabled
}
