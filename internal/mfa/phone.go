package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

var (
	ErrPhoneDelivery     = errors.New("mfa: phone delivery failed")
	ErrInvalidPhone      = phone.ErrInvalidPhone
	ErrCountryNotAllowed = errors.New("mfa: country not allowed")
	ErrSendLimit         = errors.Join(ErrThrottled, errors.New("mfa: phone send limit"))
)

type PhoneSender interface {
	Working(context.Context, string, phone.Route) (bool, error)
	DeliveryMethods(context.Context, string, phone.Route) ([]string, error)
	Send(context.Context, string, phone.Route, phone.Message) (phone.Result, error)
}

func (s *Service) PhoneMethods(ctx context.Context, tid string) ([]string, error) {
	g, err := s.st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return nil, err
	}
	if !g.Factors["sms"] || s.Phone == nil {
		return nil, nil
	}
	delivery, err := s.Phone.DeliveryMethods(ctx, tid, phone.Route{Purpose: "mfa"})
	if err != nil {
		return nil, err
	}
	cfg := struct {
		Types []string `json:"message_types"`
	}{Types: []string{"sms"}}
	if raw := g.Stored["/guardian/factors/phone/message-types"]; len(raw) > 0 {
		if err = json.Unmarshal(raw, &cfg); err != nil {
			return nil, err
		}
	}
	var out []string
	for _, m := range []string{"sms", "voice"} {
		d := m
		if d == "sms" {
			d = "text"
		}
		if slices.Contains(cfg.Types, m) && slices.Contains(delivery, d) {
			out = append(out, m)
		}
	}
	return out, nil
}
func (s *Service) BeginPhoneEnroll(ctx context.Context, tid, uid, number, method string) (*Enrollment, error) {
	normalized, err := phone.NormalizeE164(number, "")
	if err != nil {
		return nil, ErrInvalidPhone
	}
	methods, err := s.PhoneMethods(ctx, tid)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(methods, method) {
		return nil, ErrNoFactor
	}
	return s.beginEnroll(ctx, tid, uid, &store.Authenticator{TenantID: tid, UserID: uid, ID: NewMethodID("phone"), Type: "phone", Phone: normalized, PhoneMethod: method, LastStep: -1, CreatedAt: s.now()}, method)
}
func (s *Service) BeginPhoneChallenge(ctx context.Context, tid, uid, id, method string) (*Challenge, error) {
	a, err := s.st.MFA().GetAuthenticator(ctx, tid, uid, id)
	if err != nil {
		return nil, err
	}
	if a.Type != "phone" {
		return nil, ErrNoFactor
	}
	if err = enabled(ctx, s.st, tid, a.Type); err != nil {
		return nil, err
	}
	c, err := s.beginChallenge(ctx, tid, uid, a, method)
	if err == nil {
		s.emit(ctx, tid, uid, "gd_start_auth")
	}
	return c, err
}
func (s *Service) preparePhone(ctx context.Context, tid, uid string, a *store.Authenticator, method string, now time.Time) (string, error) {
	if method == "" {
		method = a.PhoneMethod
	}
	if method == "" {
		method = "sms"
	}
	methods, err := s.PhoneMethods(ctx, tid)
	if err != nil {
		return "", err
	}
	if !slices.Contains(methods, method) {
		if len(methods) == 0 {
			s.emit(ctx, tid, uid, phoneFailure(method))
			return "", ErrPhoneDelivery
		}
		return "", ErrNoFactor
	}
	tn, err := s.st.Tenants().Get(ctx, tid)
	if err != nil {
		return "", err
	}
	if !tenantrules.PhoneSettingsOf(tn).CountryAllowed(phone.CountryCode(a.Phone)) {
		return "", ErrCountryNotAllowed
	}
	if s.th == nil {
		return "", store.ErrProtectionUnimplemented
	}
	limits := []store.ProtectionLimit{{Key: store.ProtectionKey{TenantID: tid, Kind: "mfa-phone", Identifier: uid}, Algorithm: "fixed-window", Capacity: 10, Window: time.Hour}}
	if method == "voice" {
		limits = append(limits, store.ProtectionLimit{Key: store.ProtectionKey{TenantID: tid, Kind: "mfa-phone-voice", Identifier: uid}, Algorithm: "fixed-window", Capacity: 1, Window: time.Hour})
	}
	admission, err := s.th.Reserve(ctx, limits, now)
	if err != nil {
		return "", err
	}
	if !admission.Allowed {
		e := logs.Event{TenantID: tid, UserID: uid, Type: "limit_phone", Details: map[string]any{"delivery_method": method}}
		logs.RecordEvent(ctx, s.Recorder, e)
		return "", ErrSendLimit
	}
	if err = s.th.Complete(ctx, admission.Receipt, "failure", now); err != nil {
		return "", err
	}
	return method, nil
}
func phoneFailure(method string) string {
	if method == "voice" {
		return "gd_send_voice_failure"
	}
	return "gd_send_sms_failure"
}
func (s *Service) sendPhone(ctx context.Context, tid, uid string, a *store.Authenticator, method, code string) error {
	delivery := method
	if delivery == "sms" {
		delivery = "text"
	}
	typ := "otp_verify"
	if !a.Confirmed {
		typ = "otp_enroll"
	}
	_, err := s.Phone.Send(ctx, tid, phone.Route{Purpose: "mfa"}, phone.Message{TenantID: tid, UserID: uid, To: a.Phone, DeliveryMethod: delivery, Type: typ, Code: code})
	if err != nil {
		s.emit(ctx, tid, uid, phoneFailure(method))
		return ErrPhoneDelivery
	}
	event := "gd_send_sms"
	if method == "voice" {
		event = "gd_send_voice"
	}
	s.emit(ctx, tid, uid, event)
	return nil
}

// WithStore binds admission reads to the caller's existing transaction.
func (s *Service) WithStore(st store.Store) *Service {
	copy := *s
	copy.st = st
	if d, ok := s.Phone.(*phone.Dispatcher); ok {
		bound := *d
		bound.Store = st
		copy.Phone = &bound
	}
	return &copy
}
