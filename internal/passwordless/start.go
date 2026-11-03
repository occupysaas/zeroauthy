package passwordless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

// StartInput is one /passwordless/start request (or a hosted send). The
// caller has authenticated the client as the tenant's rules require.
type StartInput struct {
	TenantID, ClientID, Connection, Email, PhoneNumber, Send string // Send: code|link
	AuthParams                                               url.Values
	IP, UserAgent, Locale                                    string
	// Origin is the public tenant origin magic links point at.
	Origin string
}

// StartResult is the start response body (D-0060 P1).
type StartResult struct {
	ID, Email, PhoneNumber string
	Verified               bool
}

// Error is a refused start, with the HTTP status and OAuth error code to
// answer. RetryAfter is set (seconds) for too_many_requests.
type Error struct {
	Status            int
	Code, Description string
	RetryAfter        int
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func refuse(status int, code, description string) *Error {
	return &Error{Status: status, Code: code, Description: description}
}

const (
	linkLabel      = "passwordless-link/v1"
	verifyPath     = "/passwordless/verify_redirect"
	notEnabled     = "the connection does not exist or is not enabled for this client"
	kindStartIP    = "passwordless-start-ip"
	kindIdentifier = "passwordless-send"
)

// Start sends a code (email or SMS) or a magic link (email) and replaces any
// outstanding code or link of the identifier on the connection. Refusals are
// *Error; store failures are returned as they are (store.ErrPhoneUnavailable
// included).
func (s *Service) Start(ctx context.Context, in StartInput) (*StartResult, error) {
	t, err := s.Store.Tenants().Get(ctx, in.TenantID)
	if err != nil {
		return nil, err
	}
	client, err := s.Store.Clients().Get(ctx, in.TenantID, in.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(http.StatusUnauthorized, "invalid_client", "client authentication failed")
	}
	if err != nil {
		return nil, err
	}
	if !slices.Contains(client.GrantTypes, clientrules.GrantPasswordlessOTP) {
		return nil, refuse(http.StatusForbidden, "unauthorized_client", fmt.Sprintf("grant type %q is not allowed for this client", clientrules.GrantPasswordlessOTP))
	}
	conn, err := s.passwordlessConnection(ctx, in.TenantID, in.Connection)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !enabledFor(conn, client.ClientID)) {
		return nil, refuse(http.StatusBadRequest, "invalid_request", notEnabled)
	}
	if err != nil {
		return nil, err
	}
	opts, err := connrules.PasswordlessOf(*conn, nil)
	if err != nil {
		return nil, err
	}
	send := in.Send
	if send == "" {
		send = KindLink
		if conn.Strategy == connrules.StrategySMS {
			send = KindCode
		}
	}
	if send != KindCode && send != KindLink {
		return nil, refuse(http.StatusBadRequest, "invalid_request", "send must be code or link")
	}
	if send == KindLink && conn.Strategy != connrules.StrategyEmail {
		return nil, refuse(http.StatusBadRequest, "invalid_request", "magic links are only available for the email connection")
	}
	raw := in.Email
	if conn.Strategy == connrules.StrategySMS {
		raw = in.PhoneNumber
	}
	if raw == "" {
		return nil, refuse(http.StatusBadRequest, "invalid_request", missingIdentifier(conn.Strategy))
	}
	ident, err := NormalizeIdentifier(conn.Strategy, raw)
	if err != nil {
		if conn.Strategy == connrules.StrategySMS {
			return nil, refuse(http.StatusBadRequest, "invalid_request", "phone_number must be an E.164 phone number")
		}
		return nil, refuse(http.StatusBadRequest, "invalid_request", "email is not a valid email address")
	}
	ctx = logscrub.WithCredentials(ctx, ident)
	masked := MaskIdentifier(conn.Strategy, ident)
	base := logs.Event{TenantID: t.ID, ClientID: client.ClientID, ClientName: client.Name, UserName: masked, IP: in.IP, UserAgent: in.UserAgent}
	if conn.Strategy == connrules.StrategySMS && !tenantrules.PhoneSettingsOf(t).CountryAllowed(phone.CountryCode(ident)) {
		return nil, refuse(http.StatusBadRequest, "invalid_request", "phone numbers from this country are not allowed")
	}
	if err := s.reserveStart(ctx, t.ID, conn, ident, in.IP, base); err != nil {
		return nil, err
	}
	u, err := s.findUser(ctx, t.ID, conn, ident)
	if err != nil {
		return nil, err
	}
	switch {
	case u != nil && u.Blocked:
		return nil, refuse(http.StatusForbidden, "access_denied", "user is blocked")
	case u == nil && opts.DisableSignup:
		// P22: an unknown user cannot sign up, so no message is sent.
		return nil, refuse(http.StatusForbidden, "access_denied", "signups are disabled for this connection")
	}

	now := s.now()
	lifetime := time.Duration(opts.TOTP.TimeStep) * time.Second
	if lifetime <= 0 {
		lifetime = time.Duration(phonerules.Limits.OTPLifetimeDefaultSeconds) * time.Second
	}
	row := &store.PasswordlessCode{TenantID: t.ID, ConnectionID: conn.ID, Identifier: ident, ClientID: client.ClientID, Kind: send, ExpiresAt: now.Add(lifetime), CreatedAt: now}
	var code, link string
	if send == KindCode {
		length := opts.TOTP.Length
		if length < phonerules.Limits.OTPLengthMin || length > phonerules.Limits.OTPLengthMax {
			length = phonerules.Limits.OTPLengthDefault
		}
		code = NewCode(length)
		row.CodeHash = secrets.HashToken(code)
	} else {
		token := NewLinkToken()
		row.CodeHash = secrets.HashToken(token)
		sealed, err := s.sealParams(t.ID, row.CodeHash, linkParams(opts.AuthParams, in.AuthParams, client.ClientID))
		if err != nil {
			return nil, err
		}
		row.Request = sealed
		link = in.Origin + verifyPath + "?" + url.Values{"verification_code": {token}, "connection": {conn.Name}, "client_id": {client.ClientID}, "email": {ident}}.Encode()
	}
	ctx = logscrub.WithCredentials(ctx, code, link)
	if err := s.Store.Phone().PutPasswordlessCode(ctx, row); err != nil {
		return nil, err
	}
	// Only the latest code or link of the identifier is valid: the other
	// kind's row is replaced by an expired one.
	other := *row
	other.Kind, other.CodeHash, other.Request, other.ExpiresAt = otherKind(send), secrets.HashToken(secrets.RandomString(32)), nil, now
	if err := s.Store.Phone().PutPasswordlessCode(ctx, &other); err != nil {
		return nil, err
	}

	if err := s.deliver(ctx, t, client, conn, opts, in, ident, code, link, u); err != nil {
		if conn.Strategy == connrules.StrategySMS {
			failure := base
			failure.Type, failure.Description = phone.FailureCode("passwordless", "text"), "passwordless SMS delivery failed"
			failure.Details = map[string]any{"error_class": string(phone.ClassOf(err))}
			s.event(ctx, failure, conn)
			s.log().WarnContext(ctx, "passwordless: SMS delivery failed", "tenant", t.ID, "connection", conn.Name, "to", masked, "class", phone.ClassOf(err))
			return nil, refuse(http.StatusBadRequest, "sms_provider_error", "the SMS could not be sent")
		}
		s.log().WarnContext(ctx, "passwordless: email delivery failed", "tenant", t.ID, "connection", conn.Name, "err", err)
		return nil, refuse(http.StatusInternalServerError, "server_error", "the email could not be sent")
	}
	sent := base
	sent.Type = "cs"
	if send == KindLink {
		sent.Type = "cls"
	}
	if u != nil {
		sent.UserID = u.UserID
	}
	s.event(ctx, sent, conn)

	res := &StartResult{ID: secrets.RandomHex(phonerules.Limits.StartIDHexLength / 2)}
	res.Verified = identifierVerified(u, conn, ident)
	if conn.Strategy == connrules.StrategySMS {
		res.PhoneNumber = ident
	} else {
		res.Email = ident
	}
	return res, nil
}

func missingIdentifier(strategy string) string {
	if strategy == connrules.StrategySMS {
		return "phone_number is required"
	}
	return "email is required"
}

func otherKind(kind string) string {
	if kind == KindCode {
		return KindLink
	}
	return KindCode
}

// reserveStart charges the per-IP start limit and the identifier send budget
// (Plan 19 protection repository). Exhaustion logs api_limit (IP, email) or
// limit_phone (SMS) and refuses with too_many_requests.
func (s *Service) reserveStart(ctx context.Context, tid string, conn *store.Connection, ident, ip string, base logs.Event) error {
	lim := phonerules.Limits
	checks := []struct {
		limit store.ProtectionLimit
		code  string
	}{
		{store.ProtectionLimit{Key: store.ProtectionKey{TenantID: tid, Kind: kindStartIP, IP: protection.CanonicalIP(ip)}, Algorithm: "fixed-window", Capacity: lim.StartPerIPPerHour, Window: time.Hour}, "api_limit"},
		{store.ProtectionLimit{Key: store.ProtectionKey{TenantID: tid, Kind: kindIdentifier, ConnectionID: conn.ID, Identifier: ident}, Algorithm: "fixed-window", Capacity: lim.IdentifierSendsPerHour, Window: time.Hour}, "api_limit"},
	}
	if conn.Strategy == connrules.StrategySMS {
		checks[1].code = "limit_phone"
	}
	for _, c := range checks {
		now := s.now()
		a, err := s.Store.Protection().Reserve(ctx, []store.ProtectionLimit{c.limit}, now)
		if err != nil {
			return err
		}
		if !a.Allowed {
			wait := int(a.RetryAt.Sub(now).Seconds()) + 1
			if wait < 1 {
				wait = 1
			}
			e := base
			e.Type, e.Description = c.code, "passwordless send budget exhausted"
			e.Details = map[string]any{"retry_after_seconds": wait}
			s.event(ctx, e, conn)
			return &Error{Status: http.StatusTooManyRequests, Code: "too_many_requests", Description: "too many passwordless requests; try again later", RetryAfter: wait}
		}
		// A start spends its budget even when delivery fails (toll fraud).
		if err := s.Store.Protection().Complete(ctx, a.Receipt, "failure", now); err != nil {
			return err
		}
	}
	return nil
}

// deliver sends the code or link through the strategy's channel.
func (s *Service) deliver(ctx context.Context, t *store.Tenant, client *store.Client, conn *store.Connection, opts *connrules.PasswordlessOptions, in StartInput, ident, code, link string, u *store.User) error {
	if conn.Strategy == connrules.StrategySMS {
		if s.SMS == nil {
			return &phone.SendError{Class: phone.ClassProviderAuth, Err: phone.ErrNoProvider}
		}
		m := phone.Message{To: ident, DeliveryMethod: "text", Type: "passwordless", Code: code, Locale: in.Locale, ClientID: client.ClientID}
		if u != nil {
			m.UserID = u.UserID
		}
		ctx = phone.WithRequest(ctx, phone.Request{IP: in.IP, UserAgent: in.UserAgent})
		// A nil error from a custom provider's retry path means accepted.
		_, err := s.SMS.Send(ctx, t.ID, phone.Route{Purpose: "passwordless", ConnectionID: conn.ID}, m)
		return err
	}
	if s.Email == nil {
		return errors.New("passwordless: no email service")
	}
	m := email.PasswordlessEmail{TenantID: t.ID, ClientID: client.ClientID, To: ident, Language: in.Locale, Code: code, Link: link}
	if opts.Email != nil {
		m.From, m.Subject, m.Body = opts.Email.From, opts.Email.Subject, opts.Email.Body
	}
	return s.Email.SendPasswordless(ctx, m)
}

// linkParams merges the connection's authParams defaults with the request's
// and binds the client. Magic links never return refresh tokens.
func linkParams(defaults map[string]string, req url.Values, clientID string) url.Values {
	out := url.Values{}
	for k, v := range defaults {
		out.Set(k, v)
	}
	for k, v := range req {
		if len(v) > 0 {
			out.Set(k, v[0])
		}
	}
	out.Set("client_id", clientID)
	if scope := out.Get("scope"); scope != "" {
		out.Set("scope", withoutOfflineAccess(scope))
	}
	return out
}

func (s *Service) sealParams(tid, hash string, params url.Values) (json.RawMessage, error) {
	if s.Wrapper == nil {
		return nil, errors.New("passwordless: no key wrapper for magic links")
	}
	plain, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	sealed, err := keys.SealBound(s.Wrapper, linkLabel, []string{tid, hash}, plain)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sealed)
}

func (s *Service) openParams(tid, hash string, raw json.RawMessage) (url.Values, error) {
	var sealed []byte
	if err := json.Unmarshal(raw, &sealed); err != nil {
		return nil, err
	}
	plain, err := keys.OpenBound(s.Wrapper, linkLabel, []string{tid, hash}, sealed)
	if err != nil {
		return nil, err
	}
	out := url.Values{}
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, err
	}
	return out, nil
}
