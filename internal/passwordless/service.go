package passwordless

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/signupactions"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Code kinds stored in store.PasswordlessCode.Kind.
const (
	KindCode = "code"
	KindLink = "link"
)

// SMSSender delivers passwordless texts; *phone.Dispatcher implements it.
type SMSSender interface {
	Send(ctx context.Context, tid string, r phone.Route, m phone.Message) (phone.Result, error)
}

// EmailSender delivers passwordless emails; *email.Service implements it.
type EmailSender interface {
	SendPasswordless(ctx context.Context, m email.PasswordlessEmail) error
}

// Errors of VerifyCode and VerifyLink. Pre-user-registration refusals are
// returned as *identity.ErrSignupDenied or *identity.ErrSignupActionFailed.
var (
	// ErrInvalidCode is a wrong, expired, replaced, used or exhausted code
	// or link. A wrong code counts as an attempt.
	ErrInvalidCode = errors.New("passwordless: wrong, expired or used code")
	// ErrSignupDisabled is an unknown user on a disable_signup connection.
	ErrSignupDisabled = errors.New("passwordless: signup disabled")
	ErrUserBlocked    = errors.New("passwordless: user is blocked")
	// ErrTooManyAttempts is a brute-force block of the identifier (Plan 19).
	ErrTooManyAttempts = errors.New("passwordless: too many attempts")
)

// Service issues and verifies passwordless codes and magic links. It is safe
// for concurrent use; every check that must hold across requests is a
// conditional store update.
type Service struct {
	Store   store.Store
	Wrapper keys.Wrapper
	// SMS and Email deliver messages; nil fails the strategy's start closed.
	SMS   SMSSender
	Email EmailSender
	// Protection applies Plan 19 brute-force and IP rules to verification;
	// nil uses a store-backed service.
	Protection *protection.Service
	// Actions runs pre- and post-user-registration on first sign-in; nil
	// refuses signups while a pre-user-registration Action is bound.
	Actions *actions.Engine
	// Database inserts new users; nil uses one on Store.
	Database *identity.Database
	Recorder logs.Recorder
	Log      *slog.Logger
	Now      func() time.Time
}

// RequestInfo is the end-user request a verification belongs to.
type RequestInfo = actions.RequestInfo

type requestKey struct{}

// WithRequest attaches the end-user request: its IP keys the brute-force and
// IP rules and it feeds the registration Actions.
func WithRequest(ctx context.Context, r RequestInfo) context.Context {
	return context.WithValue(ctx, requestKey{}, r)
}

func requestFrom(ctx context.Context) RequestInfo {
	r, _ := ctx.Value(requestKey{}).(RequestInfo)
	return r
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) protection() *protection.Service {
	if s.Protection != nil {
		return s.Protection
	}
	return &protection.Service{Store: s.Store, Now: s.Now, Log: s.Log, Recorder: s.Recorder}
}

func (s *Service) database() *identity.Database {
	if s.Database != nil {
		return s.Database
	}
	return &identity.Database{Store: s.Store, Now: s.Now, Log: s.Log}
}

// NormalizeIdentifier returns the stored form of an identifier: a lowercased
// email for the email strategy, an E.164 number for sms.
func NormalizeIdentifier(strategy, raw string) (string, error) {
	switch strategy {
	case connrules.StrategyEmail:
		e := loginid.Normalize(raw)
		if identity.CheckEmail(e) != nil {
			return "", fmt.Errorf("invalid email address")
		}
		return e, nil
	case connrules.StrategySMS:
		if len(raw) > phonerules.Limits.PhoneNumberMax {
			return "", phone.ErrInvalidPhone
		}
		return phone.NormalizeE164(raw, "")
	}
	return "", fmt.Errorf("connection strategy %q is not passwordless", strategy)
}

// MaskIdentifier is the identifier as logs show it: phone numbers masked,
// email addresses as given.
func MaskIdentifier(strategy, ident string) string {
	if strategy == connrules.StrategySMS {
		return phone.Mask(ident)
	}
	return ident
}

// passwordlessConnection loads an email or sms connection by name.
func (s *Service) passwordlessConnection(ctx context.Context, tid, name string) (*store.Connection, error) {
	if !connrules.IsPasswordless(name) {
		return nil, store.ErrNotFound
	}
	conn, err := s.Store.Connections().GetByName(ctx, tid, name)
	if err != nil {
		return nil, err
	}
	if conn.Strategy != name {
		return nil, store.ErrNotFound
	}
	return conn, nil
}

func (s *Service) event(ctx context.Context, e logs.Event, conn *store.Connection) {
	ri := requestFrom(ctx)
	if e.IP == "" {
		e.IP = ri.IP
	}
	if e.UserAgent == "" {
		e.UserAgent = ri.UserAgent
	}
	if conn != nil {
		e.Connection, e.ConnectionID, e.Strategy, e.StrategyType = conn.Name, conn.ID, conn.Strategy, "passwordless"
	}
	recorder := s.Recorder
	if recorder == nil {
		recorder = logs.RecorderFromContext(ctx)
	}
	logs.RecordEvent(ctx, recorder, e)
}

// VerifyCode checks a code sent by Start for identifier (normalized by the
// caller or here) on connection and returns the user, creating it unless the
// connection disables signup. It applies the code's attempt limit and the
// tenant's brute-force rules, and marks the identifier verified.
func (s *Service) VerifyCode(ctx context.Context, tid, clientID, connection, identifier, code string) (*store.User, error) {
	conn, err := s.passwordlessConnection(ctx, tid, connection)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	ident, err := NormalizeIdentifier(conn.Strategy, identifier)
	if err != nil {
		return nil, ErrInvalidCode
	}
	t, err := s.Store.Tenants().Get(ctx, tid)
	if err != nil {
		return nil, err
	}
	prot := s.protection()
	decision, err := prot.Begin(ctx, protection.Attempt{Tenant: t, Connection: conn, Identifier: ident, IP: requestFrom(ctx).IP, Flow: "login"})
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		return nil, ErrTooManyAttempts
	}
	outcome := "refund"
	defer func() {
		if err := prot.Finish(ctx, decision.Receipt, outcome); err != nil {
			s.log().ErrorContext(ctx, "passwordless: protection completion", "tenant", tid, "err", err)
		}
	}()
	now := s.now()
	row, err := s.Store.Phone().ConsumePasswordlessCode(ctx, tid, conn.ID, ident, KindCode, secrets.HashToken(code), phonerules.Limits.OTPAttempts, now)
	if errors.Is(err, store.ErrPrecondition) {
		outcome = "failure"
		if _, ferr := s.Store.Phone().FailPasswordlessCode(ctx, tid, conn.ID, ident, KindCode, now); ferr != nil && !errors.Is(ferr, store.ErrNotFound) {
			return nil, ferr
		}
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	if row.ClientID != clientID {
		// The code was spent; a code belongs to the application it was sent for.
		outcome = "failure"
		return nil, ErrInvalidCode
	}
	outcome = "success"
	client, err := s.Store.Clients().Get(ctx, tid, clientID)
	if err != nil {
		return nil, err
	}
	return s.signIn(ctx, t, client, conn, ident)
}

// signIn finds or creates the user of a verified identifier.
func (s *Service) signIn(ctx context.Context, t *store.Tenant, client *store.Client, conn *store.Connection, ident string) (*store.User, error) {
	u, err := s.findUser(ctx, t.ID, conn, ident)
	if err != nil {
		return nil, err
	}
	if u == nil {
		opts, err := connrules.PasswordlessOf(*conn, nil)
		if err != nil {
			return nil, err
		}
		if opts.DisableSignup {
			s.event(ctx, logs.Event{TenantID: t.ID, Type: "fu", ClientID: client.ClientID, ClientName: client.Name, UserName: MaskIdentifier(conn.Strategy, ident), Description: "signup disabled"}, conn)
			return nil, ErrSignupDisabled
		}
		if u, err = s.create(ctx, t, client, conn, ident); err != nil {
			return nil, err
		}
	}
	if u.Blocked {
		return nil, ErrUserBlocked
	}
	return s.markVerified(ctx, u, conn.Strategy)
}

func (s *Service) findUser(ctx context.Context, tid string, conn *store.Connection, ident string) (*store.User, error) {
	if conn.Strategy == connrules.StrategySMS {
		users, err := s.Store.Phone().FindUsersByPhone(ctx, tid, conn.Name, ident)
		if err != nil || len(users) == 0 {
			return nil, err
		}
		return &users[0], nil
	}
	u, err := s.Store.Users().FindByLogin(ctx, tid, conn.Name, ident)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return u, err
}

// create inserts the user of a first verification (D-0060 P6 user_id).
func (s *Service) create(ctx context.Context, t *store.Tenant, client *store.Client, conn *store.Connection, ident string) (*store.User, error) {
	id := secrets.RandomHex(12)
	now := s.now()
	u := &store.User{TenantID: t.ID, UserID: conn.Strategy + "|" + id, CreatedAt: now, UpdatedAt: now,
		Identities: []store.Identity{{Connection: conn.Name, Provider: conn.Strategy, UserID: id}}}
	if conn.Strategy == connrules.StrategySMS {
		u.PhoneNumber, u.PhoneNormalized, u.PhoneVerified = ident, ident, true
		u.Name, u.Nickname = ident, ident
	} else {
		u.Email, u.EmailVerified = ident, true
		u.Name, u.Nickname = identity.DefaultNames("", "", ident, "")
		u.Picture = identity.DefaultPicture(ident)
	}
	res, ok := tenant.FromContext(ctx)
	if !ok || res.Tenant == nil || res.Tenant.ID != t.ID {
		res = tenant.Resolved{Tenant: t}
	}
	in := actions.RegistrationInput{Tenant: res, Client: client, Connection: conn, Request: requestFrom(ctx)}
	var callbacks identity.SignupActions
	if s.Actions != nil {
		callbacks = signupactions.Callbacks(s.Store, s.Actions, in)
	} else {
		callbacks = signupactions.Callbacks(s.Store, nil, in)
	}
	event := logs.Event{TenantID: t.ID, ClientID: client.ClientID, ClientName: client.Name, UserID: u.UserID, UserName: MaskIdentifier(conn.Strategy, ident)}
	err := s.database().CreatePasswordless(ctx, conn, callbacks, u)
	if errors.Is(err, identity.ErrUserExists) {
		// A concurrent first sign-in created the user.
		found, ferr := s.findUser(ctx, t.ID, conn, ident)
		if ferr != nil {
			return nil, ferr
		}
		if found != nil {
			return found, nil
		}
	}
	var denied *identity.ErrSignupDenied
	var failed *identity.ErrSignupActionFailed
	switch {
	case errors.As(err, &denied):
		event.Type, event.Description = "fs", denied.Description
		s.event(ctx, event, conn)
		return nil, err
	case errors.As(err, &failed):
		event.Type = "fs"
		s.event(ctx, event, conn)
		return nil, err
	case err != nil:
		return nil, err
	}
	event.Type = "ss"
	s.event(ctx, event, conn)
	return u, nil
}

// markVerified sets email_verified or phone_verified after a successful
// passwordless sign-in.
func (s *Service) markVerified(ctx context.Context, u *store.User, strategy string) (*store.User, error) {
	if (strategy == connrules.StrategySMS && u.PhoneVerified) || (strategy == connrules.StrategyEmail && u.EmailVerified) {
		return u, nil
	}
	if strategy == connrules.StrategySMS {
		u.PhoneVerified = true
	} else {
		u.EmailVerified = true
	}
	u.UpdatedAt = s.now()
	if err := s.Store.Users().Update(ctx, u); err != nil {
		return nil, err
	}
	return s.Store.Users().Get(ctx, u.TenantID, u.UserID)
}

// enabledFor reports whether conn is enabled for clientID.
func enabledFor(conn *store.Connection, clientID string) bool {
	return slices.Contains(conn.EnabledClients, clientID)
}
