package mfa

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	ErrInvalidCode   = errors.New("mfa: invalid code")
	ErrThrottled     = errors.New("mfa: too many attempts")
	ErrExpired       = errors.New("mfa: expired challenge")
	ErrNoFactor      = errors.New("mfa: no available factor")
	ErrEmailDelivery = errors.New("mfa: email delivery failed")
	errSealing       = errors.New("mfa: secret sealing unavailable")
	// ErrAlreadyEnrolled refuses a first-only enrollment because the user now
	// has a usable primary factor. It is also an ErrInvalidCode, so callers
	// that do not distinguish it keep answering as for a wrong code.
	ErrAlreadyEnrolled = fmt.Errorf("%w: a usable factor is already enrolled", ErrInvalidCode)
)

// Enrollment contains one-time TOTP display values. Callers must retain only
// AuthenticatorID and ChallengeID in sealed transaction state, never Secret/URI.
type Enrollment struct{ Factor, AuthenticatorID, Secret, URI, ChallengeID string }
type Challenge struct{ ID, Factor, AuthenticatorID, Method string }
type Proof struct{ Code string }
type Confirmed struct{ AuthenticatorID, RecoveryCode string }
type EmailSender interface {
	Send(context.Context, email.Event) error
}

// Service is shared by hosted login and OAuth grants. No proof/replay state is
// process-local. Recorder may be set explicitly; otherwise use the request sink.
type Service struct {
	Recorder      logs.Recorder
	st            store.Store
	sealer        keys.Wrapper
	mail          EmailSender
	th            Throttle
	now           func() time.Time
	proofCommit   func(store.Store) error
	newFactorOnly bool
	// Phone delivers SMS and voice codes; *phone.Dispatcher implements it.
	// Nil means the phone factor never works and is never offered.
	Phone PhoneSender
	// pendingRecovery is the hash of a recovery code already displayed at
	// association; it is persisted only when the enrollment is confirmed.
	pendingRecovery         string
	webAuthnBinding         passkey.Binding
	webAuthnRPID            *string
	webAuthnFirstOnly       bool
	platformEnrollmentProof bool
	webAuthnBrowserError    string
}

// NewService uses the repository's master-key wrapper and atomic protection
// repository. A nil throttle selects the same store's protection repository.
func NewService(st store.Store, sealer keys.Wrapper, mail EmailSender, th Throttle, log *slog.Logger, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if th == nil && st != nil {
		th = st.Protection()
	}
	return &Service{st: st, sealer: sealer, mail: mail, th: th, now: now}
}

// operationContext shares already-opened credential masks with all outcome
// events in this flow, including the caller's attribution/enrichment fields.
func (s *Service) operationContext(ctx context.Context, values ...string) context.Context {
	recorder := s.Recorder
	if recorder == nil {
		recorder = logs.RecorderFromContext(ctx)
	}
	ctx = logs.WithRecorder(ctx, recorder)
	logs.AddCredentials(ctx, values...)
	return logscrub.WithCredentials(ctx, values...)
}

func (s *Service) emit(ctx context.Context, tid, uid, kind string) {
	recorder := s.Recorder
	if recorder == nil {
		recorder = logs.RecorderFromContext(ctx)
	}
	logs.RecordEvent(ctx, recorder, logs.Event{TenantID: tid, UserID: uid, Type: kind, Date: s.now()})
}
func factorType(factor string) string {
	if factor == "otp" || factor == "totp" {
		return "totp"
	}
	if factor == "email" || factor == "phone" {
		return factor
	}
	return ""
}
func factorName(typ string) string {
	if typ == "totp" {
		return "otp"
	}
	return typ
}

// guardianFactor is the Guardian factor toggle that enables a method type:
// phone methods (sms or voice delivery) are enabled by the "sms" factor.
func guardianFactor(typ string) string {
	if typ == "phone" {
		return "sms"
	}
	return factorName(typ)
}
func enabled(ctx context.Context, st store.Store, tid, typ string) error {
	g, err := st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return err
	}
	if !g.Factors[guardianFactor(typ)] {
		return ErrNoFactor
	}
	return nil
}
func totpAAD(tid, uid, id string) []byte {
	b, _ := json.Marshal([]string{"mfa-totp", tid, uid, id})
	return b
}
func (s *Service) BeginEnroll(ctx context.Context, tid, uid, factor, rpID string) (out *Enrollment, err error) {
	ctx = s.operationContext(ctx)
	typ := factorType(factor)
	if typ == "" || typ == "phone" {
		// Phone enrollment needs a number and a method: BeginPhoneEnroll.
		return nil, ErrNoFactor
	}
	if err = enabled(ctx, s.st, tid, typ); err != nil {
		return nil, err
	}
	return s.beginEnroll(ctx, tid, uid, &store.Authenticator{TenantID: tid, UserID: uid, ID: NewMethodID(typ), Type: typ, LastStep: -1, CreatedAt: s.now()}, "")
}

// beginEnroll creates the pending method a and sends its first challenge
// (method is the phone delivery method). The caller emits nothing; this
// emits gd_start_enroll or gd_start_enroll_failed.
func (s *Service) beginEnroll(ctx context.Context, tid, uid string, a *store.Authenticator, method string) (out *Enrollment, err error) {
	defer func() {
		if err != nil {
			s.emit(ctx, tid, uid, "gd_start_enroll_failed")
		}
	}()
	typ := a.Type
	user, err := s.st.Users().Get(ctx, tid, uid)
	if err != nil {
		return nil, err
	}
	if typ == "totp" || typ == "phone" {
		a.CodeHash = s.pendingRecovery
	}
	e := &Enrollment{Factor: factorName(typ), AuthenticatorID: a.ID}
	switch typ {
	case "totp":
		if s.sealer == nil {
			return nil, errSealing
		}
		e.Secret = NewTOTPSecret()
		ctx = s.operationContext(ctx, e.Secret)
		a.SealedSecret, err = SealTOTPSecret(s.sealer, tid, uid, a.ID, e.Secret)
		if err != nil {
			return nil, errSealing
		}
		tenant, eerr := s.st.Tenants().Get(ctx, tid)
		if eerr != nil {
			return nil, eerr
		}
		issuer := tenant.FriendlyName
		if issuer == "" {
			issuer = tenant.Name
		}
		e.URI = TOTPURI(issuer, TOTPAccount(user), e.Secret)
		ctx = s.operationContext(ctx, e.URI)
	case "email":
		if !user.EmailVerified || user.Email == "" {
			return nil, ErrNoFactor
		}
		a.Email = user.Email
	}
	create := func(tx store.Store) error {
		if s.newFactorOnly {
			if _, e := tx.Users().GetForUpdate(ctx, tid, uid); e != nil {
				return e
			}
			list, e := tx.MFA().ListAuthenticators(ctx, tid, uid)
			if e != nil {
				return e
			}
			for _, other := range list {
				if other.Confirmed && other.Type == typ {
					return ErrNoFactor
				}
			}
		}
		return tx.MFA().CreateAuthenticator(ctx, a)
	}
	if s.newFactorOnly {
		err = s.st.WithTx(ctx, create)
	} else {
		err = create(s.st)
	}
	if err != nil {
		return nil, err
	}
	c, err := s.beginChallenge(ctx, tid, uid, a, method)
	if err != nil {
		_ = s.st.MFA().DeleteAuthenticator(ctx, tid, uid, a.ID)
		return nil, err
	}
	e.ChallengeID = c.ID
	s.emit(ctx, tid, uid, "gd_start_enroll")
	return e, nil
}
func (s *Service) BeginChallenge(ctx context.Context, tid, uid, id, rpID string) (*Challenge, error) {
	ctx = s.operationContext(ctx)
	a, err := s.st.MFA().GetAuthenticator(ctx, tid, uid, id)
	if err != nil {
		return nil, err
	}
	if factorType(a.Type) == "" {
		return nil, ErrNoFactor
	}
	if err = enabled(ctx, s.st, tid, a.Type); err != nil {
		return nil, err
	}
	c, err := s.beginChallenge(ctx, tid, uid, a, "")
	if err == nil {
		s.emit(ctx, tid, uid, "gd_start_auth")
	}
	return c, err
}

// RenewTOTPChallenge replaces an expired TOTP challenge for the same owned
// method, pending or confirmed. The TOTP secret belongs to the method, not
// the challenge, so a scanned enrollment remains valid. It emits no start
// event because no new factor interaction begins.
func (s *Service) RenewTOTPChallenge(ctx context.Context, tid, uid, id string) (*Challenge, error) {
	ctx = s.operationContext(ctx)
	a, err := s.st.MFA().GetAuthenticator(ctx, tid, uid, id)
	if err != nil {
		return nil, err
	}
	if a.Type != "totp" {
		return nil, ErrNoFactor
	}
	if err = enabled(ctx, s.st, tid, a.Type); err != nil {
		return nil, err
	}
	return s.beginChallenge(ctx, tid, uid, a, "")
}

// beginChallenge stores a new challenge for a and delivers its code. method
// selects phone delivery (sms|voice; empty uses the method's preference).
func (s *Service) beginChallenge(ctx context.Context, tid, uid string, a *store.Authenticator, method string) (*Challenge, error) {
	now := s.now()
	c := &Challenge{ID: secrets.RandomString(32), Factor: factorName(a.Type), AuthenticatorID: a.ID}
	ctx = s.operationContext(ctx, c.ID)
	saved := &store.MFAChallenge{TenantID: tid, ID: secrets.HashToken(c.ID), UserID: uid, AuthenticatorID: a.ID, Kind: a.Type, ExpiresAt: now.Add(5 * time.Minute)}
	var code string
	if a.Type == "email" {
		if err := verifiedEmail(ctx, s.st, tid, uid, a); err != nil {
			return nil, err
		}
		if err := s.reserveEmail(ctx, tid, uid, now); err != nil {
			return nil, err
		}
		code = NewEmailCode()
		saved.CodeHash = secrets.HashToken(code)
	}
	if a.Type == "phone" {
		var err error
		if c.Method, err = s.preparePhone(ctx, tid, uid, a, method, now); err != nil {
			return nil, err
		}
		code = NewEmailCode()
		saved.CodeHash = secrets.HashToken(code)
		ctx = s.operationContext(ctx, phone.CodeForms(code)...)
	}
	if err := s.st.MFA().CreateChallenge(ctx, saved); err != nil {
		return nil, err
	}
	switch a.Type {
	case "email":
		if err := s.sendEmail(ctx, tid, uid, code); err != nil {
			_ = s.st.MFA().ConsumeChallenge(ctx, tid, saved.ID, now)
			return nil, err
		}
	case "phone":
		if err := s.sendPhone(ctx, tid, uid, a, c.Method, code); err != nil {
			_ = s.st.MFA().ConsumeChallenge(ctx, tid, saved.ID, now)
			return nil, err
		}
	}
	return c, nil
}
func verifiedEmail(ctx context.Context, st store.Store, tid, uid string, a *store.Authenticator) error {
	u, err := st.Users().Get(ctx, tid, uid)
	if err != nil {
		return err
	}
	if !u.EmailVerified || a.Email == "" || u.Email != a.Email {
		return ErrNoFactor
	}
	return nil
}

func (s *Service) ConfirmEnroll(ctx context.Context, tid, uid string, e *Enrollment, proof Proof) (*Confirmed, error) {
	return s.confirmEnroll(ctx, tid, uid, e, proof, false)
}

// ConfirmFirstEnroll atomically forbids an additional confirmed primary method.
// Enrollment-only tickets without allow_multiple_enrollments use this variant.
func (s *Service) ConfirmFirstEnroll(ctx context.Context, tid, uid string, e *Enrollment, proof Proof) (*Confirmed, error) {
	return s.confirmEnroll(ctx, tid, uid, e, proof, true)
}
func (s *Service) confirmEnroll(ctx context.Context, tid, uid string, e *Enrollment, proof Proof, firstOnly bool) (*Confirmed, error) {
	ctx = s.operationContext(ctx, proof.Code)
	if e == nil {
		return nil, ErrInvalidCode
	}
	ctx = s.operationContext(ctx, e.ChallengeID)
	c := &Challenge{ID: e.ChallengeID, AuthenticatorID: e.AuthenticatorID}
	result := &Confirmed{AuthenticatorID: e.AuthenticatorID}
	err := s.check(ctx, tid, uid, c, proof, true, result, firstOnly)
	if err != nil {
		s.emit(ctx, tid, uid, "gd_start_enroll_failed")
		return nil, err
	}
	s.emit(ctx, tid, uid, "gd_enrollment_complete")
	return result, nil
}
func (s *Service) Verify(ctx context.Context, tid, uid string, c *Challenge, proof Proof) error {
	ctx = s.operationContext(ctx, proof.Code)
	if c != nil {
		ctx = s.operationContext(ctx, c.ID)
	}
	err := s.check(ctx, tid, uid, c, proof, false, nil, false)
	if err != nil {
		s.emit(ctx, tid, uid, "gd_auth_failed")
	} else {
		s.emit(ctx, tid, uid, "gd_auth_succeed")
	}
	return err
}

func (s *Service) check(ctx context.Context, tid, uid string, c *Challenge, proof Proof, enroll bool, result *Confirmed, firstOnly bool) error {
	if c == nil {
		return ErrInvalidCode
	}
	// The caller's Factor and the enrollment's Secret/URI are never authoritative.
	a, err := s.st.MFA().GetAuthenticator(ctx, tid, uid, c.AuthenticatorID)
	if err != nil {
		return err
	}
	if factorType(a.Type) == "" {
		return ErrNoFactor
	}
	if err = enabled(ctx, s.st, tid, a.Type); err != nil {
		return err
	}
	receipt, err := s.reserveProof(ctx, tid, uid, a.Type)
	if err != nil {
		return err
	}
	ctx = logscrub.WithCredentials(ctx, proof.Code)
	outcome := "refund"
	var proofErr error
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		// All enrollment confirmations share the same user lock, including ordinary
		// allow-multiple enrollment. Acquire it before any authenticator snapshot so
		// a restricted ticket cannot race another confirmation past its predicate.
		if enroll || s.proofCommit != nil {
			if _, e := tx.Users().GetForUpdate(ctx, tid, uid); e != nil {
				return e
			}
		}
		// Repeat state checks inside the proof-consumption transaction.
		current, e := tx.MFA().GetAuthenticator(ctx, tid, uid, a.ID)
		if e != nil {
			return e
		}
		if current.Type != a.Type || current.Confirmed == enroll {
			proofErr = ErrInvalidCode
			return nil
		}
		if enroll && (firstOnly || s.newFactorOnly) {
			list, e := tx.MFA().ListAuthenticators(ctx, tid, uid)
			if e != nil {
				return e
			}
			var u *store.User
			var g *store.GuardianSettings
			if firstOnly {
				if u, e = tx.Users().Get(ctx, tid, uid); e != nil {
					return e
				}
				if g, e = tx.MFA().GetGuardian(ctx, tid); e != nil {
					return e
				}
			}
			for _, other := range list {
				// First-only enrollment is blocked only by a usable primary
				// factor; a disabled or stale method must not lock the user out.
				if other.ID == current.ID {
					continue
				}
				if firstOnly && UsableMethod(u, other, g.Factors) && (!isWebAuthnFactor(other.Type) || s.webAuthnRPID == nil || other.RPID == *s.webAuthnRPID) {
					return ErrAlreadyEnrolled
				}
				if s.newFactorOnly && other.Confirmed && other.Type == current.Type {
					return ErrInvalidCode
				}
			}
		}
		if e = enabled(ctx, tx, tid, current.Type); e != nil {
			return e
		}
		ch, e := tx.MFA().GetChallenge(ctx, tid, secrets.HashToken(c.ID), s.now())
		if errors.Is(e, store.ErrNotFound) {
			proofErr = ErrExpired
			return nil
		}
		if e != nil {
			return e
		}
		if ch.UserID != uid || ch.AuthenticatorID != current.ID || ch.Kind != current.Type {
			proofErr = ErrInvalidCode
			return nil
		}
		valid := false
		var step int64
		switch current.Type {
		case "totp":
			if s.sealer == nil {
				return errSealing
			}
			plain, e := s.sealer.Unwrap(current.SealedSecret, totpAAD(tid, uid, current.ID))
			if e != nil {
				return errSealing
			}
			ctx = s.operationContext(ctx, string(plain))
			step, valid = VerifyTOTP(string(plain), proof.Code, s.now())
			valid = valid && step > current.LastStep
		case "email":
			if e = verifiedEmail(ctx, tx, tid, uid, current); e != nil {
				return e
			}
			valid = len(proof.Code) == 6 && subtle.ConstantTimeCompare([]byte(ch.CodeHash), []byte(secrets.HashToken(proof.Code))) == 1 && ch.Attempts < 5
		case "phone":
			// The code was delivered to the method's number; a provider switch
			// since the send does not affect it.
			valid = current.Phone != "" && len(proof.Code) == 6 && subtle.ConstantTimeCompare([]byte(ch.CodeHash), []byte(secrets.HashToken(proof.Code))) == 1 && ch.Attempts < 5
		}
		if !valid {
			outcome = "failure"
			proofErr = ErrInvalidCode
			if current.Type == "email" || current.Type == "phone" {
				_, e = tx.MFA().FailChallenge(ctx, tid, ch.ID)
				if e != nil && !errors.Is(e, store.ErrPrecondition) {
					return e
				}
			}
			return nil
		}
		if e = tx.MFA().ConsumeChallenge(ctx, tid, ch.ID, s.now()); e != nil {
			return e
		}
		if current.Type == "totp" {
			if e = tx.MFA().AcceptTOTPStep(ctx, tid, uid, current.ID, step, s.now()); e != nil {
				return e
			}
		}
		if enroll {
			current.Confirmed = true
			if e = tx.MFA().UpdateAuthenticator(ctx, current); e != nil {
				return e
			}
			list, e := tx.MFA().ListAuthenticators(ctx, tid, uid)
			if e != nil {
				return e
			}
			hasRecovery := false
			for _, v := range list {
				if v.Type == "recovery-code" {
					hasRecovery = true
					break
				}
			}
			if !hasRecovery && (current.Type == "totp" || current.Type == "phone") && current.CodeHash != "" {
				// The code was displayed at association; persist it now.
				if e = tx.MFA().ReplaceRecoveryCode(ctx, tid, uid, "", current.CodeHash, s.now()); e != nil {
					return e
				}
			} else if !hasRecovery {
				recovery := NewRecoveryCode()
				ctx = s.operationContext(ctx, recovery)
				if e = tx.MFA().ReplaceRecoveryCode(ctx, tid, uid, "", secrets.HashToken(recovery), s.now()); e != nil {
					return e
				}
				result.RecoveryCode = recovery
			}
		}
		if s.proofCommit != nil {
			if e := s.proofCommit(tx); e != nil {
				return e
			}
		}
		outcome = "success"
		return nil
	})
	if err != nil {
		outcome = "refund"
		if errors.Is(err, store.ErrPrecondition) {
			err = ErrInvalidCode
			outcome = "failure"
		}
	}
	if e := s.finishProof(ctx, tid, uid, a.Type, receipt, outcome); e != nil {
		return e
	}
	if err != nil {
		return err
	}
	return proofErr
}

func (s *Service) Recover(ctx context.Context, tid, uid, code string) (next string, err error) {
	ctx = s.operationContext(ctx, code)
	defer func() {
		if err != nil {
			s.emit(ctx, tid, uid, "gd_recovery_failed")
		} else {
			s.emit(ctx, tid, uid, "gd_recovery_succeed")
		}
	}()
	if err = enabled(ctx, s.st, tid, "recovery-code"); err != nil {
		return "", err
	}
	if _, err = s.st.Users().Get(ctx, tid, uid); err != nil {
		return "", err
	}
	receipt, err := s.reserveProof(ctx, tid, uid, "recovery-code")
	if err != nil {
		return "", err
	}
	ctx = logscrub.WithCredentials(ctx, code)
	outcome := "refund"
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		if s.proofCommit != nil {
			if _, e := tx.Users().GetForUpdate(ctx, tid, uid); e != nil {
				return e
			}
		}
		list, e := tx.MFA().ListAuthenticators(ctx, tid, uid)
		if e != nil {
			return e
		}
		g, e := tx.MFA().GetGuardian(ctx, tid)
		if e != nil {
			return e
		}
		if !g.Factors["recovery-code"] {
			return ErrNoFactor
		}
		u, e := tx.Users().Get(ctx, tid, uid)
		if e != nil {
			return e
		}
		var recovery *store.Authenticator
		usable := false
		for _, a := range list {
			if a.Type == "recovery-code" && a.Confirmed {
				recovery = &a
			}
			usable = usable || UsableMethod(u, a, g.Factors)
		}
		if !usable {
			return ErrNoFactor
		}
		hash := secrets.HashToken(NormalizeRecoveryCode(code))
		if recovery == nil || subtle.ConstantTimeCompare([]byte(recovery.CodeHash), []byte(hash)) != 1 {
			outcome = "failure"
			return ErrInvalidCode
		}
		next = NewRecoveryCode()
		ctx = s.operationContext(ctx, next)
		if e = tx.MFA().ReplaceRecoveryCode(ctx, tid, uid, hash, secrets.HashToken(next), s.now()); e != nil {
			return e
		}
		if s.proofCommit != nil {
			if e := s.proofCommit(tx); e != nil {
				return e
			}
		}
		outcome = "success"
		return nil
	})
	if errors.Is(err, store.ErrPrecondition) {
		err = ErrInvalidCode
		outcome = "failure"
	}
	if e := s.finishProof(ctx, tid, uid, "recovery-code", receipt, outcome); e != nil {
		return "", e
	}
	if err != nil {
		return "", err
	}
	return next, nil
}

// Unenroll removes a tenant/user-owned method and invalidates remembered MFA.
func (s *Service) Unenroll(ctx context.Context, tid, uid, id string) error {
	err := s.st.WithTx(ctx, func(tx store.Store) error {
		if e := tx.MFA().DeleteAuthenticator(ctx, tid, uid, id); e != nil {
			return e
		}
		return tx.MFA().BumpRememberEpoch(ctx, tid, uid)
	})
	if err == nil {
		s.emit(ctx, tid, uid, "gd_unenroll")
	}
	return err
}

// WithProofCommit returns a request-local view that commits additional store
// writes in the successful proof transaction. A callback error rolls back the
// proof, including recovery rotation and enrollment confirmation. Shared
// persisted throttles and delivery dependencies are retained. Callbacks must
// only use tx and must not send responses or sign tokens under its locks.
func (s *Service) WithProofCommit(commit func(store.Store) error) *Service {
	c := *s
	c.proofCommit = commit
	return &c
}

// BeginOTPChallenge chooses an owned TOTP method by proof when multiple methods
// exist. enroll selects pending methods; false selects confirmed methods.
// A wrong code still reaches exactly one ordinary Verify/ConfirmEnroll
// call, so the shared per-user throttle records one failure per submitted code.
func (s *Service) BeginOTPChallenge(ctx context.Context, tid, uid, code string, enroll bool) (*Challenge, error) {
	ctx = s.operationContext(ctx, code)
	list, err := s.st.MFA().ListAuthenticators(ctx, tid, uid)
	if err != nil {
		return nil, err
	}
	var chosen *store.Authenticator
	for _, a := range list {
		if a.Type != "totp" || a.Confirmed == enroll {
			continue
		}
		if chosen == nil {
			v := a
			chosen = &v
		}
		if s.sealer == nil {
			return nil, errSealing
		}
		plain, e := s.sealer.Unwrap(a.SealedSecret, totpAAD(tid, uid, a.ID))
		if e != nil {
			return nil, errSealing
		}
		ctx = s.operationContext(ctx, string(plain))
		if _, valid := VerifyTOTP(string(plain), code, s.now()); valid {
			v := a
			chosen = &v
			break
		}
	}
	if chosen == nil {
		return nil, ErrNoFactor
	}
	return s.BeginChallenge(ctx, tid, uid, chosen.ID, "")
}

// WithNewFactorEnrollment returns a request-local view for Actions enrollWith*.
// Both association and confirmation reject an already-confirmed method of the
// requested type under the same per-user lock used by every enrollment proof.
// Enrollment tickets with allow_multiple_enrollments must use the ordinary view.
func (s *Service) WithNewFactorEnrollment() *Service {
	local := *s
	local.newFactorOnly = true
	return &local
}

// WithPendingRecovery returns a request-local view whose TOTP enrollment
// carries the hash of a recovery code displayed at association (MFA API
// /mfa/associate). The recovery method is created only when that enrollment
// is confirmed and the user has none; an abandoned association creates none.
func (s *Service) WithPendingRecovery(hash string) *Service {
	local := *s
	local.pendingRecovery = hash
	return &local
}
