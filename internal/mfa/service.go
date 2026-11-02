package mfa

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
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
)

// Enrollment contains one-time TOTP display values. Callers must retain only
// AuthenticatorID and ChallengeID in sealed transaction state, never Secret/URI.
type Enrollment struct{ Factor, AuthenticatorID, Secret, URI, ChallengeID string }
type Challenge struct{ ID, Factor, AuthenticatorID string }
type Proof struct{ Code string }
type Confirmed struct{ AuthenticatorID, RecoveryCode string }
type EmailSender interface {
	Send(context.Context, email.Event) error
}

// Service is shared by hosted login and OAuth grants. No proof/replay state is
// process-local. Recorder may be set explicitly; otherwise use the request sink.
type Service struct {
	Recorder logs.Recorder
	st       store.Store
	sealer   keys.Wrapper
	mail     EmailSender
	th       Throttle
	now      func() time.Time
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
	if factor == "email" {
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
func enabled(ctx context.Context, st store.Store, tid, typ string) error {
	g, err := st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return err
	}
	if !g.Factors[factorName(typ)] {
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
	defer func() {
		if err != nil {
			s.emit(ctx, tid, uid, "gd_start_enroll_failed")
		}
	}()
	typ := factorType(factor)
	if typ == "" {
		return nil, ErrNoFactor
	}
	if err = enabled(ctx, s.st, tid, typ); err != nil {
		return nil, err
	}
	user, err := s.st.Users().Get(ctx, tid, uid)
	if err != nil {
		return nil, err
	}
	a := &store.Authenticator{TenantID: tid, UserID: uid, ID: NewMethodID(typ), Type: typ, LastStep: -1, CreatedAt: s.now()}
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
		e.URI = TOTPURI(issuer, user.Email, e.Secret)
		ctx = s.operationContext(ctx, e.URI)
	case "email":
		if !user.EmailVerified || user.Email == "" {
			return nil, ErrNoFactor
		}
		a.Email = user.Email
	}
	if err = s.st.MFA().CreateAuthenticator(ctx, a); err != nil {
		return nil, err
	}
	c, err := s.beginChallenge(ctx, tid, uid, a)
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
	c, err := s.beginChallenge(ctx, tid, uid, a)
	if err == nil {
		s.emit(ctx, tid, uid, "gd_start_auth")
	}
	return c, err
}
func (s *Service) beginChallenge(ctx context.Context, tid, uid string, a *store.Authenticator) (*Challenge, error) {
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
	if err := s.st.MFA().CreateChallenge(ctx, saved); err != nil {
		return nil, err
	}
	if a.Type == "email" {
		if err := s.sendEmail(ctx, tid, uid, code); err != nil {
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
		// Repeat state checks inside the proof-consumption transaction.
		current, e := tx.MFA().GetAuthenticator(ctx, tid, uid, a.ID)
		if e != nil {
			return e
		}
		if current.Type != a.Type || current.Confirmed == enroll {
			proofErr = ErrInvalidCode
			return nil
		}
		if enroll && firstOnly {
			list, e := tx.MFA().ListAuthenticators(ctx, tid, uid)
			if e != nil {
				return e
			}
			for _, other := range list {
				if other.Confirmed && other.Type != "recovery-code" {
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
		}
		if !valid {
			outcome = "failure"
			proofErr = ErrInvalidCode
			if current.Type == "email" {
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
			if !hasRecovery {
				recovery := NewRecoveryCode()
				ctx = s.operationContext(ctx, recovery)
				if e = tx.MFA().ReplaceRecoveryCode(ctx, tid, uid, "", secrets.HashToken(recovery), s.now()); e != nil {
					return e
				}
				result.RecoveryCode = recovery
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
		var recovery *store.Authenticator
		usable := false
		for _, a := range list {
			if a.Type == "recovery-code" && a.Confirmed {
				recovery = &a
			}
			if a.Confirmed && factorType(a.Type) != "" && g.Factors[factorName(a.Type)] {
				if a.Type != "email" {
					usable = true
				} else if e = verifiedEmail(ctx, tx, tid, uid, &a); e == nil {
					usable = true
				} else if !errors.Is(e, ErrNoFactor) {
					return e
				}
			}
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
