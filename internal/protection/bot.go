package protection

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// RequireChallenge reads current policy on every request. Unrelated grants and
// existing-session authorization never enter the interactive classifier.
func (s *Service) RequireChallenge(ctx context.Context, a Attempt) (bool, error) {
	if a.Tenant == nil {
		return false, store.ErrInvalid
	}
	if a.Flow != "login" && a.Flow != "signup" && a.Flow != "reset-send" && a.Flow != "reset" {
		return false, nil
	}
	t, err := s.Store.Tenants().Get(ctx, a.Tenant.ID)
	if err != nil {
		return false, err
	}
	p := t.ProtectionSettings.Bot
	if Allowlisted(CanonicalIP(a.IP), p.Allowlist) {
		return false, nil
	}
	mode := p.ChallengePasswordPolicy
	if a.Flow == "reset-send" || a.Flow == "reset" {
		mode = p.ChallengePasswordResetPolicy
	}
	required := mode == "always"
	if mode == "when_risky" {
		n, err := s.Store.Protection().RiskCount(ctx, t.ID, CanonicalIP(a.IP), s.now())
		if err != nil {
			return false, err
		}
		threshold := 5
		switch p.BotDetectionLevel {
		case "low":
			threshold = 10
		case "high":
			threshold = 1
		}
		required = n >= threshold
	}
	if required && p.MonitoringModeEnabled {
		s.Event(ctx, t.ID, "bot", "monitor", "")
		return false, nil
	}
	return required, nil
}

// RecordFailure accepts a server-generated request ID, never a form value.
// The same ID can be reported by several checks but counts only once.
func (s *Service) RecordFailure(ctx context.Context, a Attempt, id string) error {
	if a.Tenant == nil || id == "" {
		return store.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	now := s.now()
	if _, err := s.Store.Protection().Sweep(ctx, now, 32); err != nil {
		return err
	}
	return s.Store.Protection().RecordRisk(ctx, a.Tenant.ID, id, CanonicalIP(a.IP), now)
}

// QualifyingFailure excludes infrastructure failures and administrative blocks.
func QualifyingFailure(flow string, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrPasswordLeaked) || errors.Is(err, ErrCaptchaInvalid) {
		return true
	}
	if flow == "login" {
		return CredentialOutcome(err) == "failure"
	}
	var pe *identity.PolicyError
	return errors.Is(err, identity.ErrUserExists) || (errors.As(err, &pe) && strings.HasPrefix(pe.Key, "zeroauthy.signup.password"))
}
