package protection

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Attempt struct {
	Tenant               *store.Tenant
	Connection           *store.Connection
	Identifier, IP, Flow string
}
type Decision struct {
	Allowed bool
	RetryAt time.Time
	Receipt store.ProtectionReceipt
	// SubjectID is set only when login identifier resolution found a tenant user.
	SubjectID string
}
type Notifier interface {
	Notify(context.Context, string, string, string) error
}
type Service struct {
	Wrapper         keys.Wrapper
	CaptchaVerifier CaptchaVerifier
	BreachChecker   BreachChecker
	Store           store.Store
	Now             func() time.Time
	Log             *slog.Logger
	Notifier        Notifier
	Go              func(func())
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Begin reads current policy, resolves persisted login aliases and reserves all
// blocking budgets atomically, before any password hashing or external call.
func (s *Service) Begin(ctx context.Context, a Attempt) (Decision, error) {
	if a.Tenant == nil || a.Connection == nil {
		return Decision{}, store.ErrInvalid
	}
	tenant, err := s.Store.Tenants().Get(ctx, a.Tenant.ID)
	if err != nil {
		return Decision{}, err
	}
	conn, err := s.Store.Connections().Get(ctx, tenant.ID, a.Connection.ID)
	if err != nil {
		return Decision{}, err
	}
	p := tenant.ProtectionSettings
	if !tenant.ProtectionSettingsInitialized {
		p = protectionrules.Defaults()
	}
	ip := CanonicalIP(a.IP)
	identifier := loginid.Normalize(a.Identifier)
	var subjectID string
	if a.Flow == "login" {
		u, e := s.Store.Users().FindByLogin(ctx, tenant.ID, conn.Name, identifier)
		if e == nil {
			subjectID = u.UserID
			if id := u.IdentityByLogin(conn.Name, identifier); id != nil {
				identifier = IdentityIdentifier(u, id)
			}
		} else if !errors.Is(e, store.ErrNotFound) {
			return Decision{}, e
		}
	}
	var limits []store.ProtectionLimit
	if a.Flow == "login" && conn.BruteForceProtection && p.BruteForce.Enabled && !Allowlisted(ip, p.BruteForce.Allowlist) {
		if slices.Contains(p.BruteForce.Shields, "block") {
			lockout := 30 * 24 * time.Hour
			if p.LegacyLockoutSeconds > 0 {
				lockout = time.Duration(p.LegacyLockoutSeconds) * time.Second
			}
			limits = append(limits, store.ProtectionLimit{Key: LoginKey(tenant.ID, conn.ID, identifier, ip, p.BruteForce.Mode), Algorithm: "brute-force", Capacity: p.BruteForce.MaxAttempts, Lockout: lockout})
		} else {
			s.Event(ctx, tenant.ID, "brute-force", "monitor", conn.ID)
		}
		s.adminNotifications(ctx, tenant.ID, "brute-force", p.BruteForce.Shields)
	}
	// Social flows (Plan 24) use the suspicious-IP budgets only: no email
	// lookup and no password brute-force reservation.
	social := a.Flow == "social-login" || a.Flow == "social-signup"
	if (a.Flow == "login" || a.Flow == "signup" || social) && p.SuspiciousIP.Enabled && !Allowlisted(ip, p.SuspiciousIP.Allowlist) {
		if slices.Contains(p.SuspiciousIP.Shields, "block") {
			kind, rate := store.ProtectionSuspiciousIPLogin, p.SuspiciousIP.Stage.PreLogin
			if a.Flow == "signup" || a.Flow == "social-signup" {
				kind, rate = store.ProtectionSuspiciousIPRegistration, p.SuspiciousIP.Stage.PreUserRegistration
			}
			limit := store.ProtectionLimit{Key: store.ProtectionKey{TenantID: tenant.ID, Kind: kind, IP: ip}, Algorithm: "token-bucket", Capacity: rate.MaxAttempts, Refill: time.Duration(rate.Rate) * time.Millisecond}
			if a.Flow == "login" && p.LegacyIPMaxAttempts > 0 && p.LegacyLockoutSeconds > 0 {
				limit.Algorithm = "fixed-window"
				limit.Capacity = p.LegacyIPMaxAttempts
				limit.Window = time.Duration(p.LegacyLockoutSeconds) * time.Second
			}
			limits = append(limits, limit)
		} else {
			s.Event(ctx, tenant.ID, "suspicious-ip", "monitor", conn.ID)
		}
		s.adminNotifications(ctx, tenant.ID, "suspicious-ip", p.SuspiciousIP.Shields)
	}
	if a.Flow == "reset-send" {
		limits = append(limits, store.ProtectionLimit{Key: store.ProtectionKey{TenantID: tenant.ID, Kind: store.ProtectionResetMail, ConnectionID: conn.ID, Identifier: identifier}, Algorithm: "fixed-window", Capacity: 3, Window: time.Hour})
	} else if a.Flow != "login" && a.Flow != "signup" && !social {
		return Decision{}, store.ErrInvalid
	}
	now := s.now()
	// Bounded maintenance also settles abandoned receipts. Failure is fail-closed.
	if _, err := s.Store.Protection().Sweep(ctx, now, 32); err != nil {
		return Decision{}, err
	}
	d, err := s.Store.Protection().Reserve(ctx, limits, now)
	if err == nil && !d.Allowed {
		s.Event(ctx, tenant.ID, a.Flow, "denied", conn.ID)
		if subjectID != "" && a.Flow == "login" && slices.Contains(p.BruteForce.Shields, "block") && slices.Contains(p.BruteForce.Shields, "user_notification") {
			filter := store.ProtectionFilter{Kind: store.ProtectionBruteForce, ConnectionID: conn.ID, Identifier: identifier}
			if p.BruteForce.Mode != "count_per_identifier" {
				filter.IP = ip
			}
			blocks, blockErr := s.Store.Protection().Blocks(ctx, tenant.ID, filter, now)
			if blockErr != nil {
				s.Event(ctx, tenant.ID, "brute-force", "notification-check-failed", conn.ID)
			} else if len(blocks) > 0 {
				s.notify(ctx, tenant.ID, subjectID, "blocked_account")
			}
		}
	}
	return Decision{Allowed: d.Allowed, RetryAt: d.RetryAt, Receipt: d.Receipt, SubjectID: subjectID}, err
}

// Finish deliberately survives request cancellation. Credential outcomes retain
// their D-0023 classification; an interrupted infrastructure call is refunded,
// while a process crash is conservatively failed by the store after 60 seconds.
func (s *Service) Finish(ctx context.Context, r store.ProtectionReceipt, outcome string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.Store.Protection().Complete(ctx, r, outcome, s.now())
}
func Allowlisted(ip string, entries []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, entry := range entries {
		if prefix, e := netip.ParsePrefix(entry); e == nil && prefix.Contains(addr) {
			return true
		}
		if other, e := netip.ParseAddr(entry); e == nil && other.Unmap() == addr {
			return true
		}
	}
	return false
}

// ClearIdentity runs on the caller's transaction so password and automatic
// block removal commit together. Only actual aliases of this identity are used.
func ClearIdentity(ctx context.Context, st store.Store, conn *store.Connection, u *store.User) error {
	for i := range u.Identities {
		id := &u.Identities[i]
		if id.Connection != conn.Name || id.Provider != store.StrategyDatabase {
			continue
		}
		email, username := u.IdentityLogin(id)
		for _, alias := range []string{IdentityIdentifier(u, id), email, username} {
			if alias == "" {
				continue
			}
			if err := st.Protection().Clear(ctx, conn.TenantID, store.ProtectionFilter{Kind: store.ProtectionBruteForce, ConnectionID: conn.ID, Identifier: loginid.Normalize(alias)}); err != nil {
				return err
			}
		}
	}
	return nil
}

// IPBlocked reports whether ip is currently blocked by the suspicious-IP
// shield, without reserving any attempt (the social callback rechecks blocks
// without charging the pre-login budget twice).
func (s *Service) IPBlocked(ctx context.Context, tenantID, ip string) (bool, error) {
	ip = CanonicalIP(ip)
	if ip == "" {
		return false, nil
	}
	for _, kind := range []string{store.ProtectionSuspiciousIPLogin, store.ProtectionSuspiciousIPRegistration} {
		blocks, err := s.Store.Protection().Blocks(ctx, tenantID, store.ProtectionFilter{Kind: kind, IP: ip}, s.now())
		if err != nil {
			return false, err
		}
		if len(blocks) > 0 {
			return true, nil
		}
	}
	return false, nil
}
