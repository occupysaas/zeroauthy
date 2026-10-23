package store

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// ProtectionSettings contains tenant-owned policy. Fields named Legacy are
// internal compatibility state and must never be exposed through public APIs.
// CAPTCHA credentials contain versioned encrypted envelopes only. Callers must
// use keys.PatchCAPTCHA before persistence and keys.OpenCAPTCHA for verification.
type ProtectionSettings struct {
	BruteForce           BruteForcePolicy
	SuspiciousIP         SuspiciousIPPolicy
	BreachedPassword     BreachedPasswordPolicy
	Bot                  BotPolicy
	CAPTCHA              CAPTCHAPolicy
	LegacyLockoutSeconds int
	LegacyIPMaxAttempts  int
}
type BruteForcePolicy struct {
	Enabled            bool     `json:"enabled"`
	Shields            []string `json:"shields"`
	Allowlist          []string `json:"allowlist"`
	Mode               string   `json:"mode"`
	MaxAttempts        int      `json:"max_attempts"`
	FormSubmissionMode string   `json:"form_submission_mode"`
}
type SuspiciousIPPolicy struct {
	Enabled   bool               `json:"enabled"`
	Shields   []string           `json:"shields"`
	Allowlist []string           `json:"allowlist"`
	Stage     SuspiciousIPStages `json:"stage"`
}
type SuspiciousIPStages struct {
	PreLogin            ProtectionRate `json:"pre-login"`
	PreUserRegistration ProtectionRate `json:"pre-user-registration"`
	// PreCustomTokenExchange is stored only until Plan 35.
	PreCustomTokenExchange ProtectionRate `json:"pre-custom-token-exchange"`
}

// ProtectionRate.Rate is milliseconds per replenished attempt, not attempts/day.
type ProtectionRate struct {
	MaxAttempts int `json:"max_attempts"`
	Rate        int `json:"rate"`
}
type BreachedPasswordPolicy struct {
	Enabled                    bool                   `json:"enabled"`
	Shields                    []string               `json:"shields"`
	AdminNotificationFrequency []string               `json:"admin_notification_frequency"`
	Method                     string                 `json:"method"`
	Stage                      BreachedPasswordStages `json:"stage"`
}
type BreachedPasswordStages struct {
	PreUserRegistration ProtectionShields `json:"pre-user-registration"`
	PreChangePassword   ProtectionShields `json:"pre-change-password"`
}
type ProtectionShields struct {
	Shields []string `json:"shields"`
}
type BotPolicy struct {
	BotDetectionLevel       string `json:"bot_detection_level"`
	ChallengePasswordPolicy string `json:"challenge_password_policy"`
	// ChallengePasswordlessPolicy is stored only until Plan 34.
	ChallengePasswordlessPolicy  string   `json:"challenge_passwordless_policy"`
	ChallengePasswordResetPolicy string   `json:"challenge_password_reset_policy"`
	Allowlist                    []string `json:"allowlist"`
	MonitoringModeEnabled        bool     `json:"monitoring_mode_enabled"`
}
type CAPTCHAPolicy struct {
	ActiveProviderID    string                      `json:"active_provider_id"`
	Arkose              ArkoseProvider              `json:"arkose"`         // stored; verification unavailable
	AuthChallenge       AuthChallengeProvider       `json:"auth_challenge"` // stored; verification unavailable
	HCaptcha            CAPTCHAProvider             `json:"hcaptcha"`
	FriendlyCaptcha     CAPTCHAProvider             `json:"friendly_captcha"`
	RecaptchaV2         CAPTCHAProvider             `json:"recaptcha_v2"`
	RecaptchaEnterprise RecaptchaEnterpriseProvider `json:"recaptcha_enterprise"`
	SimpleCaptcha       map[string]any              `json:"simple_captcha"` // stored; verification unavailable
}
type CAPTCHAProvider struct {
	SiteKey string `json:"site_key"`
	Secret  string `json:"secret"`
}
type ArkoseProvider struct {
	CAPTCHAProvider
	ClientSubdomain string `json:"client_subdomain"`
	VerifySubdomain string `json:"verify_subdomain"`
	FailOpen        bool   `json:"fail_open"`
}
type AuthChallengeProvider struct {
	FailOpen bool `json:"fail_open"`
}
type RecaptchaEnterpriseProvider struct {
	SiteKey   string `json:"site_key"`
	APIKey    string `json:"api_key"`
	ProjectID string `json:"project_id"`
}

// Bucket kinds shared by runtime consumers, policy invalidation and block queries.
const (
	ProtectionBruteForce               = "brute-force"
	ProtectionSuspiciousIPLogin        = "suspicious-ip-login"
	ProtectionSuspiciousIPRegistration = "suspicious-ip-registration"
	ProtectionResetMail                = "reset-mail"
)

// ProtectionKey is tenant-scoped. ConnectionID is stable, never a mutable name.
type ProtectionKey struct{ TenantID, Kind, ConnectionID, Identifier, IP string }
type ProtectionLimit struct {
	Key                     ProtectionKey
	Algorithm               string // fixed-window, token-bucket, brute-force
	Capacity                int
	Window, Refill, Lockout time.Duration
}
type ProtectionReceipt struct{ TenantID, ID string }
type ProtectionAdmission struct {
	Allowed bool
	Receipt ProtectionReceipt
	RetryAt time.Time
}
type ProtectionBlock struct {
	Key          ProtectionKey
	BlockedUntil time.Time
}

// Empty fields are wildcards; public callers must construct narrowly scoped filters.
type ProtectionFilter struct{ Kind, ConnectionID, Identifier, IP string }

// Protection stores atomic admission and risk/replay state. Implementations must
// never substitute process-local counters for unavailable durable storage.
type Protection interface {
	// Reserve accepts exactly one tenant and atomically reserves all budgets or
	// none. Empty limits allow admission with an empty no-op receipt. Invalid
	// algorithms, capacities or durations return ErrInvalid. Receipt membership
	// and generations are recorded internally, never trusted from callers.
	Reserve(context.Context, []ProtectionLimit, time.Time) (ProtectionAdmission, error)
	// Complete is idempotent and accepts failure, success or refund only.
	// Invalid outcomes return ErrInvalid. An empty receipt is a no-op.
	// Stale completions cannot recreate cleared/expired generations.
	Complete(context.Context, ProtectionReceipt, string, time.Time) error
	Blocks(context.Context, string, ProtectionFilter, time.Time) ([]ProtectionBlock, error)
	Clear(context.Context, string, ProtectionFilter) error
	// UseProof atomically consumes a globally scoped opaque hash until expiry.
	// This namespace is deliberately not exposed through tenant APIs.
	UseProof(context.Context, string, time.Time, time.Time) (bool, error)
	// Risk events are idempotent by tenant/attempt ID and expire after 15 minutes.
	RecordRisk(context.Context, string, string, string, time.Time) error
	// RiskCount counts exact timestamps in the rolling interval, not fixed buckets.
	RiskCount(context.Context, string, string, time.Time) (int, error)
	Sweep(context.Context, time.Time, int) (int, error)
}

// ErrProtectionUnimplemented is a temporary fail-closed adapter error until
// drivers implement Protection in Plan 19 Task 4. It is never an allow fallback.
var ErrProtectionUnimplemented = errors.New("store: protection repository unimplemented")

// UnimplementedProtection keeps driver builds usable during the interface rollout.
type UnimplementedProtection struct{}

func (UnimplementedProtection) Reserve(context.Context, []ProtectionLimit, time.Time) (ProtectionAdmission, error) {
	return ProtectionAdmission{}, ErrProtectionUnimplemented
}
func (UnimplementedProtection) Complete(context.Context, ProtectionReceipt, string, time.Time) error {
	return ErrProtectionUnimplemented
}
func (UnimplementedProtection) Blocks(context.Context, string, ProtectionFilter, time.Time) ([]ProtectionBlock, error) {
	return nil, ErrProtectionUnimplemented
}
func (UnimplementedProtection) Clear(context.Context, string, ProtectionFilter) error {
	return ErrProtectionUnimplemented
}
func (UnimplementedProtection) UseProof(context.Context, string, time.Time, time.Time) (bool, error) {
	return false, ErrProtectionUnimplemented
}
func (UnimplementedProtection) RecordRisk(context.Context, string, string, string, time.Time) error {
	return ErrProtectionUnimplemented
}
func (UnimplementedProtection) RiskCount(context.Context, string, string, time.Time) (int, error) {
	return 0, ErrProtectionUnimplemented
}
func (UnimplementedProtection) Sweep(context.Context, time.Time, int) (int, error) {
	return 0, ErrProtectionUnimplemented
}

// ValidateProtectionSecrets prevents accidental plaintext writes across all
// drivers, including remote plugins. Authentication is performed by keys on open.
func ValidateProtectionSecrets(c CAPTCHAPolicy) error {
	for _, value := range []string{c.Arkose.Secret, c.HCaptcha.Secret, c.FriendlyCaptcha.Secret, c.RecaptchaV2.Secret, c.RecaptchaEnterprise.APIKey} {
		if value == "" {
			continue
		}
		encoded, ok := strings.CutPrefix(value, "zcap1.")
		blob, err := base64.RawURLEncoding.DecodeString(encoded)
		if !ok || err != nil || len(blob) < 32 {
			return ErrInvalid
		}
	}
	return nil
}
