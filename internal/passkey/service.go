// Package passkey binds first-factor passkey ceremonies to their request and
// delegates cryptographic checks to webauthn. HTTP callers still apply signup
// Actions, MFA, organizations and attack protection before creating a session.
package passkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Service has no process-local ceremony state. Now is injectable for expiry.
type Service struct {
	Store store.Store
	RPID  rpid.Policy
	Now   func() time.Time
}

// NewService builds the shared hosted/native ceremony service.
func NewService(st store.Store, policy rpid.Policy, now func() time.Time) *Service {
	policy.Store = st
	return &Service{Store: st, RPID: policy, Now: now}
}
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Purpose separates registration, first-factor login and WebAuthn MFA proofs.
type Purpose string

const (
	PasskeyRegister Purpose = "passkey-register"
	// PasskeyProgressiveRegister and PasskeyLocalRegister bind post-login purposes.
	PasskeyProgressiveRegister Purpose = "passkey-progressive-register"
	PasskeyLocalRegister       Purpose = "passkey-local-register"
	PasskeyLogin               Purpose = "passkey-login"
	WebAuthnRegister           Purpose = "webauthn-register"
	WebAuthnAssert             Purpose = "webauthn-assert"
)

// Binding contains only request values known before a challenge is taken.
// Origins are exact serialized strings; their order is part of this binding.
type Binding struct {
	Purpose                       Purpose
	RPID                          string
	Origins                       []string
	TxnID, CookieHash             string
	ClientID, Realm, Organization string
	UserID                        string
}

// ErrCeremony deliberately exposes no account, credential or submitted value.
// webauthn.Reason extracts the bounded failure reason through the wrapper.
var ErrCeremony = errors.New("passkey: ceremony failed")

func ceremonyError(code string) error {
	return fmt.Errorf("%w: %w", ErrCeremony, &webauthn.Error{Code: code})
}
func verificationError(err error) error {
	code := webauthn.Reason(err)
	if code == "" {
		code = "parse"
	}
	return ceremonyError(code)
}

// LoginResult identifies the credential owner, independent of a typed identifier.
// Assertion and Method contain ceremony data; never serialize them into logs,
// Actions, events or a console response.
type LoginResult struct {
	User      *store.User
	Method    *store.Authenticator
	Assertion *webauthn.Assertion
}

type publicData struct {
	BackupEligible bool     `json:"backup_eligible"`
	BackedUp       bool     `json:"backed_up"`
	AAGUID         string   `json:"aaguid"`
	UserAgent      string   `json:"user_agent"`
	Transports     []string `json:"transports"`
	IdentityUserID string   `json:"identity_user_id"`
	UserHandle     string   `json:"user_handle"`
	Attachment     string   `json:"attachment"`
}

func readPublic(a *store.Authenticator) (publicData, error) {
	var p publicData
	if err := json.Unmarshal(a.PublicData, &p); err != nil {
		return p, ceremonyError("user_handle")
	}
	h, err := base64.RawURLEncoding.DecodeString(p.UserHandle)
	if err != nil || len(h) != webauthnrules.Limits.UserHandleBytes {
		return p, ceremonyError("user_handle")
	}
	return p, nil
}

// Effective combines the stored connection prerequisites, request RP ID and
// negotiated storage capability. Invalid stored RP IDs fail closed in rpid.
func (s *Service) Effective(ctx context.Context, tid string, res tenant.Resolved, conn *store.Connection) (connrules.PasskeyPolicy, rpid.Result, bool, error) {
	if res.Tenant == nil || res.Tenant.ID != tid || conn == nil || conn.TenantID != tid {
		return connrules.PasskeyPolicy{}, rpid.Result{}, false, ErrCeremony
	}
	// A tenant whose hosted login settings were never written has the default
	// prompts (no identifier first): passkeys are stored-only, not an error.
	var prompts map[string]any
	cfg, err := s.Store.HostedLogins().Get(ctx, tid)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return connrules.PasskeyPolicy{}, rpid.Result{}, false, err
	}
	if cfg != nil {
		prompts = cfg.Prompts
	}
	p, _ := connrules.Passkeys(conn, prompts)
	policy := s.RPID
	policy.Store = s.Store
	rp, err := policy.For(ctx, res)
	if err != nil {
		return p, rp, false, err
	}
	available, err := s.supported(ctx)
	return p, rp, p.Effective && rp.Valid && available, err
}
func (s *Service) supported(ctx context.Context) (bool, error) {
	if cap, ok := s.Store.(store.WebAuthnSupporter); ok {
		if err := cap.CheckWebAuthnSupport(ctx); err != nil {
			if errors.Is(err, store.ErrWebAuthnUnavailable) {
				return false, nil
			}
			return false, err
		}
		return cap.WebAuthnSupported(), nil
	}
	switch s.Store.WebAuthn().(type) {
	case store.UnimplementedWebAuthn, *store.UnimplementedWebAuthn:
		return false, nil
	}
	return true, nil
}

// Login verifies a discoverable assertion and atomically advances the counter.
// Call Take first: every verification failure must spend its challenge.
func (s *Service) Login(ctx context.Context, tid string, raw, ch []byte, b Binding) (*LoginResult, error) {
	mask(ctx, raw, ch)
	if b.Purpose != PasskeyLogin || len(ch) != webauthnrules.Limits.ChallengeBytes {
		return nil, ceremonyError("challenge")
	}
	c, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		return nil, verificationError(err)
	}
	maskCredential(ctx, c)
	a, err := s.Store.WebAuthn().GetAuthenticatorByCredentialID(ctx, tid, c.RawID)
	if err != nil || a.Type != "passkey" || !a.Confirmed {
		return nil, ceremonyError("key")
	}
	if a.RPID != b.RPID {
		return nil, ceremonyError("rp_id")
	}
	p, err := readPublic(a)
	if err != nil {
		return nil, err
	}
	handle, _ := base64.RawURLEncoding.DecodeString(p.UserHandle)
	logs.AddCredentials(ctx, p.UserHandle)
	params := webauthn.ParamsFor(webauthn.CeremonyPasskeyLogin, "")
	proof, err := webauthn.VerifyAssertion(c, webauthn.Expect{Challenge: ch, RPID: b.RPID, Origins: b.Origins, RequireUV: params.EnforceUV, RequireUserHandle: true}, webauthn.Stored{PublicKeyCOSE: a.PublicKey, SignCount: a.SignCount, BE: p.BackupEligible, UserHandle: handle})
	if err != nil {
		return nil, verificationError(err)
	}
	u, err := s.Store.Users().Get(ctx, tid, a.UserID)
	if err != nil {
		return nil, ceremonyError("key")
	}
	if _, err = s.connection(ctx, tid, u, p.IdentityUserID, b); err != nil {
		return nil, err
	}
	if u.Blocked {
		return nil, identity.ErrUserBlocked
	}
	if err = s.Store.WebAuthn().AcceptAssertion(ctx, tid, u.UserID, a.ID, proof.SignCount, proof.BS, s.now()); err != nil {
		if errors.Is(err, store.ErrPrecondition) {
			return nil, ceremonyError("sign_count")
		}
		return nil, ceremonyError("key")
	}
	a.SignCount, a.LastAuthAt = proof.SignCount, s.now()
	p.BackedUp = proof.BS
	a.PublicData, _ = json.Marshal(p)
	return &LoginResult{User: u, Method: a, Assertion: proof}, nil
}

// connection checks the identity the passkey was enrolled for, including linked
// identities. Client and realm restrictions are applied when supplied by callers.
func (s *Service) connection(ctx context.Context, tid string, u *store.User, identityUserID string, b Binding) (*store.Connection, error) {
	for _, id := range u.Identities {
		if id.UserID != identityUserID || id.Provider != store.StrategyDatabase {
			continue
		}
		conn, err := s.Store.Connections().GetByName(ctx, tid, id.Connection)
		if err != nil {
			continue
		}
		if b.Realm != "" && b.Realm != conn.Name || b.ClientID != "" && !slices.Contains(conn.EnabledClients, b.ClientID) {
			continue
		}
		cfg, err := s.Store.HostedLogins().Get(ctx, tid)
		if err != nil {
			return nil, ceremonyError("key")
		}
		p, _ := connrules.Passkeys(conn, cfg.Prompts)
		available, err := s.supported(ctx)
		if err != nil || !available || !p.Effective {
			return nil, ceremonyError("key")
		}
		return conn, nil
	}
	return nil, ceremonyError("key")
}

// mask shares only secret masks with the enclosing flow's outcome recorder.
func mask(ctx context.Context, values ...[]byte) {
	for _, v := range values {
		logs.AddCredentials(ctx, string(v), base64.RawURLEncoding.EncodeToString(v), base64.StdEncoding.EncodeToString(v))
	}
}

func maskCredential(ctx context.Context, c *webauthn.Credential) {
	mask(ctx, c.ID, c.RawID, c.ClientDataJSON, c.AttestationObject, c.AuthenticatorData, c.Signature, c.UserHandle)
}
