package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// EnrollKind selects the passkey registration parameter-table row.
type EnrollKind int

const (
	Signup EnrollKind = iota
	Progressive
	Local
)

// UserDisplay supplies resolved connection-specific identifiers; empty fields
// use the user's email, phone, username and profile name in that order.
type UserDisplay struct{ Name, DisplayName string }

func limitError() error {
	return &identity.PolicyError{Reason: "passkey enrollment limit reached", Key: "passkey-enrollment-max-allowed-reached", Err: store.ErrPrecondition}
}

// CreationOptions uses the handle from Issue, so registration completion can
// persist exactly the user.id offered to the authenticator on any replica.
func (s *Service) CreationOptions(ctx context.Context, tid string, u *store.User, display UserDisplay, rpID string, kind EnrollKind, ch, userHandle []byte, timeout time.Duration) (webauthn.CreationOptions, error) {
	if u == nil || u.TenantID != tid || u.UserID == "" || rpID == "" || len(ch) != webauthnrules.Limits.ChallengeBytes || len(userHandle) != webauthnrules.Limits.UserHandleBytes {
		return webauthn.CreationOptions{}, ErrCeremony
	}
	ceremony := webauthn.CeremonyPasskeyRegister
	switch kind {
	case Signup, Progressive:
	case Local:
		ceremony = webauthn.CeremonyLocalEnroll
	default:
		return webauthn.CreationOptions{}, ErrCeremony
	}
	params := webauthn.ParamsFor(ceremony, "")
	as, err := s.Store.MFA().ListAuthenticators(ctx, tid, u.UserID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return webauthn.CreationOptions{}, err
	}
	o := webauthn.CreationOptions{Challenge: slices.Clone(ch), RPID: rpID, RPName: rpID, UserID: slices.Clone(userHandle), Algs: slices.Clone(webauthn.DefaultAlgs), ResidentKey: params.ResidentKey, UserVerification: params.UserVerification, Attachment: params.Attachment, Timeout: timeout}
	count := 0
	for _, a := range as {
		if a.Type != "passkey" {
			continue
		}
		count++
		if a.RPID == rpID {
			p, err := readPublic(&a)
			if err != nil {
				return webauthn.CreationOptions{}, err
			}
			o.Exclude = append(o.Exclude, webauthn.Descriptor{ID: slices.Clone(a.CredentialID), Transports: p.Transports})
		}
	}
	if count >= webauthnrules.Limits.MaxPasskeys {
		return webauthn.CreationOptions{}, limitError()
	}
	o.UserName = display.Name
	if o.UserName == "" {
		values := []struct{ kind, value string }{{"email", u.Email}, {"phone_number", u.PhoneNumber}, {"username", u.Username}}
		var conn *store.Connection
		if id := u.OwnIdentity(); id != nil {
			conn, err = s.Store.Connections().GetByName(ctx, tid, id.Connection)
			if err != nil {
				return webauthn.CreationOptions{}, err
			}
		}
		for _, v := range values {
			// Existing connections without flexible attributes retain the
			// identifier fallback; explicit inactive identifiers are skipped.
			if conn != nil && conn.Extra["attributes"] != nil && !store.IdentifierActive(conn, v.kind) {
				continue
			}
			if v.value != "" {
				o.UserName = v.value
				break
			}
		}
	}
	o.DisplayName = display.DisplayName
	if o.DisplayName == "" {
		o.DisplayName = u.Name
	}
	if o.DisplayName == "" {
		o.DisplayName = o.UserName
	}
	mask(ctx, ch, userHandle)
	return o, nil
}

// RequestOptions is discoverable: allowCredentials remains empty.
func (s *Service) RequestOptions(rpID string, ch []byte, timeout time.Duration) webauthn.RequestOptions {
	p := webauthn.ParamsFor(webauthn.CeremonyPasskeyLogin, "")
	return webauthn.RequestOptions{RPID: rpID, Challenge: slices.Clone(ch), UserVerification: p.UserVerification, Timeout: timeout}
}

func (s *Service) registration(ctx context.Context, tid string, u *store.User, identityUserID string, raw []byte, taken *Taken, userAgent string) (*store.Authenticator, error) {
	if u == nil || u.TenantID != tid || taken == nil || taken.Binding.Purpose != PasskeyRegister || taken.Binding.UserID != u.UserID || len(taken.UserHandle) != webauthnrules.Limits.UserHandleBytes || len(taken.Challenge) != webauthnrules.Limits.ChallengeBytes {
		return nil, ceremonyError("challenge")
	}
	if u.Blocked {
		return nil, identity.ErrUserBlocked
	}
	if _, err := s.connection(ctx, tid, u, identityUserID, taken.Binding); err != nil {
		return nil, err
	}
	mask(ctx, raw, taken.Challenge, taken.UserHandle)
	c, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		return nil, verificationError(err)
	}
	maskCredential(ctx, c)
	params := webauthn.ParamsFor(webauthn.CeremonyPasskeyRegister, "")
	r, err := webauthn.VerifyRegistration(c, webauthn.Expect{RPID: taken.Binding.RPID, Origins: taken.Binding.Origins, Challenge: taken.Challenge, RequireUV: params.EnforceUV})
	if err != nil {
		return nil, verificationError(err)
	}
	p := publicData{BackupEligible: r.BE, BackedUp: r.BS, AAGUID: formatAAGUID(r.AAGUID), UserAgent: userAgent, Transports: r.Transports, IdentityUserID: identityUserID, UserHandle: base64.RawURLEncoding.EncodeToString(taken.UserHandle), Attachment: r.Attachment}
	pub, err := json.Marshal(p)
	if err != nil {
		return nil, ErrCeremony
	}
	return &store.Authenticator{TenantID: tid, UserID: u.UserID, ID: "passkey|dev_" + secrets.RandomString(20), Type: "passkey", Confirmed: true, CredentialID: r.CredentialID, PublicKey: r.PublicKeyCOSE, RPID: taken.Binding.RPID, SignCount: r.SignCount, PublicData: pub, CreatedAt: s.now()}, nil
}
func formatAAGUID(a [16]byte) string {
	h := hex.EncodeToString(a[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Enroll leaves passwords and all other methods untouched. The insertion takes
// the store's per-user lock before checking handle consistency, so competing
// first enrollments cannot commit different handles. Linked credentials keep
// their original handles; new enrollment reuses the oldest existing handle.
func (s *Service) Enroll(ctx context.Context, tid string, u *store.User, identityUserID string, raw []byte, taken *Taken, userAgent string) (*store.Authenticator, error) {
	a, err := s.registration(ctx, tid, u, identityUserID, raw, taken, userAgent)
	if err != nil {
		return nil, err
	}
	err = s.Store.WithTx(ctx, func(tx store.Store) error {
		if err := tx.WebAuthn().CreatePasskey(ctx, a, webauthnrules.Limits.MaxPasskeys); err != nil {
			if errors.Is(err, store.ErrPrecondition) {
				return limitError()
			}
			return err
		}
		current, err := tx.Users().Get(ctx, tid, u.UserID)
		if err != nil {
			return err
		}
		if current.Blocked {
			return identity.ErrUserBlocked
		}
		bound := *s
		bound.Store = tx
		if _, err = bound.connection(ctx, tid, current, identityUserID, taken.Binding); err != nil {
			return err
		}
		// Read after CreatePasskey acquires the user's write lock. Returning an
		// error rolls the insertion back; never silently replace the browser's ID.
		as, err := tx.MFA().ListAuthenticators(ctx, tid, u.UserID)
		if err != nil {
			return err
		}

		handle, err := existingHandle(as, a.ID)
		if err != nil {
			return err
		}
		if handle != nil && !bytes.Equal(handle, taken.UserHandle) {
			return ceremonyError("user_handle")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Signup is the atomic persistence step after the caller's signup policy and
// pre-user-registration Action. The caller owns post-registration outcomes.
func (s *Service) Signup(ctx context.Context, tid string, draft *store.User, raw []byte, taken *Taken, userAgent string) (*store.User, *store.Authenticator, error) {
	if draft == nil {
		return nil, nil, ErrCeremony
	}
	u := *draft
	u.Identities = slices.Clone(draft.Identities)
	id := u.OwnIdentity()
	if id == nil || id.Provider != store.StrategyDatabase {
		return nil, nil, ErrCeremony
	}
	for n := range u.Identities {
		u.Identities[n].PasswordHash = ""
		u.Identities[n].ImportedHash = ""
	}
	a, err := s.registration(ctx, tid, &u, id.UserID, raw, taken, userAgent)
	if err != nil {
		return nil, nil, err
	}
	conn, err := s.Store.Connections().GetByName(ctx, tid, id.Connection)
	if err != nil {
		return nil, nil, err
	}
	if conn.DisableSignup {
		return nil, nil, identity.ErrSignupDisabled
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = s.now()
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = s.now()
	}
	if u.Name == "" {
		u.Name = u.Email
	}
	if u.Nickname == "" {
		u.Nickname = strings.SplitN(u.Email, "@", 2)[0]
	}
	if err = s.Store.WebAuthn().CreateUserWithPasskey(ctx, &u, a); err != nil {
		return nil, nil, err
	}
	return &u, a, nil
}
