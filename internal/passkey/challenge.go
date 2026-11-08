package passkey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Issued contains values sent only to the browser/native caller. Session is
// native auth_session; only HashToken(Session) is stored as ID. UserHandle is
// the registration user.id, never caller-provided enrollment metadata.
type Issued struct {
	ID, Session           string
	Challenge, UserHandle []byte
	ExpiresAt             time.Time
}

// Taken carries the trusted persisted registration metadata after single-use
// consumption. Pass this server-side value directly to Enroll or Signup; never
// decode it from browser input. Login uses Challenge and Binding.
type Taken struct {
	Challenge, UserHandle []byte
	Binding               Binding
}

type challengeData struct {
	Binding    Binding `json:"binding"`
	UserHandle []byte  `json:"user_handle,omitempty"`
}

func randomBytes(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }

// Issue stores a short-lived ceremony. Native ttl is the navigator timeout;
// NativeGrace is added only to the row expiry. Larger supplied lifetimes are
// capped; nonpositive durations use the respective documented timeout.
func (s *Service) Issue(ctx context.Context, tid string, b Binding, ttl time.Duration) (*Issued, error) {
	if !validBinding(b) {
		return nil, ceremonyError("challenge")
	}
	available, err := s.supported(ctx)
	if err != nil {
		return nil, err
	}
	if !available {
		return nil, store.ErrWebAuthnUnavailable
	}
	native := b.TxnID == ""
	max := webauthnrules.Limits.HostedChallengeTTL
	if native {
		max = webauthnrules.Limits.NativeTimeout
	}
	if ttl <= 0 || ttl > max {
		ttl = max
	}
	if native {
		ttl += webauthnrules.Limits.NativeGrace
	}
	b.Origins = slices.Clone(b.Origins)
	i := &Issued{Challenge: randomBytes(webauthnrules.Limits.ChallengeBytes), ExpiresAt: s.now().Add(ttl)}
	token := base64.RawURLEncoding.EncodeToString(randomBytes(webauthnrules.Limits.ChallengeBytes))
	i.ID = token
	if native {
		i.Session = token
		i.ID = secrets.HashToken(token)
	}
	if b.Purpose == PasskeyRegister || b.Purpose == PasskeyProgressiveRegister || b.Purpose == PasskeyLocalRegister || b.Purpose == WebAuthnRegister {
		i.UserHandle, err = s.userHandle(ctx, tid, b.UserID)
		if err != nil {
			return nil, err
		}
	}
	data, err := json.Marshal(challengeData{Binding: b, UserHandle: i.UserHandle})
	if err != nil {
		return nil, err
	}
	// All kinds use the pre-existing storage "webauthn" kind: registration
	// drafts and discoverable logins need not have an existing user row. The
	// exact purpose/user binding lives in data and is checked after consumption.
	row := &store.MFAChallenge{TenantID: tid, ID: i.ID, Kind: "webauthn", Challenge: i.Challenge, Binding: data, ExpiresAt: i.ExpiresAt}
	if err = s.Store.MFA().CreateChallenge(ctx, row); err != nil {
		return nil, err
	}
	logs.AddCredentials(ctx, i.ID, i.Session)
	mask(ctx, i.Challenge, i.UserHandle)
	return i, nil
}
func validBinding(b Binding) bool {
	switch b.Purpose {
	case PasskeyLogin, WebAuthnAssert, PasskeyRegister, PasskeyProgressiveRegister, PasskeyLocalRegister, WebAuthnRegister:
	default:
		return false
	}
	if b.RPID == "" || len(b.Origins) == 0 {
		return false
	}
	for _, o := range b.Origins {
		if o == "" {
			return false
		}
	}
	if b.TxnID == "" {
		if b.ClientID == "" || b.Realm == "" {
			return false
		}
	} else if b.CookieHash == "" {
		return false
	}
	return b.Purpose == PasskeyLogin || b.UserID != ""
}

// Take consumes before inspecting the persisted binding. Competing callers
// may read the same row, but only the atomic consumer receives its challenge.
func (s *Service) Take(ctx context.Context, tid, id string, want Binding) (*Taken, error) {
	now := s.now()
	row, err := s.Store.MFA().GetChallenge(ctx, tid, id, now)
	if err != nil {
		return nil, ceremonyError("challenge")
	}
	if err = s.Store.MFA().ConsumeChallenge(ctx, tid, id, now); err != nil {
		return nil, ceremonyError("challenge")
	}
	logs.AddCredentials(ctx, id)
	mask(ctx, row.Challenge)
	var d challengeData
	if row.Kind != "webauthn" || json.Unmarshal(row.Binding, &d) != nil || !reflect.DeepEqual(d.Binding, want) || !validBinding(d.Binding) || len(row.Challenge) != webauthnrules.Limits.ChallengeBytes {
		return nil, ceremonyError("challenge")
	}
	if (want.Purpose == PasskeyRegister || want.Purpose == WebAuthnRegister) && len(d.UserHandle) != webauthnrules.Limits.UserHandleBytes {
		return nil, ceremonyError("user_handle")
	}
	mask(ctx, d.UserHandle)
	return &Taken{Challenge: slices.Clone(row.Challenge), Binding: d.Binding, UserHandle: slices.Clone(d.UserHandle)}, nil
}

func (s *Service) userHandle(ctx context.Context, tid, uid string) ([]byte, error) {
	as, err := s.Store.MFA().ListAuthenticators(ctx, tid, uid)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	h, err := existingHandle(as, "")
	if err != nil {
		return nil, err
	}
	if h != nil {
		return h, nil
	}
	return randomBytes(webauthnrules.Limits.UserHandleBytes), nil
}

// Linked accounts can retain credentials registered with different original
// handles. Reuse a deterministic existing handle for new enrollment; assertions
// always compare with the particular credential's own handle.
func existingHandle(as []store.Authenticator, excludeID string) ([]byte, error) {
	var first *store.Authenticator
	for i := range as {
		a := &as[i]
		if a.Type != "passkey" || a.ID == excludeID {
			continue
		}
		if first == nil || a.CreatedAt.Before(first.CreatedAt) || a.CreatedAt.Equal(first.CreatedAt) && a.ID < first.ID {
			first = a
		}
	}
	if first == nil {
		return nil, nil
	}
	p, err := readPublic(first)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(p.UserHandle)
}
