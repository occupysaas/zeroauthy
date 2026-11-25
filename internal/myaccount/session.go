package myaccount

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// AuthSessionLifetime bounds an enrollment's auth_session (LR42a-3).
const AuthSessionLifetime = 5 * time.Minute

// authSessionKind marks My Account rows in the MFA challenge store.
const authSessionKind = "my-account"

const authSessionLabel = "zeroauthy my-account auth_session v1"

// errAuthSession is every unusable auth_session: unknown, tampered,
// expired, spent, or bound to another user, application or type.
var errAuthSession = errors.New("myaccount: invalid auth_session")

// authSession is what an enrollment start leaves for its verify.
type authSession struct {
	Type     string          `json:"type"`
	MethodID string          `json:"method_id"`
	Data     json.RawMessage `json:"data,omitempty"`
}

func sessionFields(c *Caller, typ, methodID, id string) []string {
	return []string{c.TenantID, c.UserID, c.ClientID, typ, methodID, id}
}

// newAuthSession stores an enrollment of typ for c and returns the opaque
// auth_session value. Only its hash is stored; the payload is sealed and
// bound to tenant, user, application and type.
func (h *Handlers) newAuthSession(ctx context.Context, c *Caller, typ, methodID string, data any) (string, error) {
	s := authSession{Type: typ, MethodID: methodID}
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return "", err
		}
		s.Data = b
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	raw := secrets.RandomString(43)
	id := secrets.HashToken(raw)
	sealed, err := keys.SealBound(h.Wrapper, authSessionLabel, sessionFields(c, typ, methodID, id), plain)
	if err != nil {
		return "", err
	}
	err = h.Store.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: c.TenantID, ID: id, UserID: c.UserID, Kind: authSessionKind, Binding: sealed, ExpiresAt: h.now().Add(AuthSessionLifetime)})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// takeAuthSession spends raw if it is c's unexpired enrollment of typ for
// methodID. A value bound to anyone or anything else is refused without
// spending it.
func (h *Handlers) takeAuthSession(ctx context.Context, c *Caller, raw, typ, methodID string) (*authSession, error) {
	if raw == "" || len(raw) > 128 {
		return nil, errAuthSession
	}
	id := secrets.HashToken(raw)
	now := h.now()
	ch, err := h.Store.MFA().GetChallenge(ctx, c.TenantID, id, now)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errAuthSession
	}
	if err != nil {
		return nil, err
	}
	if ch.Kind != authSessionKind || ch.UserID != c.UserID || !now.Before(ch.ExpiresAt) {
		return nil, errAuthSession
	}
	plain, err := keys.OpenBound(h.Wrapper, authSessionLabel, sessionFields(c, typ, methodID, id), ch.Binding)
	if err != nil {
		return nil, errAuthSession
	}
	var s authSession
	if err := json.Unmarshal(plain, &s); err != nil || s.Type != typ || s.MethodID != methodID {
		return nil, errAuthSession
	}
	if err := h.Store.MFA().ConsumeChallenge(ctx, c.TenantID, id, now); err != nil {
		if errors.Is(err, store.ErrPrecondition) || errors.Is(err, store.ErrNotFound) {
			return nil, errAuthSession
		}
		return nil, err
	}
	return &s, nil
}
