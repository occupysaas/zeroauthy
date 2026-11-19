package oauth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/dpop"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var errOnlineSession = errors.New("oauth: online session is unavailable")

func onlineSession(ctx context.Context, st store.Store, res tenant.Resolved, userID, sid string, now time.Time) (*store.LoginSession, error) {
	if sid == "" {
		return nil, errOnlineSession
	}
	s, e := st.Sessions().Get(ctx, res.Tenant.ID, sid)
	if errors.Is(e, store.ErrNotFound) {
		return nil, errOnlineSession
	}
	if e != nil {
		return nil, e
	}
	if s.UserID != userID || res.CheckOrigin(s.Origin) != nil || !now.Before(s.ExpiresAt) || !now.Before(s.IdleExpiresAt) {
		return nil, errOnlineSession
	}
	return s, nil
}

// Lock before sampling time: a browser interaction or logout can commit while
// the transaction waits for this row. Issuance only observes the locked state.
func (h *Handlers) lockedOnlineSession(ctx context.Context, st store.Store, res tenant.Resolved, userID, sid string) (*store.LoginSession, time.Time, error) {
	if sid == "" {
		return nil, time.Time{}, errOnlineSession
	}
	s, err := st.Sessions().GetForUpdate(ctx, res.Tenant.ID, sid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, time.Time{}, errOnlineSession
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	now := h.now().UTC()
	if s.UserID != userID || res.CheckOrigin(s.Origin) != nil || !now.Before(s.ExpiresAt) || !now.Before(s.IdleExpiresAt) {
		return nil, now, errOnlineSession
	}
	return s, now, nil
}

func onlineEligible(c *store.Client, rs *store.ResourceServer, s *store.LoginSession) bool {
	return rs != nil && rs.AllowOnlineAccess && s != nil && slices.Contains(c.GrantTypes, "refresh_token") && (s.CookieMode != "non-persistent" || rs.AllowOnlineAccessWithEphemeralSessions)
}
func onlineProof(ctx context.Context, c *store.Client) *Error {
	if c.TokenEndpointAuthMethod == store.AuthMethodNone && dpop.FromContext(ctx) == nil {
		return &Error{Status: 400, Code: "invalid_dpop_proof", Description: "a proof is required for online refresh tokens"}
	}
	return nil
}
func (h *Handlers) finishOnline(ctx context.Context, tx store.Store, res tenant.Resolved, c *store.Client, presented *store.RefreshToken) error {
	rt, e := tx.RefreshTokens().GetByTokenHash(ctx, presented.TenantID, presented.TokenHash)
	if e != nil {
		return e
	}
	if rt.ID != presented.ID || rt.RevokedAt != nil || rt.Access != "online" || rt.UserID != presented.UserID || rt.ClientID != c.ClientID || res.CheckOrigin(rt.Origin) != nil {
		return errOnlineSession
	}
	s, now, e := h.lockedOnlineSession(ctx, tx, res, rt.UserID, rt.SessionID)
	if e != nil {
		return e
	}
	api, e := tx.ResourceServers().GetByIdentifier(ctx, rt.TenantID, rt.Audience)
	if e != nil {
		return e
	}
	if !onlineEligible(c, api, s) {
		return errOnlineSession
	}
	if failure := onlineProof(ctx, c); failure != nil {
		return failure
	}
	// The session remains locked from validation through this interaction update.
	ri := requestInfoFrom(ctx)
	currentTenant, e := tx.Tenants().Get(ctx, res.Tenant.ID)
	if e != nil {
		return e
	}
	return tx.Sessions().Touch(ctx, s.TenantID, s.ID, now, session.IdleExpiry(currentTenant, s, now), ri.IP, ri.UserAgent)
}

func proofJKT(ctx context.Context) string {
	if p := dpop.FromContext(ctx); p != nil {
		return p.JKT
	}
	return ""
}

// endOnlineSession invalidates every ORT in this SSO session. Offline grants
// remain independent. The user lock serializes this with token issuance.
func (h *Handlers) endOnlineSession(ctx context.Context, res tenant.Resolved, rt *store.RefreshToken) error {
	return h.Store.WithTx(ctx, func(tx store.Store) error {
		if _, e := tx.Users().GetForUpdate(ctx, rt.TenantID, rt.UserID); e != nil {
			if errors.Is(e, store.ErrNotFound) {
				return nil
			}
			return e
		}
		current, e := tx.RefreshTokens().GetByTokenHash(ctx, rt.TenantID, rt.TokenHash)
		if errors.Is(e, store.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.RevokedAt != nil || !h.now().UTC().Before(current.ExpiresAt) || current.ID != rt.ID || current.ClientID != rt.ClientID || current.UserID != rt.UserID || current.Access != "online" || res.CheckOrigin(current.Origin) != nil {
			return nil
		}
		s, e := tx.Sessions().Get(ctx, rt.TenantID, current.SessionID)
		if errors.Is(e, store.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if s.UserID != rt.UserID || res.CheckOrigin(s.Origin) != nil {
			return nil
		}
		if e := tx.Sessions().Delete(ctx, rt.TenantID, s.ID); e != nil && !errors.Is(e, store.ErrNotFound) {
			return e
		}
		return tx.RefreshTokens().RevokeFamily(ctx, rt.TenantID, current.FamilyID, h.now().UTC())
	})
}
