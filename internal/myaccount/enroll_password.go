package myaccount

import (
	"cmp"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/authmethods"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// passwordSession is a started password change.
type passwordSession struct {
	IdentityUserID string `json:"identity_user_id"`
	Connection     string `json:"connection"`
}

// passwordPolicy is conn's password policy in the PasswordAuthenticationMethodPolicy shape.
func passwordPolicy(conn *store.Connection) map[string]any {
	o := conn.PasswordOptions
	cx := o.Complexity
	types := cx.CharacterTypes
	if types == nil {
		types = []string{}
	}
	fields := o.ProfileData.BlockedFields
	if fields == nil {
		fields = []string{}
	}
	return map[string]any{
		"complexity": map[string]any{
			"min_length": cmp.Or(cx.MinLength, 8), "character_types": types,
			"character_type_rule":   cmp.Or(cx.CharacterTypeRule, store.CharacterTypeRuleAll),
			"identical_characters":  cmp.Or(cx.IdenticalCharacters, store.PasswordAllow),
			"sequential_characters": cmp.Or(cx.SequentialCharacters, store.PasswordAllow),
			"max_length_exceeded":   cmp.Or(cx.MaxLengthExceeded, store.MaxLengthError),
		},
		"profile_data": map[string]any{"active": o.ProfileData.Active, "blocked_fields": fields},
		"history":      map[string]any{"active": o.History.Active, "size": o.History.Size},
		"dictionary":   map[string]any{"active": o.Dictionary.Active, "default": cmp.Or(o.Dictionary.Default, store.DictionaryEn10k)},
	}
}

var errPasswordUnsupported = badRequest("password_change_not_supported", "Passwords of this connection cannot be changed here.")

func (h *Handlers) startPassword(w http.ResponseWriter, r *http.Request, c *Caller, b createBody) {
	id, conn, p := h.databaseIdentity(r.Context(), c.User, b.Connection, b.IdentityUserID)
	if p != nil {
		writeProblem(w, r, p)
		return
	}
	if identity.IsLegacy(conn) {
		writeProblem(w, r, errPasswordUnsupported)
		return
	}
	session, err := h.newAuthSession(r.Context(), c, "password", "password|new", passwordSession{IdentityUserID: id.UserID, Connection: conn.Name})
	if err != nil {
		h.fail(w, r, "store an enrollment", err)
		return
	}
	logs.AddCredentials(r.Context(), session)
	w.Header().Set("Location", location(c, "password|new"))
	writeJSON(w, r, http.StatusAccepted, map[string]any{"id": "password|new", "auth_session": session, "policy": passwordPolicy(conn)})
}

func passwordRefused(detail string) *Problem {
	return badRequest("invalid_password", "The new password does not meet the password policy.", ValidationError{Detail: detail, Field: "new_password", Source: "body"})
}

// verifyPassword changes the password exactly like a reset: the
// connection's policy, history and breached-password checks, then in one
// transaction the user's sessions and refresh tokens end, open reset links
// are dropped, last_password_reset and the history are recorded and the
// post-change-password Actions are queued.
func (h *Handlers) verifyPassword(w http.ResponseWriter, r *http.Request, c *Caller, s *authSession, b verifyBody) {
	var ps passwordSession
	if err := json.Unmarshal(s.Data, &ps); err != nil || ps.Connection == "" {
		writeProblem(w, r, errSession())
		return
	}
	pw := b.NewPassword
	ctx := logscrub.WithCredentials(r.Context(), pw)
	logs.AddCredentials(ctx, pw)
	r = r.WithContext(ctx)
	if pw == "" {
		writeProblem(w, r, passwordRefused("new_password is required"))
		return
	}
	conn, err := h.Store.Connections().GetByName(ctx, c.TenantID, ps.Connection)
	if err != nil {
		h.fail(w, r, "load the connection", err)
		return
	}
	if identity.IsLegacy(conn) {
		writeProblem(w, r, errPasswordUnsupported)
		return
	}
	u, err := h.Store.Users().Get(ctx, c.TenantID, c.UserID)
	if err != nil {
		h.fail(w, r, "load the user", err)
		return
	}
	history, err := identity.LoadHistory(ctx, h.Store, conn, u.UserID)
	if err != nil {
		h.fail(w, r, "load the password history", err)
		return
	}
	var pe *identity.PolicyError
	if err := identity.CheckPassword(conn, identity.PersonOf(u), pw, history); errors.As(err, &pe) {
		writeProblem(w, r, passwordRefused(pe.Reason))
		return
	} else if err != nil {
		h.fail(w, r, "check the password", err)
		return
	}
	pw = identity.EffectivePassword(conn, pw)
	if h.Protection != nil {
		if _, err := h.Protection.CheckPasswordForUserResult(ctx, c.Tenant, "pre-change-password", pw, u.UserID); err != nil {
			if errors.Is(err, protection.ErrPasswordLeaked) {
				writeProblem(w, r, passwordRefused("the password has appeared in a data breach"))
			} else {
				writeProblem(w, r, problem(http.StatusServiceUnavailable, "temporarily_unavailable", "Service Unavailable", "The password could not be checked; try again later."))
			}
			return
		}
	}
	hash, err := secrets.Hash(pw)
	if err != nil {
		h.fail(w, r, "hash the password", err)
		return
	}
	res, _ := tenant.FromContext(ctx)
	now := h.now()
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		cur, err := tx.Users().GetForUpdate(ctx, c.TenantID, u.UserID)
		if err != nil {
			return err
		}
		if cur.Blocked {
			return unauthorized("The user is blocked.")
		}
		cur.LastPasswordReset, cur.UpdatedAt = &now, now
		if err := tx.Users().Update(ctx, cur); err != nil {
			return err
		}
		if h.Logout != nil {
			if err := h.Logout.WithStore(tx).EndUserSessions(ctx, c.TenantID, u.UserID, logout.PasswordChanged); err != nil {
				return err
			}
		} else if _, err := tx.Sessions().DeleteByUser(ctx, c.TenantID, u.UserID); err != nil {
			return err
		}
		if _, err := tx.RefreshTokens().RevokeByUser(ctx, c.TenantID, u.UserID, now); err != nil {
			return err
		}
		if _, err := tx.PasswordResetTickets().DeleteByUser(ctx, c.TenantID, u.UserID); err != nil {
			return err
		}
		if err := protection.ClearIdentity(ctx, tx, conn, cur); err != nil {
			return err
		}
		if err := tx.Users().SetPasswordHash(ctx, c.TenantID, u.UserID, conn.Name, hash, now); err != nil {
			return err
		}
		if err := identity.RecordPassword(ctx, tx, conn, u.UserID, hash); err != nil {
			return err
		}
		changed, err := tx.Users().Get(ctx, c.TenantID, u.UserID)
		if err != nil {
			return err
		}
		return actions.PasswordChanged(ctx, tx, h.Actions, res, changed, conn, actions.RequestInfo{IP: httpx.ClientIP(r, h.TrustProxyHeaders),
			Hostname: res.Host, Origin: res.Origin(), Method: r.Method, UserAgent: r.UserAgent(), Language: r.Header.Get("Accept-Language")})
	})
	if err != nil {
		h.fail(w, r, "change the password", err)
		return
	}
	logs.RecordEvent(ctx, logs.RecorderFromContext(ctx), logs.Event{TenantID: c.TenantID, UserID: u.UserID, ClientID: c.ClientID, Connection: conn.Name, ConnectionID: conn.ID, Strategy: conn.Strategy, Type: "scp", Date: now})
	h.created(w, r, c, authmethods.PasswordID(ps.IdentityUserID))
}
