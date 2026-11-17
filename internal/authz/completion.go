package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const pendingLoginCookie = "za_pending_login"
const pendingIdentityParam = "za_pending_identity"

type pendingLoginKey struct{}
type completionTxnKey struct{}
type pendingLogin struct {
	Transaction *store.AuthTransaction
	Session     *store.LoginSession
}

// BeginLogin records first-factor evidence on the original browser transaction.
// It is never a session: only the hosted continuation paths can read it.
func (h *Handlers) BeginLogin(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction, user *store.User, connection string, methods ...store.AuthMethod) (*store.LoginSession, error) {
	sess, _, err := h.Sessions.Prepare(r.Context(), r, res.Tenant, user.UserID, connection, h.now(), methods...)
	if err != nil {
		return nil, err
	}
	token := secrets.RandomString(43)
	sess.TokenHash = secrets.HashToken(token)
	raw, err := json.Marshal(sess)
	if err != nil {
		return nil, err
	}
	var current *store.AuthTransaction
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		var e error
		current, e = tx.AuthTransactions().Get(r.Context(), res.Tenant.ID, txn.ID)
		if e != nil {
			return e
		}
		if !h.now().Before(current.ExpiresAt) || res.CheckOrigin(current.Origin) != nil {
			return store.ErrPrecondition
		}
		fresh, e := tx.Users().Get(r.Context(), res.Tenant.ID, user.UserID)
		if e != nil {
			return e
		}
		if fresh.Blocked || fresh.Version != user.Version {
			return store.ErrPrecondition
		}
		current.Params["za_pending_user_version"] = strconv.FormatInt(user.Version, 10)
		current.Params[pendingIdentityParam] = string(raw)
		return orglogin.SaveInvitationTransaction(r.Context(), tx, current, h.now())
	})
	if err != nil {
		return nil, err
	}
	*txn = *current
	p := &pendingLogin{Transaction: current, Session: sess}
	*r = *r.WithContext(context.WithValue(r.Context(), pendingLoginKey{}, p))
	http.SetCookie(w, &http.Cookie{Name: pendingLoginCookie, Value: txn.ID + "." + token, Path: "/", MaxAge: int(txn.ExpiresAt.Sub(h.now()).Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return sess, nil
}

func (h *Handlers) pendingLogin(ctx context.Context, r *http.Request, res tenant.Resolved) (*pendingLogin, error) {
	if p, ok := ctx.Value(pendingLoginKey{}).(*pendingLogin); ok {
		return p, nil
	}
	c, err := r.Cookie(pendingLoginCookie)
	if err != nil {
		return nil, nil
	}
	id, token, ok := strings.Cut(c.Value, ".")
	if !ok {
		return nil, store.ErrInvalid
	}
	txn, err := h.Store.AuthTransactions().Get(ctx, res.Tenant.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s store.LoginSession
	if !h.now().Before(txn.ExpiresAt) || res.CheckOrigin(txn.Origin) != nil || json.Unmarshal([]byte(txn.Params[pendingIdentityParam]), &s) != nil || s.TenantID != res.Tenant.ID || s.TokenHash != secrets.HashToken(token) || res.CheckOrigin(s.Origin) != nil {
		return nil, store.ErrInvalid
	}
	u, err := h.Store.Users().Get(ctx, res.Tenant.ID, s.UserID)
	if err != nil {
		return nil, err
	}
	if u.Blocked || txn.Params["za_pending_user_version"] != strconv.FormatInt(u.Version, 10) {
		return nil, store.ErrInvalid
	}
	return &pendingLogin{Transaction: txn, Session: &s}, nil
}

// FlowSession is scoped to hosted steps and Action continuations. Authorize and
// all other SSO consumers deliberately use ActiveSession, which ignores it.
func (h *Handlers) FlowSession(ctx context.Context, r *http.Request, res tenant.Resolved) (*store.LoginSession, error) {
	p, err := h.pendingLogin(ctx, r, res)
	if err != nil {
		return nil, err
	}
	if p != nil {
		*r = *r.WithContext(context.WithValue(r.Context(), pendingLoginKey{}, p))
		return p.Session, nil
	}
	return h.ActiveSession(ctx, r, res)
}

// MarkFlowMFA is called only after server-verified hosted proof. Pending
// identities retain the proof on their transaction; existing SSO sessions keep
// the ordinary step-up behavior.
func (h *Handlers) MarkFlowMFA(r *http.Request, res tenant.Resolved, sess *store.LoginSession, factors ...string) error {
	p, err := h.pendingLogin(r.Context(), r, res)
	if err != nil {
		return err
	}
	if p == nil || p.Session.ID != sess.ID {
		if err = h.Sessions.MarkMFA(r.Context(), sess); err != nil {
			return err
		}
		for _, factor := range factors {
			if err = h.Sessions.AddMethod(r.Context(), sess, store.AuthMethod{Name: "mfa", Type: factor}); err != nil {
				return err
			}
		}
		return nil
	}
	return h.Store.WithTx(r.Context(), func(tx store.Store) error {
		cur, e := tx.AuthTransactions().Get(r.Context(), res.Tenant.ID, p.Transaction.ID)
		if e != nil {
			return e
		}
		var s store.LoginSession
		if json.Unmarshal([]byte(cur.Params[pendingIdentityParam]), &s) != nil || s.ID != sess.ID {
			return store.ErrPrecondition
		}
		s.MFAAt = h.now()
		for _, factor := range factors {
			s.AuthMethods = append(s.AuthMethods, store.AuthMethod{Name: "mfa", Type: factor, At: h.now()})
		}
		raw, e := json.Marshal(s)
		if e != nil {
			return e
		}
		cur.Params[pendingIdentityParam] = string(raw)
		if e = orglogin.SaveInvitationTransaction(r.Context(), tx, cur, h.now()); e != nil {
			return e
		}
		*sess = s
		p.Session = sess
		p.Transaction = cur
		return nil
	})
}

type consentGrantKey struct{}

// commitLogin is the single boundary for non-Action authorization effects.
// Cookie headers are staged by approve alongside code/device issuance.
func (h *Handlers) commitLogin(w http.ResponseWriter, r *http.Request, res tenant.Resolved, fr flowReq, sess *store.LoginSession) error {
	ctx := r.Context()
	p, err := h.pendingLogin(ctx, r, res)
	if err != nil {
		return err
	}
	var txn *store.AuthTransaction
	if p != nil && p.Session.ID == sess.ID {
		txn, err = h.Store.AuthTransactions().Get(ctx, res.Tenant.ID, p.Transaction.ID)
		if err != nil {
			return err
		}
		var saved store.LoginSession
		if !h.now().Before(txn.ExpiresAt) || res.CheckOrigin(txn.Origin) != nil || json.Unmarshal([]byte(txn.Params[pendingIdentityParam]), &saved) != nil || saved.ID != sess.ID || saved.UserID != sess.UserID || !saved.MFAAt.Equal(sess.MFAAt) {
			return store.ErrPrecondition
		}
		user, e := h.Store.Users().GetForUpdate(ctx, res.Tenant.ID, sess.UserID)
		if e != nil {
			return e
		}
		if user.Blocked || txn.Params["za_pending_user_version"] != strconv.FormatInt(user.Version, 10) {
			return store.ErrPrecondition
		}
		client, e := h.Store.Clients().Get(ctx, res.Tenant.ID, fr.ClientID)
		if e != nil {
			return e
		}
		conn, e := h.Store.Connections().GetByName(ctx, res.Tenant.ID, sess.Connection)
		if e != nil {
			return e
		}
		if !access.ConnectionUsable(client, conn) {
			return store.ErrPrecondition
		}
		// Claim the original authentication once. Deletion below and every write
		// share the enclosing transaction, so a failure restores the claim too.
		if err = h.Store.AuthTransactions().CompareAndSwapHosted(ctx, txn.TenantID, txn.ID, txn.HostedState.Revision, txn.HostedState, h.now()); err != nil {
			return err
		}
		txn.HostedState.Revision++
		token := secrets.RandomString(43)
		sess.TokenHash = secrets.HashToken(token)
		if err = h.Sessions.Commit(ctx, w, r, res.Tenant, sess, token); err != nil {
			return err
		}
	} else {
		txn, _ = ctx.Value(completionTxnKey{}).(*store.AuthTransaction)
	}
	if txn != nil && txn.Params[orglogin.InvitationIDParam] != "" {
		if err = h.acceptInvitation(ctx, txn, sess); err != nil {
			return err
		}
	}
	if fr.OrgID != "" {
		oc, e := orglogin.Load(ctx, h.Store, res.Tenant.ID, fr.params())
		if e != nil {
			return e
		}
		conn, e := h.Store.Connections().GetByName(ctx, res.Tenant.ID, sess.Connection)
		if e != nil {
			return e
		}
		client, e := h.Store.Clients().Get(ctx, res.Tenant.ID, fr.ClientID)
		if e != nil {
			return e
		}
		eventCtx := logs.WithEvent(ctx, logs.Event{ClientID: client.ClientID, ClientName: client.Name, Connection: conn.Name, ConnectionID: conn.ID, Strategy: conn.Strategy, StrategyType: logs.StrategyType(conn.Strategy)})
		if e = orglogin.EnsureMembership(eventCtx, h.Store, oc, sess.UserID, conn.ID); e != nil {
			return e
		}
	}
	if grant, ok := ctx.Value(consentGrantKey{}).(*store.UserGrant); ok {
		if _, err = h.Store.UserGrants().Upsert(ctx, grant); err != nil {
			return err
		}
	}
	if p != nil && p.Session.ID == sess.ID {
		if err = h.Store.Users().RecordLogin(ctx, res.Tenant.ID, sess.UserID, sess.AuthenticatedAt, sess.InitialIP); err != nil {
			return err
		}
	}
	if txn != nil {
		if err = h.Store.AuthTransactions().Delete(ctx, res.Tenant.ID, txn.ID); err != nil {
			return err
		}
		h.clearTxnCookie(w, txn)
	}
	if p != nil && p.Session.ID == sess.ID {
		http.SetCookie(w, &http.Cookie{Name: pendingLoginCookie, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	return nil
}

// prospectiveUser preserves the pre-MFA Action event's former view without
// committing its last_login/logins_count. Existing SSO does not increment them.
func (h *Handlers) prospectiveUser(r *http.Request, res tenant.Resolved, sess *store.LoginSession, u *store.User) *store.User {
	p, _ := h.pendingLogin(r.Context(), r, res)
	if p == nil || p.Session.ID != sess.ID {
		return u
	}
	copy := *u
	copy.LoginsCount++
	at := sess.AuthenticatedAt
	copy.LastLogin = &at
	copy.LastIP = httpx.RecordedIP(r, h.TrustProxyHeaders)
	return &copy
}

func (h *Handlers) completionTransaction(ctx context.Context, r *http.Request, res tenant.Resolved) (*store.AuthTransaction, error) {
	p, err := h.pendingLogin(ctx, r, res)
	if err != nil {
		return nil, err
	}
	if p != nil {
		return h.Store.AuthTransactions().Get(ctx, res.Tenant.ID, p.Transaction.ID)
	}
	txn, _ := ctx.Value(completionTxnKey{}).(*store.AuthTransaction)
	if txn == nil {
		return nil, store.ErrNotFound
	}
	return h.Store.AuthTransactions().Get(ctx, res.Tenant.ID, txn.ID)
}
