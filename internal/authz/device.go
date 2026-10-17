package authz

import (
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// CreateTxn stores a transaction bound to this browser (sets the za_txn
// cookie, scoped to cookiePath) and returns it. startTxn uses it. The
// transaction keeps a copy of params.
func (h *Handlers) CreateTxn(w http.ResponseWriter, r *http.Request, res tenant.Resolved, clientID string, params map[string]string, cookiePath string) (*store.AuthTransaction, error) {
	now := h.now()
	params = maps.Clone(params)
	if cookiePath != "/u" {
		if params == nil {
			params = map[string]string{}
		}
		params[cookiePathKey] = cookiePath
	}
	cookieValue := secrets.RandomString(43)
	txn := &store.AuthTransaction{
		TenantID:   res.Tenant.ID,
		ID:         secrets.RandomString(24),
		CookieHash: secrets.HashToken(cookieValue),
		CSRFToken:  secrets.RandomString(32),
		ClientID:   clientID,
		Params:     params,
		ExpiresAt:  now.Add(TxnLifetime),
		CreatedAt:  now,
	}
	if err := h.Store.AuthTransactions().Create(r.Context(), txn); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: TxnCookiePrefix + txn.ID, Value: cookieValue, Path: cookiePath,
		MaxAge: int(TxnLifetime / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return txn, nil
}

// EndTxn deletes txn and expires its cookie.
func (h *Handlers) EndTxn(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction) {
	ctx := r.Context()
	if err := h.Store.AuthTransactions().Delete(ctx, res.Tenant.ID, txn.ID); err != nil {
		h.log().WarnContext(ctx, "delete login transaction", "tenant", res.Tenant.ID, "err", err)
	}
	path := txn.Params[cookiePathKey]
	if path == "" {
		path = "/u"
	}
	http.SetCookie(w, &http.Cookie{Name: TxnCookiePrefix + txn.ID, Value: "", Path: path, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func deviceFlow(dc *store.DeviceCode, uiLocales string) flowReq {
	return flowReq{
		Request:        Request{ClientID: dc.ClientID, Scope: strings.Join(dc.Scopes, " "), Audience: dc.Audience, UILocales: uiLocales},
		DeviceCodeHash: dc.DeviceCodeHash,
	}
}

// ContinueDevice runs login (or session reuse, D10) and the access
// decision for a confirmed device code.
func (h *Handlers) ContinueDevice(w http.ResponseWriter, r *http.Request, res tenant.Resolved, dc *store.DeviceCode, uiLocales string) {
	ctx := r.Context()
	fr := deviceFlow(dc, uiLocales)
	client, verr, _ := h.validateFlow(ctx, res, &fr)
	if verr != nil {
		h.flowError(w, r, res, fr, verr)
		return
	}
	sess, err := h.ActiveSession(ctx, r, res)
	if err != nil {
		h.log().ErrorContext(ctx, "load session", "tenant", res.Tenant.ID, "err", err)
		h.refuse(w, r, res, client, fr, errServer())
		return
	}
	login := sess == nil
	if !login {
		if login, err = h.connectionDisabled(ctx, res, client, sess); err != nil {
			h.log().ErrorContext(ctx, "load session connection", "tenant", res.Tenant.ID, "err", err)
			h.refuse(w, r, res, client, fr, errServer())
			return
		}
	}
	if login {
		h.startLogin(w, r, res, client, fr)
		return
	}
	// The device confirmation screen was just shown.
	h.finish(w, r, res, client, fr, sess, false, true)
}

// DenyDevice marks a pending code denied and redirects to /device/denied.
func (h *Handlers) DenyDevice(w http.ResponseWriter, r *http.Request, res tenant.Resolved, dc *store.DeviceCode, uiLocales string) {
	fr := deviceFlow(dc, uiLocales)
	client, verr, _ := h.validateFlow(r.Context(), res, &fr)
	if verr != nil {
		h.flowError(w, r, res, fr, verr)
		return
	}
	h.refuse(w, r, res, client, fr, errUserDeclined())
}
