package login

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/adhub"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// ADAuthenticator checks an ad connection's username and password through
// the AD/LDAP Connector and returns the connector's profile
// (adhub.Service).
type ADAuthenticator interface {
	Authenticate(ctx context.Context, conn *store.Connection, username, password string) (json.RawMessage, error)
}

// maxADUsername bounds the sign-in name sent to the connector.
const maxADUsername = 256

// adConnections are the ad connections the transaction's application may
// use, in name order.
func (h *Handlers) adConnections(r *http.Request, f *flow) []*store.Connection {
	if h.AD == nil || f.txn.Params[store.TxnParamOrgMode] == string(authz.OrgPromptBefore) {
		return nil
	}
	ctx := r.Context()
	client, err := h.Store.Clients().Get(ctx, f.res.Tenant.ID, f.txn.ClientID)
	if err != nil {
		return nil
	}
	conns, _, err := h.Store.Connections().List(ctx, f.res.Tenant.ID, store.ConnectionFilter{Strategies: []string{store.StrategyAD}}, store.Page{})
	if err != nil {
		return nil
	}
	oc, err := orglogin.Load(ctx, h.Store, f.res.Tenant.ID, f.txn.Params)
	if err != nil {
		return nil
	}
	var out []*store.Connection
	for _, c := range EligibleConnections(conns, oc) {
		if c.Strategy == store.StrategyAD && access.ConnectionUsable(client, c) {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b *store.Connection) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// adLogin authenticates an ad connection's user through the connector
// (Plan 38a): brute-force protection by connection and username, CAPTCHA,
// the connector's answer mapped to the login errors (LR38a-9), then the
// user is provisioned or synchronized like a federated login. The password
// is never logged or stored.
func (h *Handlers) adLogin(w http.ResponseWriter, r *http.Request, f *flow, login string) {
	h.withFlowEvent(r, f)
	password := r.PostForm.Get("password")
	*r = *r.WithContext(logscrub.WithCredentials(r.Context(), password))
	ctx := r.Context()
	data := ui.LoginData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Login: login, RedirectURI: f.txn.Params["redirect_uri"]}
	if h.AD == nil || h.Federation == nil {
		data.Error = f.view.L.T(i18n.KeyErrConnectionUnavailable)
		h.renderLoginStage(w, r, http.StatusServiceUnavailable, f, data)
		return
	}
	login = strings.TrimSpace(login)
	if login == "" || len(login) > maxADUsername || strings.ContainsAny(login, "\x00\r\n") {
		data.Error = f.view.L.T(i18n.KeyWrongCredentials)
		h.renderLoginStage(w, r, http.StatusUnauthorized, f, data)
		return
	}
	svc := h.protectionService()
	decision, err := svc.Begin(ctx, protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, Identifier: strings.ToLower(login), IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "login"})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !decision.Allowed {
		data.Error = f.view.L.T(i18n.KeyTooManyAttempts)
		h.renderLoginStage(w, r, http.StatusTooManyRequests, f, data)
		return
	}
	attemptID := secrets.RandomString(32)
	if err := h.submitCaptcha(r, f.res, &f.view, "login", f.txn.ID, attemptID); err != nil {
		if finishErr := svc.Finish(ctx, decision.Receipt, "refund"); finishErr != nil {
			h.fail(w, r, finishErr, f)
			return
		}
		status, key := captchaFailure(err)
		data.Error = f.view.L.T(key)
		h.renderLoginStage(w, r, status, f, data)
		return
	}
	raw, err := h.AD.Authenticate(ctx, f.conn, login, password)
	outcome := "success"
	switch {
	case errors.Is(err, adhub.ErrWrongCredentials):
		outcome = "failure"
	case err != nil && !errors.Is(err, adhub.ErrAccountBlocked) && !errors.Is(err, adhub.ErrPasswordChangeRequired):
		outcome = "refund" // nothing was proved either way
	}
	if finishErr := svc.Finish(ctx, decision.Receipt, outcome); finishErr != nil {
		h.fail(w, r, finishErr, f)
		return
	}
	var riskErr error
	if errors.Is(err, adhub.ErrWrongCredentials) {
		riskErr = identity.ErrInvalidCredentials
	}
	if err := h.recordFailure(r, f.res, "login", attemptID, riskErr); err != nil {
		h.fail(w, r, err, f)
		return
	}
	switch {
	case errors.Is(err, adhub.ErrWrongCredentials):
		h.event(r, f, "f", &store.User{UserID: decision.SubjectID})
		h.log().InfoContext(ctx, "login failed", "tenant", f.res.Tenant.ID, "connection", f.conn.Name)
		if !h.captchaPage(w, r, f, "login") {
			return
		}
		data.Error = f.view.L.T(i18n.KeyWrongCredentials)
		h.renderLoginStage(w, r, http.StatusUnauthorized, f, data)
		return
	case errors.Is(err, adhub.ErrAccountBlocked):
		h.event(r, f, "f", &store.User{UserID: decision.SubjectID})
		data.Error = f.view.L.T(i18n.KeyUserBlocked)
		h.renderLoginStage(w, r, http.StatusForbidden, f, data)
		return
	case errors.Is(err, adhub.ErrPasswordChangeRequired):
		h.event(r, f, "f", &store.User{UserID: decision.SubjectID})
		data.Error = f.view.L.T(i18n.KeyPasswordChangeRequired)
		h.renderLoginStage(w, r, http.StatusForbidden, f, data)
		return
	case err != nil:
		h.event(r, f, "f", &store.User{UserID: decision.SubjectID})
		h.log().WarnContext(ctx, "ad login: connection not available", "tenant", f.res.Tenant.ID, "connection", f.conn.Name, "err", err.Error())
		data.Error = f.view.L.T(i18n.KeyErrConnectionUnavailable)
		h.renderLoginStage(w, r, http.StatusServiceUnavailable, f, data)
		return
	}
	profile, err := federation.ADProfile(raw, login)
	if err != nil {
		h.log().WarnContext(ctx, "ad login: connector profile refused", "tenant", f.res.Tenant.ID, "connection", f.conn.Name, "err", err.Error())
		data.Error = f.view.L.T(i18n.KeyErrConnectionUnavailable)
		h.renderLoginStage(w, r, http.StatusBadGateway, f, data)
		return
	}
	user, err := h.Federation.DirectLogin(ctx, federation.DirectLoginInput{Tenant: f.res.Tenant, Txn: f.txn, Connection: f.conn, Profile: profile})
	switch {
	case errors.Is(err, federation.ErrUserBlocked):
		data.Error = f.view.L.T(i18n.KeyUserBlocked)
		h.renderLoginStage(w, r, http.StatusForbidden, f, data)
		return
	case errors.Is(err, errOrganizationConnection):
		h.fail(w, r, err, f)
		return
	case err != nil:
		h.fail(w, r, err, f)
		return
	}
	h.complete(w, r, f, user)
}
