package login

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const (
	spSLOCookie   = "za_saml_sp_slo"
	spSLOLabel    = "saml-sp-slo/v1"
	spSLOLifetime = 10 * time.Minute
)

// spSLOState is the pending SP logout, sealed in a browser cookie.
type spSLOState struct {
	Connection string    `json:"connection"`
	RequestID  string    `json:"request_id"`
	ReturnTo   string    `json:"return_to,omitempty"`
	Expires    time.Time `json:"expires"`
}

// SAMLSPMetadata serves GET /samlp/metadata?connection={name} (Plan 37a).
func (h *Handlers) SAMLSPMetadata(w http.ResponseWriter, r *http.Request, connection string) {
	res, ok := tenant.FromContext(r.Context())
	if !ok || h.Federation == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	md, err := h.Federation.SAMLSPMetadata(r.Context(), res.Tenant, res.Origin(), connection)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		h.log().ErrorContext(r.Context(), "saml: SP metadata", "tenant", res.Tenant.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(md)
	raw, err := doc.WriteToBytes()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	_, _ = w.Write(raw)
}

// UpstreamLogout sends the browser to the samlp IdP's single logout after
// the local session ended, when the session signed in through one. It
// reports whether it answered the request; returnTo ("" = logged-out page)
// is where the browser goes once the IdP answers.
func (h *Handlers) UpstreamLogout(w http.ResponseWriter, r *http.Request, res tenant.Resolved, ended *store.LoginSession, returnTo string) bool {
	if h.Federation == nil || ended == nil {
		return false
	}
	if h.adfsUpstreamLogout(w, r, res, ended, returnTo) {
		return true
	}
	lo, err := h.Federation.SAMLLogoutRequest(r.Context(), res.Tenant, ended)
	if err != nil {
		h.log().WarnContext(r.Context(), "saml: upstream logout request", "tenant", res.Tenant.ID, "err", err)
		return false
	}
	if lo == nil {
		return false
	}
	raw, _ := json.Marshal(spSLOState{Connection: lo.Connection, RequestID: lo.RequestID, ReturnTo: returnTo, Expires: h.now().Add(spSLOLifetime)})
	sealed, err := keys.SealBound(h.Federation.Wrapper, spSLOLabel, []string{res.Tenant.ID}, raw)
	if err != nil {
		return false
	}
	http.SetCookie(w, &http.Cookie{Name: spSLOCookie, Value: base64.RawURLEncoding.EncodeToString(sealed), Path: "/samlp/",
		MaxAge: int(spSLOLifetime / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, lo.URL, http.StatusFound)
	return true
}

func (h *Handlers) spSLOState(r *http.Request, res tenant.Resolved) (spSLOState, bool) {
	var st spSLOState
	c, err := r.Cookie(spSLOCookie)
	if err != nil {
		return st, false
	}
	sealed, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return st, false
	}
	raw, err := keys.OpenBound(h.Federation.Wrapper, spSLOLabel, []string{res.Tenant.ID}, sealed)
	if err != nil || json.Unmarshal(raw, &st) != nil || !h.now().Before(st.Expires) {
		return st, false
	}
	return st, true
}

// SAMLSPLogout serves GET|POST /samlp/logout?connection={name}: the IdP's
// LogoutResponse to our LogoutRequest, or an IdP-initiated LogoutRequest.
// Both must be signed by the IdP.
func (h *Handlers) SAMLSPLogout(w http.ResponseWriter, r *http.Request, connection string) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	res, ok := tenant.FromContext(ctx)
	if !ok || h.Federation == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
	refuse := func() { ui.RenderError(w, http.StatusBadRequest, view, view.L.T(i18n.KeyErrSessionExpired)) }
	var root *etree.Element
	var relay string
	var verifyRedirect func(samlcore.Trust) error
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, federation.MaxSAMLCallbackSize)
		if r.ParseForm() != nil {
			refuse()
			return
		}
		v := r.PostForm.Get(samlcore.ParamRequest)
		if v == "" {
			v = r.PostForm.Get(samlcore.ParamResponse)
		}
		doc, err := samlcore.DecodePOST(v)
		if err != nil {
			refuse()
			return
		}
		root, relay = doc.Root(), r.PostForm.Get("RelayState")
	} else {
		msg, err := samlcore.DecodeRedirect(r.URL.RawQuery)
		if err != nil {
			refuse()
			return
		}
		root, relay, verifyRedirect = msg.Doc.Root(), msg.RelayState, msg.Verify
	}
	m, err := h.Federation.VerifySAMLLogout(ctx, res.Tenant, connection, root, verifyRedirect)
	if err != nil {
		refuse()
		return
	}
	if m.Response != nil {
		st, ok := h.spSLOState(r, res)
		http.SetCookie(w, &http.Cookie{Name: spSLOCookie, Value: "", Path: "/samlp/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
		if !ok || st.Connection != m.Connection.Name || st.RequestID != m.Response.InResponseTo || st.ReturnTo == "" {
			ui.RenderLoggedOut(w, view)
			return
		}
		http.Redirect(w, r, st.ReturnTo, http.StatusFound)
		return
	}
	status := samlcore.StatusSuccess
	sess, err := h.Authz.ActiveSession(ctx, r, res)
	switch {
	case err != nil:
		status = samlcore.StatusResponder
	case sess != nil && upstreamMatches(sess, m.Connection.ID, m.Request):
		if _, err := h.Authz.Sessions.End(ctx, w, r, res.Tenant); err != nil {
			status = samlcore.StatusResponder
		}
	case sess != nil:
		status = samlcore.StatusRequester // this browser's session is someone else's
	}
	u, err := h.Federation.SAMLLogoutResponse(ctx, res.Tenant, m.Connection, m.Request.ID, relay, status)
	if err != nil {
		ui.RenderLoggedOut(w, view)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func upstreamMatches(sess *store.LoginSession, connectionID string, lr *samlcore.LogoutRequest) bool {
	for _, p := range sess.SAMLParticipants {
		if p.ConnectionID == connectionID && p.NameID == lr.NameID && (lr.SessionIndex == "" || p.SessionIndex == lr.SessionIndex) {
			return true
		}
	}
	return false
}
