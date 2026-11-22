package samlidp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

const (
	sloCookie   = "za_saml_slo"
	sloLabel    = "saml-slo/v1"
	sloLifetime = 10 * time.Minute
)

// sloState is the single logout chain, sealed in a browser cookie.
type sloState struct {
	Requester  string                  `json:"requester"`
	RequestID  string                  `json:"request_id"`
	RelayState string                  `json:"relay,omitempty"`
	Pending    []store.SAMLParticipant `json:"pending,omitempty"`
	Current    string                  `json:"current,omitempty"`
	Expect     string                  `json:"expect,omitempty"`
	Expires    time.Time               `json:"expires"`
}

func (h *Handler) saveState(w http.ResponseWriter, res tenant.Resolved, st sloState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	sealed, err := keys.SealBound(h.Wrapper, sloLabel, []string{res.Tenant.ID}, raw)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: sloCookie, Value: base64.RawURLEncoding.EncodeToString(sealed), Path: "/samlp/",
		MaxAge: int(sloLifetime / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
	return nil
}

func clearState(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sloCookie, Value: "", Path: "/samlp/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
}

func (h *Handler) loadState(r *http.Request, res tenant.Resolved) (sloState, error) {
	var st sloState
	c, err := r.Cookie(sloCookie)
	if err != nil {
		return st, err
	}
	sealed, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return st, err
	}
	raw, err := keys.OpenBound(h.Wrapper, sloLabel, []string{res.Tenant.ID}, sealed)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(raw, &st); err != nil || !h.now().Before(st.Expires) {
		return st, errors.New("samlidp: logout state expired")
	}
	return st, nil
}

// logoutMessage is a decoded LogoutRequest or LogoutResponse.
type logoutMessage struct {
	param      string
	root       *etree.Element
	relayState string
	verify     func(samlcore.Trust) (*etree.Element, error)
	signed     bool
}

func readLogout(w http.ResponseWriter, r *http.Request) (logoutMessage, error) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			return logoutMessage{}, err
		}
		param, v := samlcore.ParamRequest, r.PostForm.Get(samlcore.ParamRequest)
		if v == "" {
			param, v = samlcore.ParamResponse, r.PostForm.Get(samlcore.ParamResponse)
		}
		doc, err := samlcore.DecodePOST(v)
		if err != nil {
			return logoutMessage{}, err
		}
		root := doc.Root()
		return logoutMessage{param: param, root: root, relayState: r.PostForm.Get("RelayState"), signed: root.FindElement("./Signature") != nil,
			verify: func(t samlcore.Trust) (*etree.Element, error) { return samlcore.VerifyEnveloped(root, t) }}, nil
	}
	msg, err := samlcore.DecodeRedirect(r.URL.RawQuery)
	if err != nil {
		return logoutMessage{}, err
	}
	root := msg.Doc.Root()
	return logoutMessage{param: msg.Param, root: root, relayState: msg.RelayState, signed: msg.Signed(), verify: func(t samlcore.Trust) (*etree.Element, error) {
		if err := msg.Verify(t); err != nil {
			return nil, err
		}
		return root, nil
	}}, nil
}

func addonOf(client *store.Client) *store.SAMLAddon {
	if client == nil || client.Addons == nil {
		return nil
	}
	return client.Addons.SAMLP
}

func logoutCallback(addon *store.SAMLAddon) string {
	if addon == nil || addon.Logout == nil {
		return ""
	}
	return addon.Logout.Callback
}

// Logout serves GET|POST /samlp/{client_id}/logout: a service provider's
// LogoutRequest, or a LogoutResponse during propagation.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request, clientID string) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	client, err := h.Store.Clients().Get(r.Context(), res.Tenant.ID, clientID)
	if err != nil || addonOf(client) == nil {
		h.page(w, r, res, http.StatusNotFound, "This application has no SAML2 Web App add-on.")
		return
	}
	msg, err := readLogout(w, r)
	if err != nil {
		h.page(w, r, res, http.StatusBadRequest, "The SAML logout message could not be read.")
		return
	}
	root := msg.root
	trust, err := spTrust(addonOf(client))
	if err != nil {
		h.page(w, r, res, http.StatusBadRequest, "The application's SAML signing certificate is invalid.")
		return
	}
	if trust != nil {
		if root, err = msg.verify(*trust); err != nil {
			h.page(w, r, res, http.StatusBadRequest, "The SAML logout message must be signed by the application.")
			return
		}
	}
	if msg.param == samlcore.ParamRequest {
		h.logoutRequest(w, r, res, client, root, msg.relayState)
		return
	}
	h.logoutResponse(w, r, res, client, root)
}

func (h *Handler) logoutRequest(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, root *etree.Element, relay string) {
	lr, err := samlcore.ParseLogoutRequest(root)
	if err != nil {
		h.page(w, r, res, http.StatusBadRequest, "The SAML message is not a LogoutRequest.")
		return
	}
	callback := logoutCallback(addonOf(client))
	if callback == "" {
		h.page(w, r, res, http.StatusBadRequest, "The application has no SAML logout callback URL.")
		return
	}
	sess, err := h.Authz.ActiveSession(r.Context(), r, res)
	if err != nil {
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	var others []store.SAMLParticipant
	matched := false
	if sess != nil && (lr.SessionIndex == "" || lr.SessionIndex == sess.ID) {
		for _, p := range sess.SAMLParticipants {
			if p.ConnectionID != "" {
				continue // an upstream IdP, not a service provider we answered
			}
			if p.ClientID == client.ClientID {
				matched = p.NameID == lr.NameID
				continue
			}
			other, err := h.Store.Clients().Get(r.Context(), res.Tenant.ID, p.ClientID)
			if err != nil || logoutCallback(addonOf(other)) == "" || !flag(addonOf(other).Logout.SLOEnabled, true) {
				continue
			}
			others = append(others, p)
		}
	}
	if !matched {
		// Nothing of this service provider's to end: answer without logging out.
		h.sendLogoutResponse(w, r, res, client, lr.ID, relay, samlcore.StatusRequester)
		return
	}
	if _, err := h.Sessions.End(r.Context(), w, r, res.Tenant); err != nil {
		h.log().ErrorContext(r.Context(), "saml: end session", "tenant", res.Tenant.ID, "err", err)
		h.sendLogoutResponse(w, r, res, client, lr.ID, relay, samlcore.StatusResponder)
		return
	}
	h.propagate(w, r, res, sloState{Requester: client.ClientID, RequestID: lr.ID, RelayState: relay, Pending: others, Expires: h.now().Add(sloLifetime)})
}

func (h *Handler) logoutResponse(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, root *etree.Element) {
	lr, err := samlcore.ParseLogoutResponse(root)
	st, serr := h.loadState(r, res)
	if err != nil || serr != nil || st.Current != client.ClientID || st.Expect == "" || lr.InResponseTo != st.Expect {
		clearState(w)
		ui.RenderLoggedOut(w, ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, "")))
		return
	}
	h.propagate(w, r, res, st)
}

// propagate sends the next LogoutRequest, or the final LogoutResponse to
// the requester.
func (h *Handler) propagate(w http.ResponseWriter, r *http.Request, res tenant.Resolved, st sloState) {
	for len(st.Pending) > 0 {
		p := st.Pending[0]
		st.Pending = st.Pending[1:]
		target, err := h.Store.Clients().Get(r.Context(), res.Tenant.ID, p.ClientID)
		callback := logoutCallback(addonOf(target))
		if err != nil || callback == "" {
			continue
		}
		addon := addonOf(target)
		signer, err := h.signer(r, res, addon)
		if err != nil {
			continue
		}
		now := h.now()
		lr := samlcore.LogoutRequest{ID: newID(), IssueInstant: now, Issuer: issuer(res, addon), Destination: callback,
			NameID: p.NameID, NameIDFormat: p.NameIDFormat, SessionIndex: p.SessionIndex, NotOnOrAfter: now.Add(5 * time.Minute)}
		loc, err := samlcore.EncodeRedirect(callback, samlcore.ParamRequest, samlcore.BuildLogoutRequest(lr), "", signer)
		if err != nil {
			continue
		}
		st.Current, st.Expect = p.ClientID, lr.ID
		if err := h.saveState(w, res, st); err != nil {
			h.log().ErrorContext(r.Context(), "saml: save logout state", "tenant", res.Tenant.ID, "err", err)
			break
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, loc, http.StatusFound)
		return
	}
	clearState(w)
	requester, err := h.Store.Clients().Get(r.Context(), res.Tenant.ID, st.Requester)
	if err != nil || logoutCallback(addonOf(requester)) == "" {
		ui.RenderLoggedOut(w, ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, "")))
		return
	}
	h.sendLogoutResponse(w, r, res, requester, st.RequestID, st.RelayState, samlcore.StatusSuccess)
}

func (h *Handler) sendLogoutResponse(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, inResponseTo, relay, status string) {
	addon := addonOf(client)
	callback := logoutCallback(addon)
	signer, err := h.signer(r, res, addon)
	if err != nil {
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	resp := samlcore.BuildLogoutResponse(samlcore.LogoutResponse{ID: newID(), InResponseTo: inResponseTo, IssueInstant: h.now(),
		Issuer: issuer(res, addon), Destination: callback, StatusCode: status})
	loc, err := samlcore.EncodeRedirect(callback, samlcore.ParamResponse, resp, relay, signer)
	if err != nil {
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, loc, http.StatusFound)
}
