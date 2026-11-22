package samlidp

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"crypto/x509"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// Limits on what a service provider sends.
const (
	maxFormBytes  = samlcore.MaxInputBytes*2 + 8192 // base64 of the largest document, plus RelayState
	maxRelayState = 2048
)

// Handler serves the SAML IdP endpoints and completes samlp transactions
// (authz.SAMLResponder).
type Handler struct {
	Store    store.Store
	Keys     *keys.Manager
	Sessions *session.Manager
	Wrapper  keys.Wrapper
	Authz    *authz.Handlers
	Now      func() time.Time
	Log      *slog.Logger
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// Binding is what a samlp transaction carries through login (stored as the
// server-only Request.SAML; never read from request parameters).
type Binding struct {
	RequestID    string `json:"id,omitempty"`
	ACS          string `json:"acs"`
	RelayState   string `json:"relay,omitempty"`
	Audience     string `json:"aud"`
	IdPInitiated bool   `json:"idp,omitempty"`
}

func (b Binding) encode() string {
	raw, _ := json.Marshal(b)
	return string(raw)
}

func decodeBinding(s string) (Binding, error) {
	var b Binding
	if err := json.Unmarshal([]byte(s), &b); err != nil || b.ACS == "" || b.Audience == "" {
		return b, errors.New("samlidp: invalid binding")
	}
	return b, nil
}

func (h *Handler) page(w http.ResponseWriter, r *http.Request, res tenant.Resolved, status int, detail string) {
	view := ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
	ui.RenderErrorDetail(w, status, view, view.L.T(i18n.KeyErrAccessDenied), detail)
}

// incoming is a decoded SP request.
type incoming struct {
	root       *etree.Element
	relayState string
	verify     func(samlcore.Trust) (*etree.Element, error)
	present    bool
}

// readRequest decodes SAMLRequest from the HTTP-Redirect query or the
// HTTP-POST form.
func readRequest(w http.ResponseWriter, r *http.Request) (incoming, error) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			return incoming{}, errors.New("malformed form")
		}
		v := r.PostForm.Get(samlcore.ParamRequest)
		if v == "" {
			return incoming{relayState: r.PostForm.Get("RelayState")}, nil
		}
		doc, err := samlcore.DecodePOST(v)
		if err != nil {
			return incoming{}, err
		}
		root := doc.Root()
		return incoming{present: true, root: root, relayState: r.PostForm.Get("RelayState"),
			verify: func(t samlcore.Trust) (*etree.Element, error) { return samlcore.VerifyEnveloped(root, t) }}, nil
	}
	if r.URL.Query().Get(samlcore.ParamRequest) == "" {
		return incoming{relayState: r.URL.Query().Get("RelayState")}, nil
	}
	msg, err := samlcore.DecodeRedirect(r.URL.RawQuery)
	if err != nil {
		return incoming{}, err
	}
	if msg.Param != samlcore.ParamRequest {
		return incoming{}, errors.New("not a request")
	}
	root := msg.Doc.Root()
	return incoming{present: true, root: root, relayState: msg.RelayState, verify: func(t samlcore.Trust) (*etree.Element, error) {
		if err := msg.Verify(t); err != nil {
			return nil, err
		}
		return root, nil
	}}, nil
}

// spTrust is the SP certificate configured on the add-on, if any.
func spTrust(addon *store.SAMLAddon) (*samlcore.Trust, error) {
	if addon.SigningCert == "" {
		return nil, nil
	}
	cert, err := clientrules.ParseCertificate(addon.SigningCert)
	if err != nil {
		return nil, err
	}
	return &samlcore.Trust{Certs: []*x509.Certificate{cert}, AllowSHA1: addon.SignatureAlgorithm == samlcore.AlgRSASHA1 || addon.DigestAlgorithm == samlcore.DigestSHA1}, nil
}

// SSO serves GET and POST /samlp/{client_id}. connection and organization
// are the documented query parameters.
func (h *Handler) SSO(w http.ResponseWriter, r *http.Request, clientID, connection, organization string) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	client, err := h.Store.Clients().Get(r.Context(), res.Tenant.ID, clientID)
	if errors.Is(err, store.ErrNotFound) || err == nil && (client.Addons == nil || client.Addons.SAMLP == nil) {
		h.page(w, r, res, http.StatusNotFound, "This application has no SAML2 Web App add-on.")
		return
	}
	if err != nil {
		h.log().ErrorContext(r.Context(), "saml: load client", "tenant", res.Tenant.ID, "err", err)
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	addon := client.Addons.SAMLP
	in, err := readRequest(w, r)
	if err != nil {
		h.page(w, r, res, http.StatusBadRequest, "The SAML request could not be read.")
		return
	}
	if len(in.relayState) > maxRelayState {
		h.page(w, r, res, http.StatusBadRequest, "RelayState is too long.")
		return
	}
	var b Binding
	prompt := ""
	if !in.present {
		b, err = h.idpInitiated(client, in.relayState)
	} else {
		b, prompt, err = h.spInitiated(r, res, client, addon, in)
	}
	if err != nil {
		h.page(w, r, res, http.StatusBadRequest, err.Error())
		return
	}
	h.Authz.AuthorizeSAML(w, r, authz.Request{ClientID: client.ClientID, RedirectURI: b.ACS, ResponseType: "code", ResponseMode: "form_post",
		Scope: "openid profile email", Connection: connection, Organization: organization, Prompt: prompt, SAML: b.encode()})
}

func (h *Handler) spInitiated(r *http.Request, res tenant.Resolved, client *store.Client, addon *store.SAMLAddon, in incoming) (Binding, string, error) {
	root := in.root
	trust, err := spTrust(addon)
	if err != nil {
		return Binding{}, "", errors.New("The application's SAML signing certificate is invalid.")
	}
	if trust != nil {
		if root, err = in.verify(*trust); err != nil {
			return Binding{}, "", errors.New("The SAML request must be signed by the application.")
		}
	}
	req, err := samlcore.ParseAuthnRequest(root)
	if err != nil {
		return Binding{}, "", errors.New("The SAML request is not an AuthnRequest.")
	}
	if req.Destination != "" && strings.TrimSuffix(req.Destination, "/") != strings.TrimSuffix(res.Origin()+r.URL.Path, "/") {
		return Binding{}, "", errors.New("The SAML request was sent to another destination.")
	}
	acs := req.ACSURL
	if acs == "" {
		acs = addon.Recipient
	}
	if acs == "" && len(client.Callbacks) > 0 {
		acs = client.Callbacks[0]
	}
	if !authz.SAMLACSAllowed(client, acs) {
		return Binding{}, "", errors.New("The ACS URL is not registered for this application.")
	}
	audience := addon.Audience
	if audience == "" {
		audience = req.Issuer
	}
	if audience == "" {
		return Binding{}, "", errors.New("The SAML request has no Issuer.")
	}
	prompt := ""
	switch {
	case req.IsPassive:
		prompt = "none"
	case req.ForceAuthn:
		prompt = "login"
	}
	return Binding{RequestID: req.ID, ACS: acs, RelayState: in.relayState, Audience: audience}, prompt, nil
}

// idpInitiated starts an unsolicited response to the add-on's recipient (or
// the first callback).
func (h *Handler) idpInitiated(client *store.Client, relayState string) (Binding, error) {
	addon := client.Addons.SAMLP
	acs := addon.Recipient
	if acs == "" && len(client.Callbacks) > 0 {
		acs = client.Callbacks[0]
	}
	if !authz.SAMLACSAllowed(client, acs) {
		return Binding{}, errors.New("IdP-initiated SSO needs a callback URL or add-on recipient.")
	}
	audience := addon.Audience
	if audience == "" {
		audience = acs
	}
	return Binding{ACS: acs, RelayState: relayState, Audience: audience, IdPInitiated: true}, nil
}
