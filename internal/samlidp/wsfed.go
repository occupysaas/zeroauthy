package samlidp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// WS-Federation passive requestor identity provider: the wsfed add-on
// (Plan 37b, D-0140). It shares the SAML IdP's profile mapper,
// api.samlResponse effects, signing key and session participants.

const (
	wsfedLifetime   = 8 * 3600 // node-wsfed default (D-0140)
	maxWCtx         = 2048
	maxWReply       = 2048
	maxWTRealm      = 1024
	maxWHR          = 128
	wsfedSignIn     = "wsignin1.0"
	wsfedSignOut    = "wsignout1.0"
	wsfedSignOutCln = "wsignoutcleanup1.0"
)

// WSFedParams are the documented WS-Fed query parameters.
type WSFedParams struct {
	Action, Realm, Reply, Context, HomeRealm, Fresh string
}

// wsfedBinding is what a WS-Fed sign-in carries through login (server-only,
// as authz.WSFedBindingPrefix + JSON).
type wsfedBinding struct {
	Reply    string `json:"reply"`
	Context  string `json:"ctx,omitempty"`
	Audience string `json:"aud"`
}

func (b wsfedBinding) encode() string {
	raw, _ := json.Marshal(b)
	return authz.WSFedBindingPrefix + string(raw)
}

func decodeWSFedBinding(s string) (wsfedBinding, error) {
	var b wsfedBinding
	raw, ok := strings.CutPrefix(s, authz.WSFedBindingPrefix)
	if !ok || json.Unmarshal([]byte(raw), &b) != nil || b.Reply == "" || b.Audience == "" {
		return b, errors.New("samlidp: invalid WS-Fed binding")
	}
	return b, nil
}

// asResource is node-wsfed's audience form: values that are not http(s)
// URLs or URNs get "urn:" prepended.
func asResource(s string) string {
	if strings.HasPrefix(s, "http:") || strings.HasPrefix(s, "https:") || strings.HasPrefix(s, "urn:") {
		return s
	}
	return "urn:" + s
}

func hasWSFed(c *store.Client) bool { return c != nil && c.Addons != nil && c.Addons.WSFed != nil }

// wsfedClient resolves the application: by path, where wtrealm (when
// present) must be its client ID or one of its client_aliases, or by
// wtrealm alone (LR37b-3). It returns a user-facing message on failure.
func (h *Handler) wsfedClient(r *http.Request, tid, clientID, realm string) (*store.Client, int, string) {
	if clientID != "" {
		c, err := h.Store.Clients().Get(r.Context(), tid, clientID)
		if errors.Is(err, store.ErrNotFound) || err == nil && !hasWSFed(c) {
			return nil, http.StatusNotFound, "This application has no WS-Fed Web App add-on."
		}
		if err != nil {
			return nil, http.StatusInternalServerError, ""
		}
		if realm != "" && realm != c.ClientID && !slices.Contains(c.ClientAliases, realm) {
			return nil, http.StatusBadRequest, "The realm (wtrealm) is not registered for this application."
		}
		return c, 0, ""
	}
	if realm == "" {
		return nil, http.StatusBadRequest, "The realm (wtrealm) is required."
	}
	c, err := h.Store.Clients().Get(r.Context(), tid, realm)
	if err == nil && hasWSFed(c) {
		return c, 0, ""
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, http.StatusInternalServerError, ""
	}
	found, _, err := h.Store.Clients().List(r.Context(), tid, store.ClientFilter{Alias: realm}, store.Page{})
	if err != nil {
		return nil, http.StatusInternalServerError, ""
	}
	if len(found) != 1 || !hasWSFed(found[0]) {
		return nil, http.StatusBadRequest, "The realm (wtrealm) is not registered for any application."
	}
	return found[0], 0, ""
}

// WSFed serves GET /wsfed/{client_id} and, with clientID empty, GET /wsfed.
func (h *Handler) WSFed(w http.ResponseWriter, r *http.Request, clientID string, p WSFedParams) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if len(p.Context) > maxWCtx || len(p.Reply) > maxWReply || len(p.Realm) > maxWTRealm || len(p.HomeRealm) > maxWHR {
		h.page(w, r, res, http.StatusBadRequest, "A WS-Federation parameter is too long.")
		return
	}
	client, status, msg := h.wsfedClient(r, res.Tenant.ID, clientID, p.Realm)
	if client == nil {
		if status == http.StatusInternalServerError {
			h.log().ErrorContext(r.Context(), "wsfed: load client", "tenant", res.Tenant.ID)
			msg = "Something went wrong."
		}
		h.page(w, r, res, status, msg)
		return
	}
	switch p.Action {
	case "", wsfedSignIn:
		h.wsfedSignIn(w, r, res, client, p)
	case wsfedSignOut, wsfedSignOutCln:
		h.wsfedSignOut(w, r, res, client, p)
	default:
		h.page(w, r, res, http.StatusBadRequest, "The WS-Federation action (wa) is not supported.")
	}
}

// wsfedReply is wreply, or the first callback that is a plain URL.
func wsfedReply(client *store.Client, reply string) string {
	if reply != "" {
		return reply
	}
	for _, cb := range client.Callbacks {
		if !strings.ContainsAny(cb, "*{}") {
			return cb
		}
	}
	return ""
}

func (h *Handler) wsfedSignIn(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, p WSFedParams) {
	reply := wsfedReply(client, p.Reply)
	if !authz.WSFedReplyAllowed(client, reply) {
		h.page(w, r, res, http.StatusBadRequest, "The reply URL (wreply) is not registered for this application.")
		return
	}
	audience := p.Realm
	if audience == "" {
		audience = reply
	}
	prompt := ""
	if p.Fresh == "0" {
		prompt = "login"
	}
	b := wsfedBinding{Reply: reply, Context: p.Context, Audience: asResource(audience)}
	h.Authz.AuthorizeSAML(w, r, authz.Request{ClientID: client.ClientID, RedirectURI: reply, ResponseType: "code", ResponseMode: "form_post",
		Scope: "openid profile email", Connection: p.HomeRealm, Prompt: prompt, SAML: b.encode()})
}

// wsfedAssertion is the SAML 1.1 assertion for user, with the add-on
// defaults (Plan 37a mapper: UPN, identities and passthrough claims on) and
// the api.samlResponse effects applied. It returns the effective add-on
// configuration for signing.
func wsfedAssertion(res tenant.Resolved, user *store.User, b wsfedBinding, se *actionresult.SAMLEffects, orgID string, now, authn time.Time) (samlcore.Assertion11Spec, *store.SAMLAddon) {
	cfg, sb := applyEffects(&store.SAMLAddon{}, Binding{ACS: b.Reply, Audience: b.Audience}, se)
	lifetime := wsfedLifetime
	if cfg.LifetimeInSeconds != nil {
		lifetime = *cfg.LifetimeInSeconds
	}
	extra := map[string]any{}
	if orgID != "" {
		extra["org_id"] = orgID
	}
	m := buildAttributes(user, cfg, extra)
	return samlcore.Assertion11Spec{ID: newID(), Issuer: issuer(res, cfg), NameID: m.NameID, NameIDFormat: cfg.NameIdentifierFormat, Audience: sb.Audience,
		IssueInstant: now, NotBefore: now, NotOnOrAfter: now.Add(time.Duration(lifetime) * time.Second), AuthnInstant: authn,
		Attributes: overrideAttributes(m.Attributes, se)}, cfg
}

// respondWSFed completes a WS-Fed sign-in: a signed SAML 1.1 assertion in
// a RequestSecurityTokenResponse, auto-posted to the reply URL.
func (h *Handler) respondWSFed(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, binding, orgID string, sess *store.LoginSession, eff *actions.Effects) {
	b, err := decodeWSFedBinding(binding)
	if err != nil || !authz.WSFedReplyAllowed(client, b.Reply) {
		h.page(w, r, res, http.StatusBadRequest, "The WS-Federation request is no longer valid.")
		return
	}
	var se *actionresult.SAMLEffects
	if eff != nil {
		se = eff.SAML
	}
	user, err := h.Store.Users().Get(r.Context(), res.Tenant.ID, sess.UserID)
	if err != nil {
		h.log().ErrorContext(r.Context(), "wsfed: load user", "tenant", res.Tenant.ID, "err", err)
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	now := h.now()
	authn := now
	if !sess.AuthenticatedAt.IsZero() {
		authn = sess.AuthenticatedAt.UTC()
	}
	spec, cfg := wsfedAssertion(res, user, b, se, orgID, now, authn)
	if spec.NameID == "" {
		h.page(w, r, res, http.StatusInternalServerError, "No attribute was found to generate the name identifier.")
		return
	}
	signer, err := effectSigner(se)
	if err != nil {
		h.page(w, r, res, http.StatusInternalServerError, "The Action's SAML signing key and certificate are invalid.")
		return
	}
	if signer == nil {
		if signer, err = h.signer(r, res, cfg); err != nil {
			h.log().ErrorContext(r.Context(), "wsfed: signing key", "tenant", res.Tenant.ID, "err", err)
			h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
			return
		}
	}
	signer.Algorithm, signer.Digest = cfg.SignatureAlgorithm, cfg.DigestAlgorithm
	assertion, err := signer.SignEnveloped11(samlcore.BuildAssertion11(spec))
	if err != nil {
		h.log().ErrorContext(r.Context(), "wsfed: sign assertion", "tenant", res.Tenant.ID, "err", err)
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	wresult, err := samlcore.BuildRSTR(b.Context, assertion)
	if err != nil {
		h.page(w, r, res, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	ui.RenderFormPost(w, i18n.ForRequest(res.Tenant, r, ""), b.Reply, url.Values{"wa": {wsfedSignIn}, "wresult": {wresult}, "wctx": {b.Context}})
}

// failWSFed answers a WS-Fed sign-in that cannot complete with an error
// page: WS-Fed has no error token, so nothing is posted to the relying
// party (LR37b-8).
func (h *Handler) failWSFed(w http.ResponseWriter, r *http.Request, res tenant.Resolved, description string) {
	h.page(w, r, res, http.StatusBadRequest, description)
}
