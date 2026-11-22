package login

import (
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// maxRelayState bounds the RelayState that may name a login attempt.
const maxRelayState = 512

// samlCallback is the samlp assertion consumer service, POST
// /login/callback?connection={name} (Plan 37a). A RelayState naming this
// browser's login attempt completes that attempt; anything else is an
// IdP-initiated login, accepted only when the connection enables it.
func (h *Handlers) samlCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	res, ok := tenant.FromContext(ctx)
	q := r.URL.Query()
	if !ok || h.Federation == nil || len(q) != 1 || len(q["connection"]) != 1 || q.Get("connection") == "" ||
		len(r.PostForm["SAMLResponse"]) != 1 || len(r.PostForm["RelayState"]) > 1 {
		h.socialFailure(w, r, nil, federation.ErrCallbackRejected)
		return
	}
	raw, relay := r.PostForm.Get("SAMLResponse"), r.PostForm.Get("RelayState")
	if relay != "" && len(relay) <= maxRelayState {
		if c, err := r.Cookie(federation.AttemptCookiePrefix + federation.StateHash(relay)[:16]); err == nil && c.Value != "" {
			h.finishCallback(w, r, res, federation.CallbackParams{State: relay, SAMLResponse: raw, FormPost: true})
			return
		}
	}
	ip := httpx.ClientIP(r, h.TrustProxyHeaders)
	if blocked, err := h.protectionService().IPBlocked(ctx, res.Tenant.ID, ip); err != nil || blocked {
		ui.RenderError(w, http.StatusTooManyRequests, ui.RequestTenant(r, res.Tenant, i18n.ForRequest(res.Tenant, r, "")),
			i18n.ForRequest(res.Tenant, r, "").T(i18n.KeyTooManyAttempts))
		return
	}
	out, err := h.Federation.CompleteSAMLUnsolicited(ctx, res.Tenant, res.Origin(), q.Get("connection"), raw)
	if err != nil {
		h.socialFailure(w, r, nil, err)
		return
	}
	sess, err := h.Authz.Sessions.Start(ctx, w, r, res.Tenant, out.User.UserID, out.Connection.Name, h.now(), store.AuthMethod{Name: "federated"})
	if err != nil {
		h.socialFailure(w, r, nil, err)
		return
	}
	if err := federation.RecordSAMLUpstream(ctx, h.Store, res.Tenant.ID, sess.ID, out.Upstream); err != nil {
		h.log().WarnContext(ctx, "saml: record upstream session", "tenant", res.Tenant.ID, "err", err)
	}
	next := "/authorize?" + out.Query.Encode()
	if out.Protocol == "samlp" {
		next = "/samlp/" + url.PathEscape(out.ClientID)
	}
	http.Redirect(w, r, next, http.StatusFound)
}
