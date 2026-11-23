package login

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// wsfedCallback receives an adfs connection's sign-in response, POST
// /login/callback with wa=wsignin1.0, wresult and wctx (Plan 37b). wctx is
// the attempt state zeroauthy sent; there is no unsolicited WS-Fed login.
func (h *Handlers) wsfedCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	res, ok := tenant.FromContext(r.Context())
	f := r.PostForm
	if !ok || h.Federation == nil || r.URL.RawQuery != "" || len(f["wresult"]) != 1 || len(f["wctx"]) != 1 || len(f["wa"]) > 1 ||
		f.Get("wa") != "" && f.Get("wa") != "wsignin1.0" || f.Get("wctx") == "" || len(f.Get("wctx")) > maxRelayState {
		h.socialFailure(w, r, nil, federation.ErrCallbackRejected)
		return
	}
	h.finishCallback(w, r, res, federation.CallbackParams{State: f.Get("wctx"), WResult: f.Get("wresult"), FormPost: true})
}

// adfsUpstreamLogout sends the browser to the ADFS sign-out of the
// session's adfs connection, returning to returnTo (LR37b-10).
func (h *Handlers) adfsUpstreamLogout(w http.ResponseWriter, r *http.Request, res tenant.Resolved, ended *store.LoginSession, returnTo string) bool {
	for _, p := range ended.SAMLParticipants {
		if p.ConnectionID == "" {
			continue
		}
		conn, err := h.Store.Connections().Get(r.Context(), res.Tenant.ID, p.ConnectionID)
		if err != nil {
			continue
		}
		if u := h.Federation.ADFSLogoutURL(res.Tenant, conn, returnTo); u != "" {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, u, http.StatusFound)
			return true
		}
	}
	return false
}
