package myorg

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Phase B operations (D-0221) not implemented yet answer 501; each task of
// the Phase B plan replaces its stubs.
func notImplemented(w http.ResponseWriter, r *http.Request, _ *Caller) {
	writeProblem(w, r, problem(http.StatusNotImplemented, "not_implemented", "Not Implemented", "This operation is not available yet."))
}

func (h *Handlers) domainIdPs(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) updateIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "updateIdP", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) deleteIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "deleteIdP", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) refreshIdPAttributes(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "refreshIdPAttributes", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) detachIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "detachIdP", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) addIdPDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "addIdPDomain", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) removeIdPDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "removeIdPDomain", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) getProvisioning(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "getProvisioning", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) createProvisioning(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "createProvisioning", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) deleteProvisioning(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "deleteProvisioning", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) refreshProvisioningAttributes(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "refreshProvisioningAttributes", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) listSCIMTokens(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "listSCIMTokens", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) createSCIMToken(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "createSCIMToken", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) getSCIMToken(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "getSCIMToken", err)
		return
	}
	notImplemented(w, r, c)
}

func (h *Handlers) deleteSCIMToken(w http.ResponseWriter, r *http.Request, c *Caller) {
	if _, _, err := h.idp(r, c, chi.URLParam(r, "idp_id")); err != nil {
		h.idpFail(w, r, c, "deleteSCIMToken", err)
		return
	}
	notImplemented(w, r, c)
}
