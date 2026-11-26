package myorg

import "net/http"

// Phase B operations (D-0221) not implemented yet answer 501; each task of
// the Phase B plan replaces its stubs.
func notImplemented(w http.ResponseWriter, r *http.Request, _ *Caller) {
	writeProblem(w, r, problem(http.StatusNotImplemented, "not_implemented", "Not Implemented", "This operation is not available yet."))
}

func (h *Handlers) getIdPConfig(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) domainIdPs(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) listIdPs(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) createIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) getIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) updateIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) deleteIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) refreshIdPAttributes(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) detachIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) addIdPDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) removeIdPDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) getProvisioning(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) createProvisioning(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) deleteProvisioning(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) refreshProvisioningAttributes(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) listSCIMTokens(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) createSCIMToken(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) getSCIMToken(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}

func (h *Handlers) deleteSCIMToken(w http.ResponseWriter, r *http.Request, c *Caller) {
	notImplemented(w, r, c)
}
