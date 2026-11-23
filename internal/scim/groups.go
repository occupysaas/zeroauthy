package scim

import "net/http"

// Groups and discovery endpoints (Task A4).

func notYet(w http.ResponseWriter, r *http.Request, h *Handler) {
	h.fail(w, r, errorf(http.StatusNotImplemented, "", "Not implemented yet."))
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request, _ *call) error {
	notYet(w, r, h)
	return nil
}
func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request, _ *call) error {
	notYet(w, r, h)
	return nil
}
func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request, _ *call) error {
	notYet(w, r, h)
	return nil
}
func (h *Handler) replaceGroup(w http.ResponseWriter, r *http.Request, _ *call) error {
	notYet(w, r, h)
	return nil
}
func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request, _ *call) error {
	notYet(w, r, h)
	return nil
}
func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request, _ *call) error {
	notYet(w, r, h)
	return nil
}
func (h *Handler) serviceProviderConfig(w http.ResponseWriter, r *http.Request) { notYet(w, r, h) }
func (h *Handler) resourceTypes(w http.ResponseWriter, r *http.Request)         { notYet(w, r, h) }
func (h *Handler) schemas(w http.ResponseWriter, r *http.Request)               { notYet(w, r, h) }
