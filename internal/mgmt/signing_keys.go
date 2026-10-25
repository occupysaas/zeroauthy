package mgmt

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/signingrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) ListSigningKeys(w http.ResponseWriter, r *http.Request) {
	tn := resolved(r)
	if tn == nil || tn.Reserved {
		Fail(w, errSystemTenant)
		return
	}
	rows, err := h.Store.SigningKeys().List(r.Context(), tn.ID)
	if err != nil {
		Fail(w, internalError(h, r, "list signing keys", err))
		return
	}
	out := make([]signingrules.ManagedKey, 0, len(rows))
	for _, k := range rows {
		p, err := signingrules.Project(k)
		if err != nil {
			Fail(w, internalError(h, r, "project signing key", err))
			return
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) GetSigningKey(w http.ResponseWriter, r *http.Request, kid string) {
	tn := resolved(r)
	if tn == nil || tn.Reserved {
		Fail(w, errSystemTenant)
		return
	}
	kid, err := url.PathUnescape(kid)
	if err != nil || kid == "" {
		Fail(w, badBody("invalid key ID"))
		return
	}
	k, err := h.Store.SigningKeys().Get(r.Context(), tn.ID, kid)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "inexistent_signing_key", "The signing key does not exist")
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get signing key", err))
		return
	}
	out, err := signingrules.Project(k)
	if err != nil {
		Fail(w, internalError(h, r, "project signing key", err))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) RotateSigningKeys(w http.ResponseWriter, r *http.Request) {
	tn := resolved(r)
	if tn == nil || tn.Reserved {
		Fail(w, errSystemTenant)
		return
	}
	result, err := h.Keys.RotateWithResult(r.Context(), tn.ID)
	if err != nil {
		Fail(w, internalError(h, r, "rotate signing keys", err))
		return
	}
	// The 201 response identifies the queued key promoted by this operation.
	out, err := signingrules.Project(result.Current)
	if err != nil {
		Fail(w, internalError(h, r, "project rotated signing key", err))
		return
	}
	h.audit(r, "rotate signing key", "kid", out.KID)
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handlers) RevokeSigningKey(w http.ResponseWriter, r *http.Request, kid string) {
	tn := resolved(r)
	if tn == nil || tn.Reserved {
		Fail(w, errSystemTenant)
		return
	}
	kid, err := url.PathUnescape(kid)
	if err != nil || kid == "" {
		Fail(w, badBody("invalid key ID"))
		return
	}
	k, err := h.Keys.Revoke(r.Context(), tn.ID, kid)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "inexistent_signing_key", "The signing key does not exist")
		return
	}
	if errors.Is(err, store.ErrInvalid) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "The signing key cannot be revoked in its current state")
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "revoke signing key", err))
		return
	}
	out, err := signingrules.Project(k)
	if err != nil {
		Fail(w, internalError(h, r, "project revoked signing key", err))
		return
	}
	h.audit(r, "revoke signing key", "kid", out.KID)
	writeJSON(w, http.StatusOK, out)
}
