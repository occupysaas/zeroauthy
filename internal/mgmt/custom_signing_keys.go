package mgmt

import (
	"errors"
	"io"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/signingrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const maxCustomSigningBodyBytes = 64 << 10

func (h *Handlers) GetCustomSigningKeys(w http.ResponseWriter, r *http.Request) {
	tn := resolved(r)
	if tn == nil || tn.Reserved {
		Fail(w, errSystemTenant)
		return
	}
	set, err := h.Store.CustomSigningKeys().Get(r.Context(), tn.ID)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "inexistent_custom_signing_keys", "Custom signing keys do not exist")
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get custom signing keys", err))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(append([]byte(nil), set.JWKS...), '\n'))
}

func (h *Handlers) PutCustomSigningKeys(w http.ResponseWriter, r *http.Request) {
	tn := resolved(r)
	if tn == nil || tn.Reserved {
		Fail(w, errSystemTenant)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCustomSigningBodyBytes))
	if err != nil {
		Fail(w, badBody("the body is too large or unreadable"))
		return
	}
	validated, err := signingrules.ParseCustom(raw)
	if err != nil {
		Fail(w, badBody("invalid custom JWKS"))
		return
	}
	ids, err := signingrules.KeyIDs(validated)
	if err != nil {
		Fail(w, badBody("invalid custom JWKS"))
		return
	}
	if err := h.Store.CustomSigningKeys().Replace(r.Context(), &store.CustomSigningKeySet{TenantID: tn.ID, JWKS: validated}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			WriteError(w, http.StatusConflict, "conflict", "A key ID conflicts with an existing managed signing key")
			return
		}
		if errors.Is(err, store.ErrInvalid) {
			Fail(w, badBody("invalid custom JWKS"))
			return
		}
		Fail(w, internalError(h, r, "replace custom signing keys", err))
		return
	}
	h.audit(r, "replace custom signing keys", "kids", ids)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(append([]byte(nil), validated...), '\n'))
}

func (h *Handlers) DeleteCustomSigningKeys(w http.ResponseWriter, r *http.Request) {
	tn := resolved(r)
	if tn == nil || tn.Reserved {
		Fail(w, errSystemTenant)
		return
	}
	set, err := h.Store.CustomSigningKeys().Get(r.Context(), tn.ID)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "inexistent_custom_signing_keys", "Custom signing keys do not exist")
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get custom signing keys for delete", err))
		return
	}
	ids, _ := signingrules.KeyIDs(set.JWKS)
	if err := h.Store.CustomSigningKeys().Delete(r.Context(), tn.ID); err != nil {
		Fail(w, internalError(h, r, "delete custom signing keys", err))
		return
	}
	h.audit(r, "delete custom signing keys", "kids", ids)
	w.WriteHeader(http.StatusNoContent)
}
