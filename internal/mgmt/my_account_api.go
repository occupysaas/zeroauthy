package mgmt

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// activateSystemAPI creates the tenant's My Account (Plan 42a, LR42a-4) or
// My Organization (Plan 42b) API when POST /resource-servers names its
// identifier. The system API's settings are fixed (apply); other fields of
// the body are ignored.
func (h *Handlers) activateSystemAPI(w http.ResponseWriter, r *http.Request, tn *store.Tenant, id string, apply func(*store.ResourceServer)) {
	rs := &store.ResourceServer{TenantID: tn.ID, ID: secrets.RandomHex(resourceServerIDBytes), Identifier: id, CreatedAt: h.now(), Origin: store.OriginAPI}
	apply(rs)
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := tx.ResourceServers().GetByIdentifier(r.Context(), tn.ID, id); err == nil {
			return errResourceServerConflict
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		err := tx.ResourceServers().Create(r.Context(), rs)
		if errors.Is(err, store.ErrConflict) {
			return errResourceServerConflict
		}
		return err
	})
	if err != nil {
		h.failTx(w, r, "activate a system API", err)
		return
	}
	logDetails(r, "activate a system API", "identifier", id, "id", rs.ID)
	view, err := h.resourceServerView(rs)
	if err != nil {
		Fail(w, internalError(h, r, "open the API signing secret", err))
		return
	}
	writeJSON(w, http.StatusCreated, view)
}
