package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

// GetTenantSettings reads current settings rather than a process-local cache.
func (h *Handlers) GetTenantSettings(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetTenantSettingsParams) {
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	current, err := h.Store.Tenants().Get(r.Context(), resolved(r).ID)
	if err != nil {
		h.failTx(w, r, "get tenant settings", err)
		return
	}
	writeJSON(w, http.StatusOK, ProjectKeeping(tenantrules.Public(current), fields, include, nil))
}

// UpdateTenantSettings merges against the locked, freshly read tenant. The
// resolved request tenant may predate a concurrent settings update.
func (h *Handlers) UpdateTenantSettings(w http.ResponseWriter, r *http.Request) {
	raw, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	patch := make(map[string]any, len(raw))
	for key, value := range raw {
		dec := json.NewDecoder(bytes.NewReader(value))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			Fail(w, badBody("invalid JSON"))
			return
		}
		patch[key] = v
	}
	var out *store.Tenant
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		current, err := tx.Tenants().Get(r.Context(), resolved(r).ID)
		if err != nil {
			return err
		}
		if current.Reserved {
			return errSystemTenant
		}
		out, err = tenantrules.Apply(current, patch)
		if err != nil {
			return badBody("%s", err)
		}
		if _, ok := patch["default_audience"]; ok && out.DefaultAudience != "" {
			_, err := tx.ResourceServers().GetByIdentifier(r.Context(), out.ID, out.DefaultAudience)
			if errors.Is(err, store.ErrNotFound) {
				return badBody("default_audience must resolve within the tenant")
			}
			if err != nil {
				return err
			}
		}
		if _, ok := patch["default_directory"]; ok && out.DefaultDirectory != "" {
			c, err := tx.Connections().GetByName(r.Context(), out.ID, out.DefaultDirectory)
			if errors.Is(err, store.ErrNotFound) {
				return badBody("default_directory must resolve within the tenant")
			}
			if err != nil {
				return err
			}
			if c.Strategy != store.StrategyDatabase {
				return badBody("default_directory must be a supported database connection")
			}
		}
		return tx.Tenants().Update(r.Context(), out)
	})
	if err != nil {
		h.failTx(w, r, "update tenant settings", err)
		return
	}
	h.audit(r, "update tenant settings")
	writeJSON(w, http.StatusOK, tenantrules.Public(out))
}
