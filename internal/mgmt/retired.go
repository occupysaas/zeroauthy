package mgmt

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

// GetRules preserves the finite collection export surface. Rule scripts are
// retired and are neither stored nor executed by zeroauthy.
func (h *Handlers) GetRules(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetRulesParams) {
	page, perPage, totals, err := Page(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, _, err := Fields(r); err != nil {
		Fail(w, err)
		return
	}
	if _, err := boolParam(r, "enabled", false); err != nil {
		Fail(w, err)
		return
	}
	WriteList(w, "rules", []map[string]any{}, page, perPage, totals)
}

// GetRulesConfigs exposes only the documented collection shape with no
// values; writes and per-key operations are intentionally absent.
func (h *Handlers) GetRulesConfigs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []map[string]any{})
}

// GetHooks preserves the finite collection export surface. Hook scripts are
// retired and are neither stored nor executed by zeroauthy.
func (h *Handlers) GetHooks(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetHooksParams) {
	page, perPage, totals, err := Page(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, _, err := Fields(r); err != nil {
		Fail(w, err)
		return
	}
	if _, err := boolParam(r, "enabled", false); err != nil {
		Fail(w, err)
		return
	}
	WriteList(w, "hooks", []map[string]any{}, page, perPage, totals)
}
