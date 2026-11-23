package samlidp

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// wsfedSignOut handles wsignout1.0 and wsignoutcleanup1.0 (Task 4).
func (h *Handler) wsfedSignOut(w http.ResponseWriter, r *http.Request, res tenant.Resolved, _ *store.Client, _ WSFedParams) {
	h.page(w, r, res, http.StatusBadRequest, "WS-Federation sign-out is not supported yet.")
}

// recordWSFedParticipant records the relying party on the session (Task 4).
func (h *Handler) recordWSFedParticipant(*http.Request, tenant.Resolved, *store.Client, *store.LoginSession, string) {}
