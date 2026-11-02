package mgmt

import (
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/resourceview"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
)

func (h *Handlers) userView(r *http.Request, u *store.User) (map[string]any, error) {
	methods, err := h.Store.MFA().ListAuthenticators(r.Context(), u.TenantID, u.UserID)
	if err != nil && !errors.Is(err, store.ErrMFAUnavailable) {
		return nil, internalError(h, r, "load user multifactor", err)
	}
	return resourceview.UserWithMFA(u, methods), nil
}
