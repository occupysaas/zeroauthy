package oauth

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type userAuthorization struct {
	API                 *store.ResourceServer
	Scopes, Permissions []string
	IncludePermissions  bool
}

// authorizeUserToken uses permissions fixed before a bound Action flow, or a
// current snapshot when no flow captured them. API definition, application
// policy and the original consent/refresh ceiling are still checked at mint.
func (h *Handlers) authorizeUserToken(ctx context.Context, tid, uid string, rs *store.ResourceServer, scopes []string, frozen *actions.RBACSnapshot) (userAuthorization, *Error) {
	out := userAuthorization{API: rs, Scopes: scopes}
	if rs == nil || rs.IsSystem {
		return out, nil
	}
	var snap *store.AuthorizationSnapshot
	if frozen != nil {
		if frozen.Audience != rs.Identifier {
			return out, serverError()
		}
		current, err := h.Store.ResourceServers().GetByIdentifier(ctx, tid, rs.Identifier)
		if errors.Is(err, store.ErrNotFound) {
			return out, invalidGrant("the requested user or audience no longer exists")
		}
		if err != nil {
			return out, serverError()
		}
		snap = &store.AuthorizationSnapshot{API: current, Permissions: frozen.Permissions}
	}
	var err error
	if snap == nil {
		snap, err = h.Store.RBAC().Snapshot(ctx, tid, uid, rs.Identifier)
	}
	if snap != nil && snap.API != nil && snap.API.Identifier != rs.Identifier {
		return out, serverError()
	}
	if errors.Is(err, store.ErrNotFound) {
		return out, invalidGrant("the requested user or audience no longer exists")
	}
	if err != nil || snap == nil || snap.API == nil {
		h.log().ErrorContext(ctx, "load RBAC snapshot", "tenant", tid, "err", err)
		return out, serverError()
	}
	out.API = snap.API
	out.Scopes = userScopes(scopes, snap.API, slices.Contains(scopes, "offline_access") && snap.API.AllowOfflineAccess)

	if !snap.API.EnforcePolicies {
		return out, nil
	}
	out.Permissions = append([]string{}, snap.Permissions...)
	slices.Sort(out.Permissions)
	out.Permissions = slices.Compact(out.Permissions)
	out.IncludePermissions = strings.HasSuffix(snap.API.TokenDialect, "_authz")
	filtered := []string{}
	for _, s := range out.Scopes {
		if slices.Contains(oidcScopes, s) || s == "offline_access" || slices.Contains(out.Permissions, s) {
			filtered = append(filtered, s)
		}
	}
	out.Scopes = filtered
	return out, nil
}
