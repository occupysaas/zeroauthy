package oauth

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type userAuthorization struct {
	API                 *store.ResourceServer
	Scopes, Permissions []string
	IncludePermissions  bool
}

// authorizeUserToken takes one current authorization snapshot. The caller
// still applies application policy and the original consent/refresh ceiling.
func (h *Handlers) authorizeUserToken(ctx context.Context, tid, uid string, rs *store.ResourceServer, scopes []string) (userAuthorization, *Error) {
	out := userAuthorization{API: rs, Scopes: scopes}
	if rs == nil || rs.IsSystem {
		return out, nil
	}
	snap, err := h.Store.RBAC().Snapshot(ctx, tid, uid, rs.Identifier)
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
