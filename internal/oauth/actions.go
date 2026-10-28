package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type requestInfoKey struct{}

// withRequestInfo records the token request for event.request. The body is
// the request's parameters; the engine drops credentials from it.
func withRequestInfo(ctx context.Context, r *http.Request, ip string, form url.Values) context.Context {
	body := make(map[string]any, len(form))
	for k := range form {
		body[k] = form.Get(k)
	}
	lang, _, _ := strings.Cut(r.Header.Get("Accept-Language"), ",")
	lang, _, _ = strings.Cut(lang, ";")
	return context.WithValue(ctx, requestInfoKey{}, actions.RequestInfo{
		IP: ip, Hostname: r.Host, Method: r.Method, UserAgent: r.UserAgent(), Language: strings.TrimSpace(lang),
		Query: map[string]any{}, Body: body,
	})
}

func requestInfoFrom(ctx context.Context) actions.RequestInfo {
	ri, _ := ctx.Value(requestInfoKey{}).(actions.RequestInfo)
	return ri
}

// loginFlow is a token-endpoint grant that runs the post-login flow.
type loginFlow struct {
	user       *store.User
	connection *store.Connection // nil when unknown
	rs         *store.ResourceServer
	protocol   string
	requested  []string
	target     []string
}

// postLogin runs the tenant's post-login flow for a token-endpoint grant,
// where api.redirect.canRedirect() is false. A denial is 403 with the
// denial's code and reason (D-0053); a failed flow is server_error with a
// generic description (the execution ID is only logged, by the engine).
// Without an engine it returns no effects.
func (h *Handlers) postLogin(ctx context.Context, res tenant.Resolved, c *store.Client, f loginFlow) (*actions.Effects, *Error) {
	if h.Actions == nil {
		return nil, nil
	}
	result, err := h.Actions.PostLogin(ctx, actions.PostLoginInput{
		Tenant: res, Client: c, User: f.user, Connection: f.connection, Request: requestInfoFrom(ctx),
		Protocol: f.protocol, RequestedScopes: f.requested, TargetScopes: f.target, ResourceServer: f.rs,
	})
	if err != nil {
		var fe *actions.ErrFlow
		if !errors.As(err, &fe) {
			h.log().ErrorContext(ctx, "run post-login Actions", "tenant", res.Tenant.ID, "err", err)
		}
		return nil, serverError()
	}
	if d := result.Denied; d != nil {
		return nil, &Error{Status: http.StatusForbidden, Code: d.Code, Description: d.Reason}
	}
	return &result.Effects, nil
}

// targetScopes is scopes after the flow's transaction target-scope edits,
// kept within ceiling when one is given (a refresh token's scopes). The
// result is still filtered by API definition, client policy and RBAC.
func targetScopes(eff *actions.Effects, scopes, ceiling []string) []string {
	if eff == nil || eff.Target == nil {
		return scopes
	}
	out := []string{}
	for _, s := range eff.Target.Scopes {
		if ceiling == nil || slices.Contains(ceiling, s) {
			out = append(out, s)
		}
	}
	return out
}

// userConnection is the connection of the user's first identity, for
// event.connection; nil when it cannot be found.
func (h *Handlers) userConnection(ctx context.Context, tenantID string, u *store.User) (*store.Connection, *Error) {
	if h.Actions == nil || len(u.Identities) == 0 {
		return nil, nil
	}
	conn, err := h.Store.Connections().GetByName(ctx, tenantID, u.Identities[0].Connection)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load connection for Actions", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	return conn, nil
}

// openEffects opens the post-login effects sealed onto a code or device
// approval; a blob that does not open fails closed.
func (h *Handlers) openEffects(ctx context.Context, tenantID, purpose, hash string, sealed []byte) (*actions.Effects, *Error) {
	if len(sealed) == 0 {
		return nil, nil
	}
	eff, err := actions.OpenEffects(h.Wrapper, tenantID, purpose, sealed, hash)
	if err != nil {
		h.log().ErrorContext(ctx, "open Action effects", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	return eff, nil
}
