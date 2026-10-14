// Package server assembles zeroauthy's HTTP handler.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/zeroauthy/zeroauthy/api"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/oidc"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type Deps struct {
	Store    store.Store
	Keys     *keys.Manager
	Resolver *tenant.Resolver
	Sessions *session.Manager
	Log      *slog.Logger
}

// authAPI adapts the handler groups to the generated ServerInterface.
// The var _ assertion fails to compile when api/authentication.yaml gains
// an operation that has no forwarding method here.
type authAPI struct {
	oidc  *oidc.Handlers
	oauth *oauth.Handlers
	authz *authz.Handlers
}

func (a authAPI) Discovery(w http.ResponseWriter, r *http.Request)  { a.oidc.Discovery(w, r) }
func (a authAPI) Jwks(w http.ResponseWriter, r *http.Request)       { a.oidc.Jwks(w, r) }
func (a authAPI) OauthToken(w http.ResponseWriter, r *http.Request) { a.oauth.OauthToken(w, r) }

func (a authAPI) Authorize(w http.ResponseWriter, r *http.Request, _ authapi.AuthorizeParams) {
	a.authz.Authorize(w, r)
}

var _ authapi.ServerInterface = authAPI{}

func New(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, requestLog(d.Log), recoverer(d.Log))

	// Operational endpoints answer on any host.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := d.Store.Ping(ctx); err != nil {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(api.AuthenticationYAML)
	})
	r.Get("/docs", serveDocs)

	// Authentication API: every route is tenant-scoped.
	r.Group(func(tr chi.Router) {
		tr.Use(d.Resolver.Middleware)
		authapi.HandlerWithOptions(authAPI{
			oidc:  &oidc.Handlers{Keys: d.Keys, Log: d.Log},
			oauth: &oauth.Handlers{Store: d.Store, Log: d.Log, Minter: &oauth.Minter{Keys: d.Keys}},
			authz: &authz.Handlers{Store: d.Store, Sessions: d.Sessions, Log: d.Log},
		}, authapi.ChiServerOptions{
			BaseRouter: tr,
			ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
				httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
			},
		})
	})
	return r
}
