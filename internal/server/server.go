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
	"github.com/zeroauthy/zeroauthy/internal/dbconn"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/login"
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

	UserThrottle      *identity.Throttle
	IPThrottle        *identity.Throttle
	TrustProxyHeaders bool
}

// authAPI adapts the handler groups to the generated ServerInterface.
// The var _ assertion fails to compile when api/authentication.yaml gains
// an operation that has no forwarding method here.
type authAPI struct {
	oidc   *oidc.Handlers
	oauth  *oauth.Handlers
	authz  *authz.Handlers
	dbconn *dbconn.Handlers
}

func (a authAPI) Discovery(w http.ResponseWriter, r *http.Request)    { a.oidc.Discovery(w, r) }
func (a authAPI) Jwks(w http.ResponseWriter, r *http.Request)         { a.oidc.Jwks(w, r) }
func (a authAPI) OauthToken(w http.ResponseWriter, r *http.Request)   { a.oauth.OauthToken(w, r) }
func (a authAPI) OauthRevoke(w http.ResponseWriter, r *http.Request)  { a.oauth.OauthRevoke(w, r) }
func (a authAPI) Userinfo(w http.ResponseWriter, r *http.Request)     { a.oidc.Userinfo(w, r) }
func (a authAPI) UserinfoPost(w http.ResponseWriter, r *http.Request) { a.oidc.Userinfo(w, r) }

func (a authAPI) DbconnectionsSignup(w http.ResponseWriter, r *http.Request) { a.dbconn.Signup(w, r) }

func (a authAPI) Authorize(w http.ResponseWriter, r *http.Request, _ authapi.AuthorizeParams) {
	a.authz.Authorize(w, r)
}

func (a authAPI) Logout(w http.ResponseWriter, r *http.Request, _ authapi.LogoutParams) {
	a.oidc.Logout(w, r)
}

func (a authAPI) OidcLogout(w http.ResponseWriter, r *http.Request, _ authapi.OidcLogoutParams) {
	a.oidc.OidcLogout(w, r)
}
func (a authAPI) OidcLogoutPost(w http.ResponseWriter, r *http.Request) { a.oidc.OidcLogout(w, r) }

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

	az := &authz.Handlers{Store: d.Store, Sessions: d.Sessions, Log: d.Log}
	lg := &login.Handlers{
		Store: d.Store, Sessions: d.Sessions, Authz: az,
		Database:     &identity.Database{Store: d.Store},
		UserThrottle: d.UserThrottle, IPThrottle: d.IPThrottle,
		TrustProxyHeaders: d.TrustProxyHeaders, Log: d.Log,
	}

	// Authentication API: every route is tenant-scoped.
	r.Group(func(tr chi.Router) {
		tr.Use(d.Resolver.Middleware, cors(d.Store))
		authapi.HandlerWithOptions(authAPI{
			oidc: &oidc.Handlers{Keys: d.Keys, Store: d.Store, Sessions: d.Sessions, Log: d.Log},
			oauth: &oauth.Handlers{
				Store: d.Store, Log: d.Log, Minter: &oauth.Minter{Keys: d.Keys},
				Database:     &identity.Database{Store: d.Store},
				UserThrottle: d.UserThrottle, IPThrottle: d.IPThrottle,
				TrustProxyHeaders: d.TrustProxyHeaders,
			},
			authz: az,
			dbconn: &dbconn.Handlers{
				Store: d.Store, Database: &identity.Database{Store: d.Store},
				IPThrottle: d.IPThrottle, TrustProxyHeaders: d.TrustProxyHeaders, Log: d.Log,
			},
		}, authapi.ChiServerOptions{
			BaseRouter: tr,
			ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
				httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
			},
		})
		preflight := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
		tr.Options("/oauth/token", preflight)
		tr.Options("/oauth/revoke", preflight)
		tr.Options("/userinfo", preflight)
		tr.Options("/dbconnections/signup", preflight)
		tr.Options("/dbconnections/change_password", preflight)
		tr.Get("/u/login", lg.LoginPage)
		tr.Post("/u/login", lg.LoginSubmit)
		tr.Get("/u/signup", lg.SignupPage)
		tr.Post("/u/signup", lg.SignupSubmit)
	})
	return r
}
