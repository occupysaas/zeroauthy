package server

import (
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// cors applies CORS. Public metadata is readable from any origin. The
// token, device code, revoke, userinfo and dbconnections endpoints accept an origin only if one of the
// tenant's clients lists it in allowed_origins or web_origins. Runs after
// tenant resolution.
func cors(st store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration", "/.well-known/jwks.json":
				w.Header().Set("Access-Control-Allow-Origin", "*")
				next.ServeHTTP(w, r)
				return
			case "/oauth/token", "/oauth/device/code", "/oauth/revoke", "/userinfo", "/dbconnections/signup", "/dbconnections/change_password":
			default:
				next.ServeHTTP(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Add("Vary", "Origin")
			res, ok := tenant.FromContext(r.Context())
			if !ok || !originAllowed(r, st, res.Tenant.ID, origin) {
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r) // no CORS headers: the browser blocks the response
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
				if h := r.Header.Get("Access-Control-Request-Headers"); h != "" {
					w.Header().Set("Access-Control-Allow-Headers", h)
				}
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func originAllowed(r *http.Request, st store.Store, tenantID, origin string) bool {
	clients, err := st.Clients().List(r.Context(), tenantID)
	if err != nil {
		return false
	}
	for _, c := range clients {
		if slices.Contains(c.AllowedOrigins, origin) || slices.Contains(c.WebOrigins, origin) {
			return true
		}
	}
	return false
}

// mgmtCORS applies CORS to the Management and system APIs: only the system
// host's origin (the console) is allowed, on every tenant (design §6).
// A preflight from any other origin is 403; other requests from it get no
// CORS headers, so the browser blocks the response.
func mgmtCORS(systemOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Add("Vary", "Origin")
			preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
			if systemOrigin == "" || origin != systemOrigin {
				if preflight {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if preflight {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
