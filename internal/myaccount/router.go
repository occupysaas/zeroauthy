package myaccount

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Path is where the API is mounted on tenant hosts.
const Path = "/me/v1"

// MaxBody bounds request bodies (attestations included).
const MaxBody = 64 << 10

// Handlers serves the My Account API.
type Handlers struct {
	Store store.Store
	Keys  *keys.Manager
	// Wrapper seals enrollment sessions (the master-key wrapper).
	Wrapper keys.Wrapper
	// MFA enrolls TOTP, email, phone and WebAuthn methods; nil disables them.
	MFA *mfa.Service
	// Passkeys enrolls passkeys and resolves RP IDs; nil disables WebAuthn.
	Passkeys *passkey.Service
	// Protection checks new passwords against breached-password detection.
	Protection *protection.Service
	// Logout ends the user's sessions after a password change.
	Logout *logout.Service
	// Actions runs post-change-password Actions.
	Actions           *actions.Engine
	TrustProxyHeaders bool
	Now               func() time.Time
	Log               *slog.Logger
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// handler is an operation: it runs for an authenticated caller holding
// the operation's scope.
type handler func(w http.ResponseWriter, r *http.Request, c *Caller)

func (h *Handlers) with(scope string, next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, p := h.authenticate(r)
		if p != nil {
			writeProblem(w, r, p)
			return
		}
		if !c.Has(scope) {
			writeProblem(w, r, forbidden(scope))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		next(w, r, c)
	}
}

// Routes is the router mounted at Path.
func (h *Handlers) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/factors", h.with("read:me:factors", h.listFactors))
	r.Get("/authentication-methods", h.with("read:me:authentication_methods", h.listMethods))
	r.Post("/authentication-methods", h.with("create:me:authentication_methods", h.createMethod))
	r.Get("/authentication-methods/{id}", h.with("read:me:authentication_methods", h.getMethod))
	r.Patch("/authentication-methods/{id}", h.with("update:me:authentication_methods", h.notImplemented))
	r.Delete("/authentication-methods/{id}", h.with("delete:me:authentication_methods", h.notImplemented))
	r.Post("/authentication-methods/{id}/verify", h.with("create:me:authentication_methods", h.verifyMethod))
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { writeProblem(w, r, notFound("Not found.")) })
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, problem(http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", "Method not allowed."))
	})
	return r
}

func (h *Handlers) notImplemented(w http.ResponseWriter, r *http.Request, _ *Caller) {
	writeProblem(w, r, problem(http.StatusNotImplemented, "not_implemented", "Not Implemented", "Not implemented yet."))
}
