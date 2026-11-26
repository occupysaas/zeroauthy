package myorg

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Path is where the API is mounted on tenant hosts.
const Path = "/my-org/v1"

// MaxBody bounds request bodies.
const MaxBody = 64 << 10

// Handlers serves the My Organization API.
type Handlers struct {
	Store   store.Store
	Keys    *keys.Manager
	Wrapper keys.Wrapper
	// Actions delivers invitation emails.
	Actions *actions.Engine
	Now     func() time.Time
	Log     *slog.Logger
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

type handler func(w http.ResponseWriter, r *http.Request, c *Caller)

func forbiddenDetail(detail string) *Problem {
	return problem(http.StatusForbidden, "forbidden", "Forbidden", detail)
}

func (h *Handlers) with(scope string, next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, p := h.authenticate(r)
		if p != nil {
			writeProblem(w, r, p)
			return
		}
		if !c.Has(scope) {
			writeProblem(w, r, problem(http.StatusForbidden, "insufficient_scope", "Insufficient Scope", "The auth token lacks the required scope: "+scope+"."))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		next(w, r, c)
	}
}

// Routes is the router mounted at Path.
func (h *Handlers) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/config", h.with("read:my_org:configuration", h.getConfig))
	r.Get("/details", h.with("read:my_org:details", h.getDetails))
	r.Patch("/details", h.with("update:my_org:details", h.patchDetails))
	r.Get("/members", h.with("read:my_org:members", h.listMembers))
	r.Get("/members/{user_id}", h.with("read:my_org:members", h.getMember))
	r.Post("/delete-memberships", h.with("delete:my_org:memberships", h.deleteMemberships))
	r.Get("/members/{user_id}/roles", h.with("read:my_org:member_roles", h.notYet))
	r.Post("/members/{user_id}/roles", h.with("create:my_org:member_roles", h.notYet))
	r.Post("/members/{user_id}/unassign-roles", h.with("delete:my_org:member_roles", h.notYet))
	r.Get("/roles", h.with("read:my_org:member_roles", h.notYet))
	r.Get("/member-invitations", h.with("read:my_org:member_invitations", h.notYet))
	r.Post("/member-invitations", h.with("create:my_org:member_invitations", h.notYet))
	r.Get("/member-invitations/{invitation_id}", h.with("read:my_org:member_invitations", h.notYet))
	r.Get("/member-invitations/{invitation_id}/roles", h.with("read:my_org:member_roles", h.notYet))
	r.Post("/delete-member-invitations", h.with("delete:my_org:member_invitations", h.notYet))
	r.Get("/user-stores", h.with("read:my_org:user_stores", h.listUserStores))
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { writeProblem(w, r, notFound("Not found.")) })
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, problem(http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", "Method not allowed."))
	})
	return r
}

func (h *Handlers) notYet(w http.ResponseWriter, r *http.Request, _ *Caller) {
	writeProblem(w, r, problem(http.StatusNotImplemented, "not_implemented", "Not Implemented", "Not implemented yet."))
}
