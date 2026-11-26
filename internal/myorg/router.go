package myorg

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"log/slog"
	"net/http"
	"strings"
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

// TXTResolver is the part of customdomain.DNSResolver that domain
// verification uses.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Handlers serves the My Organization API.
type Handlers struct {
	Store   store.Store
	Keys    *keys.Manager
	Wrapper keys.Wrapper
	// Actions delivers invitation emails.
	Actions *actions.Engine
	// DNS looks up domain verification records (LR42b-16): the deployment's
	// bounded resolver. Without one, verification answers 503.
	DNS TXTResolver
	// Writes is the Management API that identity provider and provisioning
	// writes go through (LR42b-18), so its validation, sealing and logs apply.
	Writes *mgmt.Handlers
	Now    func() time.Time
	Log    *slog.Logger
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

// with authenticates, requires every space-separated scope in scope, bounds
// the body and calls next.
func (h *Handlers) with(scope string, next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, p := h.authenticate(r)
		if p != nil {
			writeProblem(w, r, p)
			return
		}
		for _, need := range strings.Fields(scope) {
			if !c.Has(need) {
				writeProblem(w, r, problem(http.StatusForbidden, "insufficient_scope", "Insufficient Scope", "The auth token lacks the required scopes: "+strings.Join(strings.Fields(scope), ", ")+"."))
				return
			}
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
	r.Get("/members/{user_id}/roles", h.with("read:my_org:member_roles", h.listMemberRoles))
	r.Post("/members/{user_id}/roles", h.with("create:my_org:member_roles", h.assignRoles))
	r.Post("/members/{user_id}/unassign-roles", h.with("delete:my_org:member_roles", h.unassignRoles))
	r.Get("/roles", h.with("read:my_org:member_roles", h.listRoles))
	r.Get("/member-invitations", h.with("read:my_org:member_invitations", h.listInvitations))
	r.Post("/member-invitations", h.with("create:my_org:member_invitations", h.createInvitations))
	r.Get("/member-invitations/{invitation_id}", h.with("read:my_org:member_invitations", h.getInvitation))
	r.Get("/member-invitations/{invitation_id}/roles", h.with("read:my_org:member_roles", h.invitationRoles))
	r.Post("/delete-member-invitations", h.with("delete:my_org:member_invitations", h.deleteInvitations))
	r.Get("/user-stores", h.with("read:my_org:user_stores", h.listUserStores))
	// Phase B (D-0221).
	r.Get("/config/identity-providers", h.with("read:my_org:configuration", h.getIdPConfig))
	r.Get("/domains", h.with("read:my_org:domains", h.listDomains))
	r.Post("/domains", h.with("create:my_org:domains", h.createDomain))
	r.Get("/domains/{domain_id}", h.with("read:my_org:domains", h.getDomain))
	r.Delete("/domains/{domain_id}", h.with("delete:my_org:domains", h.deleteDomain))
	r.Post("/domains/{domain_id}/verify", h.with("update:my_org:domains", h.verifyDomain))
	r.Get("/domains/{domain_id}/identity-providers", h.with("read:my_org:domains read:my_org:identity_providers", h.domainIdPs))
	r.Get("/identity-providers", h.with("read:my_org:identity_providers", h.listIdPs))
	r.Post("/identity-providers", h.with("create:my_org:identity_providers", h.createIdP))
	r.Get("/identity-providers/{idp_id}", h.with("read:my_org:identity_providers", h.getIdP))
	r.Patch("/identity-providers/{idp_id}", h.with("update:my_org:identity_providers", h.updateIdP))
	r.Delete("/identity-providers/{idp_id}", h.with("delete:my_org:identity_providers", h.deleteIdP))
	r.Put("/identity-providers/{idp_id}/update-attributes", h.with("update:my_org:identity_providers", h.refreshIdPAttributes))
	r.Post("/identity-providers/{idp_id}/detach", h.with("update:my_org:identity_providers_detach", h.detachIdP))
	r.Post("/identity-providers/{idp_id}/domains", h.with("create:my_org:identity_providers_domains", h.addIdPDomain))
	r.Delete("/identity-providers/{idp_id}/domains/{domain}", h.with("delete:my_org:identity_providers_domains", h.removeIdPDomain))
	r.Get("/identity-providers/{idp_id}/provisioning", h.with("read:my_org:identity_providers_provisioning", h.getProvisioning))
	r.Post("/identity-providers/{idp_id}/provisioning", h.with("create:my_org:identity_providers_provisioning", h.createProvisioning))
	r.Delete("/identity-providers/{idp_id}/provisioning", h.with("delete:my_org:identity_providers_provisioning", h.deleteProvisioning))
	r.Put("/identity-providers/{idp_id}/provisioning/update-attributes", h.with("update:my_org:identity_providers_provisioning", h.refreshProvisioningAttributes))
	r.Get("/identity-providers/{idp_id}/provisioning/scim-tokens", h.with("read:my_org:identity_providers_scim_tokens", h.listSCIMTokens))
	r.Post("/identity-providers/{idp_id}/provisioning/scim-tokens", h.with("create:my_org:identity_providers_scim_tokens", h.createSCIMToken))
	r.Get("/identity-providers/{idp_id}/provisioning/scim-tokens/{idp_scim_token_id}", h.with("read:my_org:identity_providers_scim_tokens", h.getSCIMToken))
	r.Delete("/identity-providers/{idp_id}/provisioning/scim-tokens/{idp_scim_token_id}", h.with("delete:my_org:identity_providers_scim_tokens", h.deleteSCIMToken))
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { writeProblem(w, r, notFound("Not found.")) })
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, problem(http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", "Method not allowed."))
	})
	return r
}
