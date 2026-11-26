package myorg

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/orginvite"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type invitee struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

type createInvitations struct {
	Invitees []invitee `json:"invitees"`
	Inviter  *struct {
		Name string `json:"name"`
	} `json:"inviter"`
	IdentityProviderID string `json:"identity_provider_id"`
	UserStoreID        string `json:"user_store_id"`
	TTLSec             *int64 `json:"ttl_sec"`
}

func (h *Handlers) invitationView(ctx context.Context, in store.OrganizationInvitation) (map[string]any, error) {
	t, err := orglogin.OpenInvitationTicket(h.Wrapper, &in)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"id": in.ID, "organization_id": in.OrganizationID, "inviter": map[string]any{"name": in.InviterName}, "invitee": map[string]any{"email": in.InviteeEmail},
		"created_at": timeString(in.CreatedAt), "expires_at": timeString(in.ExpiresAt), "roles": nonNil(in.Roles), "invitation_url": t.URL, "ticket_id": t.TicketID}
	if in.ConnectionID != "" {
		key := "identity_provider_id"
		if conn, err := h.Store.Connections().Get(ctx, in.TenantID, in.ConnectionID); err == nil && conn.Strategy == store.StrategyDatabase {
			key = "user_store_id"
		}
		out[key] = in.ConnectionID
	}
	return out, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (h *Handlers) createInvitations(w http.ResponseWriter, r *http.Request, c *Caller) {
	var b createInvitations
	if p := decode(r, &b); p != nil {
		writeProblem(w, r, p)
		return
	}
	ctx := r.Context()
	fail := func(p *Problem) {
		h.event(r, c, "my_organization_api_invitation_failed")
		writeProblem(w, r, p)
	}
	if len(b.Invitees) < 1 || len(b.Invitees) > 10 {
		fail(badRequest("invalid_body", "invitees must hold 1 to 10 people.", ValidationError{Detail: "1 to 10", Field: "invitees", Source: "body"}))
		return
	}
	connID := b.UserStoreID
	if connID == "" {
		connID = b.IdentityProviderID
	}
	if connID == "" || (b.UserStoreID != "" && b.IdentityProviderID != "" && b.UserStoreID != b.IdentityProviderID) {
		fail(badRequest("invalid_body", "Name one user_store_id or identity_provider_id.", ValidationError{Detail: "required", Field: "user_store_id", Source: "body"}))
		return
	}
	var ttl int64
	if b.TTLSec != nil {
		ttl = *b.TTLSec
	}
	lifetime, err := orgrules.InvitationTTL(ttl)
	if err != nil || ttl < 0 {
		fail(badRequest("invalid_body", "ttl_sec must be 0 to 2592000.", ValidationError{Detail: "out of range", Field: "ttl_sec", Source: "body"}))
		return
	}
	landing := c.Config.InvitationLandingClientID
	if landing == "" {
		fail(badRequest("invalid_configuration", "The application's My Organization configuration has no invitation_landing_client_id."))
		return
	}
	inviter := c.User.Name
	if b.Inviter != nil && b.Inviter.Name != "" {
		inviter = b.Inviter.Name
	}
	if inviter == "" {
		inviter = c.User.Email
	}
	if len([]rune(inviter)) > 300 {
		fail(badRequest("invalid_body", "inviter.name is too long."))
		return
	}
	created := []any{}
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		hx := h.withStore(tx)
		oc, err := tx.Organizations().GetConnection(ctx, c.TenantID, c.Org.ID, connID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && !oc.IsEnabled) {
			return badRequest("invalid_body", "The user store or identity provider is not enabled for this organization.", ValidationError{Detail: "not enabled", Field: "user_store_id", Source: "body"})
		}
		if err != nil {
			return err
		}
		issuer := orginvite.Issuer{Wrapper: h.Wrapper, Actions: h.Actions}
		now := h.now()
		for i, person := range b.Invitees {
			if identity.CheckEmail(person.Email) != nil || len(person.Email) > 320 {
				return badRequest("invalid_body", "invitees["+strconv.Itoa(i)+"].email is not an email address.", ValidationError{Detail: "invalid email", Field: "invitees", Source: "body"})
			}
			roles := slices.Compact(slices.Sorted(slices.Values(person.Roles)))
			if len(person.Roles) > 10 || len(roles) != len(person.Roles) {
				return badRequest("invalid_body", "invitees["+strconv.Itoa(i)+"].roles must hold at most 10 distinct roles.")
			}
			if len(roles) > 0 {
				if err := hx.checkAssignable(ctx, c, "", roles); err != nil {
					return err
				}
			}
			email := identity.NormalizeLogin(person.Email)
			if err := hx.revokeInvitations(ctx, tx, c, email); err != nil {
				return err
			}
			in := &store.OrganizationInvitation{TenantID: c.TenantID, OrganizationID: c.Org.ID, ID: "uinv_" + secrets.RandomString(24), ClientID: landing, ConnectionID: connID,
				InviterName: inviter, InviteeEmail: email, Roles: roles, SendInvitationEmail: true, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(lifetime)}
			if len(in.Roles) == 0 {
				in.Roles = nil
			}
			if _, err := issuer.Issue(ctx, tx, in, r.Header.Get("auth0-custom-domain")); err != nil {
				var ie *orginvite.Error
				if errors.As(err, &ie) {
					return problem(ie.Status, ie.Code, http.StatusText(ie.Status), ie.Message)
				}
				return err
			}
			view, err := hx.invitationView(ctx, *in)
			if err != nil {
				return err
			}
			created = append(created, view)
		}
		return nil
	})
	if err != nil {
		h.event(r, c, "my_organization_api_invitation_failed")
		switch {
		case errors.Is(err, store.ErrNotFound):
			err = badRequest("invalid_body", "The landing application or a role does not exist.")
		case errors.Is(err, actions.ErrInvitationProviderConfiguration), errors.Is(err, actions.ErrEmailUnbound):
			err = problem(http.StatusServiceUnavailable, "email_provider_unavailable", "Service Unavailable", "The invitation email provider is unavailable.")
		}
		h.fail(w, r, "create invitations", err)
		return
	}
	h.event(r, c, "my_organization_api_invitation_succeeded")
	writeJSON(w, r, http.StatusCreated, created)
}

// revokeInvitations deletes email's pending invitations to the
// organization: a new invitation replaces them (the OpenAPI).
func (h *Handlers) revokeInvitations(ctx context.Context, tx store.Store, c *Caller, email string) error {
	page := 0
	for {
		res, err := tx.OrganizationsII().ListInvitations(ctx, c.TenantID, c.Org.ID, store.OrgPage{Page: page, PerPage: 100, Sort: "created_at:-1"})
		if err != nil {
			return err
		}
		for _, in := range res.Items {
			if in.InviteeEmail == email {
				if err := tx.OrganizationsII().DeleteInvitation(ctx, c.TenantID, c.Org.ID, in.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
					return err
				}
			}
		}
		if len(res.Items) < 100 {
			return nil
		}
		page++
	}
}

// pendingInvitations are the organization's unexpired invitations, sorted.
func (h *Handlers) pendingInvitations(ctx context.Context, c *Caller, sort string) ([]store.OrganizationInvitation, error) {
	out := []store.OrganizationInvitation{}
	now := h.now()
	for page := 0; ; page++ {
		res, err := h.Store.OrganizationsII().ListInvitations(ctx, c.TenantID, c.Org.ID, store.OrgPage{Page: page, PerPage: 100, Sort: sort})
		if err != nil {
			return nil, err
		}
		for _, in := range res.Items {
			if now.Before(in.ExpiresAt) {
				out = append(out, in)
			}
		}
		if len(res.Items) < 100 {
			return out, nil
		}
	}
}

func (h *Handlers) listInvitations(w http.ResponseWriter, r *http.Request, c *Caller) {
	p, prob := page(r)
	if prob != nil {
		writeProblem(w, r, prob)
		return
	}
	f, prob := fieldsOf(r)
	if prob != nil {
		writeProblem(w, r, prob)
		return
	}
	sort := r.URL.Query().Get("sort")
	if sort == "" {
		sort = "created_at:-1"
	}
	if sort != "created_at:-1" && sort != "created_at:1" {
		writeProblem(w, r, invalidQuery("sort", "sort must be created_at:1 or created_at:-1."))
		return
	}
	start, ok := parseOffset(p.From)
	if !ok {
		writeProblem(w, r, invalidQuery("from", "from is not a valid cursor."))
		return
	}
	all, err := h.pendingInvitations(r.Context(), c, sort)
	if err != nil {
		h.fail(w, r, "list invitations", err)
		return
	}
	items := []any{}
	for i := start; i < len(all) && len(items) < p.Take; i++ {
		v, err := h.invitationView(r.Context(), all[i])
		if err != nil {
			h.fail(w, r, "list invitations", err)
			return
		}
		items = append(items, f.apply(v))
	}
	out := map[string]any{"invitations": items}
	if next := start + len(items); next < len(all) {
		out["next"] = offsetCursor(next)
	}
	if p.IncludeTotals {
		out["total"], out["total_is_capped"] = min(len(all), totalCap), len(all) > totalCap
	}
	writeJSON(w, r, http.StatusOK, out)
}

func (h *Handlers) invitation(ctx context.Context, c *Caller, id string) (*store.OrganizationInvitation, error) {
	if len(id) > 100 {
		return nil, notFound("The invitation does not exist.")
	}
	in, err := h.Store.OrganizationsII().GetInvitation(ctx, c.TenantID, c.Org.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("The invitation does not exist.")
	}
	return in, err
}

func (h *Handlers) getInvitation(w http.ResponseWriter, r *http.Request, c *Caller) {
	f, prob := fieldsOf(r)
	if prob != nil {
		writeProblem(w, r, prob)
		return
	}
	in, err := h.invitation(r.Context(), c, chi.URLParam(r, "invitation_id"))
	if err != nil {
		h.fail(w, r, "get an invitation", err)
		return
	}
	v, err := h.invitationView(r.Context(), *in)
	if err != nil {
		h.fail(w, r, "get an invitation", err)
		return
	}
	writeJSON(w, r, http.StatusOK, f.apply(v))
}

func (h *Handlers) invitationRoles(w http.ResponseWriter, r *http.Request, c *Caller) {
	in, err := h.invitation(r.Context(), c, chi.URLParam(r, "invitation_id"))
	if err != nil {
		h.fail(w, r, "get invitation roles", err)
		return
	}
	roles := []any{}
	for _, id := range in.Roles {
		role, err := h.Store.RBAC().GetRole(r.Context(), c.TenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			h.fail(w, r, "get invitation roles", err)
			return
		}
		roles = append(roles, roleView(role))
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"roles": roles})
}

func (h *Handlers) deleteInvitations(w http.ResponseWriter, r *http.Request, c *Caller) {
	var b struct {
		Invitations []string `json:"invitations"`
	}
	if p := decode(r, &b); p != nil {
		writeProblem(w, r, p)
		return
	}
	ids := slices.Compact(slices.Sorted(slices.Values(b.Invitations)))
	if len(b.Invitations) < 1 || len(b.Invitations) > 10 || len(ids) != len(b.Invitations) {
		writeProblem(w, r, badRequest("invalid_body", "invitations must hold 1 to 10 distinct IDs.", ValidationError{Detail: "1 to 10 distinct", Field: "invitations", Source: "body"}))
		return
	}
	ctx := r.Context()
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		for _, id := range ids {
			if _, err := h.withStore(tx).invitation(ctx, c, id); err != nil {
				return err
			}
			if err := tx.OrganizationsII().DeleteInvitation(ctx, c.TenantID, c.Org.ID, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		h.event(r, c, "my_organization_api_invitation_failed")
		h.fail(w, r, "delete invitations", err)
		return
	}
	h.event(r, c, "my_organization_api_invitation_succeeded")
	w.Header().Set("x-correlation-id", correlationID(r))
	w.WriteHeader(http.StatusNoContent)
}
