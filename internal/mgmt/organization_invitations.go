package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var errOrganizationsIIUnavailable = &Error{Status: 501, Code: "organizations_ii_unavailable", Message: "The storage plugin does not support OrganizationsII"}

func (h *Handlers) orgIIAvailable(w http.ResponseWriter, r *http.Request) bool {
	if c, ok := h.Store.(store.OrganizationsIISupporter); ok {
		if err := c.CheckOrganizationsIISupport(r.Context()); err != nil {
			h.orgIIError(w, r, err)
			return false
		}
	}
	if !store.OrganizationsIISupported(h.Store) {
		Fail(w, errOrganizationsIIUnavailable)
		return false
	}
	return true
}
func (h *Handlers) orgIIError(w http.ResponseWriter, r *http.Request, err error) {
	var typed *Error
	switch {
	case errors.As(err, &typed):
		Fail(w, typed)
	case errors.Is(err, actions.ErrInvitationProviderConfiguration), errors.Is(err, actions.ErrEmailUnbound):
		Fail(w, &Error{Status: 503, Code: "email_provider_unavailable", Message: "Invitation email provider is unavailable"})
	case errors.Is(err, store.ErrOrganizationsIIUnavailable):
		Fail(w, errOrganizationsIIUnavailable)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, &Error{Status: 404, Code: "not_found", Message: "The resource does not exist"})
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrPrecondition):
		Fail(w, &Error{Status: 409, Code: "conflict", Message: "The mutation conflicts with current state"})
	case errors.Is(err, store.ErrInvalid):
		Fail(w, badBody("invalid invitation"))
	default:
		Fail(w, internalError(h, r, "organization invitation", err))
	}
}
func invitationOrg(r *http.Request, st store.Store, id string) (*store.Organization, error) {
	if !orgrules.ValidID(id) {
		return nil, errOrganizationURI
	}
	return st.Organizations().Get(r.Context(), resolved(r).ID, id)
}
func readInvitation(r *http.Request) (*store.OrganizationInvitation, int64, error) {
	body, err := decodeObject(r)
	if err != nil {
		return nil, 0, err
	}
	if err = checkBodyText(body); err != nil {
		return nil, 0, err
	}
	in := &store.OrganizationInvitation{SendInvitationEmail: true}
	var ttl int64
	for k, v := range body {
		if isNull(v) {
			return nil, 0, badBody("%s cannot be null", k)
		}
		switch k {
		case "inviter", "invitee":
			var nested map[string]json.RawMessage
			if decodeStrict(v, &nested) != nil {
				return nil, 0, badBody("%s must be an object", k)
			}
			name := "name"
			dest := &in.InviterName
			if k == "invitee" {
				name = "email"
				dest = &in.InviteeEmail
			}
			if len(nested) != 1 || decodeString(nested[name], dest) != nil || *dest == "" {
				return nil, 0, badBody("%s.%s is required", k, name)
			}
		case "client_id":
			err = decodeString(v, &in.ClientID)
		case "connection_id":
			err = decodeString(v, &in.ConnectionID)
			if err == nil && !connectionID.MatchString(in.ConnectionID) {
				err = store.ErrInvalid
			}
		case "roles":
			err = decodeStrict(v, &in.Roles)
			if err == nil && (len(in.Roles) == 0 || len(in.Roles) > orgrules.Limit("roles_per_member_max") || slices.Contains(in.Roles, "")) {
				err = store.ErrInvalid
			}
			in.Roles = slices.Compact(slices.Sorted(slices.Values(in.Roles)))
		case "user_metadata", "app_metadata":
			var m map[string]any
			err = decodeStrict(v, &m)
			if err == nil {
				err = identity.CheckMetadata(k, m)
			}
			if k == "user_metadata" {
				in.UserMetadata = m
			} else {
				in.AppMetadata = m
			}
		case "ttl_sec":
			err = json.Unmarshal(v, &ttl)
		case "send_invitation_email":
			err = decodeStrict(v, &in.SendInvitationEmail)
		default:
			return nil, 0, badBody("unknown property %q", k)
		}
		if err != nil {
			return nil, 0, badBody("invalid %s", k)
		}
	}
	if in.InviterName == "" || utf8.RuneCountInString(in.InviterName) > 300 || identity.CheckEmail(in.InviteeEmail) != nil || in.ClientID == "" {
		return nil, 0, badBody("inviter, invitee and client_id are required")
	}
	if _, err = orgrules.InvitationTTL(ttl); err != nil {
		return nil, 0, badBody("invalid ttl_sec")
	}
	in.InviteeEmail = identity.NormalizeLogin(in.InviteeEmail)
	return in, ttl, nil
}
func (h *Handlers) CreateOrganizationInvitation(w http.ResponseWriter, r *http.Request, id string) {
	if !h.orgIIAvailable(w, r) {
		return
	}
	in, ttl, err := readInvitation(r)
	if err != nil {
		Fail(w, err)
		return
	}
	lifetime, _ := orgrules.InvitationTTL(ttl)
	in.TenantID, in.OrganizationID, in.ID = resolved(r).ID, id, "uinv_"+secrets.RandomString(24)
	in.CreatedAt = h.now()
	in.UpdatedAt = in.CreatedAt
	in.ExpiresAt = in.CreatedAt.Add(lifetime)
	var ticket orglogin.InvitationTicket
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		org, err := invitationOrg(r, tx, id)
		if err != nil {
			return err
		}
		client, err := tx.Clients().Get(r.Context(), in.TenantID, in.ClientID)
		if err != nil {
			return err
		}
		if in.ConnectionID != "" {
			if _, err = tx.Connections().Get(r.Context(), in.TenantID, in.ConnectionID); err != nil {
				return err
			}
		}
		for _, role := range in.Roles {
			if _, err = tx.RBAC().GetRole(r.Context(), in.TenantID, role); err != nil {
				return err
			}
		}
		tn, err := tx.Tenants().Get(r.Context(), in.TenantID)
		if err != nil {
			return err
		}
		uri := client.InitiateLoginURI
		if uri == "" {
			uri, _ = tn.SettingsExtra["default_redirection_uri"].(string)
		}
		// A custom-domain header is always validated against this tenant; the app
		// login route itself remains the configured application URL.
		notificationHost, err := customdomain.SelectNotificationOrigin(r.Context(), tx, in.TenantID, r.Header.Get(CustomDomainHeader))
		if err != nil {
			return &Error{Status: 503, Code: "custom_domain_unavailable", Message: "The selected custom domain is unavailable"}
		}
		if u, e := url.Parse(uri); e == nil && u.Host != "" {
			if d, e := tx.CustomDomains().GetHost(r.Context(), u.Hostname()); e == nil {
				if d.TenantID != in.TenantID {
					return badBody("login URI belongs to another tenant")
				}
				if _, e = customdomain.SelectNotificationOrigin(r.Context(), tx, in.TenantID, u.Host); e != nil {
					return badBody("login URI custom domain is unavailable")
				}
			} else if !errors.Is(e, store.ErrNotFound) {
				return e
			}
		}
		ticket, err = orglogin.IssueInvitationTicket(h.Wrapper, in, uri, org.Name)
		if err != nil {
			return badBody("a valid HTTPS application or tenant login URI is required")
		}
		send := in.SendInvitationEmail
		tmpl, err := tx.EmailTemplates().Get(r.Context(), in.TenantID, "user_invitation")
		if err == nil {
			if enabled, ok := tmpl.Fields["enabled"].(bool); ok && !enabled {
				send = false
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err = tx.OrganizationsII().CreateInvitation(r.Context(), in); err != nil {
			return err
		}
		if send {
			if h.Actions == nil {
				return &Error{Status: 503, Code: "email_service_unavailable", Message: "Invitation delivery is unavailable"}
			}
			return h.Actions.EnqueueInvitation(r.Context(), tx, actions.InvitationDelivery{TenantID: in.TenantID, OrganizationID: id, InvitationID: in.ID, ClientID: in.ClientID, OrganizationName: org.Name, OrganizationDisplayName: org.DisplayName, ApplicationName: client.Name, InviterName: in.InviterName, NotificationHost: notificationHost, Language: invitationLanguage(tn), TenantName: tn.Name, TenantFriendlyName: tn.FriendlyName, TenantSupportEmail: tn.SupportEmail, TenantSupportURL: tn.SupportURL, OrganizationBranding: org.Branding, OrganizationMetadata: org.Metadata})
		}
		return nil
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	h.audit(r, "create organization invitation", "organization_id", id, "invitation_id", in.ID)
	writeJSON(w, 200, invitationView(*in, ticket))
}
func invitationView(in store.OrganizationInvitation, t orglogin.InvitationTicket) map[string]any {
	out := map[string]any{"id": in.ID, "organization_id": in.OrganizationID, "client_id": in.ClientID, "inviter": map[string]any{"name": in.InviterName}, "invitee": map[string]any{"email": in.InviteeEmail}, "created_at": in.CreatedAt.UTC(), "expires_at": in.ExpiresAt.UTC(), "ticket_id": t.TicketID, "invitation_url": t.URL}
	if in.ConnectionID != "" {
		out["connection_id"] = in.ConnectionID
	}
	if len(in.Roles) > 0 {
		out["roles"] = in.Roles
	}
	if in.UserMetadata != nil {
		out["user_metadata"] = in.UserMetadata
	}
	if in.AppMetadata != nil {
		out["app_metadata"] = in.AppMetadata
	}
	return out
}
func validInvitationID(id string) bool {
	return strings.HasPrefix(id, "uinv_") && len(id) > 5 && len(id) <= 100 && storableText(id) && !strings.ContainsAny(id, " /?#")
}
func (h *Handlers) GetOrganizationInvitation(w http.ResponseWriter, r *http.Request, id, invitationID string) {
	if !h.orgIIAvailable(w, r) {
		return
	}
	if !validInvitationID(invitationID) {
		Fail(w, &Error{Status: 400, Code: "invalid_uri", Message: "Invalid invitation ID"})
		return
	}
	if _, _, err := orgQuery(r, "fields", "include_fields"); err != nil {
		Fail(w, err)
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	for _, f := range fields {
		if !slices.Contains(invitationFields, f) {
			Fail(w, badQuery("invalid field"))
			return
		}
	}

	var out map[string]any
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := invitationOrg(r, tx, id); err != nil {
			return err
		}
		in, err := tx.OrganizationsII().GetInvitation(r.Context(), resolved(r).ID, id, invitationID)
		if err != nil {
			return err
		}
		ticket, err := orglogin.OpenInvitationTicket(h.Wrapper, in)
		if err != nil {
			return err
		}
		out = invitationView(*in, ticket)
		return nil
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	writeJSON(w, 200, Project(out, fields, include))
}
func (h *Handlers) DeleteOrganizationInvitation(w http.ResponseWriter, r *http.Request, id, invitationID string) {
	if !h.orgIIAvailable(w, r) {
		return
	}
	if !validInvitationID(invitationID) {
		Fail(w, &Error{Status: 400, Code: "invalid_uri", Message: "Invalid invitation ID"})
		return
	}
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := invitationOrg(r, tx, id); err != nil {
			return err
		}
		return tx.OrganizationsII().DeleteInvitation(r.Context(), resolved(r).ID, id, invitationID)
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	w.WriteHeader(204)
}
func (h *Handlers) ListOrganizationInvitations(w http.ResponseWriter, r *http.Request, id string) {
	if !h.orgIIAvailable(w, r) {
		return
	}
	p, _, err := orgQuery(r, "page", "per_page", "include_totals", "fields", "include_fields", "sort")
	if err != nil {
		Fail(w, err)
		return
	}
	p.Sort = r.URL.Query().Get("sort")
	if p.Sort == "" {
		p.Sort = "created_at:-1"
	}
	if p.Sort != "created_at:-1" && p.Sort != "created_at:1" {
		Fail(w, badQuery("invalid sort"))
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	for _, f := range fields {
		if !slices.Contains(invitationFields, f) {
			Fail(w, badQuery("invalid field"))
			return
		}
	}
	items := make([]map[string]any, 0)
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := invitationOrg(r, tx, id); err != nil {
			return err
		}
		res, err := tx.OrganizationsII().ListInvitations(r.Context(), resolved(r).ID, id, p)
		if err != nil {
			return err
		}
		for _, in := range res.Items {
			ticket, err := orglogin.OpenInvitationTicket(h.Wrapper, &in)
			if err != nil {
				return err
			}
			items = append(items, Project(invitationView(in, ticket), fields, include))
		}
		return nil
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	if p.IncludeTotals {
		writeJSON(w, 200, map[string]any{"invitations": items, "start": p.Page * p.PerPage, "limit": p.PerPage})
		return
	}
	writeJSON(w, 200, items)
}

func invitationLanguage(tn *store.Tenant) string {
	if len(tn.EnabledLocales) > 0 {
		return tn.EnabledLocales[0]
	}
	return "en"
}

var invitationFields = []string{"id", "organization_id", "inviter", "invitee", "created_at", "expires_at", "client_id", "connection_id", "roles", "ticket_id", "invitation_url", "user_metadata", "app_metadata"}
