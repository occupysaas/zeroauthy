// Package orginvite issues organization invitations (Plan 30) for the
// Management API and the My Organization API (Plan 42b): checks, ticket,
// storage and the invitation email, inside the caller's transaction.
package orginvite

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Error is a refusal the caller reports as is (Status, Code, Message).
type Error struct {
	Status        int
	Code, Message string
}

func (e *Error) Error() string { return e.Message }

func invalid(msg string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Payload validation error: " + msg}
}

// Issuer issues invitations.
type Issuer struct {
	Wrapper keys.Wrapper
	// Actions delivers the invitation email; nil refuses emailed invitations.
	Actions *actions.Engine
}

// Issue stores in, filled by the caller (IDs, times, client, connection,
// roles, inviter and invitee), in tx and queues its email. The client,
// connection and roles must exist; the client's login URI (or the
// tenant's default) must be HTTPS. customDomain is the
// auth0-custom-domain header, if any.
func (i Issuer) Issue(ctx context.Context, tx store.Store, in *store.OrganizationInvitation, customDomain string) (orglogin.InvitationTicket, error) {
	var ticket orglogin.InvitationTicket
	org, err := tx.Organizations().Get(ctx, in.TenantID, in.OrganizationID)
	if err != nil {
		return ticket, err
	}
	client, err := tx.Clients().Get(ctx, in.TenantID, in.ClientID)
	if err != nil {
		return ticket, err
	}
	if in.ConnectionID != "" {
		if _, err = tx.Connections().Get(ctx, in.TenantID, in.ConnectionID); err != nil {
			return ticket, err
		}
	}
	for _, role := range in.Roles {
		if _, err = tx.RBAC().GetRole(ctx, in.TenantID, role); err != nil {
			return ticket, err
		}
	}
	tn, err := tx.Tenants().Get(ctx, in.TenantID)
	if err != nil {
		return ticket, err
	}
	uri := client.InitiateLoginURI
	if uri == "" {
		uri, _ = tn.SettingsExtra["default_redirection_uri"].(string)
	}
	// A custom-domain header is always validated against this tenant; the app
	// login route itself remains the configured application URL.
	notificationHost, err := customdomain.SelectNotificationOrigin(ctx, tx, in.TenantID, customDomain)
	if err != nil {
		return ticket, &Error{Status: 503, Code: "custom_domain_unavailable", Message: "The selected custom domain is unavailable"}
	}
	if u, e := url.Parse(uri); e == nil && u.Host != "" {
		if d, e := tx.CustomDomains().GetHost(ctx, u.Hostname()); e == nil {
			if d.TenantID != in.TenantID {
				return ticket, invalid("login URI belongs to another tenant")
			}
			if _, e = customdomain.SelectNotificationOrigin(ctx, tx, in.TenantID, u.Host); e != nil {
				return ticket, invalid("login URI custom domain is unavailable")
			}
		} else if !errors.Is(e, store.ErrNotFound) {
			return ticket, e
		}
	}
	ticket, err = orglogin.IssueInvitationTicket(i.Wrapper, in, uri, org.Name)
	if err != nil {
		return ticket, invalid("a valid HTTPS application or tenant login URI is required")
	}
	send := in.SendInvitationEmail
	tmpl, err := tx.EmailTemplates().Get(ctx, in.TenantID, "user_invitation")
	if err == nil {
		if enabled, ok := tmpl.Fields["enabled"].(bool); ok && !enabled {
			send = false
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return ticket, err
	}
	if err = tx.OrganizationsII().CreateInvitation(ctx, in); err != nil {
		return ticket, err
	}
	if send {
		if i.Actions == nil {
			return ticket, &Error{Status: 503, Code: "email_service_unavailable", Message: "Invitation delivery is unavailable"}
		}
		return ticket, i.Actions.EnqueueInvitation(ctx, tx, actions.InvitationDelivery{TenantID: in.TenantID, OrganizationID: in.OrganizationID, InvitationID: in.ID, ClientID: in.ClientID, OrganizationName: org.Name, OrganizationDisplayName: org.DisplayName, ApplicationName: client.Name, InviterName: in.InviterName, NotificationHost: notificationHost, Language: Language(tn), TenantName: tn.Name, TenantFriendlyName: tn.FriendlyName, TenantSupportEmail: tn.SupportEmail, TenantSupportURL: tn.SupportURL, OrganizationBranding: org.Branding, OrganizationMetadata: org.Metadata})
	}
	return ticket, nil
}

// Language is the invitation email's language: the tenant's first enabled
// locale, else English.
func Language(tn *store.Tenant) string {
	if len(tn.EnabledLocales) > 0 {
		return tn.EnabledLocales[0]
	}
	return "en"
}
