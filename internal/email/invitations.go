package email

import (
	"bytes"
	"context"
	"errors"
	htmltemplate "html/template"
	texttemplate "text/template"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var invitationText = texttemplate.Must(texttemplate.New("user_invitation.txt").Funcs(texttemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/user_invitation.txt"))
var invitationHTML = htmltemplate.Must(htmltemplate.New("user_invitation.html").Funcs(htmltemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/user_invitation.html"))

// SnapshotInvitation freezes presentation, template and transport selection inside
// the creation transaction. Ticket material stays in its separate bound envelope.
func (s *Service) SnapshotInvitation(ctx context.Context, tx store.Store, in *actions.InvitationDelivery) error {
	tmpl, err := tx.EmailTemplates().Get(ctx, in.TenantID, "user_invitation")
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if tmpl != nil {
		if enabled, ok := tmpl.Fields["enabled"].(bool); ok && !enabled {
			in.Disabled = true
		}
		in.TemplateFields = map[string]string{}
		for _, k := range []string{"from", "subject", "body"} {
			if v, ok := tmpl.Fields[k].(string); ok {
				in.TemplateFields[k] = v
			}
		}
	}
	provider, err := tx.EmailProviders().Get(ctx, in.TenantID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if provider != nil && provider.Enabled {
		in.Provider = provider
	}
	if in.NotificationHost != "" {
		domain, err := customdomain.PublicContext(ctx, tx, in.TenantID, in.NotificationHost)
		if err != nil {
			return err
		}
		if domain != nil {
			metadata := map[string]any{}
			for k, v := range domain.Metadata {
				metadata[k] = v
			}
			in.CustomDomain = map[string]any{"domain": domain.Domain, "domain_metadata": metadata}
		}
	}
	return nil
}

// DeliverInvitation returns a rendered custom Action event, or delivers through
// the ordinary transport. The caller runs returned events in this same job.
func (s *Service) DeliverInvitation(ctx context.Context, in actions.InvitationDelivery, active *store.OrganizationInvitation) (*actions.EmailInput, error) {
	if in.Disabled {
		return nil, nil
	}
	if active.TenantID != in.TenantID || active.OrganizationID != in.OrganizationID || active.ID != in.InvitationID || active.ClientID != in.ClientID {
		return nil, store.ErrInvalid
	}
	ticket, err := orglogin.OpenInvitationTicket(s.Wrapper, active)
	if err != nil {
		return nil, err
	}
	tenant := &store.Tenant{ID: in.TenantID, Name: in.TenantName, FriendlyName: in.TenantFriendlyName, SupportEmail: in.TenantSupportEmail, SupportURL: in.TenantSupportURL, CanonicalHost: in.NotificationHost}
	l := i18n.New(tenant, in.Language)
	orgName := in.OrganizationDisplayName
	if orgName == "" {
		orgName = in.OrganizationName
	}
	data := struct {
		L                                                *i18n.Localizer
		Inviter, Organization, Application, Expiry, Link string
	}{l, in.InviterName, orgName, in.ApplicationName, active.ExpiresAt.UTC().Format(time.RFC3339), ticket.URL}
	var text, html bytes.Buffer
	if err := invitationText.Execute(&text, data); err != nil {
		return nil, err
	}
	if err := invitationHTML.Execute(&html, data); err != nil {
		return nil, err
	}
	msg := Message{Type: "user_invitation", Locale: in.Language, ClientID: in.ClientID, To: active.InviteeEmail, Subject: l.T(i18n.KeyEmailInvitationSubject), Text: text.String(), HTML: html.String(), From: s.DefaultFrom}
	if in.TemplateFields != nil {
		vars, err := BuildRenderContext(tenantRenderMap(tenant), map[string]any{"email": active.InviteeEmail}, map[string]any{"name": in.ApplicationName, "clientID": in.ClientID}, in.CustomDomain, in.Language, ticket.URL)
		if err != nil {
			return nil, err
		}
		branding := map[string]any{}
		if b := in.OrganizationBranding; b != nil {
			if b.LogoURL != nil {
				branding["logo_url"] = *b.LogoURL
			}
			if b.Colors != nil {
				branding["colors"] = map[string]any{"primary": b.Colors.Primary, "page_background": b.Colors.PageBackground}
			}
		}
		vars["inviter"] = map[string]any{"name": in.InviterName}
		metadata := map[string]any{}
		for k, v := range in.OrganizationMetadata {
			metadata[k] = v
		}
		vars["organization"] = map[string]any{"id": in.OrganizationID, "name": in.OrganizationName, "display_name": in.OrganizationDisplayName, "branding": branding, "metadata": metadata}
		vars["expires_at"] = data.Expiry
		fields := map[string]string{"from": in.TemplateFields["from"], "subject": in.TemplateFields["subject"], "html": in.TemplateFields["body"]}
		if s.Renderer == nil {
			return nil, ErrServiceUnavailable
		}
		rendered, err := s.Renderer.Render(ctx, RenderInput{Fields: fields, Variables: vars})
		if err != nil {
			return nil, err
		}
		msg.From, msg.Subject, msg.HTML, msg.Text = rendered.From, rendered.Subject, rendered.HTML, htmlToText(rendered.HTML)
	}
	if msg.From == "" && in.Provider != nil {
		msg.From = in.Provider.DefaultFrom
	}
	if msg.From == "" {
		msg.From = s.DefaultFrom
	}
	if msg.From == "" {
		msg.From = "zeroauthy@localhost"
	}
	if err := validateMessage(msg.From, msg); err != nil {
		return nil, err
	}
	if in.Provider != nil && in.Provider.Name == "custom" {
		event := emailInput(in.TenantID, msg)
		event.SensitiveValues = []string{ticket.TicketID, ticket.URL}
		event.TenantInfo = tenant
		event.Client = &store.Client{TenantID: in.TenantID, ClientID: in.ClientID, Name: in.ApplicationName}
		return &event, nil
	}
	return nil, s.deliver(ctx, in.TenantID, msg, in.Provider)
}
