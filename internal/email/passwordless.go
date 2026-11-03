package email

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// PasswordlessTemplate is the code-based template passwordless email codes use
// when the tenant has it enabled (D-0060 P19).
const PasswordlessTemplate = "auth_email_by_code"

// PasswordlessEmail is one passwordless code or magic-link email. The
// recipient need not be a user yet: users are created on verification.
// Code and Link are secrets and never logged.
type PasswordlessEmail struct {
	TenantID, ClientID, To, Language string
	Code, Link                       string
	// From, Subject and Body are the connection's email options (Liquid).
	From, Subject, Body string
}

// SendPasswordless renders and delivers a passwordless email. A code uses the
// tenant's auth_email_by_code template when it exists and is enabled; every
// other case uses the connection's own from, subject and body (P19). Delivery
// goes through the tenant's provider like every other email, and a failure
// logs fn.
func (s *Service) SendPasswordless(ctx context.Context, m PasswordlessEmail) error {
	if s.Store == nil || s.Renderer == nil || m.TenantID == "" || m.To == "" {
		return ErrServiceUnavailable
	}
	ctx = logscrub.WithCredentials(ctx, m.Code, m.Link)
	fields := map[string]string{"from": m.From, "subject": m.Subject, "html": m.Body}
	if m.Code != "" {
		policy, err := s.Resolve(ctx, m.TenantID, PasswordlessTemplate)
		if err != nil {
			return err
		}
		if policy.Enabled && policy.Template != nil {
			if body, ok := policy.Template.Fields["body"].(string); ok && body != "" {
				fields = map[string]string{"html": body}
				for _, key := range []string{"from", "subject"} {
					if v, ok := policy.Template.Fields[key].(string); ok {
						fields[key] = v
					}
				}
			}
		}
	}
	if fields["html"] == "" {
		return store.ErrInvalid
	}
	provider, err := s.providerSnapshot(ctx, m.TenantID)
	if err != nil {
		return err
	}
	tenant, err := s.Store.Tenants().Get(ctx, m.TenantID)
	if err != nil {
		return err
	}
	var app map[string]any
	if m.ClientID != "" {
		client, err := s.Store.Clients().Get(ctx, m.TenantID, m.ClientID)
		if err != nil {
			return err
		}
		app = map[string]any{"clientID": client.ClientID, "name": client.Name, "app_metadata": map[string]any{}}
	}
	language := m.Language
	if language == "" {
		language = "en"
	}
	vars, err := s.renderContext(ctx, m.TenantID, tenantRenderMap(tenant), map[string]any{"email": m.To}, app, language, m.Link)
	if err != nil {
		return err
	}
	vars["request_language"] = language
	vars["operation"] = "login"
	if m.Link != "" {
		vars["link"] = m.Link
	}
	rendered, err := s.Renderer.Render(ctx, RenderInput{Fields: fields, Variables: vars, OneTimeCode: m.Code})
	if err != nil {
		return err
	}
	msg := Message{Type: PasswordlessTemplate, Locale: language, ClientID: m.ClientID, From: rendered.From, To: m.To,
		Subject: rendered.Subject, HTML: rendered.HTML, Text: htmlToText(rendered.HTML)}
	return s.deliver(ctx, m.TenantID, msg, provider)
}
