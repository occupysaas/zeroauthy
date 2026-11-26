package email

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// AsyncApprovalTemplate is the template CIBA approval emails use (Plan 41c).
const AsyncApprovalTemplate = "async_approval"

// Built-in async_approval email, used when the tenant has not enabled its own.
const (
	defaultAsyncApprovalSubject = "Approve a sign-in request"
	defaultAsyncApprovalBody    = `<p>{{ application.name | escape }} asks you to approve a sign-in.</p>
<p>Request code: <strong>{{ binding_message | escape }}</strong></p>
<p>Check that this code matches the one shown by the application, then <a href="{{ url }}">review the request</a>.</p>
<p>If you did not expect this request, ignore this email.</p>`
)

// AsyncApprovalEmail is one CIBA approval email. URL is a working
// single-use credential and never logged.
type AsyncApprovalEmail struct {
	TenantID, ClientID, Language string
	User                         *store.User
	URL, BindingMessage          string
}

// SendAsyncApproval renders and delivers a CIBA approval email to the
// user's verified email: the tenant's async_approval template when it is
// enabled (Liquid variables application.name, url, binding_message and the
// standard ones), otherwise the built-in one.
func (s *Service) SendAsyncApproval(ctx context.Context, m AsyncApprovalEmail) error {
	if s.Store == nil || s.Renderer == nil || m.TenantID == "" || m.User == nil || m.User.Email == "" {
		return ErrServiceUnavailable
	}
	ctx = logscrub.WithCredentials(ctx, m.URL)
	fields := map[string]string{"subject": defaultAsyncApprovalSubject, "html": defaultAsyncApprovalBody}
	policy, err := s.Resolve(ctx, m.TenantID, AsyncApprovalTemplate)
	if err != nil {
		return err
	}
	if policy.Enabled && policy.Template != nil {
		if body, ok := policy.Template.Fields["body"].(string); ok && body != "" {
			fields = map[string]string{"html": body, "subject": defaultAsyncApprovalSubject}
			for _, key := range []string{"from", "subject"} {
				if v, ok := policy.Template.Fields[key].(string); ok && v != "" {
					fields[key] = v
				}
			}
		}
	}
	provider, err := s.providerSnapshot(ctx, m.TenantID)
	if err != nil {
		return err
	}
	tenant, err := s.Store.Tenants().Get(ctx, m.TenantID)
	if err != nil {
		return err
	}
	client, err := s.Store.Clients().Get(ctx, m.TenantID, m.ClientID)
	if err != nil {
		return err
	}
	app := map[string]any{"clientID": client.ClientID, "name": client.Name, "app_metadata": map[string]any{}}
	language := m.Language
	if language == "" {
		language = "en"
	}
	user := map[string]any{"email": m.User.Email, "user_id": m.User.UserID, "name": m.User.Name}
	vars, err := s.renderContext(ctx, m.TenantID, tenantRenderMap(tenant), user, app, language, m.URL)
	if err != nil {
		return err
	}
	vars["request_language"] = language
	vars["url"] = m.URL
	vars["binding_message"] = m.BindingMessage
	rendered, err := s.Renderer.Render(ctx, RenderInput{Fields: fields, Variables: vars})
	if err != nil {
		return err
	}
	msg := Message{Type: AsyncApprovalTemplate, Locale: language, ClientID: m.ClientID, From: rendered.From, To: m.User.Email,
		Subject: rendered.Subject, HTML: rendered.HTML, Text: htmlToText(rendered.HTML)}
	return s.deliver(ctx, m.TenantID, msg, provider)
}
