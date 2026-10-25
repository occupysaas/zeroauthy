package email

import (
	"context"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"
	"time"

	xhtml "golang.org/x/net/html"

	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var ErrProviderConfiguration = errors.New("email: tenant provider configuration is invalid")
var ErrServiceUnavailable = errors.New("email: delivery service is unavailable")

type Event struct {
	TenantID, UserID, ClientID, Template, Language, URL string
	Variables                                           map[string]any
}
type Policy struct {
	Enabled                bool
	Template               *store.EmailTemplate
	Lifetime               time.Duration
	ResultURL              string
	IncludeEmailInRedirect bool
}
type ProviderFactory interface {
	New(context.Context, string, int64, providers.Config) (providers.Transport, error)
}
type Service struct {
	Store       store.Store
	Wrapper     keys.Wrapper
	Renderer    Renderer
	Providers   ProviderFactory
	Fallback    Mailer
	DefaultFrom string
	Now         func() time.Time
}

func (s *Service) clock() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Resolve returns effective options for the named active flow. An absent
// record deliberately leaves localized legacy messages and flow lifetimes in
// charge; a stored disabled record suppresses delivery.
func (s *Service) Resolve(ctx context.Context, tenantID, name string) (Policy, error) {
	if s.Store == nil || tenantID == "" || name == "" {
		return Policy{}, ErrServiceUnavailable
	}
	t, err := s.Store.EmailTemplates().Get(ctx, tenantID, name)
	if errors.Is(err, store.ErrNotFound) {
		return Policy{Enabled: true}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	p := Policy{Enabled: true, Template: t}
	if enabled, ok := t.Fields["enabled"].(bool); ok {
		p.Enabled = enabled
	}
	if raw, ok := t.Fields["urlLifetimeInSeconds"]; ok && raw != nil {
		seconds, valid := wholeSeconds(raw)
		if !valid || seconds < 0 || seconds > 604800 {
			return Policy{}, store.ErrInvalid
		}
		p.Lifetime = time.Duration(seconds) * time.Second
	}
	if raw, ok := t.Fields["resultUrl"].(string); ok {
		p.ResultURL = raw
	}
	if raw, ok := t.Fields["includeEmailInRedirect"].(bool); ok {
		p.IncludeEmailInRedirect = raw
	}
	return p, nil
}

// SendMessage chooses the current tenant provider or the configured global
// mailer. It snapshots the provider before delivery and never falls back after
// a tenant-provider failure.
func (s *Service) SendMessage(ctx context.Context, tenantID string, msg Message) error {
	provider, err := s.providerSnapshot(ctx, tenantID)
	if err != nil {
		return err
	}
	return s.deliver(ctx, tenantID, msg, provider)
}

func (s *Service) providerSnapshot(ctx context.Context, tenantID string) (*store.EmailProvider, error) {
	if s.Store == nil || tenantID == "" {
		return nil, ErrServiceUnavailable
	}
	p, err := s.Store.EmailProviders().Get(ctx, tenantID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !p.Enabled {
		return nil, nil
	}
	return p, nil
}

func (s *Service) deliver(ctx context.Context, tenantID string, msg Message, p *store.EmailProvider) error {
	if p == nil {
		if s.Fallback == nil {
			return ErrServiceUnavailable
		}
		if msg.From != "" {
			if err := validateMessage(msg.From, msg); err != nil {
				return err
			}
		} else if err := validateEnvelope(msg); err != nil {
			return err
		}
		return s.Fallback.Send(ctx, msg)
	}
	from := msg.From
	if from == "" {
		from = p.DefaultFrom
	}
	if from == "" {
		from = s.DefaultFrom
	}
	if from == "" {
		from = "zeroauthy@localhost"
	}
	msg.From = from
	if err := validateMessage(from, msg); err != nil {
		return err
	}
	if s.Wrapper == nil || s.Providers == nil {
		return ErrServiceUnavailable
	}
	plain, err := keys.OpenEmailProvider(s.Wrapper, p.TenantID, p.Name, p.SealedCredentials)
	if err != nil {
		return ErrProviderConfiguration
	}
	credentials := map[string]any{}
	if err = json.Unmarshal(plain, &credentials); err != nil {
		return ErrProviderConfiguration
	}
	settings := cloneConfigMap(p.PublicConfig)
	for k, v := range settings {
		if _, exists := credentials[k]; !exists {
			credentials[k] = v
		}
	}
	transport, err := s.Providers.New(ctx, tenantID, p.Revision, providers.Config{Name: p.Name, Credentials: credentials, Settings: settings})
	if err != nil {
		return ErrProviderConfiguration
	}
	if err = transport.Send(ctx, providers.Message{From: msg.From, To: msg.To, Subject: msg.Subject, Text: msg.Text, HTML: msg.HTML}); err != nil {
		return err
	}
	return nil
}

// Send renders an enabled stored template for the canonical tenant user.
// Legacy flows without a record use SendMessage with their existing localized
// message so their established content and timing remain unchanged.
func (s *Service) Send(ctx context.Context, event Event) error {
	if event.TenantID == "" || event.UserID == "" || event.Template == "" {
		return store.ErrInvalid
	}
	provider, err := s.providerSnapshot(ctx, event.TenantID)
	if err != nil {
		return err
	}
	policy, err := s.Resolve(ctx, event.TenantID, event.Template)
	if err != nil {
		return err
	}
	if !policy.Enabled {
		return nil
	}
	if policy.Template == nil {
		return store.ErrNotFound
	}
	if s.Renderer == nil {
		return ErrServiceUnavailable
	}
	user, err := s.Store.Users().Get(ctx, event.TenantID, event.UserID)
	if err != nil {
		return err
	}
	tenant, err := s.Store.Tenants().Get(ctx, event.TenantID)
	if err != nil {
		return err
	}
	var app map[string]any
	if event.ClientID != "" {
		client, e := s.Store.Clients().Get(ctx, event.TenantID, event.ClientID)
		if e != nil {
			return e
		}
		app = map[string]any{"clientID": client.ClientID, "name": client.Name, "app_metadata": map[string]any{}}
	}
	vars, err := BuildRenderContext(tenantRenderMap(tenant), userRenderMap(user), app, event.Language, event.URL)
	if err != nil {
		return err
	}
	additional, _, err := projectVariables(event.Variables, 0)
	if err != nil {
		return err
	}
	if extra, ok := additional.(map[string]any); ok {
		for k, v := range extra {
			if k == "tenant" || k == "user" || k == "application" || k == "language" || k == "url" {
				continue
			}
			vars[k] = v
		}
	}
	fields := map[string]string{}
	for _, key := range []string{"from", "subject", "resultUrl"} {
		if value, ok := policy.Template.Fields[key].(string); ok {
			fields[key] = value
		}
	}
	body, ok := policy.Template.Fields["body"].(string)
	if !ok || body == "" {
		return store.ErrInvalid
	}
	fields["html"] = body
	rendered, err := s.Renderer.Render(ctx, RenderInput{Fields: fields, Variables: vars})
	if err != nil {
		return err
	}
	from := rendered.From
	if from == "" && provider != nil {
		from = provider.DefaultFrom
	}
	if from == "" {
		from = s.DefaultFrom
	}
	if from == "" {
		from = "zeroauthy@localhost"
	}
	msg := Message{From: from, To: user.Email, Subject: rendered.Subject, HTML: rendered.HTML, Text: htmlToText(rendered.HTML)}
	if err = validateMessage(from, msg); err != nil {
		return err
	}
	return s.deliver(ctx, event.TenantID, msg, provider)
}

// Preview renders a stored tenant template with synthetic example.invalid
// context. Overrides are limited to presentation fields and extra variables.
func (s *Service) Preview(ctx context.Context, tenantID, name string, overrides map[string]any) (Rendered, error) {
	return s.renderSynthetic(ctx, tenantID, name, "preview@example.invalid", overrides)
}

// SendTest renders a stored tenant template for a verified operator selected
// by the caller and submits it through that tenant's current provider.
func (s *Service) SendTest(ctx context.Context, tenantID, name, recipient string) error {
	if recipient == "" {
		return store.ErrInvalid
	}
	rendered, provider, err := s.renderTemplate(ctx, tenantID, name, recipient, nil)
	if err != nil {
		return err
	}
	msg := Message{From: rendered.From, To: recipient, Subject: rendered.Subject, Text: rendered.Text, HTML: rendered.HTML}
	if msg.From == "" {
		msg.From = s.DefaultFrom
	}
	if msg.From == "" {
		msg.From = "zeroauthy@localhost"
	}
	if err = validateMessage(msg.From, msg); err != nil {
		return err
	}
	return s.deliver(ctx, tenantID, msg, provider)
}

func (s *Service) renderSynthetic(ctx context.Context, tenantID, name, recipient string, overrides map[string]any) (Rendered, error) {
	returned, _, err := s.renderTemplate(ctx, tenantID, name, recipient, overrides)
	return returned, err
}

func (s *Service) renderTemplate(ctx context.Context, tenantID, name, recipient string, overrides map[string]any) (Rendered, *store.EmailProvider, error) {
	if s == nil || s.Store == nil || s.Renderer == nil {
		return Rendered{}, nil, ErrServiceUnavailable
	}
	policy, err := s.Resolve(ctx, tenantID, name)
	if err != nil {
		return Rendered{}, nil, err
	}
	if policy.Template == nil {
		return Rendered{}, nil, store.ErrNotFound
	}
	if !policy.Enabled {
		return Rendered{}, nil, store.ErrInvalid
	}
	tenant, err := s.Store.Tenants().Get(ctx, tenantID)
	if err != nil {
		return Rendered{}, nil, err
	}
	url := "https://example.invalid/" + name
	fields := map[string]string{}
	for _, key := range []string{"from", "subject", "resultUrl"} {
		if value, ok := policy.Template.Fields[key].(string); ok {
			fields[key] = value
		}
	}
	body, ok := policy.Template.Fields["body"].(string)
	if !ok || body == "" {
		return Rendered{}, nil, store.ErrInvalid
	}
	fields["body"], fields["html"] = body, body
	fields["resultUrl"] = url
	vars := map[string]any{}
	for k, v := range overrides {
		switch k {
		case "from", "subject":
			value, ok := v.(string)
			if !ok || len(value) > 1024 {
				return Rendered{}, nil, store.ErrInvalid
			}
			fields[k] = value
		case "body":
			value, ok := v.(string)
			if !ok || len(value) > 128<<10 {
				return Rendered{}, nil, store.ErrInvalid
			}
			fields["body"], fields["html"] = value, value
		case "variables":
			value, ok := v.(map[string]any)
			if !ok {
				return Rendered{}, nil, store.ErrInvalid
			}
			vars = value
		default:
			return Rendered{}, nil, store.ErrInvalid
		}
	}
	ctxVars, err := BuildRenderContext(tenantRenderMap(tenant), map[string]any{"email": recipient, "email_verified": true}, nil, "en", url)
	if err != nil {
		return Rendered{}, nil, err
	}
	for key, value := range vars {
		if key == "tenant" || key == "user" || key == "application" || key == "language" || key == "url" {
			return Rendered{}, nil, store.ErrInvalid
		}
		ctxVars[key] = value
	}
	projected, _, err := projectVariables(ctxVars, 0)
	if err != nil {
		return Rendered{}, nil, err
	}
	rendered, err := s.Renderer.Render(ctx, RenderInput{Fields: fields, Variables: projected.(map[string]any)})
	if err != nil {
		return Rendered{}, nil, err
	}
	provider, err := s.providerSnapshot(ctx, tenantID)
	if err != nil {
		return Rendered{}, nil, err
	}
	if rendered.From == "" && provider != nil {
		rendered.From = provider.DefaultFrom
	}
	if rendered.From == "" {
		rendered.From = s.DefaultFrom
	}
	if rendered.From == "" {
		rendered.From = "zeroauthy@localhost"
	}
	if rendered.ResultURL == "" {
		rendered.ResultURL = url
	}
	return rendered, provider, nil
}

func validateMessage(from string, msg Message) error {
	if err := validateEnvelope(msg); err != nil {
		return err
	}
	fromAddr, err := mail.ParseAddress(from)
	if err != nil || fromAddr.Address == "" {
		return ErrHeaderInjection
	}
	return nil
}
func validateEnvelope(msg Message) error {
	if strings.ContainsAny(msg.To+msg.Subject, "\r\n") {
		return ErrHeaderInjection
	}
	toAddr, err := mail.ParseAddress(msg.To)
	if err != nil || toAddr.Name != "" || toAddr.Address != msg.To {
		return ErrHeaderInjection
	}
	return nil
}
func tenantRenderMap(t *store.Tenant) map[string]any {
	return map[string]any{"name": t.Name, "friendly_name": t.FriendlyName, "support_email": t.SupportEmail, "support_url": t.SupportURL}
}
func userRenderMap(u *store.User) map[string]any {
	return map[string]any{"email": u.Email, "email_verified": u.EmailVerified, "picture": u.Picture, "nickname": u.Nickname, "given_name": u.GivenName, "family_name": u.FamilyName, "name": u.Name, "user_metadata": u.UserMetadata, "app_metadata": u.AppMetadata}
}
func cloneConfigMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
func wholeSeconds(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	case json.Number:
		i, e := n.Int64()
		return i, e == nil
	}
	return 0, false
}

func htmlToText(source string) string {
	if source == "" {
		return ""
	}
	z := xhtml.NewTokenizer(strings.NewReader(source))
	var out strings.Builder
	skip := 0
	for {
		tt := z.Next()
		switch tt {
		case xhtml.ErrorToken:
			if z.Err() != nil {
				return strings.TrimSpace(out.String())
			}
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			t := z.Token()
			name := strings.ToLower(t.Data)
			if name == "script" || name == "style" {
				skip++
			}
			if skip == 0 && (name == "br" || name == "p" || name == "div" || name == "li" || name == "tr" || strings.HasPrefix(name, "h")) {
				out.WriteByte('\n')
			}
		case xhtml.EndTagToken:
			t := z.Token()
			name := strings.ToLower(t.Data)
			if (name == "script" || name == "style") && skip > 0 {
				skip--
			}
			if skip == 0 && (name == "p" || name == "div" || name == "li" || name == "tr" || strings.HasPrefix(name, "h")) {
				out.WriteByte('\n')
			}
		case xhtml.TextToken:
			if skip == 0 {
				out.Write(z.Text())
			}
		}
		if out.Len() > maxOutputBytes {
			return ""
		}
	}
}
