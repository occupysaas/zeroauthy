package email

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Welcome sends the tenant's enabled welcome template once per verified
// user. Its permanent claim survives uncertain delivery failures so retries
// cannot duplicate a message that may already have been accepted.
func (s *Service) Welcome(ctx context.Context, tenantID, userID, clientID, language string) error {
	if s == nil || s.Store == nil || tenantID == "" || userID == "" {
		return ErrServiceUnavailable
	}
	user, err := s.Store.Users().Get(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if !user.EmailVerified || user.Email == "" {
		return nil
	}
	policy, err := s.Resolve(ctx, tenantID, "welcome_email")
	if err != nil {
		return err
	}
	if !policy.Enabled || policy.Template == nil {
		return nil
	}
	claimed, err := s.Store.EmailNotifications().Claim(ctx, tenantID, userID, "welcome", "welcome", s.clock(), time.Time{}, 1)
	if err != nil {
		return err
	}
	if !claimed {
		return nil
	}
	return s.Send(ctx, Event{TenantID: tenantID, UserID: userID, ClientID: clientID, Template: "welcome_email", Language: language})
}

// Notify sends a security notification to a canonical, verified tenant user.
// Claims are scoped to a purpose and fixed UTC calendar day; uncertain sends
// retain the claim for that day.
func (s *Service) Notify(ctx context.Context, tenantID, userID, purpose string) error {
	if s == nil || s.Store == nil || tenantID == "" || userID == "" {
		return ErrServiceUnavailable
	}
	if purpose != "blocked_account" && purpose != "stolen_credentials" {
		return store.ErrInvalid
	}
	user, err := s.Store.Users().Get(ctx, tenantID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !user.EmailVerified || user.Email == "" {
		return nil
	}
	policy, err := s.Resolve(ctx, tenantID, purpose)
	if err != nil {
		return err
	}
	if policy.Template != nil && !policy.Enabled {
		return nil
	}
	now := s.clock().UTC()
	day := now.Format("2006-01-02")
	expires := now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	claimed, err := s.Store.EmailNotifications().Claim(ctx, tenantID, userID, purpose, day, now, expires, 1)
	if err != nil {
		return err
	}
	if !claimed {
		return nil
	}
	if policy.Template != nil {
		return s.Send(ctx, Event{TenantID: tenantID, UserID: userID, Template: purpose, Language: "en"})
	}
	tenant, err := s.Store.Tenants().Get(ctx, tenantID)
	if err != nil {
		return err
	}
	return s.SendMessage(ctx, tenantID, SecurityNotificationMessage(i18n.New(tenant, "en"), purpose, user.Email))
}

// SecurityNotificationMessage creates localized default copy when a tenant
// has enabled a security notification shield without installing a custom template.
func SecurityNotificationMessage(l *i18n.Localizer, purpose, to string) Message {
	subjectKey, bodyKey := i18n.KeyEmailBlockedAccountSubject, i18n.KeyEmailBlockedAccountBody
	if purpose == "stolen_credentials" {
		subjectKey, bodyKey = i18n.KeyEmailStolenCredentialsSubject, i18n.KeyEmailStolenCredentialsBody
	}
	body := l.T(bodyKey)
	return Message{To: to, Subject: l.T(subjectKey), Text: body, HTML: fmt.Sprintf("<p>%s</p>", html.EscapeString(body))}
}

var ErrUnsafeEmailRedirect = errors.New("email: result URL is not an exact trusted HTTPS destination")

// ValidateEmailRedirect restricts email-ticket result URLs to an exact
// registered HTTPS callback or an origin owned by the tenant. It is separate
// from OAuth redirect validation and never changes OAuth callback matching.
func ValidateEmailRedirect(ctx context.Context, st store.Store, tenantID, clientID, resultURL string) error {
	if resultURL == "" {
		return nil
	}
	u, err := url.Parse(resultURL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || strings.Contains(resultURL, "*") {
		return ErrUnsafeEmailRedirect
	}
	if clientID != "" {
		client, e := st.Clients().Get(ctx, tenantID, clientID)
		if e == nil {
			for _, callback := range client.Callbacks {
				if resultURL == callback {
					return nil
				}
			}
		} else if !errors.Is(e, store.ErrNotFound) {
			return e
		}
	}
	tn, err := st.Tenants().Get(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, domain := range tn.Domains {
		if strings.EqualFold(u.Host, domain) {
			return nil
		}
	}
	return ErrUnsafeEmailRedirect
}
