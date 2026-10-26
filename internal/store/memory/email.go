package memory

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type emailClaimKey struct{ tenant, subject, purpose, event string }
type emailProviders struct{ s *Store }
type emailTemplates struct{ s *Store }
type emailNotifications struct{ s *Store }

func cloneEmailProvider(p *store.EmailProvider) *store.EmailProvider {
	if p == nil {
		return nil
	}
	out := *p
	out.PublicConfig = cloneJSON(p.PublicConfig)
	out.SealedCredentials = slices.Clone(p.SealedCredentials)
	return &out
}
func cloneEmailTemplate(t *store.EmailTemplate) *store.EmailTemplate {
	if t == nil {
		return nil
	}
	out := *t
	out.Fields = cloneJSON(t.Fields)
	return &out
}

func (r emailProviders) Get(_ context.Context, tenantID string) (*store.EmailProvider, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	p, ok := r.s.emailProviders[tenantID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneEmailProvider(p), nil
}
func (r emailProviders) Put(_ context.Context, p *store.EmailProvider, expected int64) error {
	if p == nil || p.TenantID == "" || p.Name == "" || expected < 0 || !validPublicEmailConfig(p) {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.tenants[p.TenantID]; !ok {
		return store.ErrNotFound
	}
	old, exists := r.s.emailProviders[p.TenantID]
	if expected == 0 {
		if exists {
			return store.ErrConflict
		}
	} else if !exists || old.Revision != expected {
		return store.ErrConflict
	}
	revision := r.s.emailProviderRevisions[p.TenantID] + 1
	copy := cloneEmailProvider(p)
	copy.Revision = revision
	r.s.emailProviders[p.TenantID] = copy
	r.s.emailProviderRevisions[p.TenantID] = revision
	return nil
}
func (r emailProviders) Delete(_ context.Context, tenantID string, expected int64) error {
	if expected <= 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	p, ok := r.s.emailProviders[tenantID]
	if !ok {
		return store.ErrNotFound
	}
	if p.Revision != expected {
		return store.ErrConflict
	}
	delete(r.s.emailProviders, tenantID)
	return nil
}

func validPublicEmailConfig(p *store.EmailProvider) bool {
	allowed := map[string]bool{}
	switch p.Name {
	case "smtp":
		allowed = map[string]bool{"smtp_host": true, "smtp_port": true, "smtp_user": true, "headers": true}
	case "sendgrid", "mandrill", "resend":
	case "mailgun":
		allowed = map[string]bool{"domain": true, "region": true}
	case "sparkpost":
		allowed = map[string]bool{"region": true}
	case "ses":
		allowed = map[string]bool{"region": true, "configuration_set_name": true}
	case "azure_cs", "ms365":
	case "custom":
		if p.Enabled {
			return false
		}
	default:
		return false
	}
	for k, value := range p.PublicConfig {
		if !allowed[k] || !nonsecretConfig(value, 0) {
			return false
		}
	}
	return true
}

func nonsecretConfig(value any, depth int) bool {
	if depth > 16 {
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			k := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
			for _, blocked := range []string{"secret", "password", "token", "credential", "authorization", "privatekey"} {
				if strings.Contains(k, blocked) {
					return false
				}
			}
			if !nonsecretConfig(child, depth+1) {
				return false
			}
		}
	case []any:
		for _, child := range v {
			if !nonsecretConfig(child, depth+1) {
				return false
			}
		}
	}
	return true
}

func (r emailTemplates) Get(_ context.Context, tenantID, name string) (*store.EmailTemplate, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	t, ok := r.s.emailTemplates[key{tenantID, name}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneEmailTemplate(t), nil
}
func (r emailTemplates) Put(_ context.Context, t *store.EmailTemplate, expected int64) error {
	if t == nil || t.TenantID == "" || t.Name == "" || expected < 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.tenants[t.TenantID]; !ok {
		return store.ErrNotFound
	}
	k := key{t.TenantID, t.Name}
	old, exists := r.s.emailTemplates[k]
	if expected == 0 {
		if exists {
			return store.ErrConflict
		}
	} else if !exists || old.Revision != expected {
		return store.ErrConflict
	}
	copy := cloneEmailTemplate(t)
	copy.Revision = 1
	if exists {
		copy.Revision = old.Revision + 1
	}
	r.s.emailTemplates[k] = copy
	return nil
}

func (r emailNotifications) Claim(_ context.Context, tenantID, subjectID, purpose, eventKey string, now, expiresAt time.Time, limit int) (bool, error) {
	if tenantID == "" || subjectID == "" || purpose == "" || limit <= 0 || (!expiresAt.IsZero() && !expiresAt.After(now)) {
		return false, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.tenants[tenantID]; !ok {
		return false, store.ErrNotFound
	}
	k := emailClaimKey{tenantID, subjectID, purpose, eventKey}
	claim, ok := r.s.emailNotifications[k]
	if ok && !claim.ExpiresAt.IsZero() && !claim.ExpiresAt.After(now) {
		delete(r.s.emailNotifications, k)
		ok = false
	}
	if !ok {
		r.s.emailNotifications[k] = store.EmailNotification{TenantID: tenantID, SubjectID: subjectID, Purpose: purpose, EventKey: eventKey, Count: 1, ExpiresAt: expiresAt}
		return true, nil
	}
	if claim.Count >= limit {
		return false, nil
	}
	claim.Count++
	r.s.emailNotifications[k] = claim
	return true, nil
}
func (r emailNotifications) Sweep(_ context.Context, before time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	removed := 0
	for k, c := range r.s.emailNotifications {
		if removed == limit {
			break
		}
		if !c.ExpiresAt.IsZero() && !c.ExpiresAt.After(before) {
			delete(r.s.emailNotifications, k)
			removed++
		}
	}
	return removed, nil
}

func (s *Store) deleteEmailClaims(tenantID, subjectID string) {
	for k := range s.emailNotifications {
		if k.tenant == tenantID && (subjectID == "" || k.subject == subjectID) {
			delete(s.emailNotifications, k)
		}
	}
}
func (s *Store) deleteOperatorEmailClaims(subjectID string) {
	for k := range s.emailNotifications {
		if k.subject == subjectID && (strings.EqualFold(k.purpose, "preview") || strings.EqualFold(k.purpose, "test")) {
			delete(s.emailNotifications, k)
		}
	}
}
