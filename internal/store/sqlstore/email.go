package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type emailProviders struct{ s *Store }
type emailTemplates struct{ s *Store }
type emailNotifications struct{ s *Store }

func (s *Store) EmailProviders() store.EmailProviders         { return emailProviders{s} }
func (s *Store) EmailTemplates() store.EmailTemplates         { return emailTemplates{s} }
func (s *Store) EmailNotifications() store.EmailNotifications { return emailNotifications{s} }

func (r emailProviders) Get(ctx context.Context, tenantID string) (*store.EmailProvider, error) {
	p := &store.EmailProvider{}
	var enabled bool
	var cfg string
	err := r.s.queryRow(ctx, `SELECT tenant_id,name,enabled,default_from,public_config,sealed_credentials,revision FROM email_providers WHERE tenant_id=?`, tenantID).Scan(&p.TenantID, &p.Name, &enabled, &p.DefaultFrom, &cfg, &p.SealedCredentials, &p.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Enabled = enabled
	if err = fromJSON(cfg, &p.PublicConfig); err != nil {
		return nil, err
	}
	return p, nil
}
func (r emailProviders) Put(ctx context.Context, p *store.EmailProvider, expected int64) error {
	if p == nil || p.TenantID == "" || p.Name == "" || expected < 0 || !validPublicEmailConfig(p) {
		return store.ErrInvalid
	}
	if p.SealedCredentials == nil {
		p = cloneEmailProviderSQL(p)
	}
	cfg, err := toJSON(p.PublicConfig)
	if err != nil {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockEmailTenant(ctx, tx, p.TenantID); err != nil {
			return err
		}
		var rev int64
		err := tx.queryRow(ctx, `SELECT revision FROM email_provider_revisions WHERE tenant_id=?`+tx.d.forUpdate, p.TenantID).Scan(&rev)
		if errors.Is(err, sql.ErrNoRows) {
			rev = 0
		} else if err != nil {
			return err
		}
		var old int64
		err = tx.queryRow(ctx, `SELECT revision FROM email_providers WHERE tenant_id=?`+tx.d.forUpdate, p.TenantID).Scan(&old)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if (expected == 0 && exists) || (expected > 0 && (!exists || old != expected)) {
			return store.ErrConflict
		}
		if rev < old {
			rev = old
		}
		next := rev + 1
		if rev == 0 {
			if _, err = tx.exec(ctx, `INSERT INTO email_provider_revisions(tenant_id,revision) VALUES(?,?)`, p.TenantID, next); err != nil {
				return tx.conflict(err)
			}
		} else {
			if _, err = tx.exec(ctx, `UPDATE email_provider_revisions SET revision=? WHERE tenant_id=?`, next, p.TenantID); err != nil {
				return err
			}
		}
		if exists {
			_, err = tx.exec(ctx, `UPDATE email_providers SET name=?,enabled=?,default_from=?,public_config=?,sealed_credentials=?,revision=? WHERE tenant_id=?`, p.Name, p.Enabled, p.DefaultFrom, cfg, p.SealedCredentials, next, p.TenantID)
		} else {
			_, err = tx.exec(ctx, `INSERT INTO email_providers(tenant_id,name,enabled,default_from,public_config,sealed_credentials,revision) VALUES(?,?,?,?,?,?,?)`, p.TenantID, p.Name, p.Enabled, p.DefaultFrom, cfg, p.SealedCredentials, next)
		}
		if err != nil {
			return tx.conflict(err)
		}
		return nil
	})
}
func (r emailProviders) Delete(ctx context.Context, tenantID string, expected int64) error {
	if tenantID == "" || expected <= 0 {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockEmailTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		var rev int64
		err := tx.queryRow(ctx, `SELECT revision FROM email_providers WHERE tenant_id=?`+tx.d.forUpdate, tenantID).Scan(&rev)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if rev != expected {
			return store.ErrConflict
		}
		_, err = tx.exec(ctx, `DELETE FROM email_providers WHERE tenant_id=?`, tenantID)
		return err
	})
}

func (r emailTemplates) Get(ctx context.Context, tenantID, name string) (*store.EmailTemplate, error) {
	t := &store.EmailTemplate{}
	var fields string
	err := r.s.queryRow(ctx, `SELECT tenant_id,name,fields,revision FROM email_templates WHERE tenant_id=? AND name=?`, tenantID, name).Scan(&t.TenantID, &t.Name, &fields, &t.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = fromJSON(fields, &t.Fields); err != nil {
		return nil, err
	}
	return t, nil
}
func (r emailTemplates) Put(ctx context.Context, t *store.EmailTemplate, expected int64) error {
	if t == nil || t.TenantID == "" || t.Name == "" || expected < 0 {
		return store.ErrInvalid
	}
	fields, err := toJSON(t.Fields)
	if err != nil {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockEmailTenant(ctx, tx, t.TenantID); err != nil {
			return err
		}
		var old int64
		err := tx.queryRow(ctx, `SELECT revision FROM email_templates WHERE tenant_id=? AND name=?`+tx.d.forUpdate, t.TenantID, t.Name).Scan(&old)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if (expected == 0 && exists) || (expected > 0 && (!exists || old != expected)) {
			return store.ErrConflict
		}
		next := int64(1)
		if exists {
			next = old + 1
		}
		if exists {
			_, err = tx.exec(ctx, `UPDATE email_templates SET fields=?,revision=? WHERE tenant_id=? AND name=?`, fields, next, t.TenantID, t.Name)
		} else {
			_, err = tx.exec(ctx, `INSERT INTO email_templates(tenant_id,name,fields,revision) VALUES(?,?,?,?)`, t.TenantID, t.Name, fields, next)
		}
		return tx.conflict(err)
	})
}

func lockEmailTenant(ctx context.Context, tx *Store, id string) error {
	var one int
	err := tx.queryRow(ctx, `SELECT 1 FROM tenants WHERE id=?`+tx.d.forUpdate, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func (r emailNotifications) Claim(ctx context.Context, tenant, subject, purpose, event string, now, expires time.Time, limit int) (bool, error) {
	if tenant == "" || subject == "" || purpose == "" || limit <= 0 || (!expires.IsZero() && !expires.After(now)) {
		return false, store.ErrInvalid
	}
	for attempt := 0; attempt < 4; attempt++ {
		claimed := false
		err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
			if err := lockEmailTenant(ctx, tx, tenant); err != nil {
				return err
			}
			var count int
			var expiry sql.NullInt64
			err := tx.queryRow(ctx, `SELECT count,expires_at FROM email_notifications WHERE tenant_id=? AND subject_id=? AND purpose=? AND event_key=?`+tx.d.forUpdate, tenant, subject, purpose, event).Scan(&count, &expiry)
			if errors.Is(err, sql.ErrNoRows) {
				_, err = tx.exec(ctx, `INSERT INTO email_notifications(tenant_id,subject_id,purpose,event_key,count,expires_at) VALUES(?,?,?,?,1,?)`, tenant, subject, purpose, event, optionalExpiry(expires))
				if err != nil {
					return tx.conflict(err)
				}
				claimed = true
				return nil
			}
			if err != nil {
				return err
			}
			if expiry.Valid && expiry.Int64 <= micros(now) {
				_, err = tx.exec(ctx, `DELETE FROM email_notifications WHERE tenant_id=? AND subject_id=? AND purpose=? AND event_key=?`, tenant, subject, purpose, event)
				if err != nil {
					return err
				}
				_, err = tx.exec(ctx, `INSERT INTO email_notifications(tenant_id,subject_id,purpose,event_key,count,expires_at) VALUES(?,?,?,?,1,?)`, tenant, subject, purpose, event, optionalExpiry(expires))
				if err != nil {
					return tx.conflict(err)
				}
				claimed = true
				return nil
			}
			if count >= limit {
				return nil
			}
			_, err = tx.exec(ctx, `UPDATE email_notifications SET count=count+1 WHERE tenant_id=? AND subject_id=? AND purpose=? AND event_key=?`, tenant, subject, purpose, event)
			if err == nil {
				claimed = true
			}
			return err
		})
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		return claimed, err
	}
	return false, store.ErrConflict
}
func optionalExpiry(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return micros(t)
}

func (r emailNotifications) Sweep(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, store.ErrInvalid
	}
	removed := 0
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) error {
		rows, err := tx.query(ctx, `SELECT tenant_id,subject_id,purpose,event_key FROM email_notifications WHERE expires_at IS NOT NULL AND expires_at<=? ORDER BY expires_at LIMIT ?`+tx.d.forUpdate, micros(before), limit)
		if err != nil {
			return err
		}
		type key struct{ t, s, p, e string }
		var keys []key
		for rows.Next() {
			var k key
			if err = rows.Scan(&k.t, &k.s, &k.p, &k.e); err != nil {
				_ = rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
		for _, k := range keys {
			res, e := tx.exec(ctx, `DELETE FROM email_notifications WHERE tenant_id=? AND subject_id=? AND purpose=? AND event_key=? AND expires_at<=?`, k.t, k.s, k.p, k.e, micros(before))
			if e != nil {
				return e
			}
			n, e := res.RowsAffected()
			if e != nil {
				return e
			}
			removed += int(n)
		}
		return nil
	})
	return removed, err
}

func cloneEmailProviderSQL(p *store.EmailProvider) *store.EmailProvider {
	c := *p
	if c.SealedCredentials == nil {
		c.SealedCredentials = []byte{}
	}
	return &c
}
func validPublicEmailConfig(p *store.EmailProvider) bool {
	allowed := map[string]bool{}
	switch p.Name {
	case "smtp":
		allowed = map[string]bool{"smtp_host": true, "smtp_port": true, "smtp_user": true, "headers": true}
	case "sendgrid", "mandrill", "resend", "azure_cs", "ms365":
	case "mailgun":
		allowed = map[string]bool{"domain": true, "region": true}
	case "sparkpost":
		allowed = map[string]bool{"region": true}
	case "ses":
		allowed = map[string]bool{"region": true, "configuration_set_name": true}
	case "custom":
		if p.Enabled {
			return false
		}
	default:
		return false
	}
	var safe func(any, int) bool
	safe = func(v any, d int) bool {
		if d > 16 {
			return false
		}
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				key := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(k))
				for _, bad := range []string{"secret", "password", "token", "credential", "authorization", "privatekey"} {
					if strings.Contains(key, bad) {
						return false
					}
				}
				if !safe(c, d+1) {
					return false
				}
			}
		case []any:
			for _, c := range x {
				if !safe(c, d+1) {
					return false
				}
			}
		}
		return true
	}
	for k, v := range p.PublicConfig {
		if !allowed[k] || !safe(v, 0) {
			return false
		}
	}
	return true
}

func (s *Store) HostedLogins() store.HostedLogins { return store.UnimplementedHostedLogins{} }
