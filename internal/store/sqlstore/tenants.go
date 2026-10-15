package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type tenants struct{ s *Store }

func (s *Store) Tenants() store.Tenants { return tenants{s} }

const tenantCols = `id, name, friendly_name, default_audience, allowed_logout_urls, enabled_locales, custom_text,
 session_lifetime, idle_session_lifetime, logo_url, primary_color, default_directory, created_at`

// prefixed prefixes each comma-separated column name in cols with p.
func prefixed(p, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = p + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

func (r tenants) Create(ctx context.Context, t *store.Tenant) error {
	return r.s.atomic(ctx, func(tx *Store) error {
		args, err := tenantArgs(t)
		if err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `INSERT INTO tenants (`+tenantCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return tx.conflict(err)
		}
		return tenants{tx}.putDomains(ctx, t.ID, t.Domains)
	})
}

// putDomains replaces a tenant's domains. A domain owned by another tenant
// violates the primary key; that error ends the call, so the failed statement
// never has to be survived by the transaction.
func (r tenants) putDomains(ctx context.Context, id string, domains []string) error {
	if _, err := r.s.exec(ctx, `DELETE FROM tenant_domains WHERE tenant_id = ?`, id); err != nil {
		return err
	}
	for i, d := range domains {
		if _, err := r.s.exec(ctx, `INSERT INTO tenant_domains (domain, tenant_id, position) VALUES (?, ?, ?)`, d, id, i); err != nil {
			return r.s.conflict(err)
		}
	}
	return nil
}

func (r tenants) Update(ctx context.Context, t *store.Tenant) error {
	return r.s.atomic(ctx, func(tx *Store) error {
		args, err := tenantArgs(t)
		if err != nil {
			return err
		}
		res, err := tx.exec(ctx, `UPDATE tenants SET name=?, friendly_name=?, default_audience=?, allowed_logout_urls=?,
 enabled_locales=?, custom_text=?, session_lifetime=?, idle_session_lifetime=?, logo_url=?, primary_color=?,
 default_directory=?, created_at=? WHERE id=?`, append(args[1:], t.ID)...)
		if err != nil {
			return tx.conflict(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
		return tenants{tx}.putDomains(ctx, t.ID, t.Domains)
	})
}

func (r tenants) Get(ctx context.Context, id string) (*store.Tenant, error) {
	return r.one(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id = ?`, id)
}

func (r tenants) GetByName(ctx context.Context, name string) (*store.Tenant, error) {
	return r.one(ctx, `SELECT `+tenantCols+` FROM tenants WHERE name = ?`, name)
}

func (r tenants) GetByDomain(ctx context.Context, domain string) (*store.Tenant, error) {
	return r.one(ctx, `SELECT `+prefixed("t.", tenantCols)+` FROM tenants t JOIN tenant_domains d ON d.tenant_id = t.id WHERE d.domain = ?`, domain)
}

func (r tenants) List(ctx context.Context) ([]*store.Tenant, error) {
	rows, err := r.s.query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for _, t := range out {
		if t.Domains, err = r.domains(ctx, t.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r tenants) one(ctx context.Context, q string, args ...any) (*store.Tenant, error) {
	t, err := scanTenant(r.s.queryRow(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Domains, err = r.domains(ctx, t.ID)
	return t, err
}

// domains returns a tenant's domains in the order they were given.
func (r tenants) domains(ctx context.Context, id string) ([]string, error) {
	rows, err := r.s.query(ctx, `SELECT domain FROM tenant_domains WHERE tenant_id = ? ORDER BY position`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanTenant(row scanner) (*store.Tenant, error) {
	var t store.Tenant
	var logout, locales, text string
	var created int64
	if err := row.Scan(&t.ID, &t.Name, &t.FriendlyName, &t.DefaultAudience, &logout, &locales, &text,
		&t.SessionLifetime, &t.IdleSessionLifetime, &t.Branding.LogoURL, &t.Branding.PrimaryColor,
		&t.DefaultDirectory, &created); err != nil {
		return nil, err
	}
	for _, j := range []struct {
		s string
		v any
	}{{logout, &t.AllowedLogoutURLs}, {locales, &t.EnabledLocales}, {text, &t.CustomText}} {
		if err := fromJSON(j.s, j.v); err != nil {
			return nil, err
		}
	}
	t.CreatedAt = fromMicros(created)
	return &t, nil
}

func tenantArgs(t *store.Tenant) ([]any, error) {
	logout, err := toJSON(t.AllowedLogoutURLs)
	if err != nil {
		return nil, err
	}
	locales, err := toJSON(t.EnabledLocales)
	if err != nil {
		return nil, err
	}
	text, err := toJSON(t.CustomText)
	if err != nil {
		return nil, err
	}
	return []any{t.ID, t.Name, t.FriendlyName, t.DefaultAudience, logout, locales, text,
		t.SessionLifetime, t.IdleSessionLifetime, t.Branding.LogoURL, t.Branding.PrimaryColor,
		t.DefaultDirectory, micros(t.CreatedAt)}, nil
}
