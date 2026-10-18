package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type tenants struct{ s *Store }

func (s *Store) Tenants() store.Tenants { return tenants{s} }

const tenantCols = `id, name, friendly_name, default_audience, allowed_logout_urls, enabled_locales, custom_text,
 session_lifetime, idle_session_lifetime, logo_url, primary_color, default_directory, created_at,
 skip_non_verifiable_callback_uri_confirmation_prompt, use_scope_descriptions_for_consent, pushed_authorization_requests_supported,
 device_flow_charset, device_flow_mask, reserved, seeded, origin`

// prefixed prefixes each comma-separated column name in cols with p.
func prefixed(p, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = p + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

func (r tenants) Create(ctx context.Context, t *store.Tenant) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		args, err := tenantArgs(t)
		if err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `INSERT INTO tenants (`+tenantCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return tx.conflict(err)
		}
		return tenants{tx}.putDomains(ctx, t.ID, t.Domains, false)
	})
}

// putDomains brings a tenant's domains to the given ordered list. When
// existing is false (Create) it only inserts. Otherwise it reads the current
// rows (the tenants row is already locked), then inserts the added domains,
// re-positions the kept ones and deletes the removed ones, all by primary key
// in sorted order; it never deletes by tenant_id, which takes gap locks on
// MySQL. A domain owned by another tenant violates the primary key; that
// error ends the call, so the failed statement never has to be survived by
// the transaction. A repeated domain in the list is a conflict.
func (r tenants) putDomains(ctx context.Context, id string, domains []string, existing bool) error {
	want := make(map[string]int, len(domains))
	for i, d := range domains {
		if _, dup := want[d]; dup {
			return store.ErrConflict
		}
		want[d] = i
	}
	have := map[string]int{}
	if existing {
		rows, err := r.s.query(ctx, `SELECT domain, position FROM tenant_domains WHERE tenant_id = ?`, id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var d string
			var p int
			if err := rows.Scan(&d, &p); err != nil {
				rows.Close()
				return err
			}
			have[d] = p
		}
		err = rows.Err()
		rows.Close() // release the single SQLite connection before writing
		if err != nil {
			return err
		}
	}
	sorted := slices.Sorted(maps.Keys(want))
	for _, d := range sorted {
		p, ok := have[d]
		switch {
		case !ok:
			if _, err := r.s.exec(ctx, `INSERT INTO tenant_domains (domain, tenant_id, position) VALUES (?, ?, ?)`, d, id, want[d]); err != nil {
				return r.s.conflict(err)
			}
		case p != want[d]:
			if _, err := r.s.exec(ctx, `UPDATE tenant_domains SET position = ? WHERE domain = ?`, want[d], d); err != nil {
				return err
			}
		}
	}
	for _, d := range slices.Sorted(maps.Keys(have)) {
		if _, kept := want[d]; kept {
			continue
		}
		if _, err := r.s.exec(ctx, `DELETE FROM tenant_domains WHERE domain = ?`, d); err != nil {
			return err
		}
	}
	return nil
}

func (r tenants) Update(ctx context.Context, t *store.Tenant) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		args, err := tenantArgs(t)
		if err != nil {
			return err
		}
		res, err := tx.exec(ctx, `UPDATE tenants SET name=?, friendly_name=?, default_audience=?, allowed_logout_urls=?,
 enabled_locales=?, custom_text=?, session_lifetime=?, idle_session_lifetime=?, logo_url=?, primary_color=?,
 default_directory=?, created_at=?, skip_non_verifiable_callback_uri_confirmation_prompt=?,
 use_scope_descriptions_for_consent=?, pushed_authorization_requests_supported=?,
 device_flow_charset=?, device_flow_mask=?, reserved=?, seeded=?, origin=? WHERE id=?`, append(args[1:], t.ID)...)
		if err != nil {
			return tx.conflict(err)
		}
		if err := expectRow(res); err != nil {
			return err
		}
		return tenants{tx}.putDomains(ctx, t.ID, t.Domains, true)
	})
}

// tenantTables are the tables whose rows belong to one tenant, by
// tenant_id. Delete empties them before it deletes the tenant row.
var tenantTables = []string{
	"operators", "password_reset_tickets", "refresh_tokens", "device_codes", "pushed_auth_requests",
	"auth_codes", "auth_transactions", "sessions", "user_grants", "user_logins", "users",
	"connections", "signing_keys", "client_grants", "resource_servers", "clients", "tenant_domains",
}

// Delete locks the tenant row, removes everything scoped to the tenant, then
// the row itself. Retried on deadlock: the range DELETEs can meet the
// sweepers' on MySQL.
func (r tenants) Delete(ctx context.Context, id string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		var one int
		err := tx.queryRow(ctx, `SELECT 1 FROM tenants WHERE id = ?`+tx.d.forUpdate, id).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		for _, table := range tenantTables {
			if _, err := tx.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = ?`, id); err != nil {
				return err
			}
		}
		_, err = tx.exec(ctx, `DELETE FROM tenants WHERE id = ?`, id)
		return err
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
	rows.Close() // release the single SQLite connection before the per-tenant domain queries
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

func scanTenant(row scanner) (*store.Tenant, error) {
	var t store.Tenant
	var logout, locales, text string
	var created int64
	if err := row.Scan(&t.ID, &t.Name, &t.FriendlyName, &t.DefaultAudience, &logout, &locales, &text,
		&t.SessionLifetime, &t.IdleSessionLifetime, &t.Branding.LogoURL, &t.Branding.PrimaryColor,
		&t.DefaultDirectory, &created, &t.SkipNonVerifiableCallbackURIConfirmationPrompt,
		&t.UseScopeDescriptionsForConsent, &t.PushedAuthorizationRequestsSupported,
		&t.DeviceFlowCharset, &t.DeviceFlowMask, &t.Reserved, &t.Seeded, &t.Origin); err != nil {
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
		t.DefaultDirectory, micros(t.CreatedAt), t.SkipNonVerifiableCallbackURIConfirmationPrompt,
		t.UseScopeDescriptionsForConsent, t.PushedAuthorizationRequestsSupported,
		t.DeviceFlowCharset, t.DeviceFlowMask, t.Reserved, t.Seeded, t.Origin}, nil
}
