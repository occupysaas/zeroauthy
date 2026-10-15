package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type connections struct{ s *Store }

func (s *Store) Connections() store.Connections { return connections{s} }

const connectionCols = `tenant_id, id, name, strategy, enabled_clients, disable_signup, requires_username,
 password_min_length, password_character_classes, created_at`

func (r connections) Create(ctx context.Context, c *store.Connection) error {
	args, err := connectionArgs(c)
	if err != nil {
		return err
	}
	_, err = r.s.exec(ctx, `INSERT INTO connections (`+connectionCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`, args...)
	return r.s.conflict(err)
}

func (r connections) Get(ctx context.Context, tenantID, id string) (*store.Connection, error) {
	c, err := scanConnection(r.s.queryRow(ctx, `SELECT `+connectionCols+` FROM connections WHERE tenant_id = ? AND id = ?`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (r connections) GetByName(ctx context.Context, tenantID, name string) (*store.Connection, error) {
	c, err := scanConnection(r.s.queryRow(ctx, `SELECT `+connectionCols+` FROM connections WHERE tenant_id = ? AND name = ?`, tenantID, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (r connections) Update(ctx context.Context, c *store.Connection) error {
	args, err := connectionArgs(c)
	if err != nil {
		return err
	}
	res, err := r.s.exec(ctx, `UPDATE connections SET name=?, strategy=?, enabled_clients=?, disable_signup=?, requires_username=?,
 password_min_length=?, password_character_classes=?, created_at=? WHERE tenant_id=? AND id=?`, append(args[2:], c.TenantID, c.ID)...)
	if err != nil {
		return r.s.conflict(err)
	}
	return expectRow(res)
}

func (r connections) List(ctx context.Context, tenantID string) ([]*store.Connection, error) {
	rows, err := r.s.query(ctx, `SELECT `+connectionCols+` FROM connections WHERE tenant_id = ? ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Connection
	for rows.Next() {
		c, err := scanConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanConnection(row scanner) (*store.Connection, error) {
	var c store.Connection
	var enabled string
	var created int64
	if err := row.Scan(&c.TenantID, &c.ID, &c.Name, &c.Strategy, &enabled, &c.DisableSignup, &c.RequiresUsername,
		&c.PasswordPolicy.MinLength, &c.PasswordPolicy.RequireCharacterClasses, &created); err != nil {
		return nil, err
	}
	if err := fromJSON(enabled, &c.EnabledClients); err != nil {
		return nil, err
	}
	c.CreatedAt = fromMicros(created)
	return &c, nil
}

func connectionArgs(c *store.Connection) ([]any, error) {
	enabled, err := toJSON(c.EnabledClients)
	if err != nil {
		return nil, err
	}
	return []any{c.TenantID, c.ID, c.Name, c.Strategy, enabled, c.DisableSignup, c.RequiresUsername,
		c.PasswordPolicy.MinLength, c.PasswordPolicy.RequireCharacterClasses, micros(c.CreatedAt)}, nil
}
