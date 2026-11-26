package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The SQL store implements store.MyOrgStore (Plan 42b, migration 0050).

func (s *Store) exists(ctx context.Context, q string, args ...any) error {
	var n int
	if err := s.queryRow(ctx, q, args...).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) PutMyOrgClientConfig(ctx context.Context, c *store.MyOrgClientConfig) error {
	if c == nil || c.TenantID == "" || c.ClientID == "" || len(c.Doc) == 0 {
		return store.ErrInvalid
	}
	return s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.exists(ctx, `SELECT COUNT(*) FROM clients WHERE tenant_id=? AND client_id=?`, c.TenantID, c.ClientID); err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `DELETE FROM my_org_client_configs WHERE tenant_id=? AND client_id=?`, c.TenantID, c.ClientID); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `INSERT INTO my_org_client_configs (tenant_id,client_id,doc) VALUES (?,?,?)`, c.TenantID, c.ClientID, string(c.Doc))
		return tx.conflict(err)
	})
}

func (s *Store) GetMyOrgClientConfig(ctx context.Context, tid, cid string) (*store.MyOrgClientConfig, error) {
	out := store.MyOrgClientConfig{TenantID: tid, ClientID: cid}
	var doc string
	err := s.queryRow(ctx, `SELECT doc FROM my_org_client_configs WHERE tenant_id=? AND client_id=?`, tid, cid).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out.Doc = []byte(doc)
	return &out, nil
}

func (s *Store) DeleteMyOrgClientConfig(ctx context.Context, tid, cid string) error {
	_, err := s.exec(ctx, `DELETE FROM my_org_client_configs WHERE tenant_id=? AND client_id=?`, tid, cid)
	return err
}

func (s *Store) SetMyOrgRoleVisible(ctx context.Context, tid, rid string, visible bool) error {
	return s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.exists(ctx, `SELECT COUNT(*) FROM rbac_roles WHERE tenant_id=? AND id=?`, tid, rid); err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `DELETE FROM my_org_visible_roles WHERE tenant_id=? AND role_id=?`, tid, rid); err != nil {
			return err
		}
		if !visible {
			return nil
		}
		_, err := tx.exec(ctx, `INSERT INTO my_org_visible_roles (tenant_id,role_id) VALUES (?,?)`, tid, rid)
		return tx.conflict(err)
	})
}

func (s *Store) ListMyOrgVisibleRoles(ctx context.Context, tid string) ([]string, error) {
	rows, err := s.query(ctx, `SELECT role_id FROM my_org_visible_roles WHERE tenant_id=? ORDER BY role_id`+s.d.byteOrder, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
