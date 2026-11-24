package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// selfService is Plan 37c Phase B state (migration 0047).
type selfService struct{ s *Store }

func (s *Store) SelfService() store.SelfService { return selfService{s} }
func (s *Store) SelfServiceSupported() bool     { return true }

const namedDocCols = `tenant_id, id, name, doc, created_at, updated_at`

// scanNamedDoc scans a profile or connection profile row.
func scanNamedDoc(row scanner) (tid, id, name string, doc json.RawMessage, created, updated time.Time, err error) {
	var raw string
	var c, u int64
	if err = row.Scan(&tid, &id, &name, &raw, &c, &u); err != nil {
		return
	}
	return tid, id, name, json.RawMessage(raw), fromMicros(c), fromMicros(u), nil
}

func (r selfService) insertNamed(ctx context.Context, table, tid, id, name string, doc json.RawMessage, created, updated time.Time) error {
	_, err := r.s.write(ctx, nil, `INSERT INTO `+table+` (`+namedDocCols+`) VALUES (?,?,?,?,?,?)`, tid, id, name, string(doc), micros(created), micros(updated))
	return r.s.conflict(err)
}

func (r selfService) updateNamed(ctx context.Context, table, tid, id, name string, doc json.RawMessage, updated time.Time) error {
	res, err := r.s.write(ctx, nil, `UPDATE `+table+` SET name = ?, doc = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`, name, string(doc), micros(updated), tid, id)
	if err != nil {
		return r.s.conflict(err)
	}
	return expectRow(res)
}

func (r selfService) countAndPage(ctx context.Context, table, tid string, p store.Page, each func(scanner) error) (int, error) {
	var total int
	if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM `+table+` WHERE tenant_id = ?`, tid).Scan(&total); err != nil {
		return 0, err
	}
	rows, err := r.s.query(ctx, `SELECT `+namedDocCols+` FROM `+table+` WHERE tenant_id = ? ORDER BY created_at, id`+r.s.d.byteOrder+pageClause(p), tid)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		if err := each(rows); err != nil {
			return 0, err
		}
	}
	return total, rows.Err()
}

func (r selfService) CreateProfile(ctx context.Context, p *store.SelfServiceProfile) error {
	return r.insertNamed(ctx, "self_service_profiles", p.TenantID, p.ID, p.Name, p.Doc, p.CreatedAt, p.UpdatedAt)
}

func scanSelfServiceProfile(row scanner) (*store.SelfServiceProfile, error) {
	var p store.SelfServiceProfile
	var err error
	p.TenantID, p.ID, p.Name, p.Doc, p.CreatedAt, p.UpdatedAt, err = scanNamedDoc(row)
	return &p, err
}

func (r selfService) GetProfile(ctx context.Context, tid, id string) (*store.SelfServiceProfile, error) {
	p, err := scanSelfServiceProfile(r.s.queryRow(ctx, `SELECT `+namedDocCols+` FROM self_service_profiles WHERE tenant_id = ? AND id = ?`, tid, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r selfService) UpdateProfile(ctx context.Context, p *store.SelfServiceProfile) error {
	return r.updateNamed(ctx, "self_service_profiles", p.TenantID, p.ID, p.Name, p.Doc, p.UpdatedAt)
}

func (r selfService) DeleteProfile(ctx context.Context, tid, id string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `DELETE FROM self_service_profiles WHERE tenant_id = ? AND id = ?`, tid, id)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		for _, table := range []string{"self_service_custom_texts", "sso_tickets"} {
			if _, err := tx.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = ? AND profile_id = ?`, tid, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r selfService) ListProfiles(ctx context.Context, tid string, p store.Page) ([]*store.SelfServiceProfile, int, error) {
	out := []*store.SelfServiceProfile{}
	total, err := r.countAndPage(ctx, "self_service_profiles", tid, p, func(row scanner) error {
		v, err := scanSelfServiceProfile(row)
		if err == nil {
			out = append(out, v)
		}
		return err
	})
	return out, total, err
}

func (r selfService) profileExists(ctx context.Context, tx *Store, tid, pid string, lock bool) error {
	q := `SELECT 1 FROM self_service_profiles WHERE tenant_id = ? AND id = ?`
	if lock {
		q += tx.d.forUpdate
	}
	var one int
	if err := tx.queryRow(ctx, q, tid, pid).Scan(&one); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	return nil
}

func (r selfService) GetCustomText(ctx context.Context, tid, pid, lang, page string) (json.RawMessage, error) {
	if err := r.profileExists(ctx, r.s, tid, pid, false); err != nil {
		return nil, err
	}
	var raw string
	err := r.s.queryRow(ctx, `SELECT doc FROM self_service_custom_texts WHERE tenant_id = ? AND profile_id = ? AND language = ? AND page = ?`, tid, pid, lang, page).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

func (r selfService) SetCustomText(ctx context.Context, tid, pid, lang, page string, text json.RawMessage) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := r.profileExists(ctx, tx, tid, pid, true); err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `DELETE FROM self_service_custom_texts WHERE tenant_id = ? AND profile_id = ? AND language = ? AND page = ?`, tid, pid, lang, page); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `INSERT INTO self_service_custom_texts (tenant_id, profile_id, language, page, doc) VALUES (?,?,?,?,?)`, tid, pid, lang, page, string(text))
		return err
	})
}

const ticketCols = `tenant_id, id, profile_id, token_hash, connection_id, doc, created_at, expires_at, revoked_at, used_at`

func scanTicket(row scanner) (*store.SSOTicket, error) {
	var t store.SSOTicket
	var raw string
	var created, expires int64
	var revoked, used sql.NullInt64
	if err := row.Scan(&t.TenantID, &t.ID, &t.ProfileID, &t.Hash, &t.ConnectionID, &raw, &created, &expires, &revoked, &used); err != nil {
		return nil, err
	}
	t.Doc, t.CreatedAt, t.ExpiresAt, t.RevokedAt, t.UsedAt = json.RawMessage(raw), fromMicros(created), fromMicros(expires), optTime(revoked), optTime(used)
	return &t, nil
}

func (r selfService) CreateTicket(ctx context.Context, t *store.SSOTicket) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := r.profileExists(ctx, tx, t.TenantID, t.ProfileID, true); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `INSERT INTO sso_tickets (`+ticketCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			t.TenantID, t.ID, t.ProfileID, t.Hash, t.ConnectionID, string(t.Doc), micros(t.CreatedAt), micros(t.ExpiresAt), nullMicros(t.RevokedAt), nullMicros(t.UsedAt))
		return tx.conflict(err)
	})
}

func (r selfService) GetTicketByHash(ctx context.Context, tid, hash string) (*store.SSOTicket, error) {
	t, err := scanTicket(r.s.queryRow(ctx, `SELECT `+ticketCols+` FROM sso_tickets WHERE tenant_id = ? AND token_hash = ?`, tid, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (r selfService) RevokeTicket(ctx context.Context, tid, pid, id string, now time.Time) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		var one int
		if err := tx.queryRow(ctx, `SELECT 1 FROM sso_tickets WHERE tenant_id = ? AND profile_id = ? AND id = ?`+tx.d.forUpdate, tid, pid, id).Scan(&one); errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		} else if err != nil {
			return err
		}
		_, err := tx.exec(ctx, `UPDATE sso_tickets SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`, micros(now), tid, id)
		return err
	})
}

func (r selfService) UseTicket(ctx context.Context, tid, id string, now time.Time) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE sso_tickets SET used_at = ? WHERE tenant_id = ? AND id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
			micros(now), tid, id, micros(now))
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 1 {
			return nil
		}
		var one int
		if err := tx.queryRow(ctx, `SELECT 1 FROM sso_tickets WHERE tenant_id = ? AND id = ?`, tid, id).Scan(&one); errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		} else if err != nil {
			return err
		}
		return store.ErrPrecondition
	})
}

func (r selfService) BindTicketConnection(ctx context.Context, tid, id, conn string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		var cur string
		if err := tx.queryRow(ctx, `SELECT connection_id FROM sso_tickets WHERE tenant_id = ? AND id = ?`+tx.d.forUpdate, tid, id).Scan(&cur); errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		} else if err != nil {
			return err
		}
		switch cur {
		case "":
			_, err := tx.exec(ctx, `UPDATE sso_tickets SET connection_id = ? WHERE tenant_id = ? AND id = ?`, conn, tid, id)
			return err
		case conn:
			return nil
		}
		return store.ErrPrecondition
	})
}

func scanConnectionProfile(row scanner) (*store.ConnectionProfile, error) {
	var p store.ConnectionProfile
	var err error
	p.TenantID, p.ID, p.Name, p.Doc, p.CreatedAt, p.UpdatedAt, err = scanNamedDoc(row)
	return &p, err
}

func (r selfService) CreateConnectionProfile(ctx context.Context, p *store.ConnectionProfile) error {
	return r.insertNamed(ctx, "connection_profiles", p.TenantID, p.ID, p.Name, p.Doc, p.CreatedAt, p.UpdatedAt)
}

func (r selfService) GetConnectionProfile(ctx context.Context, tid, id string) (*store.ConnectionProfile, error) {
	p, err := scanConnectionProfile(r.s.queryRow(ctx, `SELECT `+namedDocCols+` FROM connection_profiles WHERE tenant_id = ? AND id = ?`, tid, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r selfService) UpdateConnectionProfile(ctx context.Context, p *store.ConnectionProfile) error {
	return r.updateNamed(ctx, "connection_profiles", p.TenantID, p.ID, p.Name, p.Doc, p.UpdatedAt)
}

func (r selfService) DeleteConnectionProfile(ctx context.Context, tid, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM connection_profiles WHERE tenant_id = ? AND id = ?`, tid, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r selfService) ListConnectionProfiles(ctx context.Context, tid string, p store.Page) ([]*store.ConnectionProfile, int, error) {
	out := []*store.ConnectionProfile{}
	total, err := r.countAndPage(ctx, "connection_profiles", tid, p, func(row scanner) error {
		v, err := scanConnectionProfile(row)
		if err == nil {
			out = append(out, v)
		}
		return err
	})
	return out, total, err
}
