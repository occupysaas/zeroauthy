package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The SQL store implements store.ADHubStore (Plan 38a, migration 0046).

const adProvisioningCols = `tenant_id,connection_id,ticket_hash,ticket_sealed,signing_key_sealed,created_at`
const adSessionCols = `tenant_id,connection_id,session_id,replica_id,replica_url,cert_thumbprint,agent_ip,connected_at,last_seen_at`

func scanADProvisioning(row scanner) (*store.ADProvisioning, error) {
	var p store.ADProvisioning
	var created int64
	if err := row.Scan(&p.TenantID, &p.ConnectionID, &p.TicketHash, &p.TicketSealed, &p.SigningKeySealed, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	p.CreatedAt = fromMicros(created)
	return &p, nil
}

func (s *Store) CreateADProvisioning(ctx context.Context, p *store.ADProvisioning) error {
	if p == nil || p.TenantID == "" || p.ConnectionID == "" || p.TicketHash == "" {
		return store.ErrInvalid
	}
	_, err := s.exec(ctx, `INSERT INTO ad_provisionings (`+adProvisioningCols+`) VALUES (?,?,?,?,?,?)`,
		p.TenantID, p.ConnectionID, p.TicketHash, p.TicketSealed, p.SigningKeySealed, micros(p.CreatedAt))
	return s.conflict(err)
}

func (s *Store) GetADProvisioning(ctx context.Context, tid, cid string) (*store.ADProvisioning, error) {
	return scanADProvisioning(s.queryRow(ctx, `SELECT `+adProvisioningCols+` FROM ad_provisionings WHERE tenant_id=? AND connection_id=?`, tid, cid))
}

func (s *Store) FindADProvisioning(ctx context.Context, tid, hash string) (*store.ADProvisioning, error) {
	return scanADProvisioning(s.queryRow(ctx, `SELECT `+adProvisioningCols+` FROM ad_provisionings WHERE tenant_id=? AND ticket_hash=?`, tid, hash))
}

func (s *Store) PutADHubSession(ctx context.Context, sess *store.ADHubSession) error {
	if sess == nil || sess.TenantID == "" || sess.ConnectionID == "" || sess.SessionID == "" {
		return store.ErrInvalid
	}
	return s.atomicRetry(ctx, nil, func(tx *Store) error {
		if _, err := tx.exec(ctx, `DELETE FROM ad_hub_sessions WHERE tenant_id=? AND connection_id=? AND session_id=?`, sess.TenantID, sess.ConnectionID, sess.SessionID); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `INSERT INTO ad_hub_sessions (`+adSessionCols+`) VALUES (?,?,?,?,?,?,?,?,?)`,
			sess.TenantID, sess.ConnectionID, sess.SessionID, sess.ReplicaID, sess.ReplicaURL, sess.CertThumbprint, sess.AgentIP,
			micros(sess.ConnectedAt), micros(sess.LastSeenAt))
		return tx.conflict(err)
	})
}

func (s *Store) DeleteADHubSession(ctx context.Context, tid, cid, sid string) error {
	_, err := s.exec(ctx, `DELETE FROM ad_hub_sessions WHERE tenant_id=? AND connection_id=? AND session_id=?`, tid, cid, sid)
	return err
}

func (s *Store) ListADHubSessions(ctx context.Context, tid, cid string, seenAfter time.Time) ([]*store.ADHubSession, error) {
	rows, err := s.query(ctx, `SELECT `+adSessionCols+` FROM ad_hub_sessions WHERE tenant_id=? AND connection_id=? AND last_seen_at>? ORDER BY connected_at DESC, session_id`, tid, cid, micros(seenAfter))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*store.ADHubSession{}
	for rows.Next() {
		var x store.ADHubSession
		var connected, seen int64
		if err := rows.Scan(&x.TenantID, &x.ConnectionID, &x.SessionID, &x.ReplicaID, &x.ReplicaURL, &x.CertThumbprint, &x.AgentIP, &connected, &seen); err != nil {
			return nil, err
		}
		x.ConnectedAt, x.LastSeenAt = fromMicros(connected), fromMicros(seen)
		out = append(out, &x)
	}
	return out, rows.Err()
}

func (s *Store) PurgeADHubSessions(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	n := 0
	err := s.atomicRetry(ctx, nil, func(tx *Store) error {
		rows, err := tx.query(ctx, `SELECT tenant_id,connection_id,session_id FROM ad_hub_sessions WHERE last_seen_at<? ORDER BY last_seen_at LIMIT ?`, micros(before), limit)
		if err != nil {
			return err
		}
		var keys [][3]string
		for rows.Next() {
			var k [3]string
			if err := rows.Scan(&k[0], &k[1], &k[2]); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		n = 0
		for _, k := range keys {
			v, err := affected(tx.exec(ctx, `DELETE FROM ad_hub_sessions WHERE tenant_id=? AND connection_id=? AND session_id=? AND last_seen_at<?`, k[0], k[1], k[2], micros(before)))
			if err != nil {
				return err
			}
			n += v
		}
		return nil
	})
	return n, err
}
