package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type customSigningKeys struct{ s *Store }

func (s *Store) CustomSigningKeys() store.CustomSigningKeys { return customSigningKeys{s} }

func (r customSigningKeys) Get(ctx context.Context, tenantID string) (*store.CustomSigningKeySet, error) {
	var raw []byte
	err := r.s.queryRow(ctx, `SELECT jwks FROM custom_signing_keys WHERE tenant_id = ?`, tenantID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &store.CustomSigningKeySet{TenantID: tenantID, JWKS: append([]byte(nil), raw...)}, nil
}

func (r customSigningKeys) Replace(ctx context.Context, set *store.CustomSigningKeySet) error {
	if set == nil || set.TenantID == "" || len(set.JWKS) == 0 {
		return store.ErrInvalid
	}
	ids, err := sqlCustomKeyIDs(set.JWKS)
	if err != nil {
		return errors.Join(store.ErrInvalid, err)
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockSigningTenant(ctx, tx, set.TenantID); err != nil {
			return err
		}
		for _, kid := range ids {
			var found string
			err := tx.queryRow(ctx, `SELECT kid FROM signing_keys WHERE tenant_id = ? AND kid = ?`, set.TenantID, kid).Scan(&found)
			if err == nil {
				return store.ErrConflict
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if _, err := tx.exec(ctx, `DELETE FROM custom_signing_keys WHERE tenant_id = ?`, set.TenantID); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `INSERT INTO custom_signing_keys (tenant_id, jwks) VALUES (?, ?)`, set.TenantID, set.JWKS)
		return tx.conflict(err)
	})
}

func (r customSigningKeys) Delete(ctx context.Context, tenantID string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockSigningTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `DELETE FROM custom_signing_keys WHERE tenant_id = ?`, tenantID)
		return err
	})
}

func customHasKID(ctx context.Context, tx *Store, tenantID, kid string) (bool, error) {
	var raw []byte
	err := tx.queryRow(ctx, `SELECT jwks FROM custom_signing_keys WHERE tenant_id = ?`, tenantID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	ids, err := sqlCustomKeyIDs(raw)
	if err != nil {
		return false, errors.Join(store.ErrInvalid, err)
	}
	return slices.Contains(ids, kid), nil
}

func sqlCustomKeyIDs(raw []byte) ([]string, error) {
	var set struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	ids := make([]string, len(set.Keys))
	for i := range set.Keys {
		ids[i] = set.Keys[i].KID
	}
	return ids, nil
}
