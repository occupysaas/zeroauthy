package memory

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type dpopKey struct {
	tenant, origin, jkt string
	digest              [sha256.Size]byte
}
type dpopProofs struct{ s *Store }

func (s *Store) DPoP() store.DPoP { return dpopProofs{s} }

func (r dpopProofs) UseProof(_ context.Context, tid, origin, jkt, jti string, now, expiresAt time.Time) error {
	if tid == "" || origin == "" || jkt == "" || jti == "" || !now.Before(expiresAt) {
		return store.ErrInvalid
	}
	k := dpopKey{tid, origin, jkt, sha256.Sum256([]byte(jti))}
	r.s.lock()
	defer r.s.unlock()
	if exp, ok := r.s.dpopProofs[k]; ok && now.Before(exp) {
		return store.ErrConflict
	}
	r.s.dpopProofs[k] = expiresAt
	return nil
}

func (r dpopProofs) PurgeBefore(_ context.Context, before time.Time, limit int) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, exp := range r.s.dpopProofs {
		if n >= limit {
			break
		}
		if !exp.After(before) {
			delete(r.s.dpopProofs, k)
			n++
		}
	}
	return n, nil
}
