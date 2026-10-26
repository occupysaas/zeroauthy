package memory

import (
	"bytes"
	"context"
	"slices"
)

type passwordHistories struct{ s *Store }

func (r passwordHistories) Add(_ context.Context, tenantID, userID string, hash []byte, keep int) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tenantID, userID}
	if keep <= 0 {
		delete(r.s.passwordHistories, k)
		return nil
	}
	h := append(r.s.passwordHistories[k], bytes.Clone(hash))
	if len(h) > keep {
		h = slices.Clone(h[len(h)-keep:])
	}
	r.s.passwordHistories[k] = h
	return nil
}

func (r passwordHistories) List(_ context.Context, tenantID, userID string) ([][]byte, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	h := r.s.passwordHistories[key{tenantID, userID}]
	out := make([][]byte, len(h))
	for i, b := range h {
		out[len(h)-1-i] = bytes.Clone(b)
	}
	return out, nil
}
