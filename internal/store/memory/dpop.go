package memory

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"maps"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type dpopKey struct {
	tenant, origin, jkt string
	digest              [sha256.Size]byte
}

// Each claim has exactly one deadline. The key's current heap position allows
// atomic replacement and deletion without leaving stale deadlines to sweep.
type dpopEntry struct {
	key     dpopKey
	expires time.Time
}

type replayIndex struct {
	positions map[dpopKey]int
	deadlines []dpopEntry
}

func (h *replayIndex) Len() int { return len(h.deadlines) }
func (h *replayIndex) Less(i, j int) bool {
	return h.deadlines[i].expires.Before(h.deadlines[j].expires)
}
func (h *replayIndex) Swap(i, j int) {
	h.deadlines[i], h.deadlines[j] = h.deadlines[j], h.deadlines[i]
	h.positions[h.deadlines[i].key] = i
	h.positions[h.deadlines[j].key] = j
}
func (h *replayIndex) Push(v any) {
	entry := v.(dpopEntry)
	h.positions[entry.key] = len(h.deadlines)
	h.deadlines = append(h.deadlines, entry)
}
func (h *replayIndex) Pop() any {
	last := len(h.deadlines) - 1
	entry := h.deadlines[last]
	h.deadlines[last] = dpopEntry{}
	h.deadlines = h.deadlines[:last]
	delete(h.positions, entry.key)
	return entry
}

func (h *replayIndex) clone() replayIndex {
	return replayIndex{positions: maps.Clone(h.positions), deadlines: slices.Clone(h.deadlines)}
}

func (h *replayIndex) deleteTenant(tid string) {
	for k, i := range h.positions {
		if k.tenant == tid {
			heap.Remove(h, i)
		}
	}
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
	index := &r.s.dpopProofs
	if i, ok := index.positions[k]; ok {
		if now.Before(index.deadlines[i].expires) {
			return store.ErrConflict
		}
		index.deadlines[i].expires = expiresAt
		heap.Fix(index, i)
	} else {
		heap.Push(index, dpopEntry{k, expiresAt})
	}
	return nil
}

func (r dpopProofs) PurgeBefore(_ context.Context, before time.Time, limit int) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	index := &r.s.dpopProofs
	n := 0
	for n < limit && index.Len() > 0 && !index.deadlines[0].expires.After(before) {
		heap.Pop(index)
		n++
	}
	return n, nil
}
