package memory

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"slices"
	"time"
)

type connectionKeys struct{ s *Store }

func (s *Store) ConnectionKeys() store.ConnectionKeys { return connectionKeys{s} }
func (s *Store) ConnectionKeysSupported() bool        { return true }
func (r connectionKeys) List(_ context.Context, tid, cid string) ([]*store.ConnectionKey, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []*store.ConnectionKey{}
	for _, k := range r.s.connectionKeys {
		if k.TenantID == tid && k.ConnectionID == cid {
			out = append(out, k.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *store.ConnectionKey) int {
		rank := func(k *store.ConnectionKey) int {
			n := 0
			if k.Use == "encryption" {
				n = 3
			}
			switch k.State {
			case "next":
				n++
			case "previous":
				n += 2
			}
			return n
		}
		return rank(a) - rank(b)
	})
	return out, nil
}
func (r connectionKeys) Create(_ context.Context, tid, cid, use string, current, next *store.ConnectionKey) error {
	if err := store.ValidateConnectionKeyPair(tid, cid, use, current, next); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.connections[key{tid, cid}] == nil {
		return store.ErrNotFound
	}
	for _, k := range r.s.connectionKeys {
		if k.TenantID == tid && k.ConnectionID == cid && (k.Use == use || k.KID == current.KID || k.KID == next.KID) {
			return store.ErrConflict
		}
	}
	a, b := current.Clone(), next.Clone()
	a.State, b.State = "current", "next"
	r.s.connectionKeys[key{tid, cid + "\x00" + a.KID}] = a
	r.s.connectionKeys[key{tid, cid + "\x00" + b.KID}] = b
	return nil
}
func (r connectionKeys) Rotate(_ context.Context, tid, cid, use string, newNext *store.ConnectionKey, now time.Time) (*store.ConnectionKey, error) {
	if newNext == nil || newNext.TenantID != tid || newNext.ConnectionID != cid || newNext.Use != use || newNext.KID == "" {
		return nil, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	var current, next *store.ConnectionKey
	for _, k := range r.s.connectionKeys {
		if k.TenantID == tid && k.ConnectionID == cid {
			if k.KID == newNext.KID {
				return nil, store.ErrConflict
			}
			if k.Use == use {
				switch k.State {
				case "current":
					current = k
				case "next":
					next = k
				}
			}
		}
	}
	if current == nil || next == nil {
		return nil, store.ErrNotFound
	}
	for id, k := range r.s.connectionKeys {
		if k.TenantID == tid && k.ConnectionID == cid && k.Use == use && k.State == "previous" {
			delete(r.s.connectionKeys, id)
		}
	}
	current.State = "previous"
	next.State = "current"
	next.CurrentSince = &now
	fresh := newNext.Clone()
	fresh.State = "next"
	r.s.connectionKeys[key{tid, cid + "\x00" + fresh.KID}] = fresh
	return next.Clone(), nil
}
