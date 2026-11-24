package memory

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// directorySync is Plan 37c Phase C state (scim.v1 version 3), kept in the
// directory state so connection and tenant deletion cascade.
type directorySync struct{ s *Store }

func (s *Store) DirectorySync() store.DirectorySync { return directorySync{s} }
func (s *Store) DirectorySyncSupported() bool       { return true }

func cloneSyncGroups(in []store.SynchronizedGroup) []store.SynchronizedGroup {
	out := make([]store.SynchronizedGroup, len(in))
	for i, g := range in {
		out[i] = store.SynchronizedGroup{GroupID: g.GroupID, Doc: slices.Clone(g.Doc)}
	}
	return out
}

func (r directorySync) CreateProvisioning(_ context.Context, p *store.DirectoryProvisioning) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{p.TenantID, p.ConnectionID}
	if _, ok := r.s.directory.provisionings[k]; ok {
		return store.ErrConflict
	}
	r.s.directory.provisionings[k] = p.Clone()
	return nil
}

func (r directorySync) GetProvisioning(_ context.Context, tid, conn string) (*store.DirectoryProvisioning, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	p, ok := r.s.directory.provisionings[key{tid, conn}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return p.Clone(), nil
}

func (r directorySync) UpdateProvisioning(_ context.Context, p *store.DirectoryProvisioning) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{p.TenantID, p.ConnectionID}
	cur, ok := r.s.directory.provisionings[k]
	if !ok {
		return store.ErrNotFound
	}
	next := p.Clone()
	next.CreatedAt = cur.CreatedAt
	r.s.directory.provisionings[k] = next
	return nil
}

func (r directorySync) DeleteProvisioning(_ context.Context, tid, conn string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, conn}
	if _, ok := r.s.directory.provisionings[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.directory.provisionings, k)
	delete(r.s.directory.syncGroups, k)
	return nil
}

func (r directorySync) ListProvisionings(_ context.Context, tid string, p store.Page) ([]*store.DirectoryProvisioning, int, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []*store.DirectoryProvisioning
	for k, v := range r.s.directory.provisionings {
		if k.tenant == tid {
			all = append(all, v.Clone())
		}
	}
	slices.SortFunc(all, func(a, b *store.DirectoryProvisioning) int { return cmp.Compare(a.ConnectionID, b.ConnectionID) })
	return dirPage(all, p), len(all), nil
}

func (r directorySync) ClaimDue(_ context.Context, now time.Time, lease time.Duration, limit int) ([]*store.DirectoryProvisioning, error) {
	r.s.lock()
	defer r.s.unlock()
	var due []*store.DirectoryProvisioning
	for _, v := range r.s.directory.provisionings {
		if v.NextSyncAt != nil && !v.NextSyncAt.After(now) && (v.LeaseUntil == nil || !v.LeaseUntil.After(now)) {
			due = append(due, v)
		}
	}
	slices.SortFunc(due, func(a, b *store.DirectoryProvisioning) int {
		return cmp.Or(a.NextSyncAt.Compare(*b.NextSyncAt), cmp.Compare(a.TenantID, b.TenantID), cmp.Compare(a.ConnectionID, b.ConnectionID))
	})
	if len(due) > limit {
		due = due[:max(limit, 0)]
	}
	until := now.Add(lease)
	out := make([]*store.DirectoryProvisioning, 0, len(due))
	for _, v := range due {
		v.LeaseUntil = &until
		out = append(out, v.Clone())
	}
	return out, nil
}

func (r directorySync) ReplaceGroups(_ context.Context, tid, conn string, groups []store.SynchronizedGroup) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, conn}
	if _, ok := r.s.directory.provisionings[k]; !ok {
		return store.ErrNotFound
	}
	next := cloneSyncGroups(groups)
	slices.SortStableFunc(next, func(a, b store.SynchronizedGroup) int { return cmp.Compare(a.GroupID, b.GroupID) })
	next = slices.CompactFunc(next, func(a, b store.SynchronizedGroup) bool { return a.GroupID == b.GroupID })
	r.s.directory.syncGroups[k] = next
	return nil
}

func (r directorySync) ListGroups(_ context.Context, tid, conn string) ([]store.SynchronizedGroup, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	k := key{tid, conn}
	if _, ok := r.s.directory.provisionings[k]; !ok {
		return nil, store.ErrNotFound
	}
	return cloneSyncGroups(r.s.directory.syncGroups[k]), nil
}
