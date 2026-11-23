package memory

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// directoryState is Plan 37c's SCIM and group state (scim.v1).
type directoryState struct {
	configs map[key]*store.SCIMConfig // key{tenant, connection}
	tokens  map[key]*store.SCIMToken  // key{tenant, token id}
	groups  map[key]*store.Group      // key{tenant, group id}
	members map[memberKey]store.GroupMember
	roles   map[roleKey]bool
	// Phase C: directory provisioning by connection, and its groups.
	provisionings map[key]*store.DirectoryProvisioning // key{tenant, connection}
	syncGroups    map[key][]store.SynchronizedGroup    // key{tenant, connection}
}

type memberKey struct{ tenant, group, user string }

// roleKey is a group role assignment within a tenant.
type roleKey struct {
	tenant string
	store.GroupRole
}

func newDirectoryState() *directoryState {
	return &directoryState{configs: map[key]*store.SCIMConfig{}, tokens: map[key]*store.SCIMToken{}, groups: map[key]*store.Group{},
		members: map[memberKey]store.GroupMember{}, roles: map[roleKey]bool{},
		provisionings: map[key]*store.DirectoryProvisioning{}, syncGroups: map[key][]store.SynchronizedGroup{}}
}

func (d *directoryState) clone() *directoryState {
	out := newDirectoryState()
	for k, v := range d.provisionings {
		out.provisionings[k] = v.Clone()
	}
	for k, v := range d.syncGroups {
		out.syncGroups[k] = cloneSyncGroups(v)
	}
	for k, v := range d.configs {
		out.configs[k] = v.Clone()
	}
	for k, v := range d.tokens {
		out.tokens[k] = v.Clone()
	}
	for k, v := range d.groups {
		g := *v
		out.groups[k] = &g
	}
	for k, v := range d.members {
		out.members[k] = v
	}
	for k, v := range d.roles {
		out.roles[k] = v
	}
	return out
}

type directory struct{ s *Store }

func (s *Store) Directory() store.Directory { return directory{s} }
func (s *Store) DirectorySupported() bool   { return true }

func (r directory) CreateSCIMConfig(_ context.Context, c *store.SCIMConfig) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{c.TenantID, c.ConnectionID}
	if _, ok := r.s.directory.configs[k]; ok {
		return store.ErrConflict
	}
	r.s.directory.configs[k] = c.Clone()
	return nil
}

func (r directory) GetSCIMConfig(_ context.Context, tid, conn string) (*store.SCIMConfig, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	c, ok := r.s.directory.configs[key{tid, conn}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return c.Clone(), nil
}

func (r directory) UpdateSCIMConfig(_ context.Context, c *store.SCIMConfig) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{c.TenantID, c.ConnectionID}
	if _, ok := r.s.directory.configs[k]; !ok {
		return store.ErrNotFound
	}
	r.s.directory.configs[k] = c.Clone()
	return nil
}

func (r directory) DeleteSCIMConfig(_ context.Context, tid, conn string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, conn}
	if _, ok := r.s.directory.configs[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.directory.configs, k)
	r.s.directory.dropTokens(tid, conn)
	return nil
}

func (d *directoryState) dropTokens(tid, conn string) {
	for k, t := range d.tokens {
		if t.TenantID == tid && t.ConnectionID == conn {
			delete(d.tokens, k)
		}
	}
}

func (r directory) ListSCIMConfigs(_ context.Context, tid string) ([]*store.SCIMConfig, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []*store.SCIMConfig{}
	for k, c := range r.s.directory.configs {
		if k.tenant == tid {
			out = append(out, c.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *store.SCIMConfig) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ConnectionID, b.ConnectionID))
	})
	return out, nil
}

func (r directory) CreateSCIMToken(_ context.Context, t *store.SCIMToken) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{t.TenantID, t.ID}
	active := 0
	for _, o := range r.s.directory.tokens {
		if o.TenantID == t.TenantID && o.ConnectionID == t.ConnectionID && o.Active(t.CreatedAt) {
			active++
		}
		if o.TenantID == t.TenantID && o.Hash == t.Hash {
			return store.ErrConflict
		}
	}
	if _, ok := r.s.directory.tokens[k]; ok {
		return store.ErrConflict
	}
	if active >= store.MaxActiveSCIMTokens {
		return store.ErrSCIMTokenLimit
	}
	r.s.directory.tokens[k] = t.Clone()
	return nil
}

func sortTokens(ts []*store.SCIMToken) {
	slices.SortFunc(ts, func(a, b *store.SCIMToken) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID))
	})
}

func (r directory) ListSCIMTokens(_ context.Context, tid, conn string) ([]*store.SCIMToken, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []*store.SCIMToken{}
	for _, t := range r.s.directory.tokens {
		if t.TenantID == tid && t.ConnectionID == conn {
			out = append(out, t.Clone())
		}
	}
	sortTokens(out)
	return out, nil
}

func (r directory) DeleteSCIMToken(_ context.Context, tid, conn, id string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, id}
	t, ok := r.s.directory.tokens[k]
	if !ok || t.ConnectionID != conn {
		return store.ErrNotFound
	}
	delete(r.s.directory.tokens, k)
	return nil
}

func (r directory) UseSCIMToken(_ context.Context, tid, hash string, now time.Time) (*store.SCIMToken, error) {
	r.s.lock()
	defer r.s.unlock()
	for _, t := range r.s.directory.tokens {
		if t.TenantID == tid && t.Hash == hash {
			used := now
			t.LastUsedAt = &used
			return t.Clone(), nil
		}
	}
	return nil, store.ErrNotFound
}

func (d *directoryState) nameTaken(g *store.Group) bool {
	for _, o := range d.groups {
		if o.TenantID == g.TenantID && o.ConnectionID == g.ConnectionID && o.ID != g.ID && o.Name == g.Name {
			return true
		}
	}
	return false
}

func (r directory) CreateGroup(_ context.Context, g *store.Group) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{g.TenantID, g.ID}
	if _, ok := r.s.directory.groups[k]; ok || r.s.directory.nameTaken(g) {
		return store.ErrConflict
	}
	c := *g
	r.s.directory.groups[k] = &c
	return nil
}

func (r directory) GetGroup(_ context.Context, tid, id string) (*store.Group, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	g, ok := r.s.directory.groups[key{tid, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	c := *g
	return &c, nil
}

func (r directory) UpdateGroup(_ context.Context, g *store.Group) error {
	r.s.lock()
	defer r.s.unlock()
	cur, ok := r.s.directory.groups[key{g.TenantID, g.ID}]
	if !ok {
		return store.ErrNotFound
	}
	next := *cur
	next.Name, next.ExternalID, next.UpdatedAt = g.Name, g.ExternalID, g.UpdatedAt
	if r.s.directory.nameTaken(&next) {
		return store.ErrConflict
	}
	*cur = next
	return nil
}

func (r directory) DeleteGroup(_ context.Context, tid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.directory.groups[key{tid, id}]; !ok {
		return store.ErrNotFound
	}
	r.s.directory.dropGroup(tid, id)
	return nil
}

func (d *directoryState) dropGroup(tid, id string) {
	delete(d.groups, key{tid, id})
	for k := range d.members {
		if k.tenant == tid && k.group == id {
			delete(d.members, k)
		}
	}
	for k := range d.roles {
		if k.tenant == tid && k.GroupID == id {
			delete(d.roles, k)
		}
	}
}

func groupMatches(g *store.Group, f store.GroupFilter) bool {
	return (f.ConnectionID == "" || g.ConnectionID == f.ConnectionID) && (f.Name == "" || g.Name == f.Name) &&
		(f.ExternalID == "" || g.ExternalID == f.ExternalID) &&
		(f.NamePrefix == "" || strings.HasPrefix(strings.ToLower(g.Name), strings.ToLower(f.NamePrefix))) &&
		(len(f.IDs) == 0 || slices.Contains(f.IDs, g.ID))
}

func dirPage[T any](all []T, p store.Page) []T {
	total := len(all)
	all = all[min(max(p.Offset, 0), total):]
	if p.Limit > 0 && len(all) > p.Limit {
		all = all[:p.Limit]
	}
	return all
}

func (r directory) ListGroups(_ context.Context, tid string, f store.GroupFilter, p store.Page) ([]*store.Group, int, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []*store.Group
	for k, g := range r.s.directory.groups {
		if k.tenant == tid && groupMatches(g, f) {
			c := *g
			all = append(all, &c)
		}
	}
	slices.SortFunc(all, func(a, b *store.Group) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID))
	})
	return dirPage(all, p), len(all), nil
}

func (r directory) UpdateGroupMembers(_ context.Context, tid, gid string, add, remove []string, replace bool, now time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.directory.groups[key{tid, gid}]; !ok {
		return store.ErrNotFound
	}
	for k := range r.s.directory.members {
		if k.tenant == tid && k.group == gid && (replace && !slices.Contains(add, k.user) || slices.Contains(remove, k.user)) {
			delete(r.s.directory.members, k)
		}
	}
	for _, u := range add {
		k := memberKey{tid, gid, u}
		if _, ok := r.s.directory.members[k]; !ok {
			r.s.directory.members[k] = store.GroupMember{GroupID: gid, UserID: u, CreatedAt: now}
		}
	}
	return nil
}

func sortMembers(ms []store.GroupMember) {
	slices.SortFunc(ms, func(a, b store.GroupMember) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.UserID, b.UserID), strings.Compare(a.GroupID, b.GroupID))
	})
}

func (r directory) ListGroupMembers(_ context.Context, tid, gid string, p store.Page) ([]store.GroupMember, int, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []store.GroupMember
	for k, m := range r.s.directory.members {
		if k.tenant == tid && k.group == gid {
			all = append(all, m)
		}
	}
	sortMembers(all)
	return dirPage(all, p), len(all), nil
}

func (r directory) ListUserGroups(_ context.Context, tid, uid string) ([]store.GroupMember, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	all := []store.GroupMember{}
	for k, m := range r.s.directory.members {
		if k.tenant == tid && k.user == uid {
			all = append(all, m)
		}
	}
	sortMembers(all)
	return all, nil
}

func (r directory) AddGroupRoles(_ context.Context, tid, gid, org string, roles []string) error {
	r.s.lock()
	defer r.s.unlock()
	for _, role := range roles {
		r.s.directory.roles[roleKey{tid, store.GroupRole{GroupID: gid, RoleID: role, OrganizationID: org}}] = true
	}
	return nil
}

func (r directory) RemoveGroupRoles(_ context.Context, tid, gid, org string, roles []string) error {
	r.s.lock()
	defer r.s.unlock()
	for _, role := range roles {
		delete(r.s.directory.roles, roleKey{tid, store.GroupRole{GroupID: gid, RoleID: role, OrganizationID: org}})
	}
	return nil
}

func (r directory) ListGroupRoles(_ context.Context, tid, gid, role, org string) ([]store.GroupRole, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []store.GroupRole{}
	for k := range r.s.directory.roles {
		if k.tenant == tid && (gid == "" || k.GroupID == gid) && (role == "" || k.RoleID == role) && k.OrganizationID == org {
			out = append(out, k.GroupRole)
		}
	}
	slices.SortFunc(out, func(a, b store.GroupRole) int {
		return cmp.Or(strings.Compare(a.GroupID, b.GroupID), strings.Compare(a.RoleID, b.RoleID))
	})
	return out, nil
}

// Cascades, called with the write lock held.

func (d *directoryState) dropUsers(tid string, gone map[string]bool) {
	for k := range d.members {
		if k.tenant == tid && gone[k.user] {
			delete(d.members, k)
		}
	}
}

func (d *directoryState) dropRole(tid, role string) {
	for k := range d.roles {
		if k.tenant == tid && k.RoleID == role {
			delete(d.roles, k)
		}
	}
}

func (d *directoryState) dropOrganization(tid, org string) {
	for k := range d.roles {
		if k.tenant == tid && k.OrganizationID == org {
			delete(d.roles, k)
		}
	}
}

func (d *directoryState) dropConnection(tid, conn string) {
	delete(d.configs, key{tid, conn})
	delete(d.provisionings, key{tid, conn})
	delete(d.syncGroups, key{tid, conn})
	d.dropTokens(tid, conn)
	for k, g := range d.groups {
		if k.tenant == tid && g.ConnectionID == conn {
			d.dropGroup(tid, g.ID)
		}
	}
}

func (d *directoryState) dropTenant(tid string) {
	for k := range d.provisionings {
		if k.tenant == tid {
			delete(d.provisionings, k)
		}
	}
	for k := range d.syncGroups {
		if k.tenant == tid {
			delete(d.syncGroups, k)
		}
	}
	for k := range d.configs {
		if k.tenant == tid {
			delete(d.configs, k)
		}
	}
	for k := range d.tokens {
		if k.tenant == tid {
			delete(d.tokens, k)
		}
	}
	for k := range d.groups {
		if k.tenant == tid {
			delete(d.groups, k)
		}
	}
	for k := range d.members {
		if k.tenant == tid {
			delete(d.members, k)
		}
	}
	for k := range d.roles {
		if k.tenant == tid {
			delete(d.roles, k)
		}
	}
}
