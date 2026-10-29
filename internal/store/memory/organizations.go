package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type orgConnKey struct{ tenant, org, conn string }
type orgMemberKey struct{ tenant, org, user string }
type orgRoleKey struct{ tenant, org, user, role string }

type organizations struct{ s *Store }

func (s *Store) Organizations() store.Organizations { return organizations{s} }

// SetOrgLimits overrides the caps so conformance tests can reach them.
func (s *Store) SetOrgLimits(l store.OrgLimits) {
	s.lock()
	defer s.unlock()
	s.orgLimits = l
}

func cloneOrg(o *store.Organization) *store.Organization {
	out := *o
	if o.Branding != nil {
		b := *o.Branding
		if o.Branding.LogoURL != nil {
			v := *o.Branding.LogoURL
			b.LogoURL = &v
		}
		if o.Branding.Colors != nil {
			c := *o.Branding.Colors
			b.Colors = &c
		}
		out.Branding = &b
	}
	if o.Metadata != nil {
		out.Metadata = make(map[string]string, len(o.Metadata))
		for k, v := range o.Metadata {
			out.Metadata[k] = v
		}
	}
	return &out
}

// entry is one listable item with its sort key. Lists are ordered by
// (sort, id), reversed when desc.
type entry[T any] struct {
	item     T
	sort, id string
}

func orderEntries[T any](es []entry[T], desc bool) {
	slices.SortFunc(es, func(a, b entry[T]) int { return cmpEntry(a.sort, a.id, b.sort, b.id, desc) })
}

func cmpEntry(as, ai, bs, bi string, desc bool) int {
	n := strings.Compare(as, bs)
	if n == 0 {
		n = strings.Compare(ai, bi)
	}
	if desc {
		return -n
	}
	return n
}

// pageEntries pages es, which orderEntries already ordered. sort is the
// request's Sort value, which the cursor binds with scope.
func pageEntries[T any](es []entry[T], p store.OrgPage, scope string, desc bool) (store.OrgResult[T], error) {
	mode, err := orgrules.NormalizePage(&p)
	if err != nil {
		return store.OrgResult[T]{}, store.ErrInvalid
	}
	out := store.OrgResult[T]{Items: []T{}}
	if mode == orgrules.Offset {
		out.Total = len(es)
		start := len(es)
		// Division avoids overflow for arbitrarily large page input.
		if p.Page <= len(es)/p.PerPage {
			start = p.Page * p.PerPage
		}
		for _, e := range es[start:min(len(es), start+p.PerPage)] {
			out.Items = append(out.Items, e.item)
		}
		return out, nil
	}
	if p.From != "" {
		c, err := orgrules.DecodeCursor(p.From, scope, p.Sort)
		if err != nil {
			return out, store.ErrInvalid
		}
		es = slices.DeleteFunc(slices.Clone(es), func(e entry[T]) bool { return cmpEntry(e.sort, e.id, c.Key, c.ID, desc) <= 0 })
	}
	for _, e := range es[:min(len(es), p.Take)] {
		out.Items = append(out.Items, e.item)
	}
	if len(es) > p.Take {
		last := es[p.Take-1]
		out.Next = orgrules.EncodeCursor(orgrules.Cursor{Scope: scope, Sort: p.Sort, Key: last.sort, ID: last.id})
	}
	return out, nil
}

// pageIDs pages plain IDs ordered ascending.
func pageIDs(ids []string, p store.OrgPage, scope string) (store.OrgResult[string], error) {
	slices.Sort(ids)
	es := make([]entry[string], len(ids))
	for i, id := range ids {
		es[i] = entry[string]{item: id, id: id}
	}
	return pageEntries(es, p, scope, false)
}

// nameCollation ignores case and punctuation like the reference ordering.
var nameCollation = strings.NewReplacer("-", "", "_", "")

// pageOrgs orders and pages organizations. Offset mode without a sort is
// ascending by name; checkpoint mode without a sort is creation order.
func pageOrgs(orgs []*store.Organization, p store.OrgPage, scope string) (store.OrgResult[store.Organization], error) {
	field, desc, err := orgrules.ParseSort(p.Sort)
	if err != nil {
		return store.OrgResult[store.Organization]{}, store.ErrInvalid
	}
	if field == "" {
		field = orgrules.SortName
		if p.From != "" || p.Take > 0 {
			field = orgrules.SortCreatedAt
		}
	}
	es := make([]entry[store.Organization], len(orgs))
	for i, o := range orgs {
		e := entry[store.Organization]{item: *cloneOrg(o), id: o.ID}
		switch field {
		case orgrules.SortName:
			e.sort = nameCollation.Replace(strings.ToLower(o.Name))
		case orgrules.SortDisplayName:
			e.sort = strings.ToLower(o.DisplayName)
		default:
			e.sort = fmt.Sprintf("%020d", o.CreatedAt.UnixNano())
		}
		es[i] = e
	}
	orderEntries(es, desc)
	return pageEntries(es, p, scope, desc)
}

func orgScope(kind, tid string, rest ...string) string {
	return kind + "/" + tid + "/" + strings.Join(rest, "/")
}

func (r organizations) Create(_ context.Context, o *store.Organization, conns []store.OrganizationConnection) error {
	if o == nil || o.TenantID == "" || !orgrules.ValidID(o.ID) {
		return store.ErrInvalid
	}
	n, err := orgrules.NormalizeOrganization(*o)
	if err != nil {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	s := r.s
	if _, ok := s.tenants[o.TenantID]; !ok {
		return store.ErrNotFound
	}
	count := 0
	for k, old := range s.orgs {
		if k.tenant != o.TenantID {
			continue
		}
		count++
		if old.ID == n.ID || old.Name == n.Name {
			return store.ErrConflict
		}
	}
	if count >= s.orgLimits.OrganizationsPerTenant {
		return store.ErrPrecondition
	}
	if len(conns) > s.orgLimits.ConnectionsPerOrganization {
		return store.ErrPrecondition
	}
	seen := map[string]bool{}
	for _, c := range conns {
		if seen[c.ConnectionID] {
			return store.ErrConflict
		}
		seen[c.ConnectionID] = true
		if err := s.checkOrgConnection(o.TenantID, c); err != nil {
			return err
		}
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = s.now()
	}
	if n.UpdatedAt.IsZero() {
		n.UpdatedAt = n.CreatedAt
	}
	s.orgs[key{n.TenantID, n.ID}] = cloneOrg(&n)
	for _, c := range conns {
		c.TenantID, c.OrganizationID = n.TenantID, n.ID
		s.orgConns[orgConnKey{c.TenantID, c.OrganizationID, c.ConnectionID}] = &c
	}
	*o = *cloneOrg(&n)
	return nil
}

// checkOrgConnection verifies the connection exists and the flags suit its
// strategy. The caller holds the lock.
func (s *Store) checkOrgConnection(tid string, c store.OrganizationConnection) error {
	conn := s.connections[key{tid, c.ConnectionID}]
	if conn == nil {
		return store.ErrNotFound
	}
	if orgrules.ValidateConnection(conn.Strategy, c) != nil {
		return store.ErrInvalid
	}
	return nil
}

func (r organizations) Get(_ context.Context, tid, id string) (*store.Organization, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	o := r.s.orgs[key{tid, id}]
	if o == nil {
		return nil, store.ErrNotFound
	}
	return cloneOrg(o), nil
}

func (r organizations) GetByName(_ context.Context, tid, name string) (*store.Organization, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, o := range r.s.orgs {
		if k.tenant == tid && o.Name == name {
			return cloneOrg(o), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r organizations) List(_ context.Context, tid string, p store.OrgPage) (store.OrgResult[store.Organization], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var orgs []*store.Organization
	for k, o := range r.s.orgs {
		if k.tenant == tid {
			orgs = append(orgs, o)
		}
	}
	return pageOrgs(orgs, p, orgScope("orgs", tid))
}

func (r organizations) Update(_ context.Context, o *store.Organization) error {
	if o == nil {
		return store.ErrInvalid
	}
	n, err := orgrules.NormalizeOrganization(*o)
	if err != nil {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	cur := r.s.orgs[key{o.TenantID, o.ID}]
	if cur == nil {
		return store.ErrNotFound
	}
	for k, old := range r.s.orgs {
		if k.tenant == o.TenantID && old.ID != o.ID && old.Name == n.Name {
			return store.ErrConflict
		}
	}
	n.CreatedAt, n.UpdatedAt = cur.CreatedAt, r.s.now()
	r.s.orgs[key{o.TenantID, o.ID}] = cloneOrg(&n)
	*o = *cloneOrg(&n)
	return nil
}

func (r organizations) Delete(_ context.Context, tid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.orgs[key{tid, id}] == nil {
		return store.ErrNotFound
	}
	r.s.deleteOrg(tid, id)
	return nil
}

// deleteOrg removes an organization with its connections, members and member
// roles. The caller holds the lock.
func (s *Store) deleteOrg(tid, id string) {
	delete(s.orgs, key{tid, id})
	for k := range s.orgConns {
		if k.tenant == tid && k.org == id {
			delete(s.orgConns, k)
		}
	}
	for k := range s.orgMembers {
		if k.tenant == tid && k.org == id {
			delete(s.orgMembers, k)
		}
	}
	for k := range s.orgMemberRoles {
		if k.tenant == tid && k.org == id {
			delete(s.orgMemberRoles, k)
		}
	}
}

// cleanupOrgUser removes a deleted user's memberships and member roles. The
// caller holds the lock.
func (s *Store) cleanupOrgUser(tid, uid string) {
	for k := range s.orgMembers {
		if k.tenant == tid && k.user == uid {
			delete(s.orgMembers, k)
		}
	}
	for k := range s.orgMemberRoles {
		if k.tenant == tid && k.user == uid {
			delete(s.orgMemberRoles, k)
		}
	}
}

// cleanupOrgConnection removes a deleted connection's enablements. The caller
// holds the lock.
func (s *Store) cleanupOrgConnection(tid, connID string) {
	for k := range s.orgConns {
		if k.tenant == tid && k.conn == connID {
			delete(s.orgConns, k)
		}
	}
}

// cleanupOrgRole removes a deleted role's member assignments. The caller
// holds the lock.
func (s *Store) cleanupOrgRole(tid, roleID string) {
	for k := range s.orgMemberRoles {
		if k.tenant == tid && k.role == roleID {
			delete(s.orgMemberRoles, k)
		}
	}
}

// deleteOrgTenant removes every organization row of a tenant. The caller
// holds the lock.
func (s *Store) deleteOrgTenant(tid string) {
	for k := range s.orgs {
		if k.tenant == tid {
			delete(s.orgs, k)
		}
	}
	for k := range s.orgConns {
		if k.tenant == tid {
			delete(s.orgConns, k)
		}
	}
	for k := range s.orgMembers {
		if k.tenant == tid {
			delete(s.orgMembers, k)
		}
	}
	for k := range s.orgMemberRoles {
		if k.tenant == tid {
			delete(s.orgMemberRoles, k)
		}
	}
}

func (r organizations) Connections(_ context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[store.OrganizationConnection], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.orgs[key{tid, orgID}] == nil {
		return store.OrgResult[store.OrganizationConnection]{}, store.ErrNotFound
	}
	var es []entry[store.OrganizationConnection]
	for k, c := range r.s.orgConns {
		if k.tenant == tid && k.org == orgID {
			es = append(es, entry[store.OrganizationConnection]{item: *c, id: c.ConnectionID})
		}
	}
	orderEntries(es, false)
	return pageEntries(es, p, orgScope("conns", tid, orgID), false)
}

func (r organizations) GetConnection(_ context.Context, tid, orgID, connID string) (*store.OrganizationConnection, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	c := r.s.orgConns[orgConnKey{tid, orgID, connID}]
	if c == nil {
		return nil, store.ErrNotFound
	}
	v := *c
	return &v, nil
}

func (r organizations) PutConnection(_ context.Context, c store.OrganizationConnection, create bool) error {
	r.s.lock()
	defer r.s.unlock()
	s := r.s
	if s.orgs[key{c.TenantID, c.OrganizationID}] == nil {
		return store.ErrNotFound
	}
	if err := s.checkOrgConnection(c.TenantID, c); err != nil {
		return err
	}
	k := orgConnKey{c.TenantID, c.OrganizationID, c.ConnectionID}
	_, exists := s.orgConns[k]
	switch {
	case create && exists:
		return store.ErrConflict
	case !create && !exists:
		return store.ErrNotFound
	}
	if create {
		n := 0
		for ek := range s.orgConns {
			if ek.tenant == c.TenantID && ek.org == c.OrganizationID {
				n++
			}
		}
		if n >= s.orgLimits.ConnectionsPerOrganization {
			return store.ErrPrecondition
		}
	}
	s.orgConns[k] = &c
	return nil
}

func (r organizations) DeleteConnection(_ context.Context, tid, orgID, connID string) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.orgs[key{tid, orgID}] == nil || r.s.connections[key{tid, connID}] == nil {
		return store.ErrNotFound
	}
	delete(r.s.orgConns, orgConnKey{tid, orgID, connID})
	return nil
}

func (r organizations) ConnectionsByConnection(_ context.Context, tid, connID string) ([]store.OrganizationConnection, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []store.OrganizationConnection{}
	for k, c := range r.s.orgConns {
		if k.tenant == tid && k.conn == connID {
			out = append(out, *c)
		}
	}
	slices.SortFunc(out, func(a, b store.OrganizationConnection) int {
		return strings.Compare(a.OrganizationID, b.OrganizationID)
	})
	return out, nil
}

func (r organizations) Members(_ context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[string], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.orgs[key{tid, orgID}] == nil {
		return store.OrgResult[string]{}, store.ErrNotFound
	}
	var ids []string
	for k := range r.s.orgMembers {
		if k.tenant == tid && k.org == orgID {
			ids = append(ids, k.user)
		}
	}
	return pageIDs(ids, p, orgScope("members", tid, orgID))
}

func (r organizations) AddMembers(_ context.Context, tid, orgID string, userIDs []string) error {
	if len(userIDs) == 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.orgs[key{tid, orgID}] == nil {
		return store.ErrNotFound
	}
	for _, id := range userIDs {
		if r.s.users[key{tid, id}] == nil {
			return store.ErrNotFound
		}
	}
	for _, id := range userIDs {
		r.s.orgMembers[orgMemberKey{tid, orgID, id}] = true
	}
	return nil
}

func (r organizations) RemoveMembers(_ context.Context, tid, orgID string, userIDs []string) error {
	if len(userIDs) == 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.orgs[key{tid, orgID}] == nil {
		return store.ErrNotFound
	}
	// Role assignments stay so that re-adding the member restores them.
	for _, id := range userIDs {
		delete(r.s.orgMembers, orgMemberKey{tid, orgID, id})
	}
	return nil
}

func (r organizations) IsMember(_ context.Context, tid, orgID, userID string) (bool, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.orgs[key{tid, orgID}] == nil {
		return false, store.ErrNotFound
	}
	return r.s.orgMembers[orgMemberKey{tid, orgID, userID}], nil
}

func (r organizations) UserOrganizations(_ context.Context, tid, userID string, p store.OrgPage) (store.OrgResult[store.Organization], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.users[key{tid, userID}] == nil {
		return store.OrgResult[store.Organization]{}, store.ErrNotFound
	}
	var orgs []*store.Organization
	for k := range r.s.orgMembers {
		if k.tenant == tid && k.user == userID {
			if o := r.s.orgs[key{tid, k.org}]; o != nil {
				orgs = append(orgs, o)
			}
		}
	}
	return pageOrgs(orgs, p, orgScope("user-orgs", tid, userID))
}

// member reports whether the organization exists and userID belongs to it.
// A missing organization or non-member is ErrNotFound.
func (s *Store) member(tid, orgID, userID string) error {
	if s.orgs[key{tid, orgID}] == nil || !s.orgMembers[orgMemberKey{tid, orgID, userID}] {
		return store.ErrNotFound
	}
	return nil
}

func (r organizations) MemberRoles(_ context.Context, tid, orgID, userID string, p store.OrgPage) (store.OrgResult[string], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if err := r.s.member(tid, orgID, userID); err != nil {
		return store.OrgResult[string]{}, err
	}
	var ids []string
	for k := range r.s.orgMemberRoles {
		if k.tenant == tid && k.org == orgID && k.user == userID {
			ids = append(ids, k.role)
		}
	}
	return pageIDs(ids, p, orgScope("member-roles", tid, orgID, userID))
}

func (r organizations) ChangeMemberRoles(_ context.Context, tid, orgID, userID string, add bool, roleIDs []string) error {
	if len(roleIDs) == 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	s := r.s
	if err := s.member(tid, orgID, userID); err != nil {
		return err
	}
	if !add {
		for _, id := range roleIDs {
			delete(s.orgMemberRoles, orgRoleKey{tid, orgID, userID, id})
		}
		return nil
	}
	for _, id := range roleIDs {
		if s.roles[key{tid, id}] == nil {
			return store.ErrNotFound
		}
	}
	have := map[string]bool{}
	for k := range s.orgMemberRoles {
		if k.tenant == tid && k.org == orgID && k.user == userID {
			have[k.role] = true
		}
	}
	for _, id := range roleIDs {
		have[id] = true
	}
	if len(have) > s.orgLimits.RolesPerMember {
		return store.ErrPrecondition
	}
	for _, id := range roleIDs {
		s.orgMemberRoles[orgRoleKey{tid, orgID, userID, id}] = true
	}
	return nil
}

func (r organizations) RoleMembers(_ context.Context, tid, orgID, roleID string, p store.OrgPage) (store.OrgResult[string], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.orgs[key{tid, orgID}] == nil || r.s.roles[key{tid, roleID}] == nil {
		return store.OrgResult[string]{}, store.ErrNotFound
	}
	// Checkpoint style only: offset parameters are ignored.
	p.Page, p.PerPage, p.IncludeTotals = 0, 0, false
	if p.From == "" && p.Take == 0 {
		p.Take = orgrules.Limit("take_default")
	}
	var ids []string
	for k := range r.s.orgMemberRoles {
		if k.tenant == tid && k.org == orgID && k.role == roleID && r.s.orgMembers[orgMemberKey{tid, orgID, k.user}] {
			ids = append(ids, k.user)
		}
	}
	return pageIDs(ids, p, orgScope("role-members", tid, orgID, roleID))
}
