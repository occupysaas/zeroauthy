package memory

import (
	"bytes"
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func cloneModule(m *store.ActionModule) *store.ActionModule {
	c := *m
	c.Dependencies = cloneDeps(m.Dependencies)
	c.Secrets = cloneSecrets(m.Secrets)
	return &c
}
func cloneModuleVersion(v *store.ActionModuleVersion) *store.ActionModuleVersion {
	c := *v
	c.Dependencies = cloneDeps(v.Dependencies)
	c.Secrets = cloneSecrets(v.Secrets)
	return &c
}
func (s *Store) moduleNameTaken(tid, name string) bool {
	for k, m := range s.modules {
		if k.tenant == tid && m.Name == name {
			return true
		}
	}
	return false
}
func (r actionsRepo) CreateModule(_ context.Context, m *store.ActionModule) error {
	c := cloneModule(m)
	if c.TenantID == "" || c.ID == "" || len(actionsrules.NormalizeModule(c)) > 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[c.TenantID] == nil {
		return store.ErrNotFound
	}
	if r.s.modules[key{c.TenantID, c.ID}] != nil || r.s.moduleNameTaken(c.TenantID, c.Name) {
		return store.ErrConflict
	}
	// Tombstoned IDs cannot be recycled while their immutable versions survive.
	for k, v := range r.s.moduleVersions {
		if k.tenant == c.TenantID && v.ModuleID == c.ID {
			return store.ErrConflict
		}
	}
	n := 0
	for k := range r.s.modules {
		if k.tenant == c.TenantID {
			n++
		}
	}
	if n >= actionsrules.Inventory().Limits["modules_per_tenant"] {
		return store.ErrPrecondition
	}
	c.LatestVersionNumber = 0
	c.AllChangesPublished = false
	c.CreatedAt = r.stamp(c.CreatedAt)
	c.UpdatedAt = r.stamp(c.UpdatedAt)
	r.s.modules[key{c.TenantID, c.ID}] = c
	return nil
}
func (r actionsRepo) GetModule(_ context.Context, tid, id string) (*store.ActionModule, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	m := r.s.modules[key{tid, id}]
	if m == nil {
		return nil, store.ErrNotFound
	}
	return cloneModule(m), nil
}
func (r actionsRepo) GetModuleByName(_ context.Context, tid, name string) (*store.ActionModule, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, m := range r.s.modules {
		if k.tenant == tid && m.Name == name {
			return cloneModule(m), nil
		}
	}
	return nil, store.ErrNotFound
}
func equalModuleSecrets(a, b []store.ActionSecret) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || !bytes.Equal(a[i].Sealed, b[i].Sealed) {
			return false
		}
	}
	return true
}

// modulePublished compares content, so reverting an edit restores the published flag.
func (s *Store) modulePublished(m *store.ActionModule) bool {
	for k, v := range s.moduleVersions {
		if k.tenant != m.TenantID || v.ModuleID != m.ID || v.Number != m.LatestVersionNumber {
			continue
		}
		deps := v.Dependencies
		if b := s.builds[key{m.TenantID, v.BuildID}]; b != nil && slices.Equal(m.Dependencies, b.Requested) {
			deps = m.Dependencies
		}
		return m.Code == v.Code && m.DraftBuildID == v.BuildID && slices.Equal(m.Dependencies, deps) && equalModuleSecrets(m.Secrets, v.Secrets)
	}
	return false
}
func (r actionsRepo) UpdateModule(_ context.Context, m *store.ActionModule) error {
	c := cloneModule(m)
	if len(actionsrules.NormalizeModule(c)) > 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	old := r.s.modules[key{c.TenantID, c.ID}]
	if old == nil {
		return store.ErrNotFound
	}
	if old.Name != c.Name {
		return store.ErrInvalid
	}
	c.CreatedAt = old.CreatedAt
	c.LatestVersionNumber = old.LatestVersionNumber
	c.AllChangesPublished = r.s.modulePublished(c)
	c.UpdatedAt = r.s.now()
	r.s.modules[key{c.TenantID, c.ID}] = c
	return nil
}
func refContains(refs []store.ModuleRef, id string) bool {
	return slices.ContainsFunc(refs, func(r store.ModuleRef) bool { return r.ModuleID == id })
}

// moduleUsers is called with the store lock held and deduplicates draft/deployed use.
func (s *Store) moduleUsers(tid, id string) []store.ModuleUser {
	out := []store.ModuleUser{}
	for k, a := range s.actions {
		if k.tenant != tid {
			continue
		}
		draft := refContains(a.Modules, id)
		deployed := false
		if v := s.actionVersions[key{tid, a.DeployedVersionID}]; v != nil {
			deployed = refContains(v.Modules, id)
		}
		if draft || deployed {
			out = append(out, store.ModuleUser{Action: *cloneAction(a), InDraft: draft, InDeployed: deployed})
		}
	}
	slices.SortFunc(out, func(a, b store.ModuleUser) int { return strings.Compare(a.ID, b.ID) })
	return out
}
func (r actionsRepo) ModuleUsers(_ context.Context, tid, id string, p store.PageRequest) (store.Paged[store.ModuleUser], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.modules[key{tid, id}] == nil {
		return store.Paged[store.ModuleUser]{}, store.ErrNotFound
	}
	return page(r.s.moduleUsers(tid, id), p), nil
}
func (r actionsRepo) DeleteModule(_ context.Context, tid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.modules[key{tid, id}] == nil {
		return store.ErrNotFound
	}
	if len(r.s.moduleUsers(tid, id)) > 0 {
		return store.ErrPrecondition
	}
	delete(r.s.modules, key{tid, id})
	r.s.purgeModuleTombstones()
	return nil
}
func (r actionsRepo) ListModules(_ context.Context, tid string, p store.PageRequest) (store.Paged[store.ActionModule], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	all := []store.ActionModule{}
	for k, m := range r.s.modules {
		if k.tenant == tid {
			all = append(all, *cloneModule(m))
		}
	}
	slices.SortFunc(all, func(a, b store.ActionModule) int {
		if n := a.CreatedAt.Compare(b.CreatedAt); n != 0 {
			return n
		}
		return strings.Compare(a.ID, b.ID)
	})
	return page(all, p), nil
}
func (r actionsRepo) PublishModule(_ context.Context, tid, id string) (*store.ActionModuleVersion, error) {
	r.s.lock()
	defer r.s.unlock()
	m := r.s.modules[key{tid, id}]
	if m == nil {
		return nil, store.ErrNotFound
	}
	if m.AllChangesPublished {
		return nil, store.ErrConflict
	}
	if m.LatestVersionNumber >= actionsrules.Inventory().Limits["module_versions"] {
		return nil, store.ErrPrecondition
	}
	b := r.s.builds[key{tid, m.DraftBuildID}]
	_, artifact := r.s.artifacts[key{tid, m.DraftBuildID}]
	if b == nil || b.Status != store.BuildBuilt || !artifact {
		return nil, store.ErrBuildNotReady
	}
	v := &store.ActionModuleVersion{TenantID: tid, ModuleID: id, ID: newActionID("amv_"), Number: m.LatestVersionNumber + 1, Code: m.Code, BuildID: b.ID, Dependencies: cloneDeps(b.Resolved), Secrets: cloneSecrets(m.Secrets), CreatedAt: r.s.now()}
	r.s.moduleVersions[key{tid, v.ID}] = v
	m.LatestVersionNumber = v.Number
	m.AllChangesPublished = true
	m.UpdatedAt = v.CreatedAt
	return cloneModuleVersion(v), nil
}
func (r actionsRepo) RollbackModule(_ context.Context, tid, id, vid string) (*store.ActionModule, error) {
	r.s.lock()
	defer r.s.unlock()
	m := r.s.modules[key{tid, id}]
	v := r.s.moduleVersions[key{tid, vid}]
	if m == nil || v == nil || v.ModuleID != id {
		return nil, store.ErrNotFound
	}
	m.Code = v.Code
	m.DraftBuildID = v.BuildID
	m.Dependencies = cloneDeps(v.Dependencies)
	m.Secrets = cloneSecrets(v.Secrets)
	m.AllChangesPublished = r.s.modulePublished(m)
	m.UpdatedAt = r.s.now()
	return cloneModule(m), nil
}
func (r actionsRepo) ListModuleVersions(_ context.Context, tid, id string, p store.PageRequest) (store.Paged[store.ActionModuleVersion], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.modules[key{tid, id}] == nil {
		return store.Paged[store.ActionModuleVersion]{}, store.ErrNotFound
	}
	all := []store.ActionModuleVersion{}
	for k, v := range r.s.moduleVersions {
		if k.tenant == tid && v.ModuleID == id {
			all = append(all, *cloneModuleVersion(v))
		}
	}
	slices.SortFunc(all, func(a, b store.ActionModuleVersion) int { return b.Number - a.Number })
	return page(all, p), nil
}
func (r actionsRepo) GetModuleVersion(_ context.Context, tid, id, vid string) (*store.ActionModuleVersion, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.moduleVersions[key{tid, vid}]
	if v == nil || v.ModuleID != id {
		return nil, store.ErrNotFound
	}
	return cloneModuleVersion(v), nil
}

// resolveModuleRefs validates both supplied pairs against live tenant modules.
func (s *Store) resolveModuleRefs(tid string, refs []store.ModuleRef) ([]store.ModuleRef, error) {
	out := slices.Clone(refs)
	seen := map[string]bool{}
	for i, ref := range refs {
		var m *store.ActionModule
		if ref.ModuleID != "" {
			m = s.modules[key{tid, ref.ModuleID}]
		} else {
			for k, candidate := range s.modules {
				if k.tenant == tid && candidate.Name == ref.ModuleName {
					m = candidate
					break
				}
			}
		}
		if m == nil || ref.ModuleName != "" && ref.ModuleName != m.Name || seen[m.ID] {
			return nil, store.ErrInvalid
		}
		seen[m.ID] = true
		var v *store.ActionModuleVersion
		if ref.VersionID != "" {
			v = s.moduleVersions[key{tid, ref.VersionID}]
		} else {
			for k, candidate := range s.moduleVersions {
				if k.tenant == tid && candidate.ModuleID == m.ID && candidate.Number == ref.VersionNumber {
					v = candidate
					break
				}
			}
		}
		if v == nil || v.ModuleID != m.ID || ref.VersionNumber != 0 && ref.VersionNumber != v.Number {
			return nil, store.ErrInvalid
		}
		out[i] = store.ModuleRef{ModuleID: m.ID, ModuleName: m.Name, VersionID: v.ID, VersionNumber: v.Number}
	}
	return out, nil
}

// purgeModuleTombstones retains only hidden versions pinned by any Action version or job.
func (s *Store) purgeModuleTombstones() {
	pinned := map[key]bool{}
	for k, v := range s.actionVersions {
		for _, ref := range v.Modules {
			pinned[key{k.tenant, ref.VersionID}] = true
		}
	}
	for k, j := range s.actionJobs {
		for _, id := range j.ModuleVersionIDs {
			pinned[key{k.tenant, id}] = true
		}
	}
	for k, v := range s.moduleVersions {
		if s.modules[key{k.tenant, v.ModuleID}] == nil && !pinned[k] {
			delete(s.moduleVersions, k)
		}
	}
}
