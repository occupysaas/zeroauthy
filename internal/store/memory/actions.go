package memory

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type actionsRepo struct{ s *Store }

func (s *Store) Actions() store.Actions { return actionsRepo{s} }

func newActionID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("memory: entropy unavailable: " + err.Error())
	}
	return prefix + hex.EncodeToString(b[:])
}

func cloneDeps(d []store.Dependency) []store.Dependency { return slices.Clone(d) }
func cloneSecrets(in []store.ActionSecret) []store.ActionSecret {
	if in == nil {
		return nil
	}
	out := make([]store.ActionSecret, len(in))
	for i, v := range in {
		out[i] = v
		out[i].Sealed = bytes.Clone(v.Sealed)
	}
	return out
}
func cloneAction(a *store.Action) *store.Action {
	c := *a
	c.Modules = slices.Clone(a.Modules)
	c.Dependencies, c.Secrets = cloneDeps(a.Dependencies), cloneSecrets(a.Secrets)
	return &c
}
func cloneActionVersion(v *store.ActionVersion) *store.ActionVersion {
	c := *v
	c.Modules = slices.Clone(v.Modules)
	c.Dependencies, c.Secrets = cloneDeps(v.Dependencies), cloneSecrets(v.Secrets)
	return &c
}
func cloneBuild(b *store.Build) *store.Build {
	c := *b
	c.Requested, c.Resolved, c.Errors = cloneDeps(b.Requested), cloneDeps(b.Resolved), slices.Clone(b.Errors)
	return &c
}
func cloneExecution(e *store.Execution) *store.Execution {
	c := *e
	c.Results = slices.Clone(e.Results)
	return &c
}
func cloneContinue(v *store.ContinueState) *store.ContinueState {
	c := *v
	c.Sealed = bytes.Clone(v.Sealed)
	return &c
}
func cloneBindingLists(m map[key][]store.Binding) map[key][]store.Binding {
	out := make(map[key][]store.Binding, len(m))
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}
func cloneArtifacts(m map[key][]byte) map[key][]byte {
	out := make(map[key][]byte, len(m))
	for k, v := range m {
		out[k] = bytes.Clone(v)
	}
	return out
}

func (r actionsRepo) stamp(t time.Time) time.Time {
	if t.IsZero() {
		return r.s.now()
	}
	return t
}

func (r actionsRepo) CreateAction(_ context.Context, a *store.Action) error {
	c := cloneAction(a)
	if len(actionsrules.NormalizeAction(c)) > 0 || c.ID == "" || c.TenantID == "" {
		return store.ErrInvalid
	}
	c.DeployedVersionID = ""
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[c.TenantID] == nil {
		return store.ErrNotFound
	}
	if r.s.actions[key{c.TenantID, c.ID}] != nil || r.s.nameTaken(c.TenantID, c.Name, "") {
		return store.ErrConflict
	}
	refs, err := r.s.resolveModuleRefs(c.TenantID, c.Modules)
	if err != nil {
		return err
	}
	c.Modules = refs
	c.CreatedAt = r.stamp(c.CreatedAt)
	c.UpdatedAt = r.stamp(c.UpdatedAt)
	r.s.actions[key{c.TenantID, c.ID}] = c
	return nil
}

func (s *Store) nameTaken(tenant, name, exceptID string) bool {
	for k, old := range s.actions {
		if k.tenant == tenant && old.Name == name && old.ID != exceptID {
			return true
		}
	}
	return false
}

func (r actionsRepo) GetAction(_ context.Context, tid, id string) (*store.Action, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	a := r.s.actions[key{tid, id}]
	if a == nil {
		return nil, store.ErrNotFound
	}
	return cloneAction(a), nil
}

func (r actionsRepo) GetActionByName(_ context.Context, tid, name string) (*store.Action, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, a := range r.s.actions {
		if k.tenant == tid && a.Name == name {
			return cloneAction(a), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r actionsRepo) UpdateAction(_ context.Context, a *store.Action) error {
	c := cloneAction(a)
	if len(actionsrules.NormalizeAction(c)) > 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	old := r.s.actions[key{c.TenantID, c.ID}]
	if old == nil {
		return store.ErrNotFound
	}
	if c.Trigger != old.Trigger {
		return store.ErrInvalid
	}
	if r.s.nameTaken(c.TenantID, c.Name, c.ID) {
		return store.ErrConflict
	}
	refs, err := r.s.resolveModuleRefs(c.TenantID, c.Modules)
	if err != nil {
		return err
	}
	c.Modules = refs
	c.CreatedAt, c.DeployedVersionID = old.CreatedAt, old.DeployedVersionID
	c.UpdatedAt = r.stamp(c.UpdatedAt)
	r.s.actions[key{c.TenantID, c.ID}] = c
	return nil
}

func (r actionsRepo) DeleteAction(_ context.Context, tid, id string, force bool) error {
	r.s.lock()
	defer r.s.unlock()
	a := r.s.actions[key{tid, id}]
	if a == nil {
		return store.ErrNotFound
	}
	bound := false
	for k, list := range r.s.bindings {
		if k.tenant == tid && slices.ContainsFunc(list, func(b store.Binding) bool { return b.ActionID == id }) {
			bound = true
		}
	}
	if bound && !force {
		return store.ErrConflict
	}
	for k, list := range r.s.bindings {
		if k.tenant != tid {
			continue
		}
		if slices.ContainsFunc(list, func(b store.Binding) bool { return b.ActionID == id }) {
			r.s.bindingSets[k] = true
		}
		list = slices.DeleteFunc(slices.Clone(list), func(b store.Binding) bool { return b.ActionID == id })
		if len(list) == 0 {
			delete(r.s.bindings, k)
		} else {
			r.s.bindings[k] = list
		}
	}
	for k, v := range r.s.actionVersions {
		if k.tenant == tid && v.ActionID == id {
			delete(r.s.actionVersions, k)
		}
	}
	delete(r.s.actions, key{tid, id})
	r.s.purgeModuleTombstones()
	return nil
}

func page[T any](all []T, p store.PageRequest) store.Paged[T] {
	p = p.Normalize()
	out := store.Paged[T]{Total: len(all), Items: []T{}}
	if start := p.Page * p.PerPage; start < len(all) {
		out.Items = all[start:min(start+p.PerPage, len(all))]
	}
	return out
}

func (r actionsRepo) ListActions(_ context.Context, tid string, f store.ActionFilter) (store.Paged[store.Action], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []store.Action
	for k, a := range r.s.actions {
		if k.tenant == tid && (f.Trigger == "" || a.Trigger == f.Trigger) {
			all = append(all, *cloneAction(a))
		}
	}
	slices.SortFunc(all, func(a, b store.Action) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return page(all, f.PageRequest), nil
}

func (r actionsRepo) Deploy(_ context.Context, tid, actionID, from string) (*store.ActionVersion, error) {
	r.s.lock()
	defer r.s.unlock()
	a := r.s.actions[key{tid, actionID}]
	if a == nil {
		return nil, store.ErrNotFound
	}
	v := &store.ActionVersion{TenantID: tid, ActionID: actionID, ID: newActionID("acv_"), CreatedAt: r.s.now()}
	if from != "" {
		src := r.s.actionVersions[key{tid, from}]
		if src == nil || src.ActionID != actionID {
			return nil, store.ErrNotFound
		}
		v.Modules = slices.Clone(src.Modules)
		v.Code, v.Runtime, v.BuildID = src.Code, src.Runtime, src.BuildID
		v.Dependencies, v.Secrets = cloneDeps(src.Dependencies), cloneSecrets(src.Secrets)
	} else {
		b := r.s.builds[key{tid, a.DraftBuildID}]
		_, haveArtifact := r.s.artifacts[key{tid, a.DraftBuildID}]
		if a.DraftBuildID == "" || b == nil || b.Status != store.BuildBuilt || !haveArtifact {
			return nil, store.ErrBuildNotReady
		}
		v.Modules = slices.Clone(a.Modules)
		v.Code, v.Runtime, v.BuildID = a.Code, a.Runtime, b.ID
		v.Dependencies, v.Secrets = cloneDeps(b.Resolved), cloneSecrets(a.Secrets)
	}
	for k, o := range r.s.actionVersions {
		if k.tenant == tid && o.ActionID == actionID && o.Number >= v.Number {
			v.Number = o.Number + 1
		}
	}
	if v.Number == 0 {
		v.Number = 1
	}
	r.s.actionVersions[key{tid, v.ID}] = v
	a.DeployedVersionID, a.UpdatedAt = v.ID, v.CreatedAt
	return cloneActionVersion(v), nil
}

func (r actionsRepo) GetVersion(_ context.Context, tid, actionID, versionID string) (*store.ActionVersion, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.actionVersions[key{tid, versionID}]
	if v == nil || v.ActionID != actionID {
		return nil, store.ErrNotFound
	}
	return cloneActionVersion(v), nil
}

func (r actionsRepo) ListVersions(_ context.Context, tid, actionID string, p store.PageRequest) (store.Paged[store.ActionVersion], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []store.ActionVersion
	for k, v := range r.s.actionVersions {
		if k.tenant == tid && v.ActionID == actionID {
			all = append(all, *cloneActionVersion(v))
		}
	}
	slices.SortFunc(all, func(a, b store.ActionVersion) int { return b.Number - a.Number })
	return page(all, p), nil
}

func (r actionsRepo) PutBuild(_ context.Context, b *store.Build) error {
	if b.TenantID == "" || b.ID == "" || !b.Status.Valid() {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[b.TenantID] == nil {
		return store.ErrNotFound
	}
	r.s.builds[key{b.TenantID, b.ID}] = cloneBuild(b)
	return nil
}

func (r actionsRepo) GetBuild(_ context.Context, tid, id string) (*store.Build, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	b := r.s.builds[key{tid, id}]
	if b == nil {
		return nil, store.ErrNotFound
	}
	return cloneBuild(b), nil
}

func (r actionsRepo) PutArtifact(_ context.Context, tid, buildID string, tar []byte) error {
	if len(tar) > actionsrules.Inventory().Limits["artifact_bytes_max"] {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.builds[key{tid, buildID}] == nil {
		return store.ErrNotFound
	}
	r.s.artifacts[key{tid, buildID}] = bytes.Clone(tar)
	return nil
}

func (r actionsRepo) GetArtifact(_ context.Context, tid, buildID string) ([]byte, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	b, ok := r.s.artifacts[key{tid, buildID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return bytes.Clone(b), nil
}

// bound resolves a trigger's bindings; the caller holds a lock.
func (s *Store) bound(tid, trigger string) ([]store.BoundVersion, error) {
	out := []store.BoundVersion{}
	for _, b := range s.bindings[key{tid, trigger}] {
		a := s.actions[key{tid, b.ActionID}]
		if a == nil || a.DeployedVersionID == "" {
			return nil, store.ErrNotFound
		}
		v := s.actionVersions[key{tid, a.DeployedVersionID}]
		if v == nil {
			return nil, store.ErrNotFound
		}
		out = append(out, store.BoundVersion{Binding: b, Action: *cloneAction(a), Version: *cloneActionVersion(v)})
	}
	return out, nil
}

func (r actionsRepo) Bindings(_ context.Context, tid, trigger string) ([]store.BoundVersion, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	return r.s.bound(tid, trigger)
}

func (r actionsRepo) BindingsInitialized(_ context.Context, tid, trigger string) (bool, error) {
	if len(actionsrules.ValidateBindings(trigger, nil)) > 0 {
		return false, store.ErrInvalid
	}
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.tenants[tid] == nil {
		return false, store.ErrNotFound
	}
	return r.s.bindingSets[key{tid, trigger}] || len(r.s.bindings[key{tid, trigger}]) > 0, nil
}
func (r actionsRepo) InitializeBindings(_ context.Context, tid, trigger string, in []store.Binding) ([]store.BoundVersion, error) {
	return r.replaceBindings(tid, trigger, in, true)
}
func (r actionsRepo) ReplaceBindings(_ context.Context, tid, trigger string, in []store.Binding) ([]store.BoundVersion, error) {
	return r.replaceBindings(tid, trigger, in, false)
}
func (r actionsRepo) replaceBindings(tid, trigger string, in []store.Binding, initialize bool) ([]store.BoundVersion, error) {
	if tid == "" || len(actionsrules.ValidateBindings(trigger, in)) > 0 {
		return nil, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[tid] == nil {
		return nil, store.ErrNotFound
	}
	if initialize && (r.s.bindingSets[key{tid, trigger}] || len(r.s.bindings[key{tid, trigger}]) > 0) {
		r.s.bindingSets[key{tid, trigger}] = true
		return r.s.bound(tid, trigger)
	}
	now := r.s.now()
	next := make([]store.Binding, len(in))
	for i, b := range in {
		a := r.s.actions[key{tid, b.ActionID}]
		if a == nil || a.Trigger != trigger || a.DeployedVersionID == "" {
			return nil, store.ErrInvalid
		}
		b.TenantID, b.Trigger = tid, trigger
		if b.ID == "" {
			b.ID = newActionID("bnd_")
		}
		if b.CreatedAt.IsZero() {
			b.CreatedAt = now
		}
		if b.UpdatedAt.IsZero() {
			b.UpdatedAt = now
		}
		next[i] = b
	}
	r.s.bindingSets[key{tid, trigger}] = true
	if len(next) == 0 {
		delete(r.s.bindings, key{tid, trigger})
	} else {
		r.s.bindings[key{tid, trigger}] = next
	}
	return r.s.bound(tid, trigger)
}

func (r actionsRepo) CreateExecution(_ context.Context, e *store.Execution) error {
	if e.TenantID == "" || e.ID == "" {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[e.TenantID] == nil {
		return store.ErrNotFound
	}
	if r.s.executions[key{e.TenantID, e.ID}] != nil {
		return store.ErrConflict
	}
	c := cloneExecution(e)
	c.CreatedAt, c.UpdatedAt = r.stamp(c.CreatedAt), r.stamp(c.UpdatedAt)
	r.s.executions[key{e.TenantID, e.ID}] = c
	return nil
}

func (r actionsRepo) GetExecution(_ context.Context, tid, id string) (*store.Execution, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	e := r.s.executions[key{tid, id}]
	if e == nil {
		return nil, store.ErrNotFound
	}
	return cloneExecution(e), nil
}

func (r actionsRepo) PurgeExecutions(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, e := range r.s.executions {
		if e.CreatedAt.Before(before) {
			delete(r.s.executions, k)
			n++
		}
	}
	return n, nil
}

func (r actionsRepo) CreateContinue(_ context.Context, c *store.ContinueState) error {
	if c.TenantID == "" || c.StateHash == "" {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[c.TenantID] == nil {
		return store.ErrNotFound
	}
	k := key{c.TenantID, c.StateHash}
	if r.s.continues[k] != nil {
		return store.ErrConflict
	}
	v := cloneContinue(c)
	v.CreatedAt = r.stamp(v.CreatedAt)
	r.s.continues[k] = v
	return nil
}

func (r actionsRepo) ConsumeContinue(_ context.Context, tid, hash, sessionID string, now time.Time) (*store.ContinueState, error) {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, hash}
	v := r.s.continues[k]
	if v == nil || v.SessionID != sessionID {
		return nil, store.ErrNotFound
	}
	delete(r.s.continues, k)
	if !v.ExpiresAt.After(now) {
		return nil, store.ErrNotFound
	}
	return v, nil
}

func (r actionsRepo) PurgeContinue(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, v := range r.s.continues {
		if v.ExpiresAt.Before(before) {
			delete(r.s.continues, k)
			n++
		}
	}
	return n, nil
}

// deleteActionsTenant removes every Actions row of a tenant; the caller holds the lock.
func (s *Store) deleteActionsTenant(id string) {
	deleteTenantKeys(s.modules, id)
	deleteTenantKeys(s.moduleVersions, id)
	deleteTenantKeys(s.actionJobs, id)
	deleteTenantKeys(s.actions, id)
	deleteTenantKeys(s.actionVersions, id)
	deleteTenantKeys(s.builds, id)
	deleteTenantKeys(s.artifacts, id)
	deleteTenantKeys(s.bindings, id)
	deleteTenantKeys(s.bindingSets, id)
	deleteTenantKeys(s.executions, id)
	deleteTenantKeys(s.continues, id)
}

func deleteTenantKeys[V any](m map[key]V, tenant string) {
	maps.DeleteFunc(m, func(k key, _ V) bool { return k.tenant == tenant })
}
