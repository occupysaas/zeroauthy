package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const moduleCols = `tenant_id,id,name,code,dependencies,secrets,draft_build_id,latest_version_number,all_changes_published,created_at,updated_at`
const moduleVersionCols = `tenant_id,id,module_id,number,code,build_id,dependencies,secrets,created_at`

func scanModule(row scanner) (*store.ActionModule, error) {
	var m store.ActionModule
	var deps, secrets string
	var created, updated int64
	if err := row.Scan(&m.TenantID, &m.ID, &m.Name, &m.Code, &deps, &secrets, &m.DraftBuildID, &m.LatestVersionNumber, &m.AllChangesPublished, &created, &updated); err != nil {
		return nil, err
	}
	if err := fromJSON(deps, &m.Dependencies); err != nil {
		return nil, err
	}
	if err := fromJSON(secrets, &m.Secrets); err != nil {
		return nil, err
	}
	m.CreatedAt, m.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &m, nil
}
func scanModuleVersion(row scanner) (*store.ActionModuleVersion, error) {
	var v store.ActionModuleVersion
	var deps, secrets string
	var created int64
	if err := row.Scan(&v.TenantID, &v.ID, &v.ModuleID, &v.Number, &v.Code, &v.BuildID, &deps, &secrets, &created); err != nil {
		return nil, err
	}
	if err := fromJSON(deps, &v.Dependencies); err != nil {
		return nil, err
	}
	if err := fromJSON(secrets, &v.Secrets); err != nil {
		return nil, err
	}
	v.CreatedAt = fromMicros(created)
	return &v, nil
}
func (r actionsRepo) CreateModule(ctx context.Context, m *store.ActionModule) error {
	c := *m
	if c.TenantID == "" || c.ID == "" || len(actionsrules.NormalizeModule(&c)) > 0 {
		return store.ErrInvalid
	}
	deps, err := toJSON(c.Dependencies)
	if err != nil {
		return err
	}
	secrets, err := toJSON(c.Secrets)
	if err != nil {
		return err
	}
	return r.atomic(ctx, c.TenantID, func(tx *Store) error {
		var n int
		// Hidden IDs cannot be reused while any immutable pins survive.
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM action_modules WHERE tenant_id=? AND (id=? OR live_name=?)`, c.TenantID, c.ID, c.Name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrConflict
		}
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM action_modules WHERE tenant_id=? AND deleted=false`, c.TenantID).Scan(&n); err != nil {
			return err
		}
		if n >= actionsrules.Inventory().Limits["modules_per_tenant"] {
			return store.ErrPrecondition
		}
		_, err := tx.exec(ctx, `INSERT INTO action_modules (`+moduleCols+`,live_name,deleted) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, c.TenantID, c.ID, c.Name, c.Code, deps, secrets, c.DraftBuildID, 0, false, micros(stampTime(c.CreatedAt)), micros(stampTime(c.UpdatedAt)), c.Name, false)
		return tx.conflict(err)
	})
}
func (r actionsRepo) GetModule(ctx context.Context, tid, id string) (*store.ActionModule, error) {
	return r.oneModule(ctx, `SELECT `+moduleCols+` FROM action_modules WHERE tenant_id=? AND id=? AND deleted=false`+r.s.txLock(), tid, id)
}
func (r actionsRepo) GetModuleByName(ctx context.Context, tid, name string) (*store.ActionModule, error) {
	return r.oneModule(ctx, `SELECT `+moduleCols+` FROM action_modules WHERE tenant_id=? AND live_name=?`+r.s.txLock(), tid, name)
}
func (r actionsRepo) oneModule(ctx context.Context, q string, args ...any) (*store.ActionModule, error) {
	m, err := scanModule(r.s.queryRow(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return m, err
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
func (r actionsRepo) modulePublished(ctx context.Context, m *store.ActionModule) (bool, error) {
	if m.LatestVersionNumber == 0 {
		return false, nil
	}
	v, err := scanModuleVersion(r.s.queryRow(ctx, `SELECT `+moduleVersionCols+` FROM action_module_versions WHERE tenant_id=? AND module_id=? AND number=?`, m.TenantID, m.ID, m.LatestVersionNumber))
	if err != nil {
		return false, err
	}
	deps := v.Dependencies
	b, err := r.GetBuild(ctx, m.TenantID, v.BuildID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	if b != nil && slices.Equal(m.Dependencies, b.Requested) {
		deps = m.Dependencies
	}
	return m.Code == v.Code && m.DraftBuildID == v.BuildID && slices.Equal(m.Dependencies, deps) && equalModuleSecrets(m.Secrets, v.Secrets), nil
}
func (r actionsRepo) UpdateModule(ctx context.Context, m *store.ActionModule) error {
	c := *m
	if len(actionsrules.NormalizeModule(&c)) > 0 {
		return store.ErrInvalid
	}
	return r.atomic(ctx, c.TenantID, func(tx *Store) error {
		repo := actionsRepo{tx}
		old, err := repo.GetModule(ctx, c.TenantID, c.ID)
		if err != nil {
			return err
		}
		if old.Name != c.Name {
			return store.ErrInvalid
		}
		c.LatestVersionNumber = old.LatestVersionNumber
		published, err := repo.modulePublished(ctx, &c)
		if err != nil {
			return err
		}
		deps, err := toJSON(c.Dependencies)
		if err != nil {
			return err
		}
		secrets, err := toJSON(c.Secrets)
		if err != nil {
			return err
		}
		_, err = tx.exec(ctx, `UPDATE action_modules SET code=?,dependencies=?,secrets=?,draft_build_id=?,all_changes_published=?,updated_at=? WHERE tenant_id=? AND id=?`, c.Code, deps, secrets, c.DraftBuildID, published, micros(time.Now().UTC()), c.TenantID, c.ID)
		return err
	})
}
func (r actionsRepo) ListModules(ctx context.Context, tid string, p store.PageRequest) (store.Paged[store.ActionModule], error) {
	p = p.Normalize()
	out := store.Paged[store.ActionModule]{Items: []store.ActionModule{}}
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		out.Items = []store.ActionModule{}
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM action_modules WHERE tenant_id=? AND deleted=false`, tid).Scan(&out.Total); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT `+moduleCols+` FROM action_modules WHERE tenant_id=? AND deleted=false ORDER BY created_at,id`+tx.d.byteOrder+` LIMIT ? OFFSET ?`, tid, p.PerPage, p.Page*p.PerPage)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m, err := scanModule(rows)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, *m)
		}
		return rows.Err()
	})
	return out, err
}
func (r actionsRepo) PublishModule(ctx context.Context, tid, id string) (*store.ActionModuleVersion, error) {
	var out *store.ActionModuleVersion
	err := r.atomic(ctx, tid, func(tx *Store) error {
		repo := actionsRepo{tx}
		m, err := repo.GetModule(ctx, tid, id)
		if err != nil {
			return err
		}
		if m.AllChangesPublished {
			return store.ErrConflict
		}
		if m.LatestVersionNumber >= actionsrules.Inventory().Limits["module_versions"] {
			return store.ErrPrecondition
		}
		b, err := repo.GetBuild(ctx, tid, m.DraftBuildID)
		if errors.Is(err, store.ErrNotFound) || err == nil && b.Status != store.BuildBuilt {
			return store.ErrBuildNotReady
		}
		if err != nil {
			return err
		}
		var n int
		if err = tx.queryRow(ctx, `SELECT COUNT(*) FROM action_artifacts WHERE tenant_id=? AND build_id=?`, tid, b.ID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return store.ErrBuildNotReady
		}
		now := fromMicros(micros(time.Now().UTC()))
		v := &store.ActionModuleVersion{TenantID: tid, ID: newActionID("amv_"), ModuleID: id, Number: m.LatestVersionNumber + 1, Code: m.Code, BuildID: b.ID, Dependencies: b.Resolved, Secrets: m.Secrets, CreatedAt: now}
		deps, err := toJSON(v.Dependencies)
		if err != nil {
			return err
		}
		secrets, err := toJSON(v.Secrets)
		if err != nil {
			return err
		}
		if _, err = tx.exec(ctx, `INSERT INTO action_module_versions (`+moduleVersionCols+`) VALUES (?,?,?,?,?,?,?,?,?)`, tid, v.ID, id, v.Number, v.Code, v.BuildID, deps, secrets, micros(now)); err != nil {
			return err
		}
		if _, err = tx.exec(ctx, `UPDATE action_modules SET latest_version_number=?,all_changes_published=true,updated_at=? WHERE tenant_id=? AND id=?`, v.Number, micros(now), tid, id); err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}
func (r actionsRepo) GetModuleVersion(ctx context.Context, tid, id, vid string) (*store.ActionModuleVersion, error) {
	v, err := scanModuleVersion(r.s.queryRow(ctx, `SELECT `+moduleVersionCols+` FROM action_module_versions WHERE tenant_id=? AND module_id=? AND id=?`+r.s.txLock(), tid, id, vid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return v, err
}
func (r actionsRepo) ListModuleVersions(ctx context.Context, tid, id string, p store.PageRequest) (store.Paged[store.ActionModuleVersion], error) {
	p = p.Normalize()
	out := store.Paged[store.ActionModuleVersion]{Items: []store.ActionModuleVersion{}}
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		out.Items = []store.ActionModuleVersion{}
		if _, err := (actionsRepo{tx}).GetModule(ctx, tid, id); err != nil {
			return err
		}
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM action_module_versions WHERE tenant_id=? AND module_id=?`, tid, id).Scan(&out.Total); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT `+moduleVersionCols+` FROM action_module_versions WHERE tenant_id=? AND module_id=? ORDER BY number DESC LIMIT ? OFFSET ?`, tid, id, p.PerPage, p.Page*p.PerPage)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanModuleVersion(rows)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, *v)
		}
		return rows.Err()
	})
	return out, err
}
func (r actionsRepo) RollbackModule(ctx context.Context, tid, id, vid string) (*store.ActionModule, error) {
	var out *store.ActionModule
	err := r.atomic(ctx, tid, func(tx *Store) error {
		repo := actionsRepo{tx}
		m, err := repo.GetModule(ctx, tid, id)
		if err != nil {
			return err
		}
		v, err := repo.GetModuleVersion(ctx, tid, id, vid)
		if err != nil {
			return err
		}
		m.Code, m.DraftBuildID, m.Dependencies, m.Secrets = v.Code, v.BuildID, v.Dependencies, v.Secrets
		if err = repo.UpdateModule(ctx, m); err != nil {
			return err
		}
		out, err = repo.GetModule(ctx, tid, id)
		return err
	})
	return out, err
}
func refContains(refs []store.ModuleRef, id string) bool {
	return slices.ContainsFunc(refs, func(ref store.ModuleRef) bool { return ref.ModuleID == id })
}

// moduleUsers reads drafts and their current deployments in one snapshot. Old
// immutable versions and queued jobs keep tombstones, but do not count as use.
func (r actionsRepo) moduleUsers(ctx context.Context, tid, id string) ([]store.ModuleUser, error) {
	rows, err := r.s.query(ctx, `SELECT `+prefixed("a.", actionCols)+`,v.modules FROM actions a LEFT JOIN action_versions v ON v.tenant_id=a.tenant_id AND v.action_id=a.id AND v.id=a.deployed_version_id WHERE a.tenant_id=? ORDER BY a.id`+r.s.d.byteOrder, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.ModuleUser{}
	for rows.Next() {
		var a store.Action
		var deps, secrets, modules string
		var deployed sql.NullString
		var created, updated int64
		if err = rows.Scan(&a.TenantID, &a.ID, &a.Name, &a.Trigger, &a.Runtime, &a.Code, &deps, &secrets, &a.DraftBuildID, &a.DeployedVersionID, &created, &updated, &modules, &deployed); err != nil {
			return nil, err
		}
		for _, f := range []struct {
			s string
			v any
		}{{deps, &a.Dependencies}, {secrets, &a.Secrets}, {modules, &a.Modules}} {
			if err = fromJSON(f.s, f.v); err != nil {
				return nil, err
			}
		}
		var refs []store.ModuleRef
		if deployed.Valid {
			if err = fromJSON(deployed.String, &refs); err != nil {
				return nil, err
			}
		}
		draft, dep := refContains(a.Modules, id), refContains(refs, id)
		if draft || dep {
			a.CreatedAt, a.UpdatedAt = fromMicros(created), fromMicros(updated)
			out = append(out, store.ModuleUser{Action: a, InDraft: draft, InDeployed: dep})
		}
	}
	return out, rows.Err()
}
func (r actionsRepo) ModuleUsers(ctx context.Context, tid, id string, p store.PageRequest) (store.Paged[store.ModuleUser], error) {
	out := store.Paged[store.ModuleUser]{Items: []store.ModuleUser{}}
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		repo := actionsRepo{tx}
		if _, err := repo.GetModule(ctx, tid, id); err != nil {
			return err
		}
		all, err := repo.moduleUsers(ctx, tid, id)
		if err != nil {
			return err
		}
		p = p.Normalize()
		out.Total = len(all)
		start := min(p.Page*p.PerPage, len(all))
		out.Items = all[start:min(start+p.PerPage, len(all))]
		return nil
	})
	return out, err
}
func (r actionsRepo) DeleteModule(ctx context.Context, tid, id string) error {
	return r.atomic(ctx, tid, func(tx *Store) error {
		repo := actionsRepo{tx}
		if _, err := repo.GetModule(ctx, tid, id); err != nil {
			return err
		}
		users, err := repo.moduleUsers(ctx, tid, id)
		if err != nil {
			return err
		}
		if len(users) > 0 {
			return store.ErrPrecondition
		}
		if _, err = tx.exec(ctx, `UPDATE action_modules SET deleted=true,live_name=NULL WHERE tenant_id=? AND id=?`, tid, id); err != nil {
			return err
		}
		return repo.purgeModuleTombstones(ctx, tid)
	})
}

// Callers hold the tenant Actions lock. Pins are stored with their immutable
// snapshots; reading them here is portable across all three SQL JSON dialects.
func (r actionsRepo) purgeModuleTombstones(ctx context.Context, tid string) error {
	type hidden struct{ module, id string }
	var versions []hidden
	rows, err := r.s.query(ctx, `SELECT v.module_id,v.id FROM action_module_versions v JOIN action_modules m ON m.tenant_id=v.tenant_id AND m.id=v.module_id WHERE v.tenant_id=? AND m.deleted=true`, tid)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h hidden
		if err = rows.Scan(&h.module, &h.id); err != nil {
			rows.Close()
			return err
		}
		versions = append(versions, h)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(versions) > 0 {
		pinned := map[string]bool{}
		for _, table := range []string{"action_versions", "action_jobs"} {
			col := "modules"
			if table == "action_jobs" {
				col = "module_version_ids"
			}
			rows, err = r.s.query(ctx, `SELECT `+col+` FROM `+table+` WHERE tenant_id=?`, tid)
			if err != nil {
				return err
			}
			for rows.Next() {
				var raw string
				if err = rows.Scan(&raw); err != nil {
					rows.Close()
					return err
				}
				if table == "action_versions" {
					var refs []store.ModuleRef
					if err = fromJSON(raw, &refs); err != nil {
						rows.Close()
						return err
					}
					for _, ref := range refs {
						pinned[ref.VersionID] = true
					}
				} else {
					var ids []string
					if err = fromJSON(raw, &ids); err != nil {
						rows.Close()
						return err
					}
					for _, id := range ids {
						pinned[id] = true
					}
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
		for _, v := range versions {
			if !pinned[v.id] {
				if _, err = r.s.exec(ctx, `DELETE FROM action_module_versions WHERE tenant_id=? AND id=?`, tid, v.id); err != nil {
					return err
				}
			}
		}
	}
	_, err = r.s.exec(ctx, `DELETE FROM action_modules WHERE tenant_id=? AND deleted=true AND NOT EXISTS (SELECT 1 FROM action_module_versions v WHERE v.tenant_id=action_modules.tenant_id AND v.module_id=action_modules.id)`, tid)
	return err
}
func (r actionsRepo) resolveModuleRefs(ctx context.Context, tid string, refs []store.ModuleRef) ([]store.ModuleRef, error) {
	if len(actionsrules.ValidateModuleRefs(refs)) > 0 {
		return nil, store.ErrInvalid
	}
	out := slices.Clone(refs)
	seen := map[string]bool{}
	for i, ref := range refs {
		var m *store.ActionModule
		var err error
		if ref.ModuleID != "" {
			m, err = r.GetModule(ctx, tid, ref.ModuleID)
		} else {
			m, err = r.GetModuleByName(ctx, tid, ref.ModuleName)
		}
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrInvalid
		}
		if err != nil {
			return nil, err
		}
		if ref.ModuleName != "" && ref.ModuleName != m.Name || seen[m.ID] {
			return nil, store.ErrInvalid
		}
		seen[m.ID] = true
		var v *store.ActionModuleVersion
		if ref.VersionID != "" {
			v, err = r.GetModuleVersion(ctx, tid, m.ID, ref.VersionID)
		} else {
			v, err = scanModuleVersion(r.s.queryRow(ctx, `SELECT `+moduleVersionCols+` FROM action_module_versions WHERE tenant_id=? AND module_id=? AND number=?`, tid, m.ID, ref.VersionNumber))
		}
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrInvalid
		}
		if err != nil {
			return nil, err
		}
		if ref.VersionNumber != 0 && ref.VersionNumber != v.Number {
			return nil, store.ErrInvalid
		}
		out[i] = store.ModuleRef{ModuleID: m.ID, ModuleName: m.Name, VersionID: v.ID, VersionNumber: v.Number}
	}
	return out, nil
}
