package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type actionsRepo struct{ s *Store }

func (s *Store) Actions() store.Actions { return actionsRepo{s} }

const (
	actionCols  = `tenant_id,id,name,trigger_id,runtime,code,dependencies,secrets,draft_build_id,deployed_version_id,created_at,updated_at`
	versionCols = `tenant_id,id,action_id,number,code,runtime,build_id,dependencies,secrets,created_at`
	buildCols   = `tenant_id,id,status,requested,resolved,errors,artifact_sha256,built_at`
	execCols    = `tenant_id,id,trigger_id,status,results,created_at,updated_at`
)

// lockActions serializes a tenant's Actions writers (deploys, binding
// replacement, deletes, builds). It takes the same tenant row lock as the
// RBAC repository, so every writer queues behind one lock per tenant and a
// reader inside a transaction sees the latest committed state afterwards.
func (s *Store) lockActions(ctx context.Context, tenant string) error {
	return s.lockRBAC(ctx, tenant)
}

// atomic runs fn in a transaction holding the tenant's Actions lock.
func (r actionsRepo) atomic(ctx context.Context, tenant string, fn func(*Store) error) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockActions(ctx, tenant); err != nil {
			return err
		}
		return fn(tx)
	})
}

func newActionID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("sqlstore: entropy unavailable: " + err.Error())
	}
	return prefix + hex.EncodeToString(b[:])
}

// nonNil copies b as a non-nil slice; drivers bind a nil slice as NULL.
func nonNil(b []byte) []byte { return append([]byte{}, b...) }

func stampTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}

func scanAction(r scanner) (*store.Action, error) {
	var a store.Action
	var deps, secrets string
	var created, updated int64
	if err := r.Scan(&a.TenantID, &a.ID, &a.Name, &a.Trigger, &a.Runtime, &a.Code, &deps, &secrets, &a.DraftBuildID, &a.DeployedVersionID, &created, &updated); err != nil {
		return nil, err
	}
	if err := fromJSON(deps, &a.Dependencies); err != nil {
		return nil, err
	}
	if err := fromJSON(secrets, &a.Secrets); err != nil {
		return nil, err
	}
	a.CreatedAt, a.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &a, nil
}

func scanActionVersion(r scanner) (*store.ActionVersion, error) {
	var v store.ActionVersion
	var deps, secrets string
	var created int64
	if err := r.Scan(&v.TenantID, &v.ID, &v.ActionID, &v.Number, &v.Code, &v.Runtime, &v.BuildID, &deps, &secrets, &created); err != nil {
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

func (r actionsRepo) CreateAction(ctx context.Context, a *store.Action) error {
	c := *a
	if len(actionsrules.NormalizeAction(&c)) > 0 || c.ID == "" || c.TenantID == "" {
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
	created, updated := stampTime(c.CreatedAt), stampTime(c.UpdatedAt)
	return r.atomic(ctx, c.TenantID, func(tx *Store) error {
		_, err := tx.exec(ctx, `INSERT INTO actions (`+actionCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			c.TenantID, c.ID, c.Name, c.Trigger, c.Runtime, c.Code, deps, secrets, c.DraftBuildID, "", micros(created), micros(updated))
		return tx.conflict(err)
	})
}

func (r actionsRepo) GetAction(ctx context.Context, tenant, id string) (*store.Action, error) {
	return r.oneAction(ctx, `SELECT `+actionCols+` FROM actions WHERE tenant_id=? AND id=?`+r.s.txLock(), tenant, id)
}

func (r actionsRepo) GetActionByName(ctx context.Context, tenant, name string) (*store.Action, error) {
	return r.oneAction(ctx, `SELECT `+actionCols+` FROM actions WHERE tenant_id=? AND name=?`+r.s.txLock(), tenant, name)
}

func (r actionsRepo) oneAction(ctx context.Context, q string, args ...any) (*store.Action, error) {
	a, err := scanAction(r.s.queryRow(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return a, err
}

func (r actionsRepo) UpdateAction(ctx context.Context, a *store.Action) error {
	c := *a
	if len(actionsrules.NormalizeAction(&c)) > 0 {
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
	updated := stampTime(c.UpdatedAt)
	return r.atomic(ctx, c.TenantID, func(tx *Store) error {
		old, err := actionsRepo{tx}.GetAction(ctx, c.TenantID, c.ID)
		if err != nil {
			return err
		}
		if c.Trigger != old.Trigger {
			return store.ErrInvalid
		}
		_, err = tx.exec(ctx, `UPDATE actions SET name=?,runtime=?,code=?,dependencies=?,secrets=?,draft_build_id=?,updated_at=? WHERE tenant_id=? AND id=?`,
			c.Name, c.Runtime, c.Code, deps, secrets, c.DraftBuildID, micros(updated), c.TenantID, c.ID)
		return tx.conflict(err)
	})
}

func (r actionsRepo) DeleteAction(ctx context.Context, tenant, id string, force bool) error {
	return r.atomic(ctx, tenant, func(tx *Store) error {
		if _, err := (actionsRepo{tx}).GetAction(ctx, tenant, id); err != nil {
			return err
		}
		var n int
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM action_bindings WHERE tenant_id=? AND action_id=?`, tenant, id).Scan(&n); err != nil {
			return err
		}
		if n > 0 && !force {
			return store.ErrConflict
		}
		rows, err := tx.query(ctx, `SELECT DISTINCT trigger_id FROM action_bindings WHERE tenant_id=? AND action_id=?`, tenant, id)
		if err != nil {
			return err
		}
		var triggers []string
		for rows.Next() {
			var trigger string
			if err := rows.Scan(&trigger); err != nil {
				rows.Close()
				return err
			}
			triggers = append(triggers, trigger)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, trigger := range triggers {
			if err := (actionsRepo{tx}).markBindings(ctx, tenant, trigger); err != nil {
				return err
			}
		}
		for _, q := range []string{
			`DELETE FROM action_bindings WHERE tenant_id=? AND action_id=?`,
			`DELETE FROM action_versions WHERE tenant_id=? AND action_id=?`,
			`DELETE FROM actions WHERE tenant_id=? AND id=?`,
		} {
			if _, err := tx.exec(ctx, q, tenant, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r actionsRepo) ListActions(ctx context.Context, tenant string, f store.ActionFilter) (store.Paged[store.Action], error) {
	p := f.PageRequest.Normalize()
	out := store.Paged[store.Action]{Items: []store.Action{}}
	where, args := `tenant_id=?`, []any{tenant}
	if f.Trigger != "" {
		where += ` AND trigger_id=?`
		args = append(args, f.Trigger)
	}
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM actions WHERE `+where, args...).Scan(&out.Total); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT `+actionCols+` FROM actions WHERE `+where+` ORDER BY created_at, id`+tx.d.byteOrder+` LIMIT ? OFFSET ?`,
			append(slices.Clone(args), p.PerPage, p.Page*p.PerPage)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAction(rows)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, *a)
		}
		return rows.Err()
	})
	return out, err
}

func (r actionsRepo) Deploy(ctx context.Context, tenant, actionID, from string) (*store.ActionVersion, error) {
	var out *store.ActionVersion
	err := r.atomic(ctx, tenant, func(tx *Store) error {
		repo := actionsRepo{tx}
		a, err := repo.GetAction(ctx, tenant, actionID)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		v := &store.ActionVersion{TenantID: tenant, ActionID: actionID, ID: newActionID("acv_"), CreatedAt: now}
		if from != "" {
			src, err := repo.GetVersion(ctx, tenant, actionID, from)
			if err != nil {
				return err
			}
			v.Code, v.Runtime, v.BuildID, v.Dependencies, v.Secrets = src.Code, src.Runtime, src.BuildID, src.Dependencies, src.Secrets
		} else {
			if a.DraftBuildID == "" {
				return store.ErrBuildNotReady
			}
			b, err := repo.GetBuild(ctx, tenant, a.DraftBuildID)
			if errors.Is(err, store.ErrNotFound) || err == nil && b.Status != store.BuildBuilt {
				return store.ErrBuildNotReady
			}
			if err != nil {
				return err
			}
			var one int
			err = tx.queryRow(ctx, `SELECT 1 FROM action_artifacts WHERE tenant_id=? AND build_id=?`, tenant, b.ID).Scan(&one)
			if errors.Is(err, sql.ErrNoRows) {
				return store.ErrBuildNotReady
			}
			if err != nil {
				return err
			}
			v.Code, v.Runtime, v.BuildID, v.Dependencies, v.Secrets = a.Code, a.Runtime, b.ID, b.Resolved, a.Secrets
		}
		if err := tx.queryRow(ctx, `SELECT COALESCE(MAX(number),0)+1 FROM action_versions WHERE tenant_id=? AND action_id=?`, tenant, actionID).Scan(&v.Number); err != nil {
			return err
		}
		deps, err := toJSON(v.Dependencies)
		if err != nil {
			return err
		}
		secrets, err := toJSON(v.Secrets)
		if err != nil {
			return err
		}
		if _, err = tx.exec(ctx, `INSERT INTO action_versions (`+versionCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			tenant, v.ID, actionID, v.Number, v.Code, v.Runtime, v.BuildID, deps, secrets, micros(now)); err != nil {
			return err
		}
		if _, err = tx.exec(ctx, `UPDATE actions SET deployed_version_id=?,updated_at=? WHERE tenant_id=? AND id=?`, v.ID, micros(now), tenant, actionID); err != nil {
			return err
		}
		v.CreatedAt = fromMicros(micros(now))
		out = v
		return nil
	})
	return out, err
}

func (r actionsRepo) GetVersion(ctx context.Context, tenant, actionID, versionID string) (*store.ActionVersion, error) {
	v, err := scanActionVersion(r.s.queryRow(ctx, `SELECT `+versionCols+` FROM action_versions WHERE tenant_id=? AND action_id=? AND id=?`+r.s.txLock(), tenant, actionID, versionID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return v, err
}

func (r actionsRepo) ListVersions(ctx context.Context, tenant, actionID string, p store.PageRequest) (store.Paged[store.ActionVersion], error) {
	p = p.Normalize()
	out := store.Paged[store.ActionVersion]{Items: []store.ActionVersion{}}
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM action_versions WHERE tenant_id=? AND action_id=?`, tenant, actionID).Scan(&out.Total); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT `+versionCols+` FROM action_versions WHERE tenant_id=? AND action_id=? ORDER BY number DESC LIMIT ? OFFSET ?`,
			tenant, actionID, p.PerPage, p.Page*p.PerPage)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanActionVersion(rows)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, *v)
		}
		return rows.Err()
	})
	return out, err
}

func (r actionsRepo) PutBuild(ctx context.Context, b *store.Build) error {
	if b.TenantID == "" || b.ID == "" || !b.Status.Valid() {
		return store.ErrInvalid
	}
	var js [3]string
	for i, v := range []any{b.Requested, b.Resolved, b.Errors} {
		s, err := toJSON(v)
		if err != nil {
			return err
		}
		js[i] = s
	}
	return r.atomic(ctx, b.TenantID, func(tx *Store) error {
		if _, err := tx.exec(ctx, `DELETE FROM action_builds WHERE tenant_id=? AND id=?`, b.TenantID, b.ID); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `INSERT INTO action_builds (`+buildCols+`) VALUES (?,?,?,?,?,?,?,?)`,
			b.TenantID, b.ID, string(b.Status), js[0], js[1], js[2], b.ArtifactSHA256, micros(b.BuiltAt))
		return err
	})
}

func (r actionsRepo) GetBuild(ctx context.Context, tenant, id string) (*store.Build, error) {
	var b store.Build
	var status, req, res, errs string
	var built int64
	err := r.s.queryRow(ctx, `SELECT `+buildCols+` FROM action_builds WHERE tenant_id=? AND id=?`+r.s.txLock(), tenant, id).
		Scan(&b.TenantID, &b.ID, &status, &req, &res, &errs, &b.ArtifactSHA256, &built)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b.Status, b.BuiltAt = store.BuildStatus(status), fromMicros(built)
	for _, f := range []struct {
		s string
		v any
	}{{req, &b.Requested}, {res, &b.Resolved}, {errs, &b.Errors}} {
		if err := fromJSON(f.s, f.v); err != nil {
			return nil, err
		}
	}
	return &b, nil
}

func (r actionsRepo) PutArtifact(ctx context.Context, tenant, buildID string, tar []byte) error {
	if len(tar) > actionsrules.Inventory().Limits["artifact_bytes_max"] {
		return store.ErrInvalid
	}
	return r.atomic(ctx, tenant, func(tx *Store) error {
		if _, err := (actionsRepo{tx}).GetBuild(ctx, tenant, buildID); err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `DELETE FROM action_artifacts WHERE tenant_id=? AND build_id=?`, tenant, buildID); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `INSERT INTO action_artifacts (tenant_id,build_id,data) VALUES (?,?,?)`, tenant, buildID, nonNil(tar))
		return err
	})
}

func (r actionsRepo) GetArtifact(ctx context.Context, tenant, buildID string) ([]byte, error) {
	var data []byte
	err := r.s.queryRow(ctx, `SELECT data FROM action_artifacts WHERE tenant_id=? AND build_id=?`, tenant, buildID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}

// optional receives a column of a LEFT JOIN that may be NULL.
type optional struct {
	dst  any
	null *bool
}

func (o optional) Scan(v any) error {
	if v == nil {
		*o.null = true
		return nil
	}
	switch d := o.dst.(type) {
	case *string:
		switch x := v.(type) {
		case string:
			*d = x
		case []byte:
			*d = string(x)
		default:
			return errors.New("sqlstore: unexpected text column type")
		}
	case *int64:
		x, ok := v.(int64)
		if !ok {
			return errors.New("sqlstore: unexpected integer column type")
		}
		*d = x
	case *int:
		x, ok := v.(int64)
		if !ok {
			return errors.New("sqlstore: unexpected integer column type")
		}
		*d = int(x)
	default:
		return errors.New("sqlstore: unsupported destination")
	}
	return nil
}

// bound reads a trigger's bindings, their Actions and deployed versions in one
// statement, so the result is a single consistent snapshot. A binding whose
// Action or deployed version is missing fails the read instead of being
// skipped.
func (r actionsRepo) bound(ctx context.Context, tenant, trigger string) ([]store.BoundVersion, error) {
	rows, err := r.s.query(ctx, `SELECT b.id,b.action_id,b.display_name,b.created_at,b.updated_at,`+prefixed("a.", actionCols)+`,`+prefixed("v.", versionCols)+
		` FROM action_bindings b LEFT JOIN actions a ON a.tenant_id=b.tenant_id AND a.id=b.action_id`+
		` LEFT JOIN action_versions v ON v.tenant_id=a.tenant_id AND v.action_id=a.id AND v.id=a.deployed_version_id`+
		` WHERE b.tenant_id=? AND b.trigger_id=? ORDER BY b.position`, tenant, trigger)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.BoundVersion{}
	for rows.Next() {
		bv := store.BoundVersion{Binding: store.Binding{TenantID: tenant, Trigger: trigger}}
		var bc, bu, ac, au, vc int64
		var aDeps, aSecrets, vDeps, vSecrets string
		a, v := &bv.Action, &bv.Version
		var missing bool
		// The first five destinations are the binding's own, never NULL.
		dest := []any{&bv.ID, &bv.ActionID, &bv.DisplayName, &bc, &bu,
			&a.TenantID, &a.ID, &a.Name, &a.Trigger, &a.Runtime, &a.Code, &aDeps, &aSecrets, &a.DraftBuildID, &a.DeployedVersionID, &ac, &au,
			&v.TenantID, &v.ID, &v.ActionID, &v.Number, &v.Code, &v.Runtime, &v.BuildID, &vDeps, &vSecrets, &vc}
		wrapped := make([]any, len(dest))
		copy(wrapped, dest[:5])
		for i := 5; i < len(dest); i++ {
			wrapped[i] = optional{dst: dest[i], null: &missing}
		}
		if err := rows.Scan(wrapped...); err != nil {
			return nil, err
		}
		if missing {
			return nil, store.ErrNotFound
		}
		for _, f := range []struct {
			s string
			v any
		}{{aDeps, &a.Dependencies}, {aSecrets, &a.Secrets}, {vDeps, &v.Dependencies}, {vSecrets, &v.Secrets}} {
			if err := fromJSON(f.s, f.v); err != nil {
				return nil, err
			}
		}
		bv.CreatedAt, bv.UpdatedAt = fromMicros(bc), fromMicros(bu)
		a.CreatedAt, a.UpdatedAt, v.CreatedAt = fromMicros(ac), fromMicros(au), fromMicros(vc)
		out = append(out, bv)
	}
	return out, rows.Err()
}

// Bindings is one statement, so it is a consistent snapshot without the
// tenant lock: logins read it on every flow and must not queue behind (or
// block) the tenant's Actions writers.
func (r actionsRepo) Bindings(ctx context.Context, tenant, trigger string) ([]store.BoundVersion, error) {
	return r.bound(ctx, tenant, trigger)
}

// Binding initialization is separate from rows so an empty list remains owned.
func (r actionsRepo) BindingsInitialized(ctx context.Context, tenant, trigger string) (bool, error) {
	if len(actionsrules.ValidateBindings(trigger, nil)) > 0 {
		return false, store.ErrInvalid
	}
	var initialized bool
	err := r.s.queryRow(ctx, `SELECT EXISTS(SELECT 1 FROM action_binding_sets WHERE tenant_id=? AND trigger_id=?) OR EXISTS(SELECT 1 FROM action_bindings WHERE tenant_id=? AND trigger_id=?) FROM tenants WHERE id=?`, tenant, trigger, tenant, trigger, tenant).Scan(&initialized)
	if errors.Is(err, sql.ErrNoRows) {
		return false, store.ErrNotFound
	}
	return initialized, err
}

// markBindings is called only while holding the tenant Actions writer lock.
func (r actionsRepo) markBindings(ctx context.Context, tenant, trigger string) error {
	var exists bool
	if err := r.s.queryRow(ctx, `SELECT EXISTS(SELECT 1 FROM action_binding_sets WHERE tenant_id=? AND trigger_id=?)`, tenant, trigger).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err := r.s.exec(ctx, `INSERT INTO action_binding_sets (tenant_id,trigger_id) VALUES (?,?)`, tenant, trigger)
	return err
}
func (r actionsRepo) InitializeBindings(ctx context.Context, tenant, trigger string, in []store.Binding) ([]store.BoundVersion, error) {
	return r.replaceBindings(ctx, tenant, trigger, in, true)
}
func (r actionsRepo) ReplaceBindings(ctx context.Context, tenant, trigger string, in []store.Binding) ([]store.BoundVersion, error) {
	return r.replaceBindings(ctx, tenant, trigger, in, false)
}
func (r actionsRepo) replaceBindings(ctx context.Context, tenant, trigger string, in []store.Binding, initialize bool) ([]store.BoundVersion, error) {
	if tenant == "" || len(actionsrules.ValidateBindings(trigger, in)) > 0 {
		return nil, store.ErrInvalid
	}
	var out []store.BoundVersion
	err := r.atomic(ctx, tenant, func(tx *Store) error {
		repo := actionsRepo{tx}
		if initialize {
			initialized, err := repo.BindingsInitialized(ctx, tenant, trigger)
			if err != nil {
				return err
			}
			if initialized {
				if err := repo.markBindings(ctx, tenant, trigger); err != nil {
					return err
				}
				out, err = repo.bound(ctx, tenant, trigger)
				return err
			}
		}
		now := time.Now().UTC()
		for _, b := range in {
			a, err := (actionsRepo{tx}).GetAction(ctx, tenant, b.ActionID)
			if errors.Is(err, store.ErrNotFound) || err == nil && (a.Trigger != trigger || a.DeployedVersionID == "") {
				return store.ErrInvalid
			}
			if err != nil {
				return err
			}
		}
		if _, err := tx.exec(ctx, `DELETE FROM action_bindings WHERE tenant_id=? AND trigger_id=?`, tenant, trigger); err != nil {
			return err
		}
		for i, b := range in {
			if b.ID == "" {
				b.ID = newActionID("bnd_")
			}
			if b.CreatedAt.IsZero() {
				b.CreatedAt = now
			}
			if b.UpdatedAt.IsZero() {
				b.UpdatedAt = now
			}
			if _, err := tx.exec(ctx, `INSERT INTO action_bindings (tenant_id,trigger_id,position,id,action_id,display_name,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)`,
				tenant, trigger, i, b.ID, b.ActionID, b.DisplayName, micros(b.CreatedAt), micros(b.UpdatedAt)); err != nil {
				return err
			}
		}
		if err := repo.markBindings(ctx, tenant, trigger); err != nil {
			return err
		}
		var err error
		out, err = (actionsRepo{tx}).bound(ctx, tenant, trigger)
		return err
	})
	return out, err
}

func (r actionsRepo) CreateExecution(ctx context.Context, e *store.Execution) error {
	if e.TenantID == "" || e.ID == "" {
		return store.ErrInvalid
	}
	results, err := toJSON(e.Results)
	if err != nil {
		return err
	}
	created, updated := stampTime(e.CreatedAt), stampTime(e.UpdatedAt)
	// One INSERT per flow on the login path: no tenant lock; the primary key
	// refuses duplicates and the tenant foreign key a missing tenant.
	_, err = r.s.write(ctx, nil, `INSERT INTO action_executions (`+execCols+`) VALUES (?,?,?,?,?,?,?)`,
		e.TenantID, e.ID, e.Trigger, e.Status, results, micros(created), micros(updated))
	return r.s.insertErr(err)
}

func (r actionsRepo) GetExecution(ctx context.Context, tenant, id string) (*store.Execution, error) {
	var e store.Execution
	var results string
	var created, updated int64
	err := r.s.queryRow(ctx, `SELECT `+execCols+` FROM action_executions WHERE tenant_id=? AND id=?`, tenant, id).
		Scan(&e.TenantID, &e.ID, &e.Trigger, &e.Status, &results, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(results, &e.Results); err != nil {
		return nil, err
	}
	e.CreatedAt, e.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &e, nil
}

func (r actionsRepo) PurgeExecutions(ctx context.Context, before time.Time) (int, error) {
	return r.purge(ctx, `DELETE FROM action_executions WHERE created_at < ?`, before)
}

func (r actionsRepo) PurgeContinue(ctx context.Context, before time.Time) (int, error) {
	return r.purge(ctx, `DELETE FROM action_continues WHERE expires_at < ?`, before)
}

func (r actionsRepo) purge(ctx context.Context, q string, before time.Time) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, q, micros(before)))
		return err
	})
	return n, err
}

func (r actionsRepo) CreateContinue(ctx context.Context, c *store.ContinueState) error {
	if c.TenantID == "" || c.StateHash == "" {
		return store.ErrInvalid
	}
	created := stampTime(c.CreatedAt)
	// Like CreateExecution: no tenant lock on the login path.
	_, err := r.s.write(ctx, nil, `INSERT INTO action_continues (tenant_id,state_hash,session_id,sealed,expires_at,created_at) VALUES (?,?,?,?,?,?)`,
		c.TenantID, c.StateHash, c.SessionID, nonNil(c.Sealed), micros(c.ExpiresAt), micros(created))
	return r.s.insertErr(err)
}

// insertErr maps a duplicate key to ErrConflict and a missing tenant (the
// tenant foreign key) to ErrNotFound.
func (s *Store) insertErr(err error) error {
	if err != nil && s.d.isForeignKeyViolation(err) {
		return store.ErrNotFound
	}
	return s.conflict(err)
}

// ConsumeContinue locks the row, deletes it and only then decides whether it
// had expired, so an expired state is removed too and a state is returned to
// at most one caller.
func (r actionsRepo) ConsumeContinue(ctx context.Context, tenant, hash string, now time.Time) (*store.ContinueState, error) {
	var out *store.ContinueState
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		out = nil
		var c store.ContinueState
		var expires, created int64
		err := tx.queryRow(ctx, `SELECT tenant_id,state_hash,session_id,sealed,expires_at,created_at FROM action_continues WHERE tenant_id=? AND state_hash=?`+tx.d.forUpdate, tenant, hash).
			Scan(&c.TenantID, &c.StateHash, &c.SessionID, &c.Sealed, &expires, &created)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `DELETE FROM action_continues WHERE tenant_id=? AND state_hash=?`, tenant, hash); err != nil {
			return err
		}
		c.ExpiresAt, c.CreatedAt = fromMicros(expires), fromMicros(created)
		if expires > micros(now) {
			out = &c
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, store.ErrNotFound
	}
	return out, nil
}
