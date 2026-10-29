package actions

import (
	"context"
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// wireModule is scoped to one Action version. Only its sealed version's
// secrets are opened for the wire; module refs never select current drafts.
type wireModule struct {
	Name       string            `json:"name"`
	VersionKey string            `json:"version_key"`
	Code       string            `json:"code"`
	DepsRoot   string            `json:"deps_root"`
	Secrets    map[string]string `json:"secrets"`
}

type moduleUnit struct {
	name     string
	version  store.ActionModuleVersion
	depsRoot string
}

// loadUnits materializes immutable module refs, including hidden tombstones,
// and verifies/extracts every dependency artifact with the shared build manager.
// It never resolves by a module's current name, latest version or draft. Sealed
// continuations carry self-contained versions because deleting an Action may
// remove its store pins; normal runs read the immutable versions from storage.
func (e *Engine) loadUnits(ctx context.Context, tenantID string, units []unit) ([]unit, error) {
	out := append([]unit(nil), units...)
	for i := range out {
		u := &out[i]
		root, err := e.Builds.Ensure(ctx, tenantID, u.buildID)
		if err != nil {
			return nil, fmt.Errorf("actions: dependencies of %q: %w", u.name, err)
		}
		u.depsRoot, u.modules = root, nil
		versions, err := resolveModuleVersions(ctx, e.Store.Actions(), tenantID, *u)
		if err != nil {
			return nil, err
		}
		for j, v := range versions {
			ref := u.moduleRefs[j]
			root, err := e.Builds.Ensure(ctx, tenantID, v.BuildID)
			if err != nil {
				return nil, fmt.Errorf("actions: dependencies of module %q: %w", ref.ModuleName, err)
			}
			u.modules = append(u.modules, moduleUnit{name: ref.ModuleName, version: v, depsRoot: root})
		}
	}
	return out, nil
}

// resolveModuleVersions reads immutable store versions or validates versions
// from an authenticated continuation. It opens no secrets and extracts no
// artifacts, so suspension can call it inside the continuation transaction.
func resolveModuleVersions(ctx context.Context, repo store.Actions, tenantID string, u unit) ([]store.ActionModuleVersion, error) {
	if u.moduleVersions != nil && len(u.moduleVersions) != len(u.moduleRefs) {
		return nil, fmt.Errorf("actions: incomplete module snapshots of %q: %w", u.name, build.ErrNotBuilt)
	}
	versions := make([]store.ActionModuleVersion, 0, len(u.moduleRefs))
	names := map[string]bool{}
	for i, ref := range u.moduleRefs {
		if ref.ModuleID == "" || ref.VersionID == "" || ref.ModuleName == "" || ref.VersionNumber < 1 || names[ref.ModuleName] {
			return nil, fmt.Errorf("actions: invalid module pin of %q: %w", u.name, build.ErrNotBuilt)
		}
		names[ref.ModuleName] = true
		var v *store.ActionModuleVersion
		if u.moduleVersions != nil {
			v = &u.moduleVersions[i]
		} else {
			var err error
			v, err = repo.GetModuleVersion(ctx, tenantID, ref.ModuleID, ref.VersionID)
			if err != nil {
				return nil, fmt.Errorf("actions: module %q of %q: %w", ref.ModuleName, u.name, err)
			}
		}
		if v == nil || v.TenantID != tenantID || v.ModuleID != ref.ModuleID || v.ID != ref.VersionID || v.Number != ref.VersionNumber {
			return nil, fmt.Errorf("actions: invalid module version of %q: %w", u.name, build.ErrNotBuilt)
		}
		versions = append(versions, *v)
	}
	return versions, nil
}
