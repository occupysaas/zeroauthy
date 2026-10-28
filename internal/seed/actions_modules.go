package seed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type ActionModule struct {
	Name         string             `yaml:"name"`
	Code         string             `yaml:"code"`
	Dependencies []store.Dependency `yaml:"dependencies"`
	Secrets      []ActionSecret     `yaml:"secrets"`
	Publish      bool               `yaml:"publish"`
	APIVersion   string             `yaml:"api_version"`
}
type ActionModuleRef struct {
	ModuleID      string `yaml:"module_id"`
	ModuleName    string `yaml:"module_name"`
	VersionID     string `yaml:"module_version_id"`
	VersionNumber int    `yaml:"module_version_number"`
}

func moduleRefs(in []ActionModuleRef) []store.ModuleRef {
	out := make([]store.ModuleRef, 0, len(in))
	for _, r := range in {
		out = append(out, store.ModuleRef{ModuleID: r.ModuleID, ModuleName: r.ModuleName, VersionID: r.VersionID, VersionNumber: r.VersionNumber})
	}
	return out
}
func validateModules(in *Tenant) error {
	var errs []error
	names := map[string]bool{}
	for _, m := range in.Modules {
		if names[m.Name] {
			errs = append(errs, fmt.Errorf("duplicate module %q", m.Name))
		}
		names[m.Name] = true
		draft := &store.ActionModule{Name: m.Name, Code: m.Code, Dependencies: m.Dependencies}
		if !utf8.ValidString(m.APIVersion) || utf8.RuneCountInString(m.APIVersion) > 20 || strings.ContainsRune(m.APIVersion, 0) {
			errs = append(errs, errors.New("module api_version must be at most 20 characters without NUL"))
		}
		if strings.ContainsRune(m.Code, 0) {
			errs = append(errs, errors.New("module code must not contain NUL"))
		}
		for _, s := range m.Secrets {
			draft.Secrets = append(draft.Secrets, store.ActionSecret{Name: s.Name})
			if len(s.Value) > actionsrules.Inventory().Limits["secret_value_max"] {
				errs = append(errs, errors.New("module secret exceeds 4096 bytes"))
			}
		}
		errs = append(errs, actionsrules.NormalizeModule(draft)...)
	}
	return errors.Join(errs...)
}
func applyModules(ctx context.Context, st store.Store, in *Tenant, tid string, now func() time.Time, w keys.Wrapper, engine *actions.Engine) error {
	for _, m := range in.Modules {
		if _, err := st.Actions().GetModuleByName(ctx, tid, m.Name); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		draft := &store.ActionModule{TenantID: tid, ID: "am_" + secrets.RandomString(18), Name: m.Name, Code: m.Code, Dependencies: m.Dependencies, CreatedAt: now().UTC(), UpdatedAt: now().UTC()}
		for _, s := range m.Secrets {
			sealed, err := keys.SealModuleSecret(w, tid, draft.ID, s.Name, s.Value)
			if err != nil {
				return err
			}
			draft.Secrets = append(draft.Secrets, store.ActionSecret{Name: s.Name, Sealed: sealed, UpdatedAt: now().UTC()})
		}
		var err error
		draft.DraftBuildID, err = engine.Builds.Queue(ctx, tid, draft.Dependencies, actionsrules.Runtime)
		if err != nil {
			return fmt.Errorf("seed module %q: %w", m.Name, err)
		}
		if m.Publish {
			if err := waitSeedBuild(ctx, st, &store.Action{TenantID: tid, DraftBuildID: draft.DraftBuildID}); err != nil {
				return fmt.Errorf("seed module %q: %w", m.Name, err)
			}
		}
		err = st.WithTx(ctx, func(tx store.Store) error {
			if _, err := tx.Actions().GetModuleByName(ctx, tid, m.Name); err == nil {
				return nil
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
			if err := tx.Actions().CreateModule(ctx, draft); err != nil {
				return err
			}
			if m.Publish {
				_, err := tx.Actions().PublishModule(ctx, tid, draft.ID)
				return err
			}
			return nil
		})
		if errors.Is(err, store.ErrConflict) {
			if _, getErr := st.Actions().GetModuleByName(ctx, tid, m.Name); getErr == nil {
				continue
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}
