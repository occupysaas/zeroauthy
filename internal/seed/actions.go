package seed

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Action and Trigger use the public Management API shape. Seed Action names
// and existing nonempty binding lists are create-only in both seed modes.
type Action struct {
	Modules           []ActionModuleRef  `yaml:"modules"`
	Name              string             `yaml:"name"`
	SupportedTriggers []ActionTrigger    `yaml:"supported_triggers"`
	Code              string             `yaml:"code"`
	Dependencies      []store.Dependency `yaml:"dependencies"`
	Secrets           []ActionSecret     `yaml:"secrets"`
	Runtime           string             `yaml:"runtime"`
	Deploy            bool               `yaml:"deploy"`
}
type ActionTrigger struct {
	ID      string `yaml:"id"`
	Version string `yaml:"version"`
}
type ActionSecret struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}
type Trigger struct {
	Bindings []ActionBinding `yaml:"bindings"`
}
type ActionBinding struct {
	Ref         ActionRef `yaml:"ref"`
	DisplayName string    `yaml:"display_name"`
}
type ActionRef struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

func (a Action) draft(tenantID, id string, now time.Time, w keys.Wrapper) (*store.Action, error) {
	out := &store.Action{TenantID: tenantID, ID: id, Name: a.Name, Code: a.Code, Runtime: a.Runtime, Modules: moduleRefs(a.Modules), Dependencies: a.Dependencies, CreatedAt: now, UpdatedAt: now}
	if len(a.SupportedTriggers) != 1 {
		return nil, fmt.Errorf("Action %q requires exactly one supported trigger", a.Name)
	}
	out.Trigger = a.SupportedTriggers[0].ID
	for _, s := range a.Secrets {
		if len(s.Value) > actionsrules.Inventory().Limits["secret_value_max"] {
			return nil, errors.New("Action secret exceeds 4096 bytes")
		}
		sealed, err := keys.SealActionSecret(w, tenantID, id, s.Name, s.Value)
		if err != nil {
			return nil, err
		}
		out.Secrets = append(out.Secrets, store.ActionSecret{Name: s.Name, Sealed: sealed, UpdatedAt: now})
	}
	if errs := actionsrules.NormalizeAction(out); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}
func validateActions(in *Tenant) error {
	var errs []error
	errs = append(errs, validateModules(in))
	names := map[string]bool{}
	for _, a := range in.Actions {
		if names[a.Name] {
			errs = append(errs, fmt.Errorf("duplicate Action %q", a.Name))
		}
		names[a.Name] = true
		draft := &store.Action{Name: a.Name, Code: a.Code, Runtime: a.Runtime, Modules: moduleRefs(a.Modules), Dependencies: a.Dependencies}
		if len(a.SupportedTriggers) != 1 {
			errs = append(errs, fmt.Errorf("Action %q requires one supported trigger", a.Name))
		} else {
			draft.Trigger = a.SupportedTriggers[0].ID
		}
		for _, s := range a.Secrets {
			draft.Secrets = append(draft.Secrets, store.ActionSecret{Name: s.Name})
			if len(s.Value) > actionsrules.Inventory().Limits["secret_value_max"] {
				errs = append(errs, fmt.Errorf("Action %q secret value exceeds 4096 bytes", a.Name))
			}
		}
		errs = append(errs, actionsrules.NormalizeAction(draft)...)
	}
	for trigger, t := range in.Triggers {
		bs := []store.Binding{}
		for _, b := range t.Bindings {
			if b.Ref.Value == "" || (b.Ref.Type != "action_name" && b.Ref.Type != "action_id") {
				errs = append(errs, fmt.Errorf("seed binding ref requires action_name or action_id and a value"))
			}
			bs = append(bs, store.Binding{Trigger: trigger, ActionID: b.Ref.Value})
		}
		errs = append(errs, actionsrules.ValidateBindings(trigger, bs)...)
	}
	return errors.Join(errs...)
}
func hasActions(f *File) bool {
	for _, t := range f.Tenants {
		if len(t.Modules) > 0 || len(t.Actions) > 0 || len(t.Triggers) > 0 {
			return true
		}
	}
	return false
}

// ApplyWithActions applies ordinary seed data in its transaction, then builds
// and creates Actions outside it. A failed build leaves the ordinary seed
// applied, but creates no Action; a retry can safely finish the same seed.
func ApplyWithActions(ctx context.Context, st store.Store, f *File, now func() time.Time, w keys.Wrapper, engine *actions.Engine) error {
	if hasActions(f) && (engine == nil || engine.Builds == nil) {
		return errors.New("seed: Actions require an Actions build manager")
	}
	if err := applyOrdinary(ctx, st, f, now, w); err != nil {
		return err
	}
	if now == nil {
		now = time.Now
	}
	for _, in := range f.Tenants {
		tn, err := st.Tenants().GetByName(ctx, in.Name)
		if err != nil {
			return err
		}
		if tn.Origin == store.OriginAPI {
			continue
		}
		if err := applyModules(ctx, st, &in, tn.ID, now, w, engine); err != nil {
			return err
		}
		for _, a := range in.Actions {
			if _, err := st.Actions().GetActionByName(ctx, tn.ID, a.Name); err == nil {
				continue
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
			draft, err := a.draft(tn.ID, "act_"+secrets.RandomString(18), now().UTC(), w)
			if err != nil {
				return err
			}
			draft.DraftBuildID, err = engine.Builds.Queue(ctx, tn.ID, draft.Dependencies, draft.Runtime)
			if err != nil {
				return fmt.Errorf("seed Action %q: %w", a.Name, err)
			}
			// Wait before creation so a crash or failed build leaves no unbuilt
			// Action that a restart could mistake for an existing management edit.
			if a.Deploy {
				if err := waitSeedBuild(ctx, st, draft); err != nil {
					return fmt.Errorf("seed Action %q: %w", a.Name, err)
				}
			}
			var deployed *store.ActionVersion
			err = st.WithTx(ctx, func(tx store.Store) error {
				if _, err := tx.Actions().GetActionByName(ctx, tn.ID, a.Name); err == nil {
					return nil
				} else if !errors.Is(err, store.ErrNotFound) {
					return err
				}
				if err := tx.Actions().CreateAction(ctx, draft); err != nil {
					return err
				}
				if a.Deploy {
					var err error
					deployed, err = tx.Actions().Deploy(ctx, tn.ID, draft.ID, "")
					return err
				}
				return nil
			})
			if errors.Is(err, store.ErrConflict) {
				if _, getErr := st.Actions().GetActionByName(ctx, tn.ID, a.Name); getErr == nil {
					continue
				}
			}
			if err != nil {
				return err
			}
			if deployed != nil {
				engine.Builds.PrewarmBuild(tn.ID, deployed.BuildID)
			}
		}
		for trigger, t := range in.Triggers {
			err := st.WithTx(ctx, func(tx store.Store) error {
				initialized, err := tx.Actions().BindingsInitialized(ctx, tn.ID, trigger)
				if err != nil {
					return err
				}
				if initialized {
					return nil
				}
				bs := []store.Binding{}
				for _, b := range t.Bindings {
					var a *store.Action
					var err error
					if b.Ref.Type == "action_name" {
						a, err = tx.Actions().GetActionByName(ctx, tn.ID, b.Ref.Value)
					} else {
						a, err = tx.Actions().GetAction(ctx, tn.ID, b.Ref.Value)
					}
					if err != nil {
						return err
					}
					bs = append(bs, store.Binding{ActionID: a.ID, Trigger: trigger, DisplayName: b.DisplayName})
				}
				_, err = tx.Actions().InitializeBindings(ctx, tn.ID, trigger, bs)
				return err
			})
			if err != nil {
				return fmt.Errorf("seed trigger %q: %w", trigger, err)
			}
		}
	}
	return nil
}
func waitSeedBuild(ctx context.Context, st store.Store, a *store.Action) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, err := st.Actions().GetBuild(ctx, a.TenantID, a.DraftBuildID)
		if err != nil {
			return err
		}
		switch b.Status {
		case store.BuildBuilt:
			return nil
		case store.BuildFailed:
			return errors.New("dependency build failed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
