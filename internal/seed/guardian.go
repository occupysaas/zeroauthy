package seed

import (
	"context"
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func validateGuardian(in *Tenant) error {
	bad := func(message string) error { return fmt.Errorf("guardian %s: %w", message, store.ErrInvalid) }
	raw, supplied := in.supplied["guardian"]
	if supplied {
		object, ok := raw.(map[string]any)
		if !ok {
			return bad("must be an object")
		}
		if value, ok := object["factors"]; ok {
			factors, ok := value.(map[string]any)
			if !ok {
				return bad("factors must be an object")
			}
			for name, value := range factors {
				if _, ok := value.(bool); !ok {
					return bad("factor " + name + " must be a boolean")
				}
			}
		}
		if value, ok := object["policies"]; ok && value == nil {
			return bad("policies must be a list")
		}
	}
	if in.Guardian == nil {
		return nil
	}
	known := map[string]bool{}
	for _, factor := range mfarules.Factors() {
		known[factor.Name] = true
	}
	for name := range in.Guardian.Factors {
		if !known[name] {
			return bad("unknown factor " + name)
		}
	}
	policies := in.Guardian.Policies
	if len(policies) > 1 || len(policies) == 1 && policies[0] != "all-applications" && policies[0] != "confidence-score" {
		return bad("policies must be [], [all-applications] or [confidence-score]")
	}
	return nil
}

// applyGuardian runs in the enclosing seed transaction and retains the store's
// version predicate. No-op seeds do not advance the configuration version.
func applyGuardian(ctx context.Context, st store.Store, tid string, in *Tenant) error {
	if err := validateGuardian(in); err != nil {
		return err
	}
	patch := in.Guardian
	if patch == nil || len(patch.Factors) == 0 && patch.Policies == nil {
		return nil
	}
	g, err := st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return err
	}
	if g.Factors == nil {
		g.Factors = map[string]bool{}
	}
	changed := false
	for name, enabled := range patch.Factors {
		if g.Factors[name] != enabled {
			g.Factors[name] = enabled
			changed = true
		}
	}
	if patch.Policies != nil && !slices.Equal(patch.Policies, g.Policies) {
		g.Policies = slices.Clone(patch.Policies)
		changed = true
	}
	if !changed {
		return nil
	}
	return st.MFA().PutGuardian(ctx, g, g.Version)
}
