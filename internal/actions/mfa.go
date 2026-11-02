package actions

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Compile the same frozen schemas used to document Actions MFA. No second
// argument vocabulary is maintained by the runner or the command validator.
var mfaSchemas = func() map[string]*jsonschema.Schema {
	out := map[string]*jsonschema.Schema{}
	for _, m := range mfarules.Inventory().ActionMembers {
		compiler := jsonschema.NewCompiler()
		name := "urn:zeroauthy:actions:" + m.Name
		if err := compiler.AddResource(name, m.Arguments); err != nil {
			panic(err)
		}
		schema, err := compiler.Compile(name)
		if err != nil {
			panic(err)
		}
		out[strings.TrimPrefix(m.Name, "api.")] = schema
	}
	return out
}()

func (a *accum) applyMFA(c command) error {
	schema := mfaSchemas[c.Op]
	raw, err := json.Marshal(c.Args)
	var args []any
	if err != nil || json.Unmarshal(raw, &args) != nil {
		return invalid(c.Op, "invalid MFA arguments")
	}
	// A zero-argument Go command marshals nil as null; normalize to an array.
	if args == nil {
		args = []any{}
	}
	if err = schema.Validate(args); err != nil {
		return invalid(c.Op, "invalid MFA arguments")
	}
	m := mfarules.ActionMember("api." + c.Op)
	if m.RequiresCustomizeMFA && !a.customizeMFA {
		return invalid(c.Op, "customize_mfa_in_postlogin_action must be enabled")
	}
	old := a.eff.MFA
	if c.Op == "multifactor.enable" {
		if old != nil && old.Mode != "" {
			return invalid(c.Op, "multifactor.enable cannot be combined with authentication MFA methods")
		}
		provider := args[0].(string)
		if provider == "duo" {
			return invalid(c.Op, "Duo MFA provider is not configured")
		}
		next := &MFAEffects{Provider: provider}
		if len(args) > 1 {
			next.AllowRememberBrowser, _ = args[1].(map[string]any)["allowRememberBrowser"].(bool)
		}
		a.eff.MFA = next
		return nil
	}
	if old != nil && old.Provider != "" {
		return invalid(c.Op, "authentication MFA methods cannot be combined with multifactor.enable")
	}
	factors := []any{}
	if strings.HasSuffix(c.Op, "Any") {
		factors = args[0].([]any)
	} else {
		factors = append(factors, args[0])
		if len(args) > 1 {
			if additional, ok := args[1].(map[string]any)["additionalFactors"].([]any); ok {
				factors = append(factors, additional...)
			}
		}
	}
	group := []string{}
	for _, v := range factors {
		typ := v.(map[string]any)["type"].(string)
		if !slices.Contains(m.AvailableFactors, typ) {
			return invalid(c.Op, "factor %s is unavailable", typ)
		}
		if !slices.Contains(group, typ) {
			group = append(group, typ)
		}
	}
	mode := "challenge"
	if strings.HasPrefix(c.Op, "authentication.enroll") {
		mode = "enroll"
	}
	if old != nil && old.Mode != mode {
		return invalid(c.Op, "challenge and enrollment cannot be combined")
	}
	next := &MFAEffects{Mode: mode, Any: strings.HasSuffix(c.Op, "Any"), Factors: [][]string{}}
	if old != nil {
		next.Factors = slices.Clone(old.Factors)
	}
	next.Factors = append(next.Factors, group)
	a.eff.MFA = next
	return nil
}

// enrolledFactors contains only public types and public options. Phone methods
// have no stored SMS/voice discriminator; omit options rather than invent it.
func (e *Engine) enrolledFactors(ctx context.Context, tid, uid string) ([]map[string]any, error) {
	out := []map[string]any{}
	aa, err := e.Store.MFA().ListAuthenticators(ctx, tid, uid)
	if errors.Is(err, store.ErrMFAUnavailable) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, a := range aa {
		if !a.Confirmed {
			continue
		}
		typ := a.Type
		if typ == "totp" {
			typ = "otp"
		}
		if !slices.Contains([]string{"otp", "email", "recovery-code", "webauthn-roaming", "webauthn-platform", "phone", "push-notification"}, typ) {
			continue
		}
		out = append(out, map[string]any{"type": typ})
	}
	return out, nil
}
