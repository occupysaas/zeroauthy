package myorg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/orgidp"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// profileDoc is the part of a connection profile (Plan 37c) the My
// Organization API reads (LR42b-21, LR42b-22).
type profileDoc struct {
	present      bool
	Organization struct {
		ShowAsButton            string `json:"show_as_button"`
		AssignMembershipOnLogin string `json:"assign_membership_on_login"`
	} `json:"organization"`
	EnabledFeatures   []string                    `json:"enabled_features"`
	StrategyOverrides map[string]strategyOverride `json:"strategy_overrides"`
	Provisioning      *provisioningDoc            `json:"provisioning"`
}

type strategyOverride struct {
	EnabledFeatures *[]string        `json:"enabled_features"`
	Provisioning    *provisioningDoc `json:"provisioning"`
}

type provisioningDoc struct {
	SCIM *struct {
		Tokens tokensDoc `json:"tokens"`
	} `json:"scim"`
}

type tokensDoc struct {
	Scopes           []string `json:"scopes"`
	DefaultExpiry    *int     `json:"default_expiry"`
	MaxAllowedExpiry *int     `json:"max_allowed_expiry"`
}

// profile is the application's connection profile; an absent or unknown
// profile is the zero profileDoc (present false).
func (h *Handlers) profile(ctx context.Context, c *Caller) (*profileDoc, error) {
	doc := &profileDoc{}
	id := c.Config.ConnectionProfileID
	if id == "" || !store.SelfServiceAvailable(h.Store) {
		return doc, nil
	}
	p, err := h.Store.SelfService().GetConnectionProfile(ctx, c.TenantID, id)
	if errors.Is(err, store.ErrNotFound) {
		return doc, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(p.Doc, doc); err != nil {
		return nil, err
	}
	doc.present = true
	return doc, nil
}

// canSet reports whether administrators choose a flag the profile governs
// with mode (none, optional, required); without a profile they cannot.
func canSet(mode string) bool { return mode == "optional" }

// flag is the value of a profile-governed flag: required is true, none (or
// no profile) false, optional the requested value (false by default).
func (p *profileDoc) flag(mode string, requested *bool) bool {
	switch mode {
	case "required":
		return true
	case "optional":
		return requested != nil && *requested
	}
	return false
}

// checkFlags refuses a requested flag value the profile does not let
// administrators choose.
func (p *profileDoc) checkFlags(showAsButton, assignMembership *bool) *Problem {
	for _, f := range []struct {
		name, mode string
		v          *bool
	}{{"show_as_button", p.Organization.ShowAsButton, showAsButton}, {"assign_membership_on_login", p.Organization.AssignMembershipOnLogin, assignMembership}} {
		if f.v != nil && !canSet(f.mode) && *f.v != p.flag(f.mode, nil) {
			return problem(http.StatusForbidden, "insufficient_access", "Forbidden", f.name+" is set by the application's connection profile.")
		}
	}
	return nil
}

// features are the strategy's enabled features: its override's, else the
// profile's.
func (p *profileDoc) features(strategy string) []string {
	if o, ok := p.StrategyOverrides[strategy]; ok && o.EnabledFeatures != nil {
		return *o.EnabledFeatures
	}
	return p.EnabledFeatures
}

// provisions reports whether the profile enables SCIM provisioning for the
// strategy.
func (p *profileDoc) provisions(strategy string) bool {
	return slices.Contains(p.features(strategy), "scim")
}

// tokens are the strategy's SCIM token settings: its override's, else the
// profile's.
func (p *profileDoc) tokens(strategy string) *tokensDoc {
	if o, ok := p.StrategyOverrides[strategy]; ok && o.Provisioning != nil && o.Provisioning.SCIM != nil {
		return &o.Provisioning.SCIM.Tokens
	}
	if p.Provisioning != nil && p.Provisioning.SCIM != nil {
		return &p.Provisioning.SCIM.Tokens
	}
	return nil
}

// configKey is the OpenAPI's strategies key (googleapps for google-apps).
func configKey(strategy string) string {
	if strategy == "google-apps" {
		return "googleapps"
	}
	return strategy
}

func (h *Handlers) getIdPConfig(w http.ResponseWriter, r *http.Request, c *Caller) {
	prof, err := h.profile(r.Context(), c)
	if err != nil {
		h.event(r, c, cfgEventFail)
		h.fail(w, r, "identity provider configuration", err)
		return
	}
	strategies := map[string]any{}
	for _, s := range orgidp.Strategies {
		if !slices.Contains(c.Config.AllowedStrategies, s) {
			continue
		}
		features, methods := []string{}, []string{}
		entry := map[string]any{}
		for _, f := range prof.features(s) {
			switch f {
			case "scim":
				features, methods = append(features, "provisioning"), append(methods, "scim")
				if t := prof.tokens(s); t != nil {
					tokens := map[string]any{"scopes": t.Scopes}
					if t.Scopes == nil {
						tokens["scopes"] = scimScopes
					}
					if t.DefaultExpiry != nil {
						tokens["default_expiry"] = *t.DefaultExpiry
					}
					if t.MaxAllowedExpiry != nil {
						tokens["max_allowed_expiry"] = *t.MaxAllowedExpiry
					}
					entry["provisioning"] = map[string]any{"scim": map[string]any{"tokens": tokens}}
				}
			case "universal_logout":
				features = append(features, "universal_logout")
			}
		}
		entry["enabled_features"], entry["provisioning_methods"] = features, methods
		strategies[configKey(s)] = entry
	}
	writeJSON(w, r, http.StatusOK, map[string]any{
		"organization": map[string]any{
			"can_set_show_as_button":             canSet(prof.Organization.ShowAsButton),
			"can_set_assign_membership_on_login": canSet(prof.Organization.AssignMembershipOnLogin),
		},
		"strategies":            strategies,
		"domain_aliases_config": map[string]any{"domain_verification": "optional"},
	})
}

// scimScopes are the SCIM token scopes (the OpenAPI's enum).
var scimScopes = []string{"get:users", "post:users", "patch:users", "delete:users", "put:users"}
