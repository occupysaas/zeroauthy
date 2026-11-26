// Package myorgrules validates the My Organization API's settings (Plan
// 42b): an application's my_organization_configuration, from Auth0's
// Management OpenAPI (ClientMyOrganization*Configuration).
package myorgrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// Strategies are the allowed_strategies values.
var Strategies = []string{"pingfederate", "adfs", "waad", "google-apps", "okta", "oidc", "samlp"}

// ThirdPartyAccess is the third_party_client_access setting.
type ThirdPartyAccess struct {
	DefaultValue  string   `json:"default_value"`
	AllowedValues []string `json:"allowed_values"`
}

// Config is an application's my_organization_configuration.
type Config struct {
	ConnectionProfileID              string            `json:"connection_profile_id,omitempty"`
	UserAttributeProfileID           string            `json:"user_attribute_profile_id,omitempty"`
	AllowedStrategies                []string          `json:"allowed_strategies"`
	ThirdPartyClientAccess           *ThirdPartyAccess `json:"third_party_client_access,omitempty"`
	ConnectionDeletionBehavior       string            `json:"connection_deletion_behavior"`
	InvitationLandingClientID        string            `json:"invitation_landing_client_id,omitempty"`
	EnforcePermissionCeiling         bool              `json:"enforce_permission_ceiling"`
	EnforceSelfAssignmentRestriction bool              `json:"enforce_self_assignment_restriction"`
}

// ThirdParty is the third-party access setting, with Auth0's default
// (block, block only).
func (c *Config) ThirdParty() ThirdPartyAccess {
	if c.ThirdPartyClientAccess == nil {
		return ThirdPartyAccess{DefaultValue: "block", AllowedValues: []string{"block"}}
	}
	return *c.ThirdPartyClientAccess
}

// Parse validates raw. Unknown members, missing required ones and values
// outside the enums are refused.
func Parse(raw json.RawMessage) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, errors.New("my_organization_configuration must be an object")
	}
	for _, k := range []string{"allowed_strategies", "connection_deletion_behavior"} {
		if _, ok := probe[k]; !ok {
			return nil, fmt.Errorf("my_organization_configuration.%s is required", k)
		}
	}
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("invalid my_organization_configuration: %v", err)
	}
	if c.AllowedStrategies == nil {
		return nil, errors.New("my_organization_configuration.allowed_strategies must be an array")
	}
	seen := map[string]bool{}
	for _, s := range c.AllowedStrategies {
		if !slices.Contains(Strategies, s) || seen[s] {
			return nil, fmt.Errorf("my_organization_configuration.allowed_strategies: %q is not allowed or repeated", s)
		}
		seen[s] = true
	}
	if c.ConnectionDeletionBehavior != "allow" && c.ConnectionDeletionBehavior != "allow_if_empty" {
		return nil, errors.New("my_organization_configuration.connection_deletion_behavior must be allow or allow_if_empty")
	}
	if t := c.ThirdPartyClientAccess; t != nil {
		if t.DefaultValue != "block" || len(t.AllowedValues) == 0 {
			return nil, errors.New("my_organization_configuration.third_party_client_access needs default_value block and allowed_values")
		}
		for i, v := range t.AllowedValues {
			if (v != "allow" && v != "block") || slices.Contains(t.AllowedValues[:i], v) {
				return nil, errors.New("my_organization_configuration.third_party_client_access.allowed_values must be allow or block, once each")
			}
		}
	}
	for name, v := range map[string]string{"connection_profile_id": c.ConnectionProfileID, "user_attribute_profile_id": c.UserAttributeProfileID, "invitation_landing_client_id": c.InvitationLandingClientID} {
		if len(v) > 255 {
			return nil, fmt.Errorf("my_organization_configuration.%s is too long", name)
		}
	}
	return &c, nil
}
