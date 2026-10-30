package deploymigration

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ValidateOrganizations limits offline imports to the pinned Deploy CLI 9.1.0
// organization shape. This is a portability check, not an authorization check.
// Unsupported policy is an error before any destination write, never discarded.
func ValidateOrganizations(source Export) error {
	var orgs []map[string]json.RawMessage
	if raw := source.Resources["organizations"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &orgs); err != nil {
			return errors.New("deploymigration: organizations must be an array")
		}
	}

	var clients []struct {
		ID   string `json:"client_id"`
		Name string `json:"name"`
	}
	if raw := source.Resources["clients"]; len(raw) > 0 {
		if json.Unmarshal(raw, &clients) != nil {
			return errors.New("deploymigration: invalid clients")
		}
	}
	clientNames := map[string]string{}
	for _, c := range clients {
		if c.ID != "" && c.Name != "" {
			clientNames[c.ID] = c.Name
		}
	}
	var grants []map[string]json.RawMessage
	if raw := source.Resources["clientGrants"]; len(raw) > 0 {
		if json.Unmarshal(raw, &grants) != nil {
			return errors.New("deploymigration: invalid client grants")
		}
	}
	grantCount := map[string]int{}
	for _, g := range grants {
		var ref string
		_ = json.Unmarshal(g["client_id"], &ref)
		if name := clientNames[ref]; name != "" {
			ref = name
		}
		grantCount[ref]++
	}
	for _, org := range orgs {
		allowed := map[string]bool{"id": true, "name": true, "display_name": true, "branding": true, "metadata": true, "connections": true, "clients": true, "client_grants": true, "discovery_domains": true, "third_party_client_access": true, "is_app_entitlement_active": true}
		for k := range org {
			if !allowed[k] {
				return fmt.Errorf("deploymigration: unsupported organization field %q", k)
			}
		}

		for _, field := range []string{"clients", "client_grants"} {
			var rows []map[string]json.RawMessage
			if raw := org[field]; len(raw) > 0 {
				if json.Unmarshal(raw, &rows) != nil {
					return fmt.Errorf("deploymigration: invalid organization %s", field)
				}
			}
			for _, row := range rows {

				if field == "client_grants" {
					var ref string
					if json.Unmarshal(row["client_id"], &ref) != nil || ref == "" || grantCount[ref] != 1 {
						return errors.New("deploymigration: organization grant reference must resolve to exactly one application grant; use explicit seed client/audience references")
					}
				}
				for k := range row {
					if k != "client_id" && !(field == "clients" && k == "use_for_member_access") {
						return fmt.Errorf("deploymigration: unsupported organization %s field %q", field, k)
					}
				}
			}
		}
		var conns []map[string]json.RawMessage
		if raw := org["connections"]; len(raw) > 0 {
			if json.Unmarshal(raw, &conns) != nil {
				return errors.New("deploymigration: invalid organization connections")
			}
		}
		for _, c := range conns {
			for k := range c {
				switch k {
				case "name", "connection_id", "organization_connection_name", "assign_membership_on_login", "show_as_button", "is_signup_enabled", "organization_access_level", "is_enabled":
				case "organization_member_access_level":
					var level string
					if json.Unmarshal(c[k], &level) != nil || level != "limited" {
						return errors.New("deploymigration: Deploy CLI 9.1.0 cannot preserve organization_member_access_level")
					}
				default:
					return fmt.Errorf("deploymigration: unsupported organization connection field %q", k)
				}
			}
		}
		var domains []map[string]json.RawMessage
		if raw := org["discovery_domains"]; len(raw) > 0 {
			if json.Unmarshal(raw, &domains) != nil {
				return errors.New("deploymigration: invalid organization discovery domains")
			}
		}
		for _, d := range domains {
			for k := range d {
				switch k {
				case "id", "domain", "status", "use_for_organization_discovery", "verification_host", "verification_txt":
				default:
					return fmt.Errorf("deploymigration: unsupported organization domain field %q", k)
				}
			}
			var status string
			if raw := d["status"]; len(raw) > 0 {
				if json.Unmarshal(raw, &status) != nil || status != "pending" {
					return errors.New("deploymigration: verified organization domains require explicit destination attestation")
				}
			}
		}
	}
	// The 9.1.0 client-grant schema has no organization policy fields. Default
	// deny/false from API reads is inert; an active value cannot be promised.
	for _, g := range grants {
		if raw := g["organization_usage"]; len(raw) > 0 {
			var v string
			if json.Unmarshal(raw, &v) != nil || v != "deny" {
				return errors.New("deploymigration: Deploy CLI 9.1.0 cannot preserve active grant organization_usage")
			}
		}
		if raw := g["allow_any_organization"]; len(raw) > 0 {
			var v bool
			if json.Unmarshal(raw, &v) != nil || v {
				return errors.New("deploymigration: Deploy CLI 9.1.0 cannot preserve allow_any_organization")
			}
		}
	}
	return nil
}
