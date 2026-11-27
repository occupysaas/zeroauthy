package deploymigration

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// FederationImport makes the private staging connection array for the actual
// Deploy CLI. Public exports remain unchanged. Each provider credential must
// come from the explicit injection map, never an exported mask or fallback.
func FederationImport(export Export, credentials map[string]string) (json.RawMessage, error) {
	var rows []map[string]any
	if json.Unmarshal(export.Resources["connections"], &rows) != nil || len(rows) == 0 {
		return nil, errors.New("deploymigration: federation connections are missing")
	}
	for _, row := range rows {
		strategy, _ := row["strategy"].(string)
		if !rules.IsFederated(strategy) {
			return nil, errors.New("deploymigration: unsupported federation strategy")
		}
		name, _ := row["name"].(string)
		secret := credentials[name]
		options, ok := row["options"].(map[string]any)
		if !ok {
			return nil, errors.New("deploymigration: federation options are missing")
		}
		_, exportedClient := options["client_secret"]
		_, exportedApple := options["app_secret"]
		// samlp, adfs and front-channel OIDC carry no provider secret
		// (Plans 37a, 37b).
		front := strategy == rules.OIDC && options["type"] != "back_channel" || strategy == rules.SAMLP || strategy == rules.ADFS
		optional := front || (strategy == rules.OIDC || strategy == rules.Okta) && options["token_endpoint_auth_method"] == "private_key_jwt"
		if exportedClient || exportedApple || !optional && strings.TrimSpace(secret) == "" || strings.Contains(secret, "********") || front && secret != "" {
			return nil, errors.New("deploymigration: explicit provider-secret injection is required")
		}
		if secret != "" {
			options[rules.SecretOption(strategy)] = secret
		}
		if strategy == rules.GitHub || rules.IsDescriptorSocial(strategy) {
			// Fail before the Deploy CLI runs: a scope that disagrees with
			// the flags is rejected, never silently rewritten.
			if _, errs := rules.Parse(rules.Input{Strategy: strategy, Name: name, Options: options, HasSealedSecret: true}); len(errs) > 0 {
				return nil, errors.New("deploymigration: invalid " + strategy + " connection: " + errs[0].Error())
			}
		}
		if strategy == rules.OAuth2 {
			scripts, ok := options["scripts"].(map[string]any)
			if !ok {
				return nil, errors.New("deploymigration: OAuth profile script is required")
			}
			script, ok := scripts["fetchUserProfile"].(string)
			if !ok || strings.TrimSpace(script) == "" {
				return nil, errors.New("deploymigration: OAuth profile script is required")
			}
			if isOAuthScriptReference(script) {
				b, ok := export.Files[strings.TrimPrefix(script, "file://")]
				if !ok || len(b) == 0 || len(b) > rules.MaxScriptBytes || !utf8.Valid(b) {
					return nil, errors.New("deploymigration: materialized OAuth profile script is unavailable")
				}
				scripts["fetchUserProfile"] = string(b)
			}
		}
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return nil, errors.New("deploymigration: invalid federation import")
	}
	return b, nil
}

func isOAuthScriptReference(script string) bool {
	s := strings.TrimSpace(script)
	return strings.HasPrefix(s, "file://") || strings.HasSuffix(s, ".js")
}
