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
		if _, exported := options["client_secret"]; exported || strings.TrimSpace(secret) == "" || strings.Contains(secret, "********") {
			return nil, errors.New("deploymigration: explicit provider-secret injection is required")
		}
		options["client_secret"] = secret
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
