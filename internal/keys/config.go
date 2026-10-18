package keys

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// connectionConfigAAD binds a sealed configuration to its tenant and
// connection, so a blob copied between rows does not open.
//
// The '|'-joined form is unambiguous only because both IDs are generated:
// "ten_" and "con_" followed by alphanumerics (secrets.RandomString), never
// containing '|'. Configurations sealed this way exist in deployed databases
// (Plan 8), so the format is kept as is; new sealed values use
// lengthPrefixed (see clientSecretAAD).
func connectionConfigAAD(tenantID, connectionID string) []byte {
	return []byte("connection-config|" + tenantID + "|" + connectionID)
}

// SealConnectionConfig envelope-encrypts a custom database connection's
// configuration map. An empty map yields nil, so connections without
// configuration store nothing.
func SealConnectionConfig(w Wrapper, tenantID, connectionID string, cfg map[string]string) ([]byte, error) {
	if len(cfg) == 0 {
		return nil, nil
	}
	plain, err := json.Marshal(cfg)
	if err != nil {
		return nil, errors.New("keys: encode connection configuration")
	}
	return seal(w, plain, connectionConfigAAD(tenantID, connectionID))
}

// OpenConnectionConfig reverses SealConnectionConfig. A nil blob opens to an
// empty map. Errors never include configuration values.
func OpenConnectionConfig(w Wrapper, tenantID, connectionID string, sealed []byte) (map[string]string, error) {
	out := map[string]string{}
	if len(sealed) == 0 {
		return out, nil
	}
	plain, err := unseal(w, sealed, connectionConfigAAD(tenantID, connectionID))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, errors.New("keys: malformed connection configuration")
	}
	return out, nil
}

// configValuePrefix marks the opaque form in which the Management API
// returns one configuration value (D-0042). A value that starts with it is
// never plaintext: it must open, or the API refuses it.
const configValuePrefix = "zcv1."

// IsConfigValueBlob reports whether s is in the form SealConfigValue makes.
func IsConfigValueBlob(s string) bool { return strings.HasPrefix(s, configValuePrefix) }

func configValueAAD(tenantID, connectionID, key string) []byte {
	return lengthPrefixed("connection-config-value/v1", tenantID, connectionID, key)
}

// SealConfigValue envelope-encrypts one configuration value and returns it as
// a printable blob bound to the tenant, connection and key. Sealing is
// randomized: two blobs of one value differ, so callers compare by opening.
func SealConfigValue(w Wrapper, tenantID, connectionID, key, value string) (string, error) {
	if w == nil {
		return "", errors.New("keys: a master key wrapper is required to seal a configuration value")
	}
	sealed, err := seal(w, []byte(value), configValueAAD(tenantID, connectionID, key))
	if err != nil {
		return "", errors.New("keys: seal configuration value")
	}
	return configValuePrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// OpenConfigValue reverses SealConfigValue. Errors never include the blob or
// the value.
func OpenConfigValue(w Wrapper, tenantID, connectionID, key, blob string) (string, error) {
	if w == nil {
		return "", errors.New("keys: a master key wrapper is required to open a configuration value")
	}
	enc, ok := strings.CutPrefix(blob, configValuePrefix)
	if !ok {
		return "", errors.New("keys: not a configuration value blob")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", errors.New("keys: malformed configuration value blob")
	}
	plain, err := unseal(w, sealed, configValueAAD(tenantID, connectionID, key))
	if err != nil {
		return "", errors.New("keys: configuration value blob does not open")
	}
	return string(plain), nil
}
