package keys

import (
	"encoding/json"
	"errors"
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
