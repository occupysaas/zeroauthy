package keys

import "errors"

// actionSecretLabel names the sealed form of an Action secret value.
const actionSecretLabel = "action-secret/v1"

// SealActionSecret envelope-encrypts one Action secret value bound to its
// tenant, Action and secret name, so a blob copied to another Action, tenant
// or name does not open. Versions keep the Action's ID, so a deployed
// snapshot opens under the same binding. Errors never include the value.
func SealActionSecret(w Wrapper, tenantID, actionID, name, value string) ([]byte, error) {
	if w == nil {
		return nil, errors.New("keys: a master key wrapper is required to seal an Action secret")
	}
	return SealBound(w, actionSecretLabel, []string{tenantID, actionID, name}, []byte(value))
}

// OpenActionSecret reverses SealActionSecret under the same tenant, Action
// and name.
func OpenActionSecret(w Wrapper, tenantID, actionID, name string, sealed []byte) (string, error) {
	if w == nil {
		return "", errors.New("keys: a master key wrapper is required to open an Action secret")
	}
	plain, err := OpenBound(w, actionSecretLabel, []string{tenantID, actionID, name}, sealed)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
