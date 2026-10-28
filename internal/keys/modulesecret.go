package keys

// moduleSecretLabel deliberately differs from the Action secret domain, even
// when a tenant chooses identical Action and Module identifiers.
const moduleSecretLabel = "action-module-secret/v1"

// SealModuleSecret seals a module's secret under its tenant, module and name.
// Immutable versions retain these sealed bytes and the module identity.
func SealModuleSecret(w Wrapper, tenantID, moduleID, name, value string) ([]byte, error) {
	return SealBound(w, moduleSecretLabel, []string{tenantID, moduleID, name}, []byte(value))
}

// OpenModuleSecret opens only the matching module secret snapshot.
func OpenModuleSecret(w Wrapper, tenantID, moduleID, name string, sealed []byte) (string, error) {
	plain, err := OpenBound(w, moduleSecretLabel, []string{tenantID, moduleID, name}, sealed)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
