package tenantrules

import "github.com/zeroauthy/zeroauthy/internal/store"

// DynamicClientRegistration reports flags.enable_dynamic_client_registration
// (Plan 41b): open registration at /oidc/register.
func DynamicClientRegistration(t *store.Tenant) bool {
	if t == nil {
		return false
	}
	flags, _ := t.SettingsExtra["flags"].(map[string]any)
	on, _ := flags["enable_dynamic_client_registration"].(bool)
	return on
}

// DynamicClientRegistrationMode is the third_party_security_mode of clients
// created through /oidc/register: the tenant's
// dynamic_client_registration_security_mode, strict when unset.
func DynamicClientRegistrationMode(t *store.Tenant) string {
	if t != nil && t.SettingsExtra["dynamic_client_registration_security_mode"] == store.SecurityModePermissive {
		return store.SecurityModePermissive
	}
	return store.SecurityModeStrict
}

// ClientIDMetadataDocuments reports client_id_metadata_document_supported:
// Client ID Metadata Document URLs are accepted as client_id.
func ClientIDMetadataDocuments(t *store.Tenant) bool {
	if t == nil {
		return false
	}
	on, _ := t.SettingsExtra["client_id_metadata_document_supported"].(bool)
	return on
}

// ClientIDMetadataDocumentRegistration reports whether an unknown Client ID
// Metadata Document URL creates a client: it needs both CIMD settings
// (LR41b-7).
func ClientIDMetadataDocumentRegistration(t *store.Tenant) bool {
	if !ClientIDMetadataDocuments(t) {
		return false
	}
	on, _ := t.SettingsExtra["client_id_metadata_document_dynamic_registration_supported"].(bool)
	return on
}
