package tenantrules

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestDynamicRegistrationSettings(t *testing.T) {
	off := &store.Tenant{}
	if DynamicClientRegistration(off) || ClientIDMetadataDocuments(off) || ClientIDMetadataDocumentRegistration(off) || DynamicClientRegistration(nil) {
		t.Fatal("defaults must be off")
	}
	if DynamicClientRegistrationMode(off) != store.SecurityModeStrict || DynamicClientRegistrationMode(nil) != store.SecurityModeStrict {
		t.Fatal("mode defaults to strict")
	}
	on := &store.Tenant{SettingsExtra: map[string]any{
		"flags": map[string]any{"enable_dynamic_client_registration": true},
		"dynamic_client_registration_security_mode":                  "permissive",
		"client_id_metadata_document_dynamic_registration_supported": true,
	}}
	if !DynamicClientRegistration(on) || DynamicClientRegistrationMode(on) != store.SecurityModePermissive {
		t.Fatal("DCR settings not read")
	}
	// Dynamic CIMD registration needs CIMD support too (LR41b-7).
	if ClientIDMetadataDocumentRegistration(on) {
		t.Fatal("dynamic CIMD registration without CIMD support")
	}
	on.SettingsExtra["client_id_metadata_document_supported"] = true
	if !ClientIDMetadataDocuments(on) || !ClientIDMetadataDocumentRegistration(on) {
		t.Fatal("CIMD settings not read")
	}
}
