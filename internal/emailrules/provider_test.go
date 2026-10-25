package emailrules

import (
	"encoding/json"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestValidateProviderCredentialsAndRedaction(t *testing.T) {
	secret := "SENTINEL_EMAIL_SECRET"
	provider := rawProvider(map[string]any{
		"name": "sendgrid", "enabled": true, "default_from_address": "mail@example.test",
		"credentials": map[string]any{"api_key": secret}, "settings": map[string]any{},
	})
	if err := ValidateProvider(provider, nil); err != nil {
		t.Fatalf("valid provider rejected: %v", err)
	}
	if err := ValidateProvider(rawProvider(map[string]any{"name": "mailgun", "enabled": true, "credentials": map[string]any{"api_key": "secret", "domain": "mg.example.test", "region": nil}}), nil); err != nil {
		t.Fatalf("nullable region rejected: %v", err)
	}
	stored := &store.EmailProvider{Name: "sendgrid", Enabled: true, DefaultFrom: "mail@example.test", PublicConfig: map[string]any{"region": "eu"}, SealedCredentials: []byte(secret)}
	projected := ProjectProvider(stored)
	b, _ := json.Marshal(projected)
	if string(b) == "" || contains(string(b), secret) || contains(string(b), "SealedCredentials") {
		t.Fatalf("secret leaked from public projection: %s", b)
	}
	for _, bad := range []map[string]any{
		{"name": "custom", "enabled": true},
		{"name": "sendgrid", "enabled": true, "credentials": map[string]any{"api_key": ""}},
		{"name": "sendgrid", "enabled": true, "credentials": map[string]any{"api_key": secret, "smtp_pass": "bad"}},
		{"name": "smtp", "enabled": true, "credentials": map[string]any{"smtp_host": "localhost", "smtp_pass": secret}},
	} {
		if err := ValidateProvider(rawProvider(bad), nil); err == nil {
			t.Errorf("invalid provider accepted: %#v", bad)
		}
	}
}

func rawProvider(v any) map[string]json.RawMessage {
	b, _ := json.Marshal(v)
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(b, &raw)
	return raw
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
