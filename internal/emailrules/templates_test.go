package emailrules

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTemplateValidation(t *testing.T) {
	tests := []struct {
		name             string
		raw              map[string]json.RawMessage
		partial, wantErr bool
	}{
		{"complete", map[string]json.RawMessage{"template": json.RawMessage(`"verify_email"`), "body": json.RawMessage(`"Hi {{ user.name }}"`), "subject": json.RawMessage(`"Verify"`), "enabled": json.RawMessage(`true`)}, false, false},
		{"partial", map[string]json.RawMessage{"enabled": json.RawMessage(`false`)}, true, false},
		{"unknown", map[string]json.RawMessage{"body": json.RawMessage(`"x"`), "secret": json.RawMessage(`"s"`)}, true, true},
		{"wrong type", map[string]json.RawMessage{"enabled": json.RawMessage(`"yes"`)}, true, true},
		{"unsupported syntax", map[string]json.RawMessage{"syntax": json.RawMessage(`"handlebars"`)}, true, true},
		{"oversize", map[string]json.RawMessage{"body": json.RawMessage(`"` + strings.Repeat("x", 131073) + `"`)}, true, true},
		{"file include", map[string]json.RawMessage{"body": json.RawMessage(`"{% include 'x' %}"`)}, true, true},
		{"unmatched end tag", map[string]json.RawMessage{"body": json.RawMessage(`"{% endfor %}"`)}, true, true},
		{"too long lifetime", map[string]json.RawMessage{"urlLifetimeInSeconds": json.RawMessage(`604801`)}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.raw, tt.partial)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTemplate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
