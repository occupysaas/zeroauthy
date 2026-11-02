package deploymigration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadGuardianDirectory(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"factors/otp.json":                 `{"name":"otp","enabled":true}`,
		"providers/sms-twilio.json":        `{"name":"sms","provider":"twilio","sid":"fixture-account"}`,
		"templates/sms.json":               `{"name":"sms","enrollment_message":"Enroll {{code}}","verification_message":"Verify {{code}}"}`,
		"policies.json":                    `{"policies":["all-applications"]}`,
		"phoneFactorSelectedProvider.json": `{"provider":"twilio"}`,
		"phoneFactorMessageTypes.json":     `{"message_types":["sms","voice"]}`,
		"phoneFactorSettings.json":         `{"otp_length":6,"otp_expiration_time":300}`,
		"emailFactorSettings.json":         `{"otp_length":6,"otp_expiration_time":300}`,
		"settings.json":                    `{"show_factor_list_on_enrollment":true}`,
	}
	for name, data := range files {
		p := filepath.Join(dir, "guardian", name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	export, err := LoadExport(dir, "directory")
	if err != nil {
		t.Fatal(err)
	}
	wants := map[string]string{
		"guardianFactors":                     `[{"name":"otp","enabled":true}]`,
		"guardianFactorProviders":             `[{"name":"sms","provider":"twilio","sid":"fixture-account"}]`,
		"guardianFactorTemplates":             `[{"name":"sms","enrollment_message":"Enroll {{code}}","verification_message":"Verify {{code}}"}]`,
		"guardianPolicies":                    files["policies.json"],
		"guardianPhoneFactorSelectedProvider": files["phoneFactorSelectedProvider.json"],
		"guardianPhoneFactorMessageTypes":     files["phoneFactorMessageTypes.json"],
		"guardianPhoneFactorSettings":         files["phoneFactorSettings.json"],
		"guardianEmailFactorSettings":         files["emailFactorSettings.json"],
		"guardianSettings":                    files["settings.json"],
	}
	for name, want := range wants {
		var gotValue, wantValue any
		if err := json.Unmarshal(export.Resources[name], &gotValue); err != nil {
			t.Errorf("%s missing/invalid: %v", name, err)
			continue
		}
		if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotValue, wantValue) {
			t.Errorf("%s shape/fields changed: %s", name, export.Resources[name])
		}
	}
	if len(export.Files) != 0 {
		t.Fatal("Guardian config treated as opaque files")
	}
}
