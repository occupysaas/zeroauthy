package deploymigration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLogStreamExportFormats(t *testing.T) {
	rows := `[{"name":"Audit HTTP","type":"http","status":"paused","sink":{"httpEndpoint":"https://logs.example.invalid/","httpContentFormat":"JSONARRAY"},"filters":[{"type":"category","name":"auth.login.success"}],"pii_config":{"log_fields":["email"],"method":"hash","algorithm":"xxhash"}},{"name":"Audit Datadog","type":"datadog","status":"active","sink":{"datadogRegion":"eu"},"filters":[]}]`
	for _, format := range []string{"yaml", "directory"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			path := dir
			if format == "yaml" {
				path = filepath.Join(dir, "tenant.yaml")
				if err := os.WriteFile(path, []byte("logStreams: "+rows), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(filepath.Join(dir, "log-streams"), 0700); err != nil {
					t.Fatal(err)
				}
				var streams []json.RawMessage
				json.Unmarshal([]byte(rows), &streams)
				for i, b := range streams {
					if err := os.WriteFile(filepath.Join(dir, "log-streams", string(rune('a'+i))+".json"), b, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			got, err := LoadExport(path, format)
			if err != nil {
				t.Fatal(err)
			}
			var want, actual any
			json.Unmarshal([]byte(rows), &want)
			if err = json.Unmarshal(got.Resources["logStreams"], &actual); err != nil {
				t.Fatalf("log streams not loaded: %v", err)
			}
			if !reflect.DeepEqual(want, actual) {
				t.Fatalf("lost stream fields: %s", got.Resources["logStreams"])
			}
		})
	}
}
