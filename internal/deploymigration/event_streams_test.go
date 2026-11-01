package deploymigration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEventStreamExportFormats(t *testing.T) {
	rows := `[{"name":"Audit webhook","status":"disabled","subscriptions":[{"event_type":"user.created"}],"destination":{"type":"webhook","configuration":{"webhook_endpoint":"https://events.example.invalid/","webhook_authorization":{"method":"bearer"}}}},{"name":"Audit action","status":"enabled","subscriptions":[{"event_type":"user.updated"}],"destination":{"type":"action","configuration":{"action_id":"Receive events"}}}]`
	for _, format := range []string{"yaml", "directory"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			path := dir
			if format == "yaml" {
				path = filepath.Join(dir, "tenant.yaml")
				if err := os.WriteFile(path, []byte("eventStreams: "+rows), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(filepath.Join(dir, "event-streams"), 0700); err != nil {
					t.Fatal(err)
				}
				var streams []json.RawMessage
				json.Unmarshal([]byte(rows), &streams)
				for i, b := range streams {
					if err := os.WriteFile(filepath.Join(dir, "event-streams", string(rune('a'+i))+".json"), b, 0600); err != nil {
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
			if err = json.Unmarshal(got.Resources["eventStreams"], &actual); err != nil {
				t.Fatalf("event streams not loaded: %v", err)
			}
			if !reflect.DeepEqual(want, actual) {
				t.Fatalf("lost stream fields: %s", got.Resources["eventStreams"])
			}
		})
	}
}

func TestEventStreamExportConfigurationIsOpaque(t *testing.T) {
	// Public usernames may resemble file references. Event streams have no
	// materialized file fields, so loading must preserve strings without reads.
	row := `{"name":"Events","destination":{"type":"webhook","configuration":{"webhook_endpoint":"https://source.example/intake?client=source-id","webhook_authorization":{"method":"basic","username":"file://missing-private-file"}}}}`
	for _, format := range []string{"yaml", "directory"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			input := dir
			if format == "yaml" {
				input = filepath.Join(dir, "tenant.yaml")
				if err := os.WriteFile(input, []byte("eventStreams: ["+row+"]"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(filepath.Join(dir, "event-streams"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "event-streams", "events.json"), []byte(row), 0600); err != nil {
					t.Fatal(err)
				}
			}
			export, err := LoadExport(input, format)
			if err != nil {
				t.Fatal(err)
			}
			if len(export.Files) != 0 {
				t.Fatal("opaque configuration read a file")
			}
			var rows []map[string]any
			if err = json.Unmarshal(export.Resources["eventStreams"], &rows); err != nil {
				t.Fatal(err)
			}
			cfg := rows[0]["destination"].(map[string]any)["configuration"].(map[string]any)
			if cfg["webhook_authorization"].(map[string]any)["username"] != "file://missing-private-file" {
				t.Fatal("configuration rewritten")
			}
		})
	}
}
