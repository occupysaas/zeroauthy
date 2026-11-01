package logstream

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPIIExactFrozenFieldsNestedCopies(t *testing.T) {
	body := []byte(`{"first_name":"Alice","last_name":"Smith","username":"alice","email":"a@example.com","phone":"12345","address":{"street":"Main"},"details":[{"email":"nested@example.com","Email":"case-preserved","preferred_email":"name-preserved","huge":9007199254740993}]}`)
	original := bytes.Clone(body)
	fields := []string{"first_name", "last_name", "username", "email", "phone", "address", "preferred_email", "Email"}
	for _, method := range []string{"mask", "hash"} {
		t.Run(method, func(t *testing.T) {
			out, err := outgoing(context.Background(), body, &store.LogStreamPII{LogFields: fields, Method: method, Algorithm: "xxhash"})
			if err != nil {
				t.Fatal(err)
			}
			var v map[string]any
			if err = json.Unmarshal(out, &v); err != nil {
				t.Fatal(err)
			}
			for _, field := range fields[:6] {
				if method == "mask" && v[field] != logrules.Marker {
					t.Fatal(field, v[field])
				}
				if method == "hash" {
					value, ok := v[field].(string)
					if !ok || len(value) != 16 {
						t.Fatal(field, v[field])
					}
				}
			}
			nested := v["details"].([]any)[0].(map[string]any)
			if nested["Email"] != "case-preserved" || nested["preferred_email"] != "name-preserved" || nested["email"] == "nested@example.com" {
				t.Fatal(nested)
			}
			if !bytes.Contains(out, []byte("9007199254740993")) || !bytes.Equal(body, original) {
				t.Fatal("numeric precision or original changed")
			}
		})
	}
}

func TestOutgoingPreservesTrustedMetadataWithShortCredentials(t *testing.T) {
	body := []byte(`{"date":"2026-10-30T12:00:00Z","type":"s","log_id":"00000000000000000000000000000000000000000000000000000001","_id":"00000000000000000000000000000000000000000000000000000001","description":"echo s e 0 d","details":{"actions":{"executions":["exe_abcdefghijklmnopqrstuvwx"]},"dynamic-e":"echo e","password":"hidden"},"email":"alice@example.com"}`)
	original := bytes.Clone(body)
	for _, secret := range []string{"e", "s", "0", "d"} {
		t.Run(secret, func(t *testing.T) {
			out, err := outgoing(logscrub.WithCredentials(context.Background(), secret), body, &store.LogStreamPII{LogFields: []string{"email"}, Method: "mask"})
			if err != nil {
				t.Fatal(err)
			}
			var got, want map[string]any
			json.Unmarshal(out, &got)
			json.Unmarshal(body, &want)
			for _, key := range []string{"date", "type", "log_id", "_id"} {
				if got[key] != want[key] {
					t.Fatalf("metadata %s=%v want %v", key, got[key], want[key])
				}
			}
			details, ok := got["details"].(map[string]any)
			if !ok {
				t.Fatalf("details=%v", got)
			}
			acts := details["actions"].(map[string]any)
			if acts["executions"].([]any)[0] != "exe_abcdefghijklmnopqrstuvwx" {
				t.Fatal(acts)
			}
			if strings.Contains(got["description"].(string), secret) {
				t.Fatal(got)
			}
			key := "email"
			if secret == "e" {
				key = "[REDACTED]mail"
			}
			if got[key] != logrules.Marker {
				t.Fatal(got)
			}
			if !bytes.Equal(body, original) {
				t.Fatal("stored body changed")
			}
		})
	}
}
