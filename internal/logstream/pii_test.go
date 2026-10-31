package logstream

import (
	"bytes"
	"context"
	"encoding/json"
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
