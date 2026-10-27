package store

import (
	"errors"
	"testing"
)

func TestMicrosoftIdentityEncoding(t *testing.T) {
	const oid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const tid = "11111111-2222-3333-4444-555555555555"
	for _, tc := range []struct {
		provider, id, sub string
		multi, valid      bool
	}{
		{"windowslive", "Case|Sensitive", "Case|Sensitive", false, true},
		{"waad", "corp|" + oid, oid, false, true},
		{"waad", "corp|" + tid + ":" + oid, tid + ":" + oid, true, true},
		{"waad", "corp|" + oid, "", true, false},
		{"waad", "corp|" + tid + ":" + oid, "", false, false},
		{"waad", "corp|AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "", false, false},
		{"waad", "corp|9188040d-6c67-4c5b-b112-36a304b66dad:" + oid, "", true, false},
		{"waad", "corp|not-guid", "", false, false},
		{"waad", "other|" + oid, "", false, false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			extra := map[string]any{"tenant_domain": tid}
			if tc.multi {
				extra = map[string]any{"useCommonEndpoint": true}
			}
			u := &User{TenantID: "ten", Identities: []Identity{{Provider: tc.provider, Connection: "corp", UserID: tc.id}}}
			keys, err := ResolveFederatedKeys(u, func(string) (*Connection, error) {
				return &Connection{ID: "con", Strategy: tc.provider, Extra: extra}, nil
			})
			if !tc.valid {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("wanted invalid, got %v %+v", err, keys)
				}
				return
			}
			if err != nil || len(keys) != 1 || keys[0].Subject != tc.sub {
				t.Fatalf("keys %+v %v", keys, err)
			}
		})
	}
}
