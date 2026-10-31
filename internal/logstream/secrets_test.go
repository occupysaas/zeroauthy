package logstream_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logstream"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestStreamSecretsBoundEnvelope(t *testing.T) {
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &store.LogStream{TenantID: "tenant", ID: "stream", Type: "http"}
	private := map[string]any{"httpAuthorization": "SENTINEL_PRIVATE_SECRET"}
	s.SealedSecrets, err = logstream.SealSecrets(w, s, private)
	if err != nil || bytes.Contains(s.SealedSecrets, []byte("SENTINEL_PRIVATE_SECRET")) {
		t.Fatal("unsealed credentials", err)
	}
	opened, err := logstream.OpenSecrets(w, s)
	if err != nil || opened["httpAuthorization"] != private["httpAuthorization"] {
		t.Fatal(opened, err)
	}
	for _, change := range []func(*store.LogStream){func(s *store.LogStream) { s.TenantID = "other" }, func(s *store.LogStream) { s.ID = "other" }, func(s *store.LogStream) { s.Type = "segment" }, func(s *store.LogStream) { s.SealedSecrets = []byte("SENTINEL_PRIVATE_SECRET") }} {
		copy := *s
		change(&copy)
		_, err = logstream.OpenSecrets(w, &copy)
		if err == nil || strings.Contains(err.Error(), "SENTINEL_") {
			t.Fatal("invalid binding or leaked diagnostics", err)
		}
	}
	if _, err = logstream.SealSecrets(nil, s, private); err == nil {
		t.Fatal("nil wrapper accepted")
	}
	if _, err = logstream.OpenSecrets(nil, s); err == nil {
		t.Fatal("nil wrapper accepted")
	}
	if _, err = logstream.SealSecrets(w, nil, private); err == nil {
		t.Fatal("nil stream accepted")
	}
	if _, err = logstream.OpenSecrets(w, nil); err == nil {
		t.Fatal("nil stream accepted")
	}
	empty := &store.LogStream{TenantID: "tenant", ID: "stream", Type: "eventbridge"}
	if sealed, err := logstream.SealSecrets(nil, empty, nil); err != nil || len(sealed) != 0 {
		t.Fatal("empty secret needs no key", err)
	}
	if private, err := logstream.OpenSecrets(nil, empty); err != nil || len(private) != 0 {
		t.Fatal(private, err)
	}
}
