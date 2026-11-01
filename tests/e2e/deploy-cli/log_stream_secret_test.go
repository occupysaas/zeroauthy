package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logstream"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

// The deploy lane checks encryption and actual private import state locally;
// the public API never provides a secret-recovery path.
func TestE2EPrivateLogStreamSecretsAfterImport(t *testing.T) {
	httpSecret, keySecret := os.Getenv("E2E_M31_STREAM_HTTP_SECRET"), os.Getenv("E2E_M31_STREAM_DATADOG_SECRET")
	if os.Getenv("E2E_M20_WORK") == "" || httpSecret == "" || keySecret == "" {
		t.Skip("only runs in isolated deploy CLI lane")
	}
	ctx := context.Background()
	key, err := base64.StdEncoding.DecodeString(os.Getenv("ZEROAUTHY_SECURITY__MASTER_KEY"))
	if err != nil {
		t.Fatal("invalid fixture master key")
	}
	w, err := keys.NewLocalWrapper(key)
	if err != nil {
		t.Fatal("cannot load fixture wrapper")
	}
	st, err := sqlstore.Open(ctx, os.Getenv("E2E_M20_TARGET_DSN"))
	if err != nil {
		t.Fatal("cannot open fixture database")
	}
	defer st.Close()
	tenant, err := st.Tenants().GetByName(ctx, "e2ecli-target")
	if err != nil {
		t.Fatal("missing target tenant")
	}
	rows, err := st.Logs().ListLogStreams(ctx, tenant.ID)
	if err != nil || len(rows) != 2 {
		t.Fatal("expected both imported streams")
	}
	for _, s := range rows {
		private, err := logstream.OpenSecrets(w, &s)
		if err != nil {
			t.Fatal("private stream secret cannot decrypt")
		}
		switch s.Type {
		case "http":
			if private["httpAuthorization"] != httpSecret {
				t.Fatal("HTTP secret lost or replaced")
			}
		case "datadog":
			if private["datadogApiKey"] != keySecret {
				t.Fatal("Datadog secret lost or replaced")
			}
		default:
			t.Fatal("unexpected stream type")
		}
		public, _ := json.Marshal(s.Sink)
		for _, secret := range []string{httpSecret, keySecret} {
			if bytes.Contains(public, []byte(secret)) || bytes.Contains(s.SealedSecrets, []byte(secret)) {
				t.Fatal("plaintext secret persisted")
			}
		}
	}
}
