package keys

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmailProviderEnvelope(t *testing.T) {
	master := bytes.Repeat([]byte{0x53}, 32)
	wrapper, err := NewLocalWrapper(master)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("SENTINEL_EMAIL_PROVIDER_SECRET")
	sealed, err := SealEmailProvider(wrapper, "tenant-a", "sendgrid", secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("sealed bytes contain plaintext secret")
	}
	opened, err := OpenEmailProvider(wrapper, "tenant-a", "sendgrid", sealed)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("open = %q, %v", opened, err)
	}
	for _, tc := range []struct {
		tenant, provider string
		key              []byte
	}{{"tenant-b", "sendgrid", master}, {"tenant-a", "mailgun", master}, {"a", "bc", master}, {"tenant-a", "sendgrid", bytes.Repeat([]byte{0x24}, 32)}} {
		other, e := NewLocalWrapper(tc.key)
		if e != nil {
			t.Fatal(e)
		}
		got, e := OpenEmailProvider(other, tc.tenant, tc.provider, sealed)
		if e == nil || got != nil {
			t.Errorf("unexpected open for tenant=%q provider=%q: %q", tc.tenant, tc.provider, got)
		}
		if strings.Contains(strings.ToLower(errorString(e)), "sentinel") {
			t.Errorf("error disclosed plaintext: %v", e)
		}
	}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
