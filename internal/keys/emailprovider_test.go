package keys

import (
	"bytes"
	"crypto/rand"
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

func TestEmailProviderSplitEnvelopeBinding(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	w, err := NewLocalWrapper(master)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"example":true}`)
	old, err := SealEmailProvider(w, "t", "smtp", payload)
	if err != nil {
		t.Fatal(err)
	}
	current, err := SealEmailProviderSecrets(w, "t", "smtp", payload)
	if err != nil {
		t.Fatal(err)
	}
	if EmailProviderSecretsOnly(old) || !EmailProviderSecretsOnly(current) {
		t.Fatal("incorrect envelope format")
	}
	got, err := OpenEmailProvider(w, "t", "smtp", current)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("split envelope roundtrip failed")
	}
	tampered := bytes.Clone(current)
	tampered[len(tampered)-1] ^= 1
	for _, tc := range []struct {
		id, kind string
		sealed   []byte
	}{
		{"other", "smtp", current}, {"t", "ses", current}, {"t", "smtp", tampered},
		{"t", "smtp", current[len(splitEmailProviderTag):]},
		{"t", "smtp", append([]byte(splitEmailProviderTag), old...)},
	} {
		if got, err := OpenEmailProvider(w, tc.id, tc.kind, tc.sealed); err == nil || got != nil {
			t.Fatal("opened a transplanted or altered envelope")
		}
	}
}
