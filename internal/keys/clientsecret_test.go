package keys

import (
	"bytes"
	"testing"
)

func TestClientSecretRoundTrip(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	sealed, err := SealClientSecret(w, "ten_1", "cli_1", "very-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("very-secret-value")) {
		t.Fatal("sealed bytes contain the plaintext")
	}
	got, err := OpenClientSecret(w, "ten_1", "cli_1", sealed)
	if err != nil || got != "very-secret-value" {
		t.Fatalf("open = %q, %v", got, err)
	}
}

func TestClientSecretAADBinding(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	sealed, err := SealClientSecret(w, "ten_1", "cli_1", "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenClientSecret(w, "ten_2", "cli_1", sealed); err == nil {
		t.Error("opened under another tenant")
	}
	if _, err := OpenClientSecret(w, "ten_1", "cli_2", sealed); err == nil {
		t.Error("opened under another client")
	}
	// A connection configuration blob for the same IDs must not open as a secret.
	cfg, _ := SealConnectionConfig(w, "ten_1", "cli_1", map[string]string{"K": "v"})
	if _, err := OpenClientSecret(w, "ten_1", "cli_1", cfg); err == nil {
		t.Error("connection configuration opened as a client secret")
	}
	other, _ := NewLocalWrapper(testMasterKey(2))
	if _, err := OpenClientSecret(other, "ten_1", "cli_1", sealed); err == nil {
		t.Error("opened under another master key")
	}
}

func TestClientSecretAADIsInjective(t *testing.T) {
	if bytes.Equal(clientSecretAAD("a|b", "c"), clientSecretAAD("a", "b|c")) {
		t.Fatal("AAD is ambiguous across the field boundary")
	}
	w, _ := NewLocalWrapper(testMasterKey(1))
	sealed, _ := SealClientSecret(w, "ten_1", "x|y", "s")
	if _, err := OpenClientSecret(w, "ten_1|x", "y", sealed); err == nil {
		t.Error("opened with the boundary shifted")
	}
}

func TestClientSecretRejectsEmpty(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	if _, err := SealClientSecret(w, "t", "c", ""); err == nil {
		t.Error("sealed an empty secret")
	}
	if _, err := SealClientSecret(nil, "t", "c", "s"); err == nil {
		t.Error("sealed without a wrapper")
	}
	if _, err := OpenClientSecret(w, "t", "c", nil); err == nil {
		t.Error("opened an empty blob")
	}
	if _, err := OpenClientSecret(nil, "t", "c", []byte("x")); err == nil {
		t.Error("opened without a wrapper")
	}
	if _, err := OpenClientSecret(w, "t", "c", []byte("garbage")); err == nil {
		t.Error("opened garbage")
	}
}
