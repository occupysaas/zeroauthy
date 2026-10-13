package keys

import (
	"bytes"
	"testing"
)

func testMasterKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestLocalWrapper(t *testing.T) {
	w, err := NewLocalWrapper(testMasterKey(1))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := w.Wrap([]byte("data key"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("data key")) {
		t.Fatal("ciphertext contains plaintext")
	}
	pt, err := w.Unwrap(ct, []byte("aad"))
	if err != nil || string(pt) != "data key" {
		t.Fatalf("Unwrap = %q, %v", pt, err)
	}
	if _, err := w.Unwrap(ct, []byte("other aad")); err == nil {
		t.Fatal("Unwrap accepted wrong AAD")
	}
	other, _ := NewLocalWrapper(testMasterKey(2))
	if _, err := other.Unwrap(ct, []byte("aad")); err == nil {
		t.Fatal("Unwrap accepted wrong master key")
	}
	if _, err := NewLocalWrapper([]byte("short")); err == nil {
		t.Fatal("short master key accepted")
	}
}

func TestEnvelope(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	blob, err := seal(w, []byte("private key bytes"), []byte("ten|kid"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("private key bytes")) {
		t.Fatal("sealed blob contains plaintext")
	}
	pt, err := unseal(w, blob, []byte("ten|kid"))
	if err != nil || string(pt) != "private key bytes" {
		t.Fatalf("unseal = %q, %v", pt, err)
	}
	if _, err := unseal(w, blob, []byte("ten|other")); err == nil {
		t.Fatal("unseal accepted wrong AAD")
	}
}
