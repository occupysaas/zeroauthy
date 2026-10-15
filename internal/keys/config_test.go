package keys

import (
	"bytes"
	"maps"
	"testing"
)

func TestConnectionConfigRoundTrip(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	in := map[string]string{"API_URL": "https://legacy.example", "API_TOKEN": "s3cret"}
	sealed, err := SealConnectionConfig(w, "ten_1", "con_1", in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("s3cret")) {
		t.Fatal("sealed bytes contain the plaintext value")
	}
	out, err := OpenConnectionConfig(w, "ten_1", "con_1", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(in, out) {
		t.Fatalf("round trip = %v, want %v", out, in)
	}
}

func TestConnectionConfigAADBinding(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	sealed, err := SealConnectionConfig(w, "ten_1", "con_1", map[string]string{"K": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenConnectionConfig(w, "ten_2", "con_1", sealed); err == nil {
		t.Error("opened under another tenant")
	}
	if _, err := OpenConnectionConfig(w, "ten_1", "con_2", sealed); err == nil {
		t.Error("opened under another connection")
	}
}

func TestConnectionConfigEmpty(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	sealed, err := SealConnectionConfig(w, "t", "c", map[string]string{})
	if err != nil || sealed != nil {
		t.Fatalf("empty map sealed to %v, %v; want nil, nil", sealed, err)
	}
	out, err := OpenConnectionConfig(w, "t", "c", nil)
	if err != nil || out == nil || len(out) != 0 {
		t.Fatalf("nil opened to %v, %v; want empty non-nil map", out, err)
	}
}
