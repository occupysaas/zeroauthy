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

func TestConfigValueBlob(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	blob, err := SealConfigValue(w, "ten_1", "con_1", "API_TOKEN", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !IsConfigValueBlob(blob) || bytes.Contains([]byte(blob), []byte("s3cret")) {
		t.Fatalf("blob %q is not an opaque blob", blob)
	}
	got, err := OpenConfigValue(w, "ten_1", "con_1", "API_TOKEN", blob)
	if err != nil || got != "s3cret" {
		t.Fatalf("open = %q, %v", got, err)
	}
	// Bound to tenant, connection and key.
	for _, c := range [][3]string{{"ten_2", "con_1", "API_TOKEN"}, {"ten_1", "con_2", "API_TOKEN"}, {"ten_1", "con_1", "OTHER"}} {
		if _, err := OpenConfigValue(w, c[0], c[1], c[2], blob); err == nil {
			t.Errorf("opened under %v", c)
		}
	}
	if IsConfigValueBlob("plain") {
		t.Error("plain text taken for a blob")
	}
	if _, err := OpenConfigValue(w, "ten_1", "con_1", "API_TOKEN", "zcv1.not-base64!"); err == nil {
		t.Error("opened garbage")
	}
}
