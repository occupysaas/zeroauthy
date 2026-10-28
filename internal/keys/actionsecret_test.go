package keys

import (
	"bytes"
	"testing"
)

func TestActionSecretBound(t *testing.T) {
	w, err := NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealActionSecret(w, "t1", "act_1", "KEY", "value")
	if err != nil || bytes.Contains(sealed, []byte("value")) {
		t.Fatalf("%v", err)
	}
	if v, err := OpenActionSecret(w, "t1", "act_1", "KEY", sealed); err != nil || v != "value" {
		t.Fatalf("%q %v", v, err)
	}
	for _, b := range [][3]string{{"t2", "act_1", "KEY"}, {"t1", "act_2", "KEY"}, {"t1", "act_1", "OTHER"}} {
		if _, err := OpenActionSecret(w, b[0], b[1], b[2], sealed); err == nil {
			t.Fatalf("opened under %v", b)
		}
	}
	if _, err := SealActionSecret(nil, "t1", "a", "k", "v"); err == nil {
		t.Fatal("sealed without a wrapper")
	}
}
