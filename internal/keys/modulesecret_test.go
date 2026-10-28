package keys

import (
	"bytes"
	"testing"
)

func TestModuleSecretBound(t *testing.T) {
	w, err := NewLocalWrapper(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealModuleSecret(w, "t1", "same-id", "KEY", "module-value")
	if err != nil || bytes.Contains(sealed, []byte("module-value")) {
		t.Fatalf("seal: %v", err)
	}
	if got, err := OpenModuleSecret(w, "t1", "same-id", "KEY", sealed); err != nil || got != "module-value" {
		t.Fatalf("open: %q %v", got, err)
	}
	for _, binding := range [][3]string{{"t2", "same-id", "KEY"}, {"t1", "other-id", "KEY"}, {"t1", "same-id", "OTHER"}} {
		if _, err := OpenModuleSecret(w, binding[0], binding[1], binding[2], sealed); err == nil {
			t.Fatalf("opened under %v", binding)
		}
	}
	if _, err := OpenActionSecret(w, "t1", "same-id", "KEY", sealed); err == nil {
		t.Fatal("module secret opened in Action domain")
	}
	a, err := SealActionSecret(w, "t1", "same-id", "KEY", "action-value")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenModuleSecret(w, "t1", "same-id", "KEY", a); err == nil {
		t.Fatal("Action secret opened in Module domain")
	}
	if _, err := SealModuleSecret(nil, "t1", "m", "KEY", "value"); err == nil {
		t.Fatal("sealed without wrapper")
	}
	if _, err := OpenModuleSecret(nil, "t1", "m", "KEY", sealed); err == nil {
		t.Fatal("opened without wrapper")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenModuleSecret(w, "t1", "same-id", "KEY", sealed); err == nil {
		t.Fatal("tampered secret opened")
	}
}
