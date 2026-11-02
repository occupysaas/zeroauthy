package mfa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSealTOTPSecretBinding(t *testing.T) {
	w, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	sealed, err := SealTOTPSecret(w, "tenant", "user", "totp|dev_method", secret)
	if err != nil || len(sealed) == 0 || bytes.Contains(sealed, []byte(secret)) {
		t.Fatal("TOTP secret not sealed")
	}
	plain, err := w.Unwrap(sealed, []byte(`["mfa-totp","tenant","user","totp|dev_method"]`))
	if err != nil || string(plain) != secret {
		t.Fatal("canonical binding does not open")
	}
	for _, aad := range []string{`["mfa-totp","other","user","totp|dev_method"]`, `["mfa-totp","tenant","other","totp|dev_method"]`, `["mfa-totp","tenant","user","totp|dev_other"]`} {
		if _, err = w.Unwrap(sealed, []byte(aad)); err == nil {
			t.Fatal("different binding opened")
		}
	}
	for _, bad := range []string{"", "NOT_BASE32!"} {
		if _, err = SealTOTPSecret(w, "tenant", "user", "method", bad); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("invalid secret error=%v", err)
		}
	}
	if _, err = SealTOTPSecret(nil, "tenant", "user", "method", secret); err == nil {
		t.Fatal("missing master-key wrapper accepted")
	}
}
