package phone

import (
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSenderFor(t *testing.T) {
	id := func(b []byte) ([]byte, error) { return b, nil }
	for _, p := range []store.PhoneProvider{
		{Name: "twilio", Configuration: []byte(`{"sid":"AC1","default_from":"+1555"}`), SealedCredentials: []byte(`{"auth_token":"t"}`)},
		{Name: "sns", Configuration: []byte(`{"region":"us-east-1"}`), SealedCredentials: []byte(`{"access_key_id":"a","secret_access_key":"s"}`)},
	} {
		if s, err := SenderFor(p, id, nil); err != nil || s == nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
	}
	if _, err := SenderFor(store.PhoneProvider{Name: "custom"}, id, nil); !errors.Is(err, ErrActionProvider) {
		t.Fatalf("custom: %v", err)
	}
	bad := func([]byte) ([]byte, error) { return nil, errors.New("secret-bearing detail") }
	_, err := SenderFor(store.PhoneProvider{Name: "twilio", Configuration: []byte(`{}`)}, bad, nil)
	if err == nil || err.Error() == "secret-bearing detail" {
		t.Fatalf("unseal error leaked or missing: %v", err)
	}
}
