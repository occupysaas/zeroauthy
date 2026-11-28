package actions

import (
	"bytes"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"testing"
	"time"
)

func TestCompletionEffectsConsentOnly(t *testing.T) {
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	at := time.Now().UTC()
	want := &Effects{Session: &SessionEffects{ExpiresAt: &at, CookieMode: "non-persistent", Metadata: []MetadataOp{{Op: "set", Key: "k", Value: "v"}}}, PrimaryUserID: "auth0|primary", RecordedMethods: []string{"https://factor.test/"}}
	for _, purpose := range []string{SealConsent, SealCode, SealDevice} {
		b, err := SealEffects(w, "t", purpose, want, "binding")
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenEffects(w, "t", purpose, b, "binding")
		if err != nil {
			t.Fatal(err)
		}
		if purpose == SealConsent {
			if got.Session == nil || got.PrimaryUserID != want.PrimaryUserID || len(got.RecordedMethods) != 1 {
				t.Fatalf("completion effects lost: %+v", got)
			}
		} else if got.Session != nil || got.PrimaryUserID != "" || len(got.RecordedMethods) != 0 {
			t.Fatalf("completion effects escaped into %s", purpose)
		}
	}
}
