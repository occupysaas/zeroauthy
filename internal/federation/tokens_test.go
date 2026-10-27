package federation

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestFederatedToken(t *testing.T) {
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	k := store.FederatedIdentityKey{TenantID: "t1", ConnectionID: "c", Subject: "s"}
	in := TokenSet{AccessToken: "secret-access", RefreshToken: "secret-refresh", TokenType: "Bearer", Scope: "openid", ExpiresAt: fixedTime.Add(time.Hour), IDToken: "dropped"}
	sealed, err := SealTokens(w, k, in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret-access")) || bytes.Contains(sealed, []byte("secret-refresh")) {
		t.Fatal("token stored in plaintext")
	}
	got, err := OpenTokens(w, k, sealed)
	if err != nil || got.AccessToken != in.AccessToken || got.RefreshToken != in.RefreshToken || !got.ExpiresAt.Equal(in.ExpiresAt) || got.IDToken != "" {
		t.Fatalf("%+v %v", got, err)
	}
	for _, other := range []store.FederatedIdentityKey{{TenantID: "t2", ConnectionID: "c", Subject: "s"}, {TenantID: "t1", ConnectionID: "c2", Subject: "s"}, {TenantID: "t1", ConnectionID: "c", Subject: "S"}} {
		if _, err := OpenTokens(w, other, sealed); err == nil {
			t.Fatalf("opened under %+v", other)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("error leaks token")
		}
	}
	if _, err := SealTokens(w, k, TokenSet{}); err == nil {
		t.Fatal("sealed an empty token set")
	}
}
