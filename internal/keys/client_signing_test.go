package keys

import (
	"bytes"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
	"time"
)

func TestClientSigningSecret(t *testing.T) {
	w, _ := NewLocalWrapper([]byte(secrets.RandomString(32)))
	at := time.Now().UTC()
	old, newest := secrets.RandomString(48), secrets.RandomString(48)
	sealed, _ := SealClientSecret(w, "t", "c", old)
	current, _ := SealClientSecret(w, "t", "c", newest)
	base := store.Client{TenantID: "t", ClientID: "c", AppType: store.AppTypeRegularWeb, TokenEndpointAuthMethod: store.AuthMethodClientSecretPost, Secrets: []store.ClientSecret{{Sealed: sealed, CreatedAt: at.Add(-time.Hour)}, {Sealed: current, CreatedAt: at}}}
	key, err := ClientSigningSecret(w, &base, at)
	if err != nil || !bytes.Equal(key, []byte(newest)) {
		t.Fatal("newest active secret not selected")
	}
	for _, mutate := range []func(*store.Client){
		func(c *store.Client) { c.TokenEndpointAuthMethod = store.AuthMethodNone },
		func(c *store.Client) { c.TokenEndpointAuthMethod = ""; c.PrivateKeyJWTCredentials = []string{"key"} },
		func(c *store.Client) { c.AppType = store.AppTypeSPA },
		func(c *store.Client) { c.Secrets = []store.ClientSecret{{Hash: "legacy"}} },
		func(c *store.Client) { c.TenantID = "other" },
		func(c *store.Client) {
			expires := at
			c.Secrets = []store.ClientSecret{{Sealed: current, ExpiresAt: &expires}}
		},
	} {
		c := base
		mutate(&c)
		if _, err := ClientSigningSecret(w, &c, at); err == nil {
			t.Fatal("unusable client secret accepted")
		}
	}
}
