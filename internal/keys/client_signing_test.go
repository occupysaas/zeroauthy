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

	// Slice order does not decide: the newest CreatedAt wins.
	reversed := base
	reversed.Secrets = []store.ClientSecret{base.Secrets[1], base.Secrets[0]}
	if key, err := ClientSigningSecret(w, &reversed, at); err != nil || !bytes.Equal(key, []byte(newest)) {
		t.Fatal("selection depends on slice order")
	}

	// An expired newer secret is skipped in favour of the older active one.
	expired := at
	fallback := base
	fallback.Secrets = []store.ClientSecret{{Sealed: sealed, CreatedAt: at.Add(-time.Hour)}, {Sealed: current, CreatedAt: at, ExpiresAt: &expired}}
	if key, err := ClientSigningSecret(w, &fallback, at); err != nil || !bytes.Equal(key, []byte(old)) {
		t.Fatal("expired newest secret was used or active older secret ignored")
	}

	// A secret shorter than 32 bytes is never an HS256 key, even when newest.
	short, _ := SealClientSecret(w, "t", "c", secrets.RandomString(31))
	weak := base
	weak.Secrets = []store.ClientSecret{{Sealed: sealed, CreatedAt: at.Add(-time.Hour)}, {Sealed: short, CreatedAt: at}}
	if _, err := ClientSigningSecret(w, &weak, at); err == nil {
		t.Fatal("31-byte secret accepted as HS256 key")
	}
}
