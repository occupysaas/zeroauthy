package seed

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type oldMicrosoftStore struct{ store.Store }

func (s oldMicrosoftStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(oldMicrosoftStore{tx}) })
}
func TestMicrosoftSeedCapability(t *testing.T) {
	for _, strategy := range []string{"windowslive", "google-oauth2"} {
		t.Run(strategy, func(t *testing.T) {
			st := memory.New()
			defer st.Close()
			f, err := Parse([]byte("tenants:\n - name: acme\n   connections:\n    - name: provider\n      strategy: " + strategy + "\n      options: {client_id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, client_secret: secret}\n"))
			if err != nil {
				t.Fatal(err)
			}
			err = Apply(context.Background(), oldMicrosoftStore{st}, f, fixedNow, testWrapper(t))
			if strategy == "windowslive" {
				if err == nil {
					t.Fatal("Microsoft seed accepted old plugin")
				}
				if strings.Contains(err.Error(), "secret") {
					t.Fatal("secret in failure")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
