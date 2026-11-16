package store_test

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type unimplementedCredentials struct{ store.Store }

func (unimplementedCredentials) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}

type supporterStore struct {
	store.Store
	err error
	ok  bool
}

func (s supporterStore) CheckClientCredentialsSupport(context.Context) error { return s.err }
func (s supporterStore) ClientCredentialsSupported() bool                    { return s.ok }

func TestClientCredentialsAvailable(t *testing.T) {
	ctx := context.Background()
	m := memory.New()
	for name, tc := range map[string]struct {
		s    store.Store
		want bool
	}{
		"built-in":              {m, true},
		"unimplemented":         {unimplementedCredentials{m}, false},
		"supporter yes":         {supporterStore{m, nil, true}, true},
		"supporter not latched": {supporterStore{m, nil, false}, false},
		"supporter check fails": {supporterStore{m, store.ErrClientCredentialsUnavailable, true}, false},
	} {
		if got := store.ClientCredentialsAvailable(ctx, tc.s); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}
