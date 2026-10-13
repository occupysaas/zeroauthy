// Package storage opens a store.Store driver from a DSN.
package storage

import (
	"context"
	"fmt"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// Open returns the driver named by the DSN scheme. Only memory:// exists in
// this release. sqlite, postgres, mysql and plugin drivers come in later
// releases.
func Open(_ context.Context, dsn string) (store.Store, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		return nil, fmt.Errorf("storage: DSN %q has no scheme (e.g. memory://)", dsn)
	}
	switch u.Scheme {
	case "memory":
		return memory.New(), nil
	default:
		return nil, fmt.Errorf("storage: driver %q is not available in this build", u.Scheme)
	}
}
