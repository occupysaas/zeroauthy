// Package storage opens a store.Store driver from a DSN.
package storage

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

// Open returns the driver named by the DSN scheme: memory://, sqlite://,
// postgres:// (or postgresql://), mysql://. plugin:// comes with the gRPC
// plugin host.
func Open(ctx context.Context, dsn string) (store.Store, error) {
	// Errors never quote the DSN: it may carry a password. A *url.Error
	// embeds the whole URL, so it is not wrapped either.
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, errors.New("storage: DSN is not a valid URL; check the host, the port and the percent-encoding of the user name and password")
	}
	if u.Scheme == "" {
		return nil, errors.New("storage: DSN has no scheme (e.g. memory://, sqlite:///path.db)")
	}
	switch u.Scheme {
	case "memory":
		return memory.New(), nil
	case "sqlite", "postgres", "postgresql", "mysql":
		return sqlstore.Open(ctx, dsn)
	default:
		return nil, fmt.Errorf("storage: driver %q is not available in this build", u.Scheme)
	}
}

// Migrator is implemented by drivers with a schema (the SQL drivers).
type Migrator interface {
	Migrate(ctx context.Context) error
	CheckSchema(ctx context.Context) error
}
