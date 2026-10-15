package sqlstore

import (
	"database/sql"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type scanner interface{ Scan(...any) error }

// expectRow maps "no row affected" to store.ErrNotFound.
func expectRow(res sql.Result) error {
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}
