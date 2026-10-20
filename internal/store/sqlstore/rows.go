package sqlstore

import (
	"database/sql"
	"math"
	"strconv"

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

// pageClause is the LIMIT and OFFSET of p. The numbers are integers built
// here, never caller text. SQLite and MySQL want a LIMIT with an OFFSET, so
// "no limit" is the largest BIGINT.
func pageClause(p store.Page) string {
	limit, offset := int64(p.Limit), int64(max(p.Offset, 0))
	if limit <= 0 {
		limit = math.MaxInt64
	}
	return ` LIMIT ` + strconv.FormatInt(limit, 10) + ` OFFSET ` + strconv.FormatInt(offset, 10)
}
