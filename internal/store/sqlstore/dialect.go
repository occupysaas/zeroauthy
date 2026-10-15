package sqlstore

import (
	"errors"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type dialect struct {
	name      string // "sqlite", "postgres", "mysql"
	driver    string // database/sql driver name
	numbered  bool   // $1-style placeholders
	forUpdate string // row-lock suffix for SELECT inside a transaction
}

var (
	dSQLite   = dialect{name: "sqlite", driver: "sqlite"}
	dPostgres = dialect{name: "postgres", driver: "pgx", numbered: true, forUpdate: " FOR UPDATE"}
	dMySQL    = dialect{name: "mysql", driver: "mysql", forUpdate: " FOR UPDATE"}
)

// rebind turns ? placeholders into $1, $2, … for PostgreSQL. Queries in this
// package never contain a literal '?'.
func (d dialect) rebind(q string) string {
	if !d.numbered {
		return q
	}
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isUniqueViolation reports whether err is a unique/primary-key violation.
func (d dialect) isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23505"
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1062
	}
	var sq *sqlite.Error
	if errors.As(err, &sq) {
		c := sq.Code()
		return c == sqlite3.SQLITE_CONSTRAINT_UNIQUE || c == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	}
	return false
}
