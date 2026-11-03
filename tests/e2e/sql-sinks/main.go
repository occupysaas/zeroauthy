// sql-sinks snapshots every persisted privacy sink using the selected E2E DSN.
// It deliberately has no mutation path and does not dump users/provider secrets.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
	"net"
	"net/url"
	"os"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "SQL sink dump failed:", err)
		os.Exit(1)
	}
}
func run() error {
	dsn := os.Getenv("E2E_M34_DSN")
	scheme, rest, _ := strings.Cut(dsn, "://")
	driver, native := scheme, dsn
	switch scheme {
	case "sqlite":
		native = rest
	case "postgres", "postgresql":
		driver = "pgx"
	case "mysql":
		u, e := url.Parse(dsn)
		if e != nil {
			return fmt.Errorf("invalid mysql DSN")
		}
		c := mysql.NewConfig()
		c.User = u.User.Username()
		c.Passwd, _ = u.User.Password()
		c.Net = "tcp"
		port := u.Port()
		if port == "" {
			port = "3306"
		}
		c.Addr = net.JoinHostPort(u.Hostname(), port)
		c.DBName = strings.TrimPrefix(u.Path, "/")
		native = c.FormatDSN()
	default:
		return fmt.Errorf("unsupported SQL backend")
	}
	db, e := sql.Open(driver, native)
	if e != nil {
		return e
	}
	defer db.Close()
	enc := json.NewEncoder(os.Stdout)
	for _, table := range []string{"tenant_logs", "action_executions", "tenant_events", "event_deliveries"} {
		rows, e := db.Query("SELECT * FROM " + table)
		if e != nil {
			return e
		}
		cols, e := rows.Columns()
		if e != nil {
			return e
		}
		n := 0
		for rows.Next() {
			v := make([]any, len(cols))
			ptr := make([]any, len(cols))
			for i := range v {
				ptr[i] = &v[i]
			}
			if e = rows.Scan(ptr...); e != nil {
				return e
			}
			m := map[string]any{}
			for i, k := range cols {
				if b, ok := v[i].([]byte); ok {
					m[k] = string(b)
				} else {
					m[k] = v[i]
				}
			}
			if e = enc.Encode(map[string]any{"table": table, "value": m}); e != nil {
				return e
			}
			n++
		}
		if e = rows.Err(); e != nil {
			return e
		}
		rows.Close()
		if n == 0 {
			return fmt.Errorf("%s unexpectedly empty", table)
		}
	}
	return nil
}
