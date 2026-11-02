package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

type mfaFaultConnector struct {
	driver   driver.Driver
	dsn      string
	deletes  atomic.Int32
	injected atomic.Bool
}

func (c *mfaFaultConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.driver.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &mfaFaultConn{Conn: conn, c: c}, nil
}
func (c *mfaFaultConnector) Driver() driver.Driver { return c.driver }

type mfaFaultConn struct {
	driver.Conn
	c *mfaFaultConnector
}

func (c *mfaFaultConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *mfaFaultConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *mfaFaultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(q, "DELETE FROM mfa_tokens") && c.c.deletes.Add(1) == 2 && c.c.injected.CompareAndSwap(false, true) {
		return nil, &mysql.MySQLError{Number: 1213, Message: "injected deadlock"}
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func TestMFAPurgeRetriesRollbackCount(t *testing.T) {
	ctx := context.Background()
	dsn := dsnsUnderTest(t)["sqlite"](t)
	s := mustOpen(t, dsn)
	for _, h := range []string{"a", "b"} {
		_, err := s.exec(ctx, `INSERT INTO mfa_tokens (tenant_id,hash,user_id,client_id,data,expires_at) VALUES (?,?,?,?,?,?)`, "t", h, "u", "", "{}", 1)
		mustEvent(t, err)
	}
	_, native, err := parseDSN(dsn)
	mustEvent(t, err)
	c := &mfaFaultConnector{driver: s.db.Driver(), dsn: native}
	db := sql.OpenDB(c)
	t.Cleanup(func() { db.Close() })
	fault := &Store{db: db, q: db, d: s.d}
	n, err := fault.MFA().PurgeMFA(ctx, time.Unix(100, 0), 2)
	mustEvent(t, err)
	var left int
	mustEvent(t, s.queryRow(ctx, `SELECT COUNT(*) FROM mfa_tokens`).Scan(&left))
	if !c.injected.Load() || n != 2 || left != 0 {
		t.Fatalf("injected=%v count=%d remaining=%d", c.injected.Load(), n, left)
	}
}
