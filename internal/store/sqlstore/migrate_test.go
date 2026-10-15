package sqlstore

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestSplitStatements(t *testing.T) {
	got := splitStatements("-- c\nCREATE TABLE a (\n  x INT\n);\n\nCREATE INDEX i ON a (x);\n")
	if len(got) != 2 || got[0] != "CREATE TABLE a (\n  x INT\n)" || got[1] != "CREATE INDEX i ON a (x)" {
		t.Fatalf("%q", got)
	}
}

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			dsn := mk(t)
			s := mustOpenRaw(t, dsn)
			if v, err := s.SchemaVersion(ctx); err != nil || v != 0 {
				t.Fatalf("empty database: version %d err %v", v, err)
			}
			err := s.CheckSchema(ctx)
			if err == nil || !strings.Contains(err.Error(), "run zeroauthy migrate") {
				t.Fatalf("unmigrated CheckSchema: %v", err)
			}
			for i := 0; i < 2; i++ { // second run is a no-op
				if err := s.Migrate(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if v, err := s.SchemaVersion(ctx); err != nil || v != s.LatestVersion() || v == 0 {
				t.Fatalf("after Migrate: version %d latest %d err %v", v, s.LatestVersion(), err)
			}
			if err := s.CheckSchema(ctx); err != nil {
				t.Fatal(err)
			}
			var n int
			if err := s.queryRow(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&n); err != nil || n != 1 {
				t.Fatalf("schema_migrations rows: %d %v", n, err)
			}

			// Database ahead of the binary.
			if _, err := s.exec(ctx, "INSERT INTO schema_migrations (version, applied_at) VALUES (?, 0)", s.LatestVersion()+1); err != nil {
				t.Fatal(err)
			}
			if err := s.CheckSchema(ctx); err == nil || !strings.Contains(err.Error(), "newer than this binary") {
				t.Fatalf("CheckSchema ahead: %v", err)
			}
			if err := s.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "newer than this binary") {
				t.Fatalf("Migrate ahead: %v", err)
			}
		})
	}
}

func TestMigrateConcurrent(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		if name == "sqlite" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			dsn := mk(t)
			var wg sync.WaitGroup
			errs := make(chan error, 10)
			for i := 0; i < 10; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					s, err := Open(ctx, dsn)
					if err != nil {
						errs <- err
						return
					}
					defer s.Close()
					errs <- s.Migrate(ctx)
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Error(err)
				}
			}
			s := mustOpenRaw(t, dsn)
			if err := s.CheckSchema(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestSchemaTables checks the full DDL applies and that the signing-key
// current/next invariant is enforced by the database.
func TestSchemaConstraints(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ins := func(kid, status string) error {
				_, err := s.exec(ctx, "INSERT INTO signing_keys (tenant_id, kid, alg, status, private_key, public_jwk, created_at) VALUES ('t', ?, 'RS256', ?, ?, ?, 0)", kid, status, []byte{1}, []byte{2})
				return s.conflict(err)
			}
			if err := ins("k1", "current"); err != nil {
				t.Fatal(err)
			}
			if err := ins("k2", "retired"); err != nil {
				t.Fatal(err)
			}
			if err := ins("k3", "retired"); err != nil {
				t.Fatal(err)
			}
			if err := ins("k4", "current"); err == nil {
				t.Fatal("second current key must violate the unique index")
			}
			if _, err := s.exec(ctx, "INSERT INTO tenant_domains (domain, tenant_id, position) VALUES ('d', 'missing', 0)"); err == nil {
				t.Fatal("tenant_domains must reference tenants")
			}
		})
	}
}
