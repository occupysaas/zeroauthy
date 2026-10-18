package sqlstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSplitStatements(t *testing.T) {
	got := splitStatements("-- c\nCREATE TABLE a (\n  x INT\n);\n\nCREATE INDEX i ON a (x);\n")
	if len(got) != 2 || got[0] != "CREATE TABLE a (\n  x INT\n)" || got[1] != "CREATE INDEX i ON a (x)" {
		t.Fatalf("%q", got)
	}
}

func TestMigrationSetsMatch(t *testing.T) {
	var base []int64
	for i, d := range []dialect{dSQLite, dPostgres, dMySQL} {
		ms, err := (&Store{d: d}).migrations()
		if err != nil {
			t.Fatal(err)
		}
		var vs []int64
		for _, m := range ms {
			vs = append(vs, m.version)
		}
		if i == 0 {
			base = vs
		} else if !reflect.DeepEqual(base, vs) {
			t.Errorf("%s migrations %v differ from sqlite %v", d.name, vs, base)
		}
	}
	if len(base) == 0 {
		t.Fatal("no migrations")
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
			if err := s.queryRow(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&n); err != nil || int64(n) != s.LatestVersion() {
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
// TestTrailingSpaceKeys: keys differing only by a trailing space are distinct
// on every dialect (MySQL needs a NO PAD collation for this).
func TestTrailingSpaceKeys(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			for _, id := range []string{"acme", "acme "} {
				_, err := s.exec(ctx, "INSERT INTO tenants (id, name, friendly_name, default_audience, allowed_logout_urls, enabled_locales, custom_text, session_lifetime, idle_session_lifetime, logo_url, primary_color, default_directory, created_at) VALUES (?, ?, '', '', '[]', '[]', '{}', 0, 0, '', '', '', 0)", id, id)
				if err != nil {
					t.Fatalf("insert %q: %v", id, err)
				}
			}
			var n int
			if err := s.queryRow(ctx, "SELECT COUNT(*) FROM tenants WHERE id = ?", "acme ").Scan(&n); err != nil || n != 1 {
				t.Fatalf("exact lookup matched %d rows (err %v)", n, err)
			}
		})
	}
}

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
			if err := ins("k4", "current"); !errors.Is(err, store.ErrConflict) {
				t.Fatal("second current key must violate the unique index")
			}
			if _, err := s.exec(ctx, "INSERT INTO tenant_domains (domain, tenant_id, position) VALUES ('d', 'missing', 0)"); err == nil {
				t.Fatal("tenant_domains must reference tenants")
			}
		})
	}
}

func TestLatestVersion(t *testing.T) {
	for _, d := range []dialect{dSQLite, dPostgres, dMySQL} {
		if v := (&Store{d: d}).LatestVersion(); v != 11 {
			t.Errorf("%s LatestVersion = %d, want 11", d.name, v)
		}
	}
}

// openAtVersion opens a fresh database and applies only the migrations up to
// version, through the same path Migrate uses.
func openAtVersion(t *testing.T, dsn string, version int64) *Store {
	t.Helper()
	s := mustOpenRaw(t, dsn)
	if err := s.migrateTo(context.Background(), version); err != nil {
		t.Fatal(err)
	}
	return s
}

func mustExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.exec(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func TestMigration0003Defaults(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 2)
			mustExec(t, s, `INSERT INTO clients (tenant_id, client_id, name, app_type, secrets, token_endpoint_auth_method,
 grant_types, callbacks, allowed_logout_urls, web_origins, allowed_origins, id_token_lifetime, refresh_token, created_at)
 VALUES ('t','c','n','spa','null','none','null','null','null','null','null',0,'null',0)`)
			mustExec(t, s, `INSERT INTO resource_servers (tenant_id, id, identifier, name, scopes, signing_alg, token_lifetime, allow_offline_access, created_at)
 VALUES ('t','rs','https://api','n','null','RS256',0,false,0)`)
			mustExec(t, s, `INSERT INTO client_grants (tenant_id, id, client_id, audience, scopes, created_at) VALUES ('t','g','c','https://api','null',0)`)
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			c, err := s.Clients().Get(ctx, "t", "c")
			if err != nil || !c.IsFirstParty || c.ThirdPartySecurityMode != "" || c.SkipNonVerifiableCallbackURIConfirmationPrompt != nil {
				t.Fatalf("client after migration: %+v %v", c, err)
			}
			rs, err := s.ResourceServers().Get(ctx, "t", "rs")
			if err != nil || !rs.SkipConsentForVerifiableFirstPartyClients || rs.SubjectTypeAuthorization != (store.SubjectTypeAuthorization{}) {
				t.Fatalf("resource server after migration: %+v %v", rs, err)
			}
			g, err := s.ClientGrants().Find(ctx, "t", "c", "https://api", store.SubjectTypeClient)
			if err != nil || g.SubjectType != store.SubjectTypeClient {
				t.Fatalf("grant after migration: %+v %v", g, err)
			}
		})
	}
}

func TestMigration0004Defaults(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 3)
			mustExec(t, s, `INSERT INTO tenants (id, name, friendly_name, default_audience, allowed_logout_urls, enabled_locales, custom_text,
 session_lifetime, idle_session_lifetime, logo_url, primary_color, default_directory, created_at,
 skip_non_verifiable_callback_uri_confirmation_prompt, use_scope_descriptions_for_consent)
 VALUES ('t','acme','Acme','','null','null','null',0,0,'','','',0,false,false)`)
			mustExec(t, s, `INSERT INTO clients (tenant_id, client_id, name, app_type, secrets, token_endpoint_auth_method,
 grant_types, callbacks, allowed_logout_urls, web_origins, allowed_origins, id_token_lifetime, refresh_token, created_at,
 is_first_party, third_party_security_mode, redirection_policy)
 VALUES ('t','c','n','spa','null','none','null','null','null','null','null',0,'null',0,true,'','')`)
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			tn, err := s.Tenants().Get(ctx, "t")
			if err != nil || tn.PushedAuthorizationRequestsSupported {
				t.Fatalf("tenant after migration: %+v %v", tn, err)
			}
			c, err := s.Clients().Get(ctx, "t", "c")
			if err != nil || c.RequirePushedAuthorizationRequests {
				t.Fatalf("client after migration: %+v %v", c, err)
			}
		})
	}
}
