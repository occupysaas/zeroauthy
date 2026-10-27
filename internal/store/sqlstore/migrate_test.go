package sqlstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
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
		if v := (&Store{d: d}).LatestVersion(); v != 22 {
			t.Errorf("%s LatestVersion = %d, want 22", d.name, v)
		}
	}
}

func TestMigration0019PreservesLegacyHostedData(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 18)
			tenant := &store.Tenant{ID: "legacy", Name: "legacy", Branding: store.Branding{LogoURL: "https://example.test/logo.svg", PrimaryColor: "#123456"}, CustomText: store.CustomText{"login": {"en": {"login": {"title": strings.Repeat("A", 1<<20)}}}}}
			args, err := tenantArgs(tenant)
			if err != nil {
				t.Fatal(err)
			}
			placeholders := strings.TrimSuffix(strings.Repeat("?,", len(args)-1), ",")
			if _, err := s.exec(ctx, "INSERT INTO tenants ("+strings.TrimSuffix(tenantCols, ", canonical_host")+") VALUES ("+placeholders+")", args[:len(args)-1]...); err != nil {
				t.Fatal(err)
			}
			mustExec(t, s, `INSERT INTO auth_transactions (tenant_id,id,cookie_hash,csrf_token,client_id,params,expires_at,created_at) VALUES ('legacy','flow','cookie','csrf','spa','{"scope":"openid"}',9999999999999999,1)`)
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			got, err := (hostedlogin.Service{Store: s}).Load(ctx, "legacy")
			if err != nil {
				t.Fatal(err)
			}
			if got.Branding["logo_url"] != "https://example.test/logo.svg" || len(got.CustomText["login"]["en"]["login"]["title"]) != 1<<20 {
				t.Fatal("legacy branding or oversized text lost")
			}
			tx, err := s.AuthTransactions().Get(ctx, "legacy", "flow")
			if err != nil {
				t.Fatal(err)
			}
			if tx.HostedState.Step != "" || tx.HostedState.Revision != 0 || tx.Params["scope"] != "openid" {
				t.Fatalf("in-flight transaction changed: %+v", tx)
			}
			got.Branding["logo_url"] = "https://example.test/new.svg"
			if err := s.HostedLogins().Put(ctx, got, got.Revision); err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			after, err := s.HostedLogins().Get(ctx, "legacy")
			if err != nil {
				t.Fatal(err)
			}
			if after.Branding["logo_url"] != "https://example.test/new.svg" {
				t.Fatal("migration overwrote API edit")
			}
		})
	}
}

func TestSigningMigration(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 16)
			mustExec(t, s, `INSERT INTO signing_keys (tenant_id, kid, alg, status, private_key, public_jwk, created_at) VALUES ('legacy','kid','RS256','current',?,?,123)`, []byte("sealed"), []byte(`{"kid":"kid"}`))
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			got, err := s.SigningKeys().Get(ctx, "legacy", "kid")
			if err != nil {
				t.Fatal(err)
			}
			if got.KID != "kid" || got.Status != store.KeyCurrent || got.CreatedAt.UnixMicro() != 123 || len(got.CertificateDER) != 0 || got.CurrentSince != nil || got.CurrentUntil != nil || got.RevokedAt != nil {
				t.Fatalf("legacy signing record changed: %+v", got)
			}
			if _, err := s.CustomSigningKeys().Get(ctx, "legacy"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("custom set should begin absent: %v", err)
			}
		})
	}
}

// A dialect with no embedded migrations is a build defect: LatestVersion
// panics rather than reporting a wrong version.
func TestLatestVersionPanicsWithoutMigrations(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("LatestVersion did not panic")
		}
	}()
	(&Store{d: dialect{name: "nope"}}).LatestVersion()
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

// Migration 0013 turns the two password policy columns into
// password_options as store.LegacyComplexity maps them, keeps the login
// throttle on, and leaves the new settings at their zero values.
func TestMigration0013ConvertsPasswordPolicy(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 12)
			type row struct{ minLength, classes int }
			rows := map[string]row{"c0": {0, 0}, "c1": {10, 1}, "c2": {6, 2}, "c3": {12, 3}, "c4": {8, 4}}
			for id, r := range rows {
				mustExec(t, s, `INSERT INTO connections (tenant_id, id, name, strategy, enabled_clients, disable_signup, requires_username,
 password_min_length, password_character_classes, created_at) VALUES ('t', ?, ?, 'auth0', '["spa"]', false, false, ?, ?, 0)`,
					id, id, r.minLength, r.classes)
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			for id, r := range rows {
				c, err := s.Connections().Get(ctx, "t", id)
				if err != nil {
					t.Fatal(err)
				}
				want := store.PasswordOptions{Complexity: store.LegacyComplexity(r.minLength, r.classes)}
				if !reflect.DeepEqual(c.PasswordOptions, want) {
					t.Errorf("%s: PasswordOptions = %+v, want %+v", id, c.PasswordOptions, want)
				}
				if !c.BruteForceProtection || c.UsernameMin != 0 || c.UsernameMax != 0 || c.Origin != "" || c.Extra != nil ||
					!reflect.DeepEqual(c.EnabledClients, []string{"spa"}) {
					t.Errorf("%s: unexpected settings %+v", id, c)
				}
			}
		})
	}
}

func TestMigration0016PreservesData(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 15)
			tenant := &store.Tenant{ID: "legacy", Name: "legacy", FriendlyName: "Existing", SessionLifetime: 3600}
			args, err := tenantArgs(tenant)
			if err != nil {
				t.Fatal(err)
			}
			oldCols := strings.Join(strings.Split(tenantCols, ",")[:21], ",")
			mustExec(t, s, `INSERT INTO tenants (`+oldCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args[:21]...)
			user := &store.User{TenantID: "legacy", UserID: "auth0|existing", Email: "old@example.test"}
			if err := s.Users().Create(ctx, user); err != nil {
				t.Fatal(err)
			}
			job := &store.Job{TenantID: "legacy", ID: "job", Type: store.JobType("users_import"), Status: store.JobStatus("pending"), Input: []byte("preserved input")}
			if err := s.Jobs().Create(ctx, job); err != nil {
				t.Fatal(err)
			}
			mustExec(t, s, `INSERT INTO sessions (tenant_id,id,token_hash,user_id,connection,authenticated_at,client_ids,expires_at,idle_expires_at,created_at,updated_at,last_interacted_at,initial_ip,initial_user_agent,last_ip,last_user_agent) VALUES ('legacy','session','hash','auth0|existing','Database',0,'["spa"]',999,888,0,0,0,'','','','')`)
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			got, err := s.Tenants().Get(ctx, "legacy")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tenant) {
				t.Fatalf("tenant changed: %#v", got)
			}
			gotUser, err := s.Users().Get(ctx, "legacy", user.UserID)
			if err != nil || !reflect.DeepEqual(gotUser, user) {
				t.Fatalf("user changed: %v", err)
			}
			gotJob, err := s.Jobs().Get(ctx, "legacy", "job")
			if err != nil || !reflect.DeepEqual(gotJob, job) {
				t.Fatalf("job changed: %v", err)
			}
			session, err := s.Sessions().Get(ctx, "legacy", "session")
			if err != nil || session.CookieMode != "" || session.TokenHash != "hash" || micros(session.ExpiresAt) != 999 || len(session.ClientIDs) != 1 {
				t.Fatalf("session changed: %v", err)
			}
			for _, table := range []string{"protection_buckets", "protection_receipts", "protection_reservations", "protection_proofs", "protection_risk_events"} {
				var n int
				if err := s.queryRow(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil || n != 0 {
					t.Fatalf("table %s: %v", table, err)
				}
			}
		})
	}
}
