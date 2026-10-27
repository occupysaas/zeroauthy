package sqlstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// insertLegacyConnection writes a connection row as schema version 20 knew it.
func insertLegacyConnection(t *testing.T, s *Store, c *store.Connection) {
	t.Helper()
	args, err := connectionArgs(c)
	if err != nil {
		t.Fatal(err)
	}
	cols := strings.TrimSuffix(connectionCols, ", federation_revision, federation_secrets_sealed")
	args = args[:len(args)-2]
	mustExec(t, s, "INSERT INTO connections ("+cols+") VALUES ("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
}

func insertLegacyUser(t *testing.T, s *Store, u *store.User) {
	t.Helper()
	args, err := userArgs(u)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, s, "INSERT INTO users ("+userCols+") VALUES ("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
}

func legacyFixture(t *testing.T, s *Store) {
	t.Helper()
	insertLegacyConnection(t, s, &store.Connection{TenantID: "t", ID: "con_g", Name: "google", Strategy: "google-oauth2"})
	insertLegacyConnection(t, s, &store.Connection{TenantID: "t", ID: "con_o", Name: "prov", Strategy: "oauth2"})
	insertLegacyConnection(t, s, &store.Connection{TenantID: "t", ID: "con_db", Name: "Database", Strategy: "auth0"})
	insertLegacyUser(t, s, &store.User{TenantID: "t", UserID: "google-oauth2|Imported",
		Identities: []store.Identity{{Connection: "google", Provider: "google-oauth2", UserID: "Imported"}}})
	insertLegacyUser(t, s, &store.User{TenantID: "t", UserID: "auth0|primary", Email: "p@example.test",
		Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "primary"},
			{Connection: "prov", Provider: "oauth2", UserID: "prov|linked|part", ProfileData: map[string]any{"email": "l@example.test"}}}})
	mustExec(t, s, `INSERT INTO user_logins (tenant_id, connection, kind, value, user_id) VALUES ('t','Database','email','p@example.test','auth0|primary')`)
	mustExec(t, s, `INSERT INTO user_logins (tenant_id, connection, kind, value, user_id) VALUES ('t','prov','email','l@example.test','auth0|primary')`)
}

func TestMigration0021BackfillsFederatedIdentities(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 20)
			legacyFixture(t, s)
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct{ conn, sub, owner string }{
				{"con_g", "Imported", "google-oauth2|Imported"}, {"con_o", "linked|part", "auth0|primary"},
			} {
				u, err := s.Users().FindByIdentity(ctx, "t", c.conn, c.sub)
				if err != nil || u.UserID != c.owner {
					t.Fatalf("%s/%s: %v %v", c.conn, c.sub, u, err)
				}
			}
			// The database login of the primary survives; the linked
			// federated email is no login.
			if _, err := s.Users().FindByLogin(ctx, "t", "Database", "p@example.test"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Users().FindByLogin(ctx, "t", "prov", "l@example.test"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("stale federated login kept: %v", err)
			}
			c, err := s.Connections().Get(ctx, "t", "con_g")
			if err != nil || c.FederationRevision != 0 || c.FederationSecretsSealed != nil {
				t.Fatalf("defaults %v %v", c, err)
			}
		})
	}
}

func TestMigration0021StopsOnAmbiguousIdentities(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		for _, tc := range []struct {
			name string
			bad  *store.User
			want string
		}{
			{"duplicate owner", &store.User{TenantID: "t", UserID: "auth0|thief", Identities: []store.Identity{
				{Connection: "Database", Provider: "auth0", UserID: "thief"},
				{Connection: "google", Provider: "google-oauth2", UserID: "Imported", ProfileData: map[string]any{}}}}, "auth0|thief"},
			{"unresolved connection", &store.User{TenantID: "t", UserID: "oidc|gone|x", Identities: []store.Identity{
				{Connection: "gone", Provider: "oidc", UserID: "gone|x"}}}, "oidc|gone|x"},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				s := openAtVersion(t, mk(t), 20)
				legacyFixture(t, s)
				insertLegacyUser(t, s, tc.bad)
				err := s.Migrate(ctx)
				if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "operator correction") {
					t.Fatalf("migrate error %v", err)
				}
				if v, _ := s.SchemaVersion(ctx); v != 20 {
					t.Fatalf("schema version %d after failed backfill", v)
				}
			})
		}
	}
}

// Two handles on one database stand in for two replicas: the SQL row and
// unique constraints, not process locks, decide the winners.
func TestFederationIndependentHandles(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			dsn := mk(t)
			a := mustOpen(t, dsn)
			b := mustOpen(t, dsn)
			if err := a.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			if err := a.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "con_g", Name: "google", Strategy: "google-oauth2"}); err != nil {
				t.Fatal(err)
			}
			handles := []*Store{a, b}
			const n = 6
			errs := make(chan error, n)
			for i := range n {
				go func() {
					errs <- handles[i%2].Users().Create(ctx, &store.User{TenantID: "t", UserID: "google-oauth2|race",
						Identities: []store.Identity{{Connection: "google", Provider: "google-oauth2", UserID: "race"}}})
				}()
			}
			won := 0
			for range n {
				if err := <-errs; err == nil {
					won++
				} else if !errors.Is(err, store.ErrConflict) {
					t.Fatalf("provision error %v", err)
				}
			}
			if won != 1 {
				t.Fatalf("%d users provisioned", won)
			}

			exp := time.Now().Add(time.Minute)
			if err := a.Federation().CreateAttempt(ctx, &store.FederationAttempt{StateHash: "s", TenantID: "t", TransactionID: "tx",
				ConnectionID: "con_g", CookieHash: "c", Origin: "o", ExpiresAt: exp, CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			for i := range n {
				go func() {
					_, err := handles[i%2].Federation().ClaimAttempt(ctx, "t", "s", "c", "o", time.Now())
					errs <- err
				}()
			}
			won = 0
			for range n {
				if err := <-errs; err == nil {
					won++
				} else if !errors.Is(err, store.ErrAlreadyUsed) {
					t.Fatalf("claim error %v", err)
				}
			}
			if won != 1 {
				t.Fatalf("%d claims won", won)
			}
		})
	}
}

func TestMicrosoftIdentityMigration0021LeavesMixedLegacyRowsUntouched(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 20)
			legacyFixture(t, s)
			// Unknown, legacy Microsoft encoding beside a valid Plan 24 identity
			// must be handled by application preflight after migration, never backfilled.
			insertLegacyUser(t, s, &store.User{TenantID: "t", UserID: "auth0|mixed", Identities: []store.Identity{
				{Connection: "Database", Provider: "auth0", UserID: "mixed"},
				{Connection: "google", Provider: "google-oauth2", UserID: "mixed-google", ProfileData: map[string]any{}},
				{Connection: "unknown-ms", Provider: "windowslive", UserID: "legacy-ms", ProfileData: map[string]any{}},
			}})
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			u, err := s.Users().FindByIdentity(ctx, "t", "con_g", "mixed-google")
			if err != nil || u.UserID != "auth0|mixed" || len(u.Identities) != 3 {
				t.Fatalf("mixed user %+v %v", u, err)
			}
			var n int
			if err := s.queryRow(ctx, `SELECT COUNT(*) FROM federated_identities WHERE tenant_id=? AND subject=?`, "t", []byte("legacy-ms")).Scan(&n); err != nil || n != 0 {
				t.Fatalf("Microsoft backfilled %d %v", n, err)
			}
		})
	}
}

func TestMicrosoftIdentityIndependentHandles(t *testing.T) {
	ctx := context.Background()
	const oid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const tid = "11111111-2222-3333-4444-555555555555"
	for name, mk := range dsnsUnderTest(t) {
		for _, tc := range []struct {
			name, provider, sub, id string
			extra                   map[string]any
		}{
			{"personal", "windowslive", "CaseSensitive", "CaseSensitive", nil},
			{"single", "waad", oid, "provider|" + oid, map[string]any{"tenant_domain": tid}},
			{"multi", "waad", tid + ":" + oid, "provider|" + tid + ":" + oid, map[string]any{"useCommonEndpoint": true}},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				dsn := mk(t)
				a := mustOpen(t, dsn)
				b := mustOpen(t, dsn)
				if err := a.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
					t.Fatal(err)
				}
				if err := a.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "ms", Name: "provider", Strategy: tc.provider, Extra: tc.extra}); err != nil {
					t.Fatal(err)
				}
				handles := []*Store{a, b}
				outcomes := make(chan error, 6)
				for i := range 6 {
					go func() {
						outcomes <- handles[i%2].Users().Create(ctx, &store.User{TenantID: "t", UserID: store.FederatedPublicID(tc.provider, "provider", tc.sub), Email: "same@x.test", Identities: []store.Identity{{Connection: "provider", Provider: tc.provider, UserID: tc.id}}})
					}()
				}
				won := 0
				for range 6 {
					if err := <-outcomes; err == nil {
						won++
					} else if !errors.Is(err, store.ErrConflict) {
						t.Fatal(err)
					}
				}
				if won != 1 {
					t.Fatalf("%d provisioned", won)
				}
				u, err := b.Users().FindByIdentity(ctx, "t", "ms", tc.sub)
				if err != nil || u.UserID != store.FederatedPublicID(tc.provider, "provider", tc.sub) {
					t.Fatalf("owner %+v %v", u, err)
				}
			})
		}
	}
}
