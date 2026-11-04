package sqlstore

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/logsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestUpgradeFromOldestSchema is the 1.0 release gate "migrations tested from
// the oldest supported schema": a database created at schema version 1 and
// filled with rows as the version 1 code wrote them (raw SQL, JSON in the
// shapes that code encoded) is migrated one version at a time to the latest,
// and every row reads back through the current store API. Rows are seeded
// again at version 28 for the log search backfill of migration 29, the only
// transforming migration whose table did not exist at version 1. The fresh
// database to latest check is TestMigrate.
func TestUpgradeFromOldestSchema(t *testing.T) {
	ctx := context.Background()
	const (
		created  = int64(1_700_000_000_000_000) // micros
		later    = int64(1_700_000_100_000_000)
		far      = int64(4_000_000_000_000_000)
		pwHash   = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA"
		secHash  = "$argon2id$v=19$m=65536,t=3,p=4$c2VjcmV0c2FsdA$c2VjcmV0aGFzaHNlY3JldGhhc2g"
		dbConn   = "Username-Password-Authentication"
		tenantID = "acme"
	)
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 1)
			if v, err := s.SchemaVersion(ctx); err != nil || v != 1 {
				t.Fatalf("version %d err %v", v, err)
			}

			// Version 1 rows.
			mustExec(t, s, `INSERT INTO tenants (id, name, friendly_name, default_audience, allowed_logout_urls, enabled_locales, custom_text,
 session_lifetime, idle_session_lifetime, logo_url, primary_color, default_directory, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				tenantID, "acme", "Acme Inc", "https://api.acme.test", `["https://acme.test/bye"]`, `["en","fr"]`,
				`{"login":{"en":{"login":{"title":"Welcome to Acme"}}}}`, 7200, 1800, "https://acme.test/logo.svg", "#ff5500", dbConn, created)
			mustExec(t, s, `INSERT INTO tenant_domains (domain, tenant_id, position) VALUES ('login.acme.test', ?, 0)`, tenantID)
			mustExec(t, s, `INSERT INTO clients (tenant_id, client_id, name, app_type, secrets, token_endpoint_auth_method, grant_types,
 callbacks, allowed_logout_urls, web_origins, allowed_origins, id_token_lifetime, refresh_token, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				tenantID, "web", "Acme Web", "regular_web", `[{"hash":"`+secHash+`","created_at":1700000000000000,"expires_at":null}]`,
				"client_secret_post", `["authorization_code","refresh_token"]`, `["https://acme.test/callback"]`,
				`["https://acme.test/"]`, `["https://acme.test"]`, `[]`, 3600,
				`{"Rotating":true,"Leeway":30,"Expiring":true,"TokenLifetime":2592000,"IdleTokenLifetime":1296000}`, created)
			mustExec(t, s, `INSERT INTO resource_servers (tenant_id, id, identifier, name, scopes, signing_alg, token_lifetime, allow_offline_access, created_at)
 VALUES (?,?,?,?,?,?,?,?,?)`, tenantID, "rs_api", "https://api.acme.test", "Acme API",
				`[{"Value":"read:items","Description":"Read items"}]`, "RS256", 86400, true, created)
			mustExec(t, s, `INSERT INTO client_grants (tenant_id, id, client_id, audience, scopes, created_at) VALUES (?,?,?,?,?,?)`,
				tenantID, "cgr_1", "web", "https://api.acme.test", `["read:items"]`, created)
			mustExec(t, s, `INSERT INTO signing_keys (tenant_id, kid, alg, status, private_key, public_jwk, created_at) VALUES (?,?,?,?,?,?,?)`,
				tenantID, "kid1", "RS256", "current", []byte("sealed-private-key"), []byte(`{"kid":"kid1"}`), created)
			mustExec(t, s, `INSERT INTO connections (tenant_id, id, name, strategy, enabled_clients, disable_signup, requires_username,
 password_min_length, password_character_classes, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
				tenantID, "con_db", dbConn, "auth0", `["web"]`, true, true, 10, 3, created)
			mustExec(t, s, `INSERT INTO connections (tenant_id, id, name, strategy, enabled_clients, disable_signup, requires_username,
 password_min_length, password_character_classes, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
				tenantID, "con_google", "google-oauth2", "google-oauth2", `["web"]`, false, false, 0, 0, created)
			insertUser := func(id, email, username, identities string, verified, blocked bool, last any, logins int) {
				mustExec(t, s, `INSERT INTO users (tenant_id, user_id, email, email_verified, username, name, nickname, picture, given_name,
 family_name, user_metadata, blocked, identities, last_login, logins_count, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
					tenantID, id, email, verified, username, "Jane Doe", "jane", "https://acme.test/jane.png", "Jane", "Doe",
					`{"theme":"dark"}`, blocked, identities, last, logins, created, later)
			}
			insertUser("auth0|jane", "jane@acme.test", "jane",
				`[{"Connection":"`+dbConn+`","Provider":"auth0","UserID":"jane","PasswordHash":"`+pwHash+`"}]`, true, false, later, 3)
			insertUser("google-oauth2|1234", "g@acme.test", "",
				`[{"Connection":"google-oauth2","Provider":"google-oauth2","UserID":"1234","PasswordHash":""}]`, false, true, nil, 0)
			mustExec(t, s, `INSERT INTO user_logins (tenant_id, connection, kind, value, user_id) VALUES (?,?,'email','jane@acme.test','auth0|jane')`, tenantID, dbConn)
			mustExec(t, s, `INSERT INTO user_logins (tenant_id, connection, kind, value, user_id) VALUES (?,?,'username','jane','auth0|jane')`, tenantID, dbConn)
			mustExec(t, s, `INSERT INTO sessions (tenant_id, id, token_hash, user_id, connection, authenticated_at, client_ids, expires_at, idle_expires_at, created_at)
 VALUES (?,?,?,?,?,?,?,?,?,?)`, tenantID, "ses_1", "session-hash", "auth0|jane", dbConn, created, `["web"]`, far, far-1, created)
			mustExec(t, s, `INSERT INTO refresh_tokens (tenant_id, id, token_hash, family_id, client_id, user_id, session_id, scopes, audience,
 auth_time, rotating, expires_at, idle_expires_at, rotated_at, revoked_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				tenantID, "rt_1", "refresh-hash", "fam_1", "web", "auth0|jane", "ses_1", `["openid","offline_access","read:items"]`,
				"https://api.acme.test", created, true, far, far-2, later, nil, created)
			mustExec(t, s, `INSERT INTO password_reset_tickets (tenant_id, id, token_hash, user_id, connection, client_id, lang, expires_at, used_at, created_at)
 VALUES (?,?,?,?,?,?,?,?,?,?)`, tenantID, "prt_1", "ticket-hash", "auth0|jane", dbConn, "web", "fr", far, nil, created)

			// Step through every version.
			for v := int64(2); v <= s.LatestVersion(); v++ {
				if err := s.migrateTo(ctx, v); err != nil {
					t.Fatalf("migrate to %d: %v", v, err)
				}
				if got, err := s.SchemaVersion(ctx); err != nil || got != v {
					t.Fatalf("after migrating to %d: version %d err %v", v, got, err)
				}
				if v == 28 {
					at := logTime(time.UnixMicro(later))
					mustExec(t, s, `INSERT INTO tenant_logs (tenant_id,log_id,date,committed_at,type,user_id,client_id,connection_id,organization_id,ip,body) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
						tenantID, store.FormatLogID(1), at, at, "s", "auth0|jane", "web", "con_db", "", "203.0.113.7", []byte(`{"client_name":"Acme Web"}`))
				}
			}
			if err := s.CheckSchema(ctx); err != nil {
				t.Fatal(err)
			}

			// Read everything back through the current store API.
			tn, err := s.Tenants().Get(ctx, tenantID)
			if err != nil {
				t.Fatal(err)
			}
			if tn.Name != "acme" || tn.FriendlyName != "Acme Inc" || tn.DefaultAudience != "https://api.acme.test" ||
				!reflect.DeepEqual(tn.AllowedLogoutURLs, []string{"https://acme.test/bye"}) || !reflect.DeepEqual(tn.EnabledLocales, []string{"en", "fr"}) ||
				tn.SessionLifetime != 7200 || tn.IdleSessionLifetime != 1800 || tn.DefaultDirectory != dbConn ||
				!reflect.DeepEqual(tn.Domains, []string{"login.acme.test"}) || tn.CreatedAt.UnixMicro() != created {
				t.Fatalf("tenant: %+v", tn)
			}
			if got, err := s.Tenants().GetByDomain(ctx, "login.acme.test"); err != nil || got.ID != tenantID {
				t.Fatalf("tenant by domain: %v %v", got, err)
			}
			if h, err := s.CustomDomains().GetHost(ctx, "login.acme.test"); err != nil || h.TenantID != tenantID || h.Kind != store.HostOperator || !h.Active {
				t.Fatalf("host binding: %+v %v", h, err)
			}
			hl, err := (hostedlogin.Service{Store: s}).Load(ctx, tenantID)
			if err != nil {
				t.Fatal(err)
			}
			if hl.Branding["logo_url"] != "https://acme.test/logo.svg" || hl.CustomText["login"]["en"]["login"]["title"] != "Welcome to Acme" {
				t.Fatalf("hosted login: %+v", hl)
			}

			c, err := s.Clients().Get(ctx, tenantID, "web")
			if err != nil {
				t.Fatal(err)
			}
			if c.Name != "Acme Web" || c.AppType != "regular_web" || len(c.Secrets) != 1 || c.Secrets[0].Hash != secHash ||
				c.Secrets[0].CreatedAt.UnixMicro() != created || c.Secrets[0].ExpiresAt != nil || c.TokenEndpointAuthMethod != "client_secret_post" ||
				!reflect.DeepEqual(c.GrantTypes, []string{"authorization_code", "refresh_token"}) ||
				!reflect.DeepEqual(c.Callbacks, []string{"https://acme.test/callback"}) || c.IDTokenLifetime != 3600 ||
				c.RefreshToken != (store.RefreshTokenPolicy{Rotating: true, Leeway: 30, Expiring: true, TokenLifetime: 2592000, IdleTokenLifetime: 1296000}) ||
				!c.IsFirstParty {
				t.Fatalf("client: %+v", c)
			}
			rs, err := s.ResourceServers().GetByIdentifier(ctx, tenantID, "https://api.acme.test")
			if err != nil || rs.ID != "rs_api" || !reflect.DeepEqual(rs.Scopes, []store.Scope{{Value: "read:items", Description: "Read items"}}) ||
				rs.TokenLifetime != 86400 || !rs.AllowOfflineAccess || rs.SigningAlg != "RS256" {
				t.Fatalf("resource server: %+v %v", rs, err)
			}
			g, err := s.ClientGrants().Find(ctx, tenantID, "web", "https://api.acme.test", store.SubjectTypeClient)
			if err != nil || g.ID != "cgr_1" || !reflect.DeepEqual(g.Scopes, []string{"read:items"}) {
				t.Fatalf("client grant: %+v %v", g, err)
			}
			k, err := s.SigningKeys().Get(ctx, tenantID, "kid1")
			if err != nil || k.Alg != "RS256" || k.Status != store.KeyCurrent || string(k.PrivateKey) != "sealed-private-key" || string(k.PublicJWK) != `{"kid":"kid1"}` {
				t.Fatalf("signing key: %+v %v", k, err)
			}

			conn, err := s.Connections().GetByName(ctx, tenantID, dbConn)
			if err != nil {
				t.Fatal(err)
			}
			if conn.ID != "con_db" || conn.Strategy != "auth0" || !reflect.DeepEqual(conn.EnabledClients, []string{"web"}) ||
				!conn.DisableSignup || !conn.RequiresUsername || !conn.BruteForceProtection ||
				!reflect.DeepEqual(conn.PasswordOptions, store.PasswordOptions{Complexity: store.LegacyComplexity(10, 3)}) {
				t.Fatalf("connection: %+v", conn)
			}

			u, err := s.Users().FindByLogin(ctx, tenantID, dbConn, "jane@acme.test")
			if err != nil {
				t.Fatal(err)
			}
			if u.UserID != "auth0|jane" || u.Email != "jane@acme.test" || !u.EmailVerified || u.Username != "jane" || u.Name != "Jane Doe" ||
				u.GivenName != "Jane" || u.FamilyName != "Doe" || u.Picture != "https://acme.test/jane.png" || u.Blocked ||
				u.UserMetadata["theme"] != "dark" || u.AppMetadata != nil || u.LoginsCount != 3 ||
				u.LastLogin == nil || u.LastLogin.UnixMicro() != later || u.CreatedAt.UnixMicro() != created || u.UpdatedAt.UnixMicro() != later ||
				len(u.Identities) != 1 || u.Identities[0].PasswordHash != pwHash || u.Identities[0].Connection != dbConn || u.Identities[0].Provider != "auth0" {
				t.Fatalf("user: %+v", u)
			}
			if byName, err := s.Users().FindByLogin(ctx, tenantID, dbConn, "jane"); err != nil || byName.UserID != "auth0|jane" {
				t.Fatalf("username login: %v %v", byName, err)
			}
			if fed, err := s.Users().FindByIdentity(ctx, tenantID, "con_google", "1234"); err != nil || fed.UserID != "google-oauth2|1234" || !fed.Blocked || fed.LastLogin != nil {
				t.Fatalf("federated user: %+v %v", fed, err)
			}

			ses, err := s.Sessions().GetByTokenHash(ctx, tenantID, "session-hash")
			if err != nil || ses.ID != "ses_1" || ses.UserID != "auth0|jane" || !reflect.DeepEqual(ses.ClientIDs, []string{"web"}) ||
				ses.ExpiresAt.UnixMicro() != far || ses.IdleExpiresAt.UnixMicro() != far-1 || ses.UpdatedAt.UnixMicro() != created {
				t.Fatalf("session: %+v %v", ses, err)
			}
			rt, err := s.RefreshTokens().GetByTokenHash(ctx, tenantID, "refresh-hash")
			if err != nil || rt.ID != "rt_1" || rt.FamilyID != "fam_1" || rt.ClientID != "web" || rt.UserID != "auth0|jane" || rt.SessionID != "ses_1" ||
				!reflect.DeepEqual(rt.Scopes, []string{"openid", "offline_access", "read:items"}) || rt.Audience != "https://api.acme.test" ||
				!rt.Rotating || rt.ExpiresAt.UnixMicro() != far || rt.IdleExpiresAt.UnixMicro() != far-2 ||
				rt.RotatedAt == nil || rt.RotatedAt.UnixMicro() != later || rt.RevokedAt != nil || rt.Origin != "" || rt.OrganizationID != "" {
				t.Fatalf("refresh token: %+v %v", rt, err)
			}
			tk, err := s.PasswordResetTickets().GetByTokenHash(ctx, tenantID, "ticket-hash")
			if err != nil || tk.ID != "prt_1" || tk.UserID != "auth0|jane" || tk.Connection != dbConn || tk.ClientID != "web" || tk.Lang != "fr" {
				t.Fatalf("password reset ticket: %+v %v", tk, err)
			}

			q, err := logsearch.Parse(`client_name:"Acme Web"`)
			if err != nil {
				t.Fatal(err)
			}
			logs, total, err := s.Logs().SearchLogs(ctx, tenantID, q, store.LogPage{PerPage: 10, IncludeTotals: true})
			if err != nil || total != 1 || len(logs) != 1 || logs[0].UserID != "auth0|jane" {
				t.Fatalf("log search: %+v %d %v", logs, total, err)
			}
		})
	}
}
