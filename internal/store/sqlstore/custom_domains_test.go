package sqlstore

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestMigration0020PreservesLegacyBytes(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 19)
			mustExec(t, s, `INSERT INTO tenants (id,name,friendly_name,default_audience,allowed_logout_urls,enabled_locales,custom_text,session_lifetime,idle_session_lifetime,logo_url,primary_color,default_directory,created_at) VALUES ('legacy','legacy','Kept','','[]','[]','{}',3600,1800,'','','',123)`)
			mustExec(t, s, `INSERT INTO tenant_domains (domain,tenant_id,position) VALUES ('LOGIN.example.test.','legacy',0)`)
			mustExec(t, s, `INSERT INTO tenant_domains (domain,tenant_id,position) VALUES ('second.example.test','legacy',1)`)
			key := []byte{0, 255, 1, 2, 3, 128}
			email := []byte{255, 0, 254, 127}
			mustExec(t, s, `INSERT INTO signing_keys (tenant_id,kid,alg,status,private_key,public_jwk,created_at) VALUES ('legacy','kid','RS256','current',?, ?,123)`, key, []byte(`{"kid":"kid"}`))
			mustExec(t, s, `INSERT INTO email_provider_revisions (tenant_id,revision) VALUES ('legacy',7)`)
			mustExec(t, s, `INSERT INTO email_providers (tenant_id,name,enabled,default_from,public_config,sealed_credentials,revision) VALUES ('legacy','smtp',true,'from@example.test','{}',?,7)`, email)
			mustExec(t, s, `INSERT INTO auth_codes (tenant_id,code_hash,client_id,redirect_uri,user_id,session_id,scopes,audience,nonce,code_challenge,code_challenge_method,auth_time,expires_at,created_at) VALUES ('legacy','code','client','https://callback','user','session','["openid"]','aud','nonce','challenge','S256',123,9999999999999999,123)`)
			mustExec(t, s, `INSERT INTO password_reset_tickets (tenant_id,id,token_hash,user_id,connection,client_id,lang,expires_at,used_at,created_at,result_url,include_email_in_redirect,mark_email_verified) VALUES ('legacy','reset','reset-hash','user','db','client','en',9999999999999999,NULL,123,'https://result.example.test',true,true)`)

			mustExec(t, s, `INSERT INTO sessions (tenant_id,id,token_hash,user_id,connection,authenticated_at,client_ids,expires_at,idle_expires_at,created_at,updated_at,last_interacted_at,initial_ip,initial_user_agent,last_ip,last_user_agent) VALUES ('legacy','session','session-hash','user','db',123,'["client"]',9999999999999999,9999999999999998,123,124,125,'192.0.2.1','initial','192.0.2.2','last')`)
			mustExec(t, s, `INSERT INTO auth_transactions (tenant_id,id,cookie_hash,csrf_token,client_id,params,expires_at,created_at,hosted_state,hosted_revision) VALUES ('legacy','transaction','cookie','csrf','client','{"scope":"openid"}',9999999999999999,123,'{"Step":"password","Revision":2}',2)`)
			mustExec(t, s, `INSERT INTO pushed_auth_requests (tenant_id,id_hash,client_id,params,expires_at,created_at,used_at) VALUES ('legacy','par','client','{"scope":"openid"}',9999999999999999,123,NULL)`)
			mustExec(t, s, `INSERT INTO device_codes (tenant_id,device_code_hash,user_code_hash,client_id,scopes,audience,status,user_id,granted_scopes,last_polled_at,expired_reported_at,expires_at,created_at) VALUES ('legacy','device','user-code','client','["openid"]','aud','pending','','[]',NULL,NULL,9999999999999999,123)`)
			mustExec(t, s, `INSERT INTO refresh_tokens (tenant_id,id,token_hash,family_id,client_id,user_id,session_id,scopes,audience,auth_time,rotating,expires_at,idle_expires_at,rotated_at,revoked_at,created_at) VALUES ('legacy','refresh','refresh-hash','family','client','user','session','["openid"]','aud',123,true,9999999999999999,9999999999999998,NULL,NULL,123)`)
			mustExec(t, s, `INSERT INTO email_verification_tickets (tenant_id,id,token_hash,user_id,connection,client_id,lang,expires_at,used_at,created_at,result_url,include_email_in_redirect,email) VALUES ('legacy','verify','verify-hash','user','db','client','en',9999999999999999,NULL,123,'https://result.example.test',true,'verify@example.test')`)
			tables := []string{"tenants", "tenant_domains", "signing_keys", "email_provider_revisions", "email_providers", "sessions", "auth_transactions", "auth_codes", "pushed_auth_requests", "device_codes", "refresh_tokens", "password_reset_tickets", "email_verification_tickets"}
			columns := map[string][]string{}
			before := map[string][][]any{}
			for _, table := range tables {
				columns[table], before[table] = legacySnapshot(t, s, table, nil)
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			for _, table := range tables {
				_, after := legacySnapshot(t, s, table, columns[table])
				if !reflect.DeepEqual(before[table], after) {
					t.Fatalf("migration changed old columns of %s: before%#v after%#v", table, before[table], after)
				}
			}
			for _, table := range []string{"sessions", "auth_transactions", "auth_codes", "pushed_auth_requests", "device_codes", "refresh_tokens", "password_reset_tickets", "email_verification_tickets"} {
				var origin string
				if err := s.queryRow(ctx, `SELECT origin FROM `+table).Scan(&origin); err != nil || origin != "" {
					t.Fatalf("legacy %s origin=%q err=%v", table, origin, err)
				}
			}

			var gotKey, gotEmail []byte
			if err := s.queryRow(ctx, `SELECT private_key FROM signing_keys WHERE tenant_id='legacy'`).Scan(&gotKey); err != nil {
				t.Fatal(err)
			}
			if err := s.queryRow(ctx, `SELECT sealed_credentials FROM email_providers WHERE tenant_id='legacy'`).Scan(&gotEmail); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key, gotKey) || !bytes.Equal(email, gotEmail) {
				t.Fatal("migration changed ciphertext bytes")
			}
			tn, err := s.Tenants().Get(ctx, "legacy")
			if err != nil {
				t.Fatal(err)
			}
			if tn.CanonicalHost != "" || len(tn.Domains) != 2 || tn.Domains[0] != "LOGIN.example.test." || tn.Domains[1] != "second.example.test" {
				t.Fatalf("legacy canonical/projection changed: %+v", tn)
			}
			h, err := s.CustomDomains().GetHost(ctx, "login.example.test")
			if err != nil {
				t.Fatal(err)
			}
			if h.Kind != store.HostOperator || !h.Active || h.TenantID != "legacy" {
				t.Fatalf("legacy claim: %+v", h)
			}
			code, err := s.AuthCodes().Consume(ctx, "legacy", "code", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if code.Origin != "" || code.Nonce != "nonce" || code.ExpiresAt.UnixMicro() != 9999999999999999 {
				t.Fatalf("legacy code changed: %+v", code)
			}
			ticket, err := s.PasswordResetTickets().Consume(ctx, "legacy", "reset-hash", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if ticket.Origin != "" || ticket.Connection != "db" {
				t.Fatalf("legacy ticket changed: %+v", ticket)
			}
		})
	}
}

// Checked leases must be valid at publication, even when the callback outlives
// the original lease. A rolled-back savepoint must discard its guard.
func TestTLSLeaseCommitAndSavepoint(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			lease, err := s.TLSAssets().ClaimLease(ctx, "resource", "owner", 80*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			err = s.WithTx(ctx, func(tx store.Store) error {
				if err := tx.TLSAssets().CheckLease(ctx, *lease); err != nil {
					return err
				}
				if err := tx.TLSAssets().Put(ctx, &store.TLSAsset{Key: "publication"}, 0); err != nil {
					return err
				}
				time.Sleep(120 * time.Millisecond)
				return nil
			})
			if !errors.Is(err, store.ErrConflict) {
				t.Fatalf("expired publication committed: %v", err)
			}
			if _, err = s.TLSAssets().Get(ctx, "publication"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal(err)
			}
			lease, err = s.TLSAssets().ClaimLease(ctx, "resource", "owner", 80*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			stop := errors.New("savepoint rollback")
			err = s.WithTx(ctx, func(tx store.Store) error {
				err := tx.WithTx(ctx, func(inner store.Store) error {
					if e := inner.TLSAssets().CheckLease(ctx, *lease); e != nil {
						return e
					}
					return stop
				})
				if !errors.Is(err, stop) {
					return err
				}
				time.Sleep(120 * time.Millisecond)
				return tx.TLSAssets().Put(ctx, &store.TLSAsset{Key: "unguarded"}, 0)
			})
			if err != nil {
				t.Fatalf("rolled back check leaked: %v", err)
			}
		})
	}
}

func TestMigration0020RetriesInterruptedBackfill(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 19)
			for _, id := range []string{"a", "b"} {
				mustExec(t, s, `INSERT INTO tenants (id,name,friendly_name,default_audience,allowed_logout_urls,enabled_locales,custom_text,session_lifetime,idle_session_lifetime,logo_url,primary_color,default_directory,created_at) VALUES (?,?,'','','[]','[]','{}',0,0,'','','',0)`, id, id)
			}
			mustExec(t, s, `INSERT INTO tenant_domains (domain,tenant_id,position) VALUES ('LOGIN.example.test.','a',0)`)
			mustExec(t, s, `INSERT INTO tenant_domains (domain,tenant_id,position) VALUES ('login.example.test','b',0)`)
			if err := s.Migrate(ctx); err == nil {
				t.Fatal("normalized legacy overlap silently adopted")
			}
			version, err := s.SchemaVersion(ctx)
			if err != nil || version != 19 {
				t.Fatalf("failed backfill marked migrated: %d %v", version, err)
			}
			mustExec(t, s, `DELETE FROM tenant_domains WHERE tenant_id='b'`)
			mustExec(t, s, `INSERT INTO tenant_domains (domain,tenant_id,position) VALUES ('other.example.test','b',0)`)
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("retry after interrupted migration: %v", err)
			}
			for host, tenant := range map[string]string{"login.example.test": "a", "other.example.test": "b"} {
				h, err := s.CustomDomains().GetHost(ctx, host)
				if err != nil || h.TenantID != tenant || h.Kind != store.HostOperator || !h.Active {
					t.Fatalf("claim %s: %+v %v", host, h, err)
				}
			}
		})
	}
}

// Read identical legacy columns before/after adding schema columns. Copy byte
// buffers because database/sql drivers may reuse them on the next Scan.
func legacySnapshot(t *testing.T, s *Store, table string, columns []string) ([]string, [][]any) {
	t.Helper()
	projection := "*"
	if columns != nil {
		projection = strings.Join(columns, ",")
	}
	rows, err := s.query(context.Background(), `SELECT `+projection+` FROM `+table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err = rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out [][]any
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		for i, v := range values {
			if b, ok := v.([]byte); ok {
				values[i] = bytes.Clone(b)
			}
		}
		out = append(out, values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns, out
}

func TestMigration0020GrandfathersUnchangedProjection(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 19)
			mustExec(t, s, `INSERT INTO tenants (id,name,friendly_name,default_audience,allowed_logout_urls,enabled_locales,custom_text,session_lifetime,idle_session_lifetime,logo_url,primary_color,default_directory,created_at) VALUES ('legacy','legacy','','','[]','[]','{}',0,0,'','','',0)`)
			original := []string{"LOGIN.example.test.", "login.example.test", "SECOND.example.test."}
			for i, host := range original {
				mustExec(t, s, `INSERT INTO tenant_domains (domain,tenant_id,position) VALUES (?,'legacy',?)`, host, i)
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			tn, err := s.Tenants().Get(ctx, "legacy")
			if err != nil {
				t.Fatal(err)
			}
			tn.FriendlyName = "Metadata changed"
			if err := s.Tenants().Update(ctx, tn); err != nil {
				t.Fatalf("metadata-only legacy update: %v", err)
			}
			tn.CanonicalHost = "login.example.test"
			if err := s.Tenants().Update(ctx, tn); err != nil {
				t.Fatalf("canonical initialization: %v", err)
			}
			got, err := s.Tenants().Get(ctx, tn.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Domains, original) || got.CanonicalHost != "login.example.test" {
				t.Fatalf("legacy projection rewritten: %+v", got)
			}
			for _, host := range original {
				h, err := s.CustomDomains().GetHost(ctx, host)
				if err != nil || h.TenantID != "legacy" || !h.Active {
					t.Fatalf("legacy claim: %+v %v", h, err)
				}
			}
			got.Domains = append(got.Domains, "new.example.test")
			if err := s.Tenants().Update(ctx, got); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("changed duplicate input accepted: %v", err)
			}
		})
	}
}
