package server

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
	"time"
)

func TestConsoleWebAuthnProjection(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	u := &store.User{TenantID: tn.ID, UserID: "auth0|console-key", Email: "console@example.test", CreatedAt: time.Now()}
	if err := st.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	a := &store.Authenticator{TenantID: tn.ID, UserID: u.UserID, ID: "passkey|dev_console", Type: "passkey", Confirmed: true, Name: "Laptop", RPID: "login.example.test", CreatedAt: time.Now(), CredentialID: []byte("credential-secret"), PublicKey: []byte("public-key-secret"), PublicData: []byte(`{"user_handle":"handle-secret","backup_eligible":true,"backed_up":true,"aaguid":"model-uuid"}`)}
	if err := st.WebAuthn().CreatePasskey(ctx, a, 20); err != nil {
		t.Fatal(err)
	}
	op, _ := operatorToken(t, st, "console-keys@example.test")
	base := "https://" + mgmtSystemHost + "/api/system/tenants/acme/users/auth0%7Cconsole-key/authentication-methods"
	for _, method := range []string{"GET", "PATCH"} {
		path := base
		var body any
		if method == "PATCH" {
			path += "/passkey%7Cdev_console"
			body = map[string]any{"name": "Renamed"}
		}
		rec, out := sendRaw(h, method, path, op, body)
		if rec.Code != 200 {
			t.Fatalf("%s %d %s", method, rec.Code, rec.Body)
		}
		for _, secret := range []string{"key_id", "public_key", "user_handle", "credential-secret", "public-key-secret", "handle-secret"} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Fatalf("response leaked %s", secret)
			}
		}
		if !strings.Contains(rec.Body.String(), "model-uuid") || !strings.Contains(rec.Body.String(), "multi_device") {
			t.Fatalf("missing metadata %v", out)
		}
	}
	for _, path := range []string{strings.Replace(base, "/acme/", "/missing/", 1), strings.Replace(base, "auth0%7Cconsole-key", "auth0%7Cforeign", 1), strings.Replace(base, mgmtSystemHost, "acme.example.test", 1)} {
		rec, _ := sendRaw(h, "GET", path, op, nil)
		if rec.Code != 404 {
			t.Fatalf("foreign path %d %s", rec.Code, rec.Body)
		}
	}
	limited, uid := tenantOperatorToken(t, st, "limited-console-key@example.test", []string{"*"})
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: mustSystemID(t, st), UserID: uid, Tenants: []string{"system"}}); err != nil {
		t.Fatal(err)
	}
	rec, _ := sendRaw(h, "GET", base, limited, nil)
	if rec.Code != 403 {
		t.Fatalf("live grant %d", rec.Code)
	}
}
func TestConsoleRelyingPartyStatus(t *testing.T) {
	h, st := newMgmtEnv(t)
	op, _ := operatorToken(t, st, "console-rp@example.test")
	rec, out := sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants/acme/relying-party-ids", op, nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rows := out.([]any)
	if len(rows) == 0 {
		t.Fatal("no hosts")
	}
	found := false
	for _, row := range rows {
		m := row.(map[string]any)
		if m["host"] == "acme.example.test" {
			found = true
			if m["relying_party_identifier"] != "acme.example.test" || m["valid"] != true || m["kind"] != "canonical" {
				t.Fatal(m)
			}
		}
	}
	if !found {
		t.Fatal("canonical host absent")
	}
}

func TestConsoleRelyingPartyStrictPolicy(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared", true: "strict"}[strict], func(t *testing.T) {
			h, st := newMgmtEnvWith(t, func(d *Deps) { d.RestrictSharedRPIDs = strict; d.BaseDomain = "example.test" })
			ctx := context.Background()
			tn, _ := st.Tenants().GetByName(ctx, "acme")
			tn.Domains = append(tn.Domains, "alias.example.test:9543")
			tn.DomainRPIDs = map[string]string{"alias.example.test:9543": "example.test"}
			if err := st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			if err := st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "alias.example.test:9543", TenantID: tn.ID, Kind: store.HostOperator, Active: true}); err != nil {
				t.Fatal(err)
			}
			for _, d := range []*store.CustomDomain{
				{TenantID: tn.ID, ID: "dom-ready", Domain: "login.customer.test", Status: "ready", RelyingPartyIdentifier: "customer.test"},
				{TenantID: tn.ID, ID: "dom-invalid", Domain: "bad.customer.test", Status: "ready", RelyingPartyIdentifier: "unrelated.test"},
				{TenantID: tn.ID, ID: "dom-pending", Domain: "pending.customer.test", Status: "pending_verification"},
			} {
				if err := st.CustomDomains().Create(ctx, d); err != nil {
					t.Fatal(err)
				}
				if err := st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: tn.ID, DomainID: d.ID, Kind: store.HostPublic, Active: d.Status == "ready"}); err != nil {
					t.Fatal(err)
				}
			}
			op, _ := operatorToken(t, st, "console-status@example.test")
			rec, out := sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants/acme/relying-party-ids", op, nil)
			if rec.Code != 200 {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			rows := map[string]map[string]any{}
			for _, v := range out.([]any) {
				m := v.(map[string]any)
				rows[m["host"].(string)] = m
			}
			if len(rows) != 6 {
				t.Fatalf("all hosts %v", rows)
			}
			alias := rows["alias.example.test:9543"]
			if alias["valid"] == strict || alias["origin"] != "https://alias.example.test:9543" || alias["kind"] != string(rpid.KindOperator) || alias["relying_party_identifier"] != "example.test" {
				t.Fatalf("alias %v", alias)
			}
			if rows["login.customer.test"]["valid"] != true || rows["bad.customer.test"]["valid"] != false || rows["pending.customer.test"]["valid"] != false {
				t.Fatal(rows)
			}
		})
	}
}

func TestConsoleMethodTargetPhonePolicy(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	tn.SettingsExtra = map[string]any{"flags": map[string]any{"disable_management_api_sms_obfuscation": false}}
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	uid := "auth0|console-phone"
	if err := st.Users().Create(ctx, &store.User{TenantID: tn.ID, UserID: uid, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: tn.ID, UserID: uid, ID: "phone|dev_test", Type: "phone", Phone: "+14155551234", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	op, _ := operatorToken(t, st, "console-phone@example.test")
	rec, _ := sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants/acme/users/auth0%7Cconsole-phone/authentication-methods", op, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "+14155551234") || !strings.Contains(rec.Body.String(), "1234") {
		t.Fatalf("target masking %d %s", rec.Code, rec.Body)
	}
}
