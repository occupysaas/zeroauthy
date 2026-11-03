package connrules

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPasswordlessConnectionCreate(t *testing.T) {
	t.Run("email defaults", func(t *testing.T) {
		s := mustAPI(t, `{"name":"email","strategy":"email","options":{"email":{"from":"Acme <no-reply@acme.test>"}}}`)
		var c store.Connection
		Apply(s, &c)
		got, err := PasswordlessOf(c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.Email == nil || got.Email.From != "Acme <no-reply@acme.test>" || got.Email.Syntax != "liquid" || got.Email.Subject == "" || got.Email.Body == "" {
			t.Fatalf("email = %+v", got.Email)
		}
		if got.TOTP.Length != 6 || got.TOTP.TimeStep != 180 || !got.BruteForce || got.DisableSignup || got.SMS != nil {
			t.Fatalf("options = %+v", got)
		}
	})
	t.Run("sms defaults", func(t *testing.T) {
		s := mustAPI(t, `{"name":"sms","strategy":"sms","options":{"from":"+15555550100","twilio_sid":"AC`+strings.Repeat("a", 32)+`"}}`)
		var c store.Connection
		Apply(s, &c)
		got, err := PasswordlessOf(c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.SMS == nil || got.SMS.Provider != "twilio" || got.SMS.Syntax != "md_with_macros" || got.SMS.Template == "" || got.SMS.From != "+15555550100" {
			t.Fatalf("sms = %+v", got.SMS)
		}
		if got.TOTP.Length != 6 || got.TOTP.TimeStep != 180 {
			t.Fatalf("totp = %+v", got.TOTP)
		}
	})
	t.Run("authParams as object or query string", func(t *testing.T) {
		s := mustAPI(t, `{"name":"email","strategy":"email","options":{"email":{"from":"a@b.test"},"authParams":{"scope":"openid email"}}}`)
		var c store.Connection
		Apply(s, &c)
		got, _ := PasswordlessOf(c, nil)
		if got.AuthParams["scope"] != "openid email" {
			t.Fatalf("authParams = %v", got.AuthParams)
		}
		s = mustAPI(t, `{"name":"email","strategy":"email","options":{"email":{"from":"a@b.test"},"authParams":"scope=openid&x=1"}}`)
		Apply(s, &c)
		got, _ = PasswordlessOf(c, nil)
		if got.AuthParams["scope"] != "openid" || got.AuthParams["x"] != "1" {
			t.Fatalf("authParams = %v", got.AuthParams)
		}
	})
	t.Run("name must equal the strategy", func(t *testing.T) {
		wantErr(t, "name", decode(t, `{"name":"magic","strategy":"email","options":{}}`), true, `must be named "email"`)
		wantErr(t, "name", decode(t, `{"name":"email","strategy":"sms","options":{}}`), true, `must be named "sms"`)
	})
	t.Run("schema violations", func(t *testing.T) {
		wantErr(t, "totp length", decode(t, `{"name":"email","strategy":"email","options":{"totp":{"length":3}}}`), true, "options.totp.length")
		wantErr(t, "time step", decode(t, `{"name":"email","strategy":"email","options":{"totp":{"time_step":59}}}`), true, "options.totp.time_step")
		wantErr(t, "syntax", decode(t, `{"name":"email","strategy":"email","options":{"email":{"syntax":"md"}}}`), true, "options.email.syntax")
		wantErr(t, "provider", decode(t, `{"name":"sms","strategy":"sms","options":{"provider":"nexmo"}}`), true, "options.provider")
		wantErr(t, "twilio sid", decode(t, `{"name":"sms","strategy":"sms","options":{"twilio_sid":"nope"}}`), true, "options.twilio_sid")
		wantErr(t, "sms syntax", decode(t, `{"name":"sms","strategy":"sms","options":{"syntax":"html"}}`), true, "options.syntax")
	})
	t.Run("unsupported strategy still refused", func(t *testing.T) {
		wantErr(t, "strategy", decode(t, `{"name":"voice","strategy":"voice"}`), true, "not supported")
	})
}

func TestDatabaseOptionsRejectedOnPasswordless(t *testing.T) {
	for _, body := range []string{
		`{"name":"email","strategy":"email","options":{"passwordPolicy":"good"}}`,
		`{"name":"email","strategy":"email","options":{"requires_username":true}}`,
		`{"name":"sms","strategy":"sms","options":{"enabledDatabaseCustomization":true,"customScripts":{"login":"x"}}}`,
		`{"name":"sms","strategy":"sms","options":{"validation":{"username":{"min":1,"max":10}}}}`,
		`{"name":"sms","strategy":"sms","options":{"import_mode":true}}`,
	} {
		wantErr(t, body, decode(t, body), true, `database options are not supported on strategy`)
	}
	for _, key := range []string{"mfa", "authentication_methods", "passkey_options", "precedence", "attributes", "strategy_version", "disable_self_service_change_password"} {
		s := decode(t, `{"name":"email","strategy":"email","options":{}}`)
		s.Options.Extra[key] = map[string]any{}
		wantErr(t, key, s, true, `option "`+key+`" is not supported on strategy "email"`)
	}
	// Options both passwordless strategies keep.
	mustAPI(t, `{"name":"email","strategy":"email","options":{"disable_signup":true,"brute_force_protection":false,"non_persistent_attrs":["a"]}}`)
}

func TestSMSGatewayURLValidated(t *testing.T) {
	base := func(u string) string {
		return `{"name":"sms","strategy":"sms","options":{"provider":"sms_gateway","gateway_url":"` + u + `"}}`
	}
	for _, u := range []string{"https://sms.example.test/send", "https://sms.example.test:8443/v1/send?x=1", "https://8.8.8.8/send"} {
		mustAPI(t, base(u))
	}
	for _, u := range []string{
		"http://sms.example.test/send", "ftp://sms.example.test", "https://127.0.0.1/x", "https://10.1.2.3/x",
		"https://192.168.0.5/x", "https://172.16.0.1/x", "https://169.254.169.254/latest", "https://[::1]/x",
		"https://0.0.0.0/x", "https://localhost/x", "https://api.localhost/x", "https://[fd00::1]/x",
		"https://user:pw@sms.example.test/x", "https://[::ffff:10.0.0.1]/x",
	} {
		wantErr(t, u, decode(t, base(u)), true, "gateway_url")
	}
	wantErr(t, "missing", decode(t, `{"name":"sms","strategy":"sms","options":{"provider":"sms_gateway"}}`), true, "gateway_url is required")
}

func TestPasswordlessSecretsMerge(t *testing.T) {
	tok := strings.Repeat("t", 32)
	s := decode(t, `{"name":"sms","strategy":"sms","options":{"twilio_token":"`+tok+`","gateway_authentication":{"audience":"a","method":"bearer","secret":"gw"}}}`)
	CreateDefaults(s)
	if errs := NormalizeAPI(s); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := MergePasswordlessSecrets(s, nil)
	if got[SecretTwilioToken] != tok || got[SecretGatewaySecret] != "gw" {
		t.Fatalf("secrets = %v", got)
	}
	var c store.Connection
	Apply(s, &c)
	if _, ok := c.Extra["twilio_token"]; ok {
		t.Fatal("twilio_token left in Extra")
	}
	if ga, _ := c.Extra["gateway_authentication"].(map[string]any); ga == nil || ga["secret"] != nil {
		t.Fatalf("gateway_authentication = %v", c.Extra["gateway_authentication"])
	}
	// Update without secrets keeps them, with the stored names known to validation.
	p := decode(t, `{"name":"sms","strategy":"sms","options":{"gateway_authentication":{"audience":"b","method":"bearer"}}}`)
	p.StoredSecrets = map[string]bool{SecretTwilioToken: true, SecretGatewaySecret: true}
	if errs := NormalizeAPI(p); len(errs) > 0 {
		t.Fatal(errs)
	}
	got = MergePasswordlessSecrets(p, got)
	if got[SecretTwilioToken] != tok || got[SecretGatewaySecret] != "gw" {
		t.Fatalf("kept = %v", got)
	}
	// Without a stored secret the gateway secret is required.
	wantErr(t, "secret", decode(t, `{"name":"sms","strategy":"sms","options":{"gateway_authentication":{"audience":"b","method":"bearer"}}}`), true, "secret")
}
