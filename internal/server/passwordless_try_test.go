package server

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type passwordlessTryTransport func(*http.Request) (*http.Response, error)

func (f passwordlessTryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPasswordlessTryRoute(t *testing.T) {
	const (
		recipient = "try@example.test"
		connID    = "con_TryEmail"
		systemURL = "https://" + mgmtSystemHost + "/api/system/tenants/"
		path      = "acme/connections/" + connID + "/passwordless/try"
	)
	status := http.StatusAccepted
	var deliveries []string
	var wrapper keys.Wrapper
	h, st := newMgmtEnvWith(t, func(d *Deps) {
		wrapper = d.Wrapper
		renderer, err := email.NewRenderer()
		if err != nil {
			t.Fatal(err)
		}
		d.EmailService = &email.Service{
			Store: d.Store, Wrapper: wrapper, Renderer: renderer,
			Providers: &providers.Factory{HTTPClient: &http.Client{Transport: passwordlessTryTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://api.sendgrid.com/v3/mail/send" || r.Method != http.MethodPost ||
					r.Header.Get("Authorization") != "Bearer fixture-provider-key" {
					t.Errorf("delivery did not use the saved SendGrid provider")
				}
				defer r.Body.Close()
				data, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				deliveries = append(deliveries, string(data))
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("fixture provider diagnostics"))}, nil
			})}},
		}
	})
	ctx := context.Background()
	acme, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	acme.SettingsExtra = map[string]any{"flags": map[string]any{"enforce_client_authentication_on_passwordless_start": true}}
	if err := st.Tenants().Update(ctx, acme); err != nil {
		t.Fatal(err)
	}
	globex := &store.Tenant{ID: "globex-id", Name: "globex", Domains: []string{"globex.example.test"}}
	if err := st.Tenants().Create(ctx, globex); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*store.Client{
		{TenantID: acme.ID, ClientID: "try-app", Name: "Passwordless", TokenEndpointAuthMethod: store.AuthMethodClientSecretPost, GrantTypes: []string{clientrules.GrantPasswordlessOTP}},
		{TenantID: acme.ID, ClientID: "disabled-app", Name: "Disabled", GrantTypes: []string{clientrules.GrantPasswordlessOTP}},
		{TenantID: acme.ID, ClientID: "other-grant", Name: "Other grant", GrantTypes: []string{clientrules.GrantAuthorizationCode}},
	} {
		if err := st.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	conn := &store.Connection{TenantID: acme.ID, ID: connID, Name: "email", Strategy: "email",
		EnabledClients: []string{"try-app", "other-grant"},
		Extra: map[string]any{"email": map[string]any{
			"subject": "Saved connection settings",
			"body":    "fixture-code={{ code }} {{ link }}",
		}},
	}
	for _, c := range []*store.Connection{
		conn,
		{TenantID: acme.ID, ID: "con_TryDB", Name: "try-db", Strategy: store.StrategyDatabase},
		{TenantID: acme.ID, ID: "con_TrySMS", Name: "sms", Strategy: "sms", EnabledClients: []string{"try-app"}},
		{TenantID: globex.ID, ID: "con_OtherTenant", Name: "email", Strategy: "email"},
	} {
		if err := st.Connections().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := keys.SealEmailProvider(wrapper, acme.ID, "sendgrid", []byte(`{"api_key":"fixture-provider-key"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: acme.ID, Name: "sendgrid", Enabled: true,
		DefaultFrom: "sender@example.test", SealedCredentials: sealed}, 0); err != nil {
		t.Fatal(err)
	}
	all, userID := operatorToken(t, st, "passwordless-op@example.test")
	acmeOnly := mintTargetOperator(t, st, userID, []string{"acme"})
	globexOnly := mintTargetOperator(t, st, userID, []string{"globex"})
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: mustSystemID(t, st), UserID: userID, Tenants: []string{"acme"}}); err != nil {
		t.Fatal(err)
	}
	m2m := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	body := func(client, to, send string) map[string]string {
		return map[string]string{"client_id": client, "email": to, "send": send}
	}
	valid := body("try-app", recipient, "code")

	for _, tc := range []struct {
		name, url, token string
		body             map[string]string
		want             int
		code             string
	}{
		{"no token", systemURL + path, "", valid, 401, "invalid_token"},
		{"tenant M2M", systemURL + path, m2m, valid, 401, "invalid_token"},
		{"tenant host", "https://acme.example.test/api/system/tenants/" + path, acmeOnly, valid, 404, ""},
		{"signed grant", systemURL + path, globexOnly, valid, 403, "insufficient_scope"},
		{"persisted grant", systemURL + "globex/connections/con_OtherTenant/passwordless/try", all, valid, 403, "insufficient_scope"},
		{"foreign connection ID", systemURL + "acme/connections/con_OtherTenant/passwordless/try", acmeOnly, valid, 404, "inexistent_connection"},
		{"wrong strategy", systemURL + "acme/connections/con_TryDB/passwordless/try", acmeOnly, valid, 400, "invalid_body"},
		{"unknown app", systemURL + path, acmeOnly, body("unknown", recipient, "code"), 401, "invalid_client"},
		{"missing OTP grant", systemURL + path, acmeOnly, body("other-grant", recipient, "code"), 403, "unauthorized_client"},
		{"client not enabled", systemURL + path, acmeOnly, body("disabled-app", recipient, "code"), 400, "invalid_request"},
		{"invalid email", systemURL + path, acmeOnly, body("try-app", "bad-email", "code"), 400, "invalid_request"},
		{"provider override", systemURL + path, acmeOnly, map[string]string{"client_id": "try-app", "email": recipient, "send": "code", "gateway_url": "https://override.invalid"}, 400, "invalid_body"},
		{"SMS link", systemURL + "acme/connections/con_TrySMS/passwordless/try", acmeOnly, map[string]string{"client_id": "try-app", "phone_number": "+14155550123", "send": "link"}, 400, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, result := sendRaw(h, http.MethodPost, tc.url, tc.token, tc.body)
			if rec.Code != tc.want || errCode(result) != tc.code {
				t.Errorf("got %d %s, want %d %q", rec.Code, rec.Body, tc.want, tc.code)
			}
		})
	}
	t.Run("public start still requires client authentication", func(t *testing.T) {
		publicBody := body("try-app", recipient, "code")
		publicBody["connection"] = "email"
		rec, _ := sendRaw(h, http.MethodPost, "https://acme.example.test/passwordless/start", acmeOnly, publicBody)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("public start = %d %s", rec.Code, rec.Body)
		}
	})
	if len(deliveries) != 0 {
		t.Fatalf("refused calls delivered %d messages", len(deliveries))
	}

	t.Run("provider delivers code and magic link, response is empty", func(t *testing.T) {
		for _, send := range []string{"code", "link"} {
			rec, _ := sendRaw(h, http.MethodPost, systemURL+path, acmeOnly, body("try-app", recipient, send))
			if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
				t.Errorf("%s response = %d %s", send, rec.Code, rec.Body)
			}
		}
		if len(deliveries) != 2 {
			t.Fatalf("sent %d messages, want 2", len(deliveries))
		}
		for _, message := range deliveries {
			if !strings.Contains(message, recipient) || !strings.Contains(message, "Saved connection settings") {
				t.Error("message did not use the requested recipient and saved connection")
			}
		}
		if !regexp.MustCompile(`fixture-code=[0-9]{6}\b`).MatchString(deliveries[0]) {
			t.Error("the delivered email did not contain the generated code")
		}
		if !regexp.MustCompile(`https://acme\.example\.test/passwordless/verify_redirect\?[^" ]*verification_code=[A-Za-z0-9_-]+`).MatchString(deliveries[1]) {
			t.Error("the delivered email did not contain a magic link on the target tenant host")
		}
	})

	t.Run("provider failure is generic", func(t *testing.T) {
		status = http.StatusBadGateway
		before := len(deliveries)
		rec, result := sendRaw(h, http.MethodPost, systemURL+path, acmeOnly, body("try-app", "provider-failure@example.test", "code"))
		if rec.Code != http.StatusInternalServerError || errCode(result) != "server_error" ||
			strings.Contains(rec.Body.String(), "fixture provider diagnostics") || len(deliveries) != before+1 {
			t.Errorf("provider failure = %d %s with %d delivery attempts", rec.Code, rec.Body, len(deliveries)-before)
		}
		status = http.StatusAccepted
	})

	t.Run("start budget applies with retry-after", func(t *testing.T) {
		bounded := body("try-app", "budget@example.test", "code")
		for i := 0; i < phonerules.Limits.IdentifierSendsPerHour; i++ {
			rec, _ := sendRaw(h, http.MethodPost, systemURL+path, acmeOnly, bounded)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("send %d = %d %s", i+1, rec.Code, rec.Body)
			}
		}
		before := len(deliveries)
		rec, result := sendRaw(h, http.MethodPost, systemURL+path, acmeOnly, bounded)
		if rec.Code != http.StatusTooManyRequests || errCode(result) != "too_many_requests" ||
			rec.Header().Get("Retry-After") == "" || len(deliveries) != before {
			t.Errorf("exhausted budget = %d %s with %d delivery attempts", rec.Code, rec.Body, len(deliveries)-before)
		}
	})

	t.Run("missing SMS provider is generic", func(t *testing.T) {
		rec, result := sendRaw(h, http.MethodPost, systemURL+"acme/connections/con_TrySMS/passwordless/try", acmeOnly,
			map[string]string{"client_id": "try-app", "phone_number": "+14155550123", "send": "code"})
		if rec.Code != http.StatusBadRequest || errCode(result) != "sms_provider_error" {
			t.Errorf("missing SMS provider = %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("disabled signup refuses an unknown recipient", func(t *testing.T) {
		conn.DisableSignup = true
		if err := st.Connections().Update(ctx, conn); err != nil {
			t.Fatal(err)
		}
		before := len(deliveries)
		rec, result := sendRaw(h, http.MethodPost, systemURL+path, acmeOnly, body("try-app", "new@example.test", "code"))
		if rec.Code != http.StatusForbidden || errCode(result) != "access_denied" || len(deliveries) != before {
			t.Errorf("disabled signup = %d %s with %d delivery attempts", rec.Code, rec.Body, len(deliveries)-before)
		}
	})
}
