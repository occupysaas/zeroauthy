package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestIngressRegistersCredentialsBeforeParseFailures(t *testing.T) {
	for _, tc := range []struct {
		name, media, body string
		par               bool
	}{
		{"token form", formType, "code=private-code&ticket=private-ticket&password=private-password&x=a&x=b", false},
		{"token JSON", "application/json", `{"code":"private-code","ticket":"private-ticket","password":"private-password","x":{}}`, false},
		{"PAR form", formType, "code=private-code&ticket=private-ticket&password=private-password&x=a&x=b", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.media)
			r.SetBasicAuth("client", url.QueryEscape("decoded:basic secret"))
			raw := r.Header.Get("Authorization")
			w := httptest.NewRecorder()
			if tc.par {
				parsePARRequest(w, r)
			} else {
				parseTokenRequest(w, r)
			}
			for _, v := range []string{"private-code", "private-ticket", "private-password", "decoded:basic secret", url.QueryEscape("decoded:basic secret"), raw} {
				if got := logscrub.MaskText(r.Context(), v); got != logscrub.Marker {
					t.Errorf("unregistered %q => %q", v, got)
				}
			}
		})
	}
}

func TestIngressStoredEventPrivacy(t *testing.T) {
	for _, name := range []string{"token success", "code success", "code failure", "PAR failure", "PAR partial failure", "PAR disabled"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			if name == "PAR disabled" {
				tn, err := f.st.Tenants().GetByName(ctx, "acme")
				if err != nil {
					t.Fatal(err)
				}
				tn.PushedAuthorizationRequestsSupported = false
				if err = f.st.Tenants().Update(ctx, tn); err != nil {
					t.Fatal(err)
				}
			}
			tid := f.tenantID(t, "acme")
			rec := logs.NewRecorder(f.st, logs.Config{}, nil)
			f.h.Recorder = rec
			secret := "p@ss:w+rd"
			id := "m2m-basic"
			path := "/oauth/token"
			form := cc(id, "", "audience", acmeAPI)
			handler := f.server(t, false)
			extra := "private-ticket"
			form.Set("ticket", extra)

			if strings.HasPrefix(name, "code") {
				id = "code-spa"
				secret = ""
				code := "invalid-private-code"
				if name == "code success" {
					code = f.issueCode(t, id, "https://app.acme.test/cb", acmeAPI, []string{"openid"}, pkceChallenge)
				}
				extra = code
				form = codeForm(code, id, "https://app.acme.test/cb", pkceVerifier)
			}
			if strings.HasPrefix(name, "PAR") {
				id = "par-basic"
				secret = "par-basic-secret"
				path = "/oauth/par"
				form = parForm("redirect_uri", "https://wrong.test/cb")
				form.Del("client_secret")
				form.Del("client_id")
				form.Set("ticket", extra)
				handler = tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthPar))
			}
			client, err := f.st.Clients().Get(ctx, tid, id)
			if err != nil {
				t.Fatal(err)
			}
			client.Name = "echo " + secret + extra
			if err = f.st.Clients().Update(ctx, client); err != nil {
				t.Fatal(err)
			}
			body := form.Encode()
			if strings.Contains(name, "partial failure") {
				body += "&x=a&x=b"
			}
			r := httptest.NewRequest("POST", "https://acme.example.test"+path, strings.NewReader(body))
			r.Header.Set("Content-Type", formType)
			r.Header.Set("User-Agent", "echo "+secret+extra)
			if secret != "" {
				r.SetBasicAuth(id, url.QueryEscape(secret))
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if err := rec.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			events, _, err := f.st.Logs().SearchLogs(ctx, tid, nil, store.LogPage{PerPage: 100})
			if err != nil || len(events) == 0 {
				t.Fatalf("events=%v err=%v status=%d", events, err, w.Code)
			}
			for _, event := range events {
				var doc map[string]any
				if err = json.Unmarshal(event.Body, &doc); err != nil {
					t.Fatal(err)
				}
				if doc["type"] != event.Type || doc["date"] == nil {
					t.Fatalf("schema corrupted %s", event.Body)
				}
				for _, v := range []string{secret, extra} {
					if v != "" && strings.Contains(string(event.Body), v) {
						t.Fatalf("credential leaked: %s", event.Body)
					}
				}
			}
		})
	}
}

func TestIngressBasicAndProtocolCredentialsInActionConsole(t *testing.T) {
	f := newActionsFixture(t)
	ctx := context.Background()
	c, err := f.st.Clients().Get(ctx, f.tid, "ropg")
	if err != nil {
		t.Fatal(err)
	}
	c.TokenEndpointAuthMethod = store.AuthMethodClientSecretBasic
	if err = f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	f.actions.PostLogin(t, f.tid, "ingress-console", `exports.onExecutePostLogin=()=>console.log('ropg-secret','private-code','private-ticket');`)
	form := pw("ropg", "", "alice@acme.test", "alice password 1")
	form.Set("code", "private-code")
	form.Set("ticket", "private-ticket")
	response, _ := f.call(t, true, tokenCall{host: acmeHost, form: form, basicID: "ropg", basicSecret: "ropg-secret"})
	if response.Code != http.StatusOK {
		t.Fatalf("response=%d %s", response.Code, response.Body)
	}
	executions, err := f.st.Actions().ListExecutions(ctx, f.tid, store.ExecutionFilter{})
	if err != nil || len(executions) != 1 {
		t.Fatalf("executions=%v err=%v", executions, err)
	}
	for _, result := range executions[0].Results {
		if len(result.Logs) == 0 {
			t.Fatal("missing console")
		}
		for _, line := range result.Logs {
			for _, secret := range []string{"ropg-secret", "private-code", "private-ticket"} {
				if strings.Contains(line, secret) {
					t.Fatalf("console leaked %q", line)
				}
			}
		}
	}
}
