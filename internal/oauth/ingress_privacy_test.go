package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

// Every credential accepted by the new grants must be registered by the body
// parser, including on returns that never reach authentication or grant code.
func TestMFAIngressRegistersCredentials(t *testing.T) {
	credentials := url.Values{
		"mfa_token": {"opaque-ingress-MFA-token"}, "otp": {"246802"}, "oob_code": {"opaque-ingress-OOB-handle"},
		"binding_code": {"123456"}, "recovery_code": {"ABCDEFGHIJKLMNOPQRSTUVWX"},
	}
	for _, media := range []string{formType, "application/json"} {
		for _, partial := range []bool{false, true} {
			name := media + "/valid"
			if partial {
				name = media + "/parse failure"
			}
			t.Run(name, func(t *testing.T) {
				body := credentials.Encode()
				if media == "application/json" {
					values := map[string]any{}
					for key, v := range credentials {
						values[key] = v[0]
					}
					raw, _ := json.Marshal(values)
					body = string(raw)
					if partial {
						body = body[:len(body)-1] + `,"zz_invalid":{}}`
					}
				} else if partial {
					body += "&x=a&x=b"
				}
				r := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(body))
				r.Header.Set("Content-Type", media)
				_, failure := parseTokenRequest(httptest.NewRecorder(), r)
				if partial && failure == nil || !partial && failure != nil {
					t.Fatalf("parse result=%v", failure)
				}
				for key, v := range credentials {
					if got := logscrub.MaskText(r.Context(), v[0]); got != logscrub.Marker {
						t.Errorf("unregistered MFA credential %s: %q", key, got)
					}
				}
			})
		}
	}
}

type unavailableIngressLogs struct{ store.Store }

func (s unavailableIngressLogs) Logs() store.Logs { return store.UnimplementedLogs{} }

func TestMFAIngressFailurePrivacy(t *testing.T) {
	for _, media := range []string{formType, "application/json"} {
		for _, failure := range []string{"invalid client", "unauthorized grant"} {
			for _, sink := range []string{"store", "slog fallback"} {
				t.Run(media+"/"+failure+"/"+sink, func(t *testing.T) {
					f := newFixture(t)
					ctx := context.Background()
					tid := f.tenantID(t, "acme")
					binding := "123456"
					form := url.Values{"grant_type": {oobGrant}, "client_id": {binding}, "mfa_token": {"opaque-failure-MFA-token"}, "otp": {"246802"}, "oob_code": {"opaque-failure-OOB-handle"}, "binding_code": {binding}, "recovery_code": {"ABCDEFGHIJKLMNOPQRSTUVWX"}}
					status, code := 401, "invalid_client"
					if failure == "unauthorized grant" {
						form.Set("client_id", "web")
						form.Set("client_secret", "web-secret")
						status, code = 403, "unauthorized_client"
					}
					// Attribute the supplied credentials to ordinary, non-secret-named fields.
					// Value masking, rather than key masking, must protect these fields.
					values := []string{form.Get("mfa_token"), form.Get("otp"), form.Get("oob_code"), binding, form.Get("recovery_code")}
					agent := "credentials=" + strings.Join(values, ";")
					var output bytes.Buffer
					f.h.Log = slog.New(logscrub.Handler(slog.NewJSONHandler(&output, nil)))
					var recordingStore store.Store = f.st
					if sink == "slog fallback" {
						recordingStore = unavailableIngressLogs{f.st}
					}
					recorder := logs.NewRecorder(recordingStore, logs.Config{Now: fixedNow}, f.h.Log)
					f.h.Recorder = recorder
					body := form.Encode()
					if media == "application/json" {
						values := map[string]any{}
						for key, v := range form {
							values[key] = v[0]
						}
						raw, _ := json.Marshal(values)
						body = string(raw)
					}
					r := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(body))
					r.Header.Set("Content-Type", media)
					r.Header.Set("User-Agent", agent)
					r = r.WithContext(logs.WithEvent(r.Context(), logs.Event{UserName: "binding=" + binding}))
					handler := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						f.h.OauthToken(w, r)
						// Early client/grant rejection intentionally has no grant-outcome
						// emitter. Exercise the real Recorder and slog sinks at that request
						// boundary without adding new production emission behavior.
						outcomeCtx := logs.WithEvent(r.Context(), logs.FromRequest(r))
						logs.RecordEvent(outcomeCtx, recorder, logs.Event{TenantID: tid, Type: "feoobft"})
						f.h.log().InfoContext(outcomeCtx, "test token rejection boundary", "user_name", "binding="+binding, "user_agent", agent)
					}))
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					var response map[string]any
					_ = json.Unmarshal(w.Body.Bytes(), &response)
					if w.Code != status || response["error"] != code {
						t.Fatalf("rejection=%d %v", w.Code, response)
					}
					if err := recorder.Flush(ctx); err != nil {
						t.Fatal(err)
					}
					var event map[string]any
					if sink == "store" {
						rows, _, err := f.st.Logs().SearchLogs(ctx, tid, nil, store.LogPage{PerPage: 100})
						if err != nil || len(rows) != 1 {
							t.Fatalf("events=%d err=%v", len(rows), err)
						}
						if err = json.Unmarshal(rows[0].Body, &event); err != nil {
							t.Fatal(err)
						}
					}
					sawDiagnostic, sawBoundary := false, false
					for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
						var doc map[string]any
						if err := json.Unmarshal([]byte(line), &doc); err != nil {
							t.Fatal(err)
						}
						// Time is sink-generated; inspect actual attributed payloads separately
						// so a coincidental six-digit timestamp cannot cause a false leak.
						delete(doc, "time")
						if doc["msg"] == "client authentication failed: unknown client" {
							sawDiagnostic = true
							if doc["client_id"] != logscrub.Marker {
								t.Errorf("client authentication leaked binding code: %v", doc)
							}
						}
						if doc["msg"] == "test token rejection boundary" {
							sawBoundary = true
							if doc["user_name"] != "binding="+logscrub.Marker {
								t.Errorf("rejection boundary leaked binding code: %v", doc)
							}
						}
						if doc["msg"] == "tenant log event" {
							event, _ = doc["event"].(map[string]any)
						}
						raw, _ := json.Marshal(doc)
						for _, value := range values {
							if strings.Contains(string(raw), value) {
								t.Errorf("credential %q leaked to slog", value)
							}
						}
					}
					if failure == "invalid client" && !sawDiagnostic {
						t.Error("actual unknown-client diagnostic missing")
					}
					if !sawBoundary {
						t.Error("rejection boundary slog missing")
					}
					if event == nil || event["type"] != "feoobft" || event["user_name"] != "binding="+logscrub.Marker || !strings.Contains(fmt.Sprint(event["user_agent"]), "credentials=") {
						t.Errorf("enriched masked outcome missing: %v", event)
					}
					raw, _ := json.Marshal(event)
					for _, value := range values {
						if strings.Contains(string(raw), value) {
							t.Errorf("credential %q leaked through Recorder", value)
						}
					}
				})
			}
		}
	}
}
