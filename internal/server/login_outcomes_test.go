package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// These requests traverse the mounted tenant resolver, hosted forms, session
// cookies and authorization issuance. Removing the issuance event must fail
// both empty-engine cases, independently of Action execution logging.
func TestHostedLoginOutcomeEvents(t *testing.T) {
	for _, tc := range []struct {
		name, action, password string
		engine, signup         bool
		want                   []string
	}{
		{name: "no engine", password: "alice password 1", want: []string{"s", "s", "ssa"}},
		{name: "no bindings", engine: true, password: "alice password 1", want: []string{"s", "s", "ssa"}},
		{name: "action success", engine: true, action: `exports.onExecutePostLogin=()=>{};`, password: "alice password 1", want: []string{"s", "s", "ssa"}},
		{name: "action deny", engine: true, action: `exports.onExecutePostLogin=(e,a)=>a.access.deny('refused');`, password: "alice password 1", want: []string{"f"}},
		{name: "action throw", engine: true, action: `exports.onExecutePostLogin=()=>{throw Error('private failure')};`, password: "alice password 1", want: []string{"actions_execution_failed", "f"}},
		{name: "short credential", password: "s", want: []string{"s", "s", "ssa"}},
		{name: "signup", signup: true, password: "new password 1", want: []string{"s", "ss"}},
		{name: "signup denied after creation", signup: true, engine: true, action: `exports.onExecutePostLogin=(e,a)=>a.access.deny('refused');`, password: "new password 1", want: []string{"f", "ss"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var recorder *logs.AsyncRecorder
			var ae *actionstest.Env
			seedText := flowSeed

			e := newFlowEnvSeed(t, seedText, func(d *Deps) {
				recorder = logs.NewRecorder(d.Store, logs.Config{}, slog.New(slog.DiscardHandler))
				d.Recorder = recorder
				if tc.engine {
					ae = actionstest.NewOffline(t, d.Store, d.Wrapper)
					d.Actions = ae.Engine
				}
			})
			tn, err := e.st.Tenants().GetByName(ctx, "flow")
			if err != nil {
				t.Fatal(err)
			}
			if tc.password == "s" {
				user, err := e.st.Users().FindByLogin(ctx, tn.ID, "Username-Password-Authentication", "alice@flow.test")
				if err != nil {
					t.Fatal(err)
				}
				hash, err := secrets.Hash(tc.password)
				if err != nil {
					t.Fatal(err)
				}
				if err := e.st.Users().SetPasswordHash(ctx, tn.ID, user.UserID, "Username-Password-Authentication", hash, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if tc.action != "" {
				ae.PostLogin(t, tn.ID, "outcome", tc.action)
			}
			client, err := e.st.Clients().Get(ctx, tn.ID, "spa")
			if err != nil {
				t.Fatal(err)
			}
			client.Name = tc.password // registered values are hidden even in attribution
			if err := e.st.Clients().Update(ctx, client); err != nil {
				t.Fatal(err)
			}
			c := e.client(t)
			resp, _ := fetch(t, c, authorizeURL(e.base))
			loginURL, err := resp.Location()
			if err != nil {
				t.Fatal(err)
			}
			path := "/u/login"
			if tc.signup {
				path = "/u/signup"
				loginURL.Path = path
			}
			_, page := fetch(t, c, loginURL.String())
			csrf := csrfRe.FindStringSubmatch(page)
			if csrf == nil {
				t.Fatalf("missing form: %s", page)
			}
			form := url.Values{"hosted_revision": {hostedRevision(page)}, "state": {loginURL.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"alice@flow.test"}, "password": {tc.password}}
			if tc.signup {
				form.Set("email", "new@flow.test")
			}
			req, _ := http.NewRequest("POST", e.base+path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("User-Agent", "Outcome browser")
			resp, body := mustDo(t, c, req)
			cb, err := resp.Location()
			if err != nil || resp.StatusCode != 302 || cb.Host != "app.flow.test" {
				t.Fatalf("outcome=%d %v %s", resp.StatusCode, cb, body)
			}
			denied := slices.Contains(tc.want, "f")
			if (cb.Query().Get("code") == "") != denied {
				t.Fatalf("code/error=%v", cb)
			}
			if !denied && !tc.signup {
				client.Name = "Flow app"
				if err := e.st.Clients().Update(ctx, client); err != nil {
					t.Fatal(err)
				}
				for _, prompt := range []string{"", "none"} {
					resp, body = fetch(t, c, authorizeURL(e.base, "prompt", prompt))
					cb, err = resp.Location()
					if err != nil || cb.Query().Get("code") == "" {
						t.Fatalf("session reuse=%d %v %s", resp.StatusCode, cb, body)
					}
				}
			}
			if err := recorder.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			events, _, err := e.st.Logs().SearchLogs(ctx, tn.ID, nil, store.LogPage{PerPage: 20, Ascending: true})
			if err != nil {
				t.Fatal(err)
			}
			codes := []string{}
			for i, event := range events {
				codes = append(codes, event.Type)
				var doc map[string]any
				if err := json.Unmarshal(event.Body, &doc); err != nil {
					t.Fatal(err)
				}
				expected := func(v string) string {
					if i == 0 && tc.password == "s" {
						return strings.ReplaceAll(v, "s", logscrub.Marker)
					}
					return v
				}
				if doc["type"] != event.Type || doc["date"] == "" || event.UserID == "" || event.ClientID != expected("spa") || doc["hostname"] != strings.TrimPrefix(e.base, "https://") {
					t.Fatalf("attribution=%s", event.Body)
				}
				if i == 0 && (event.ConnectionID == "" || doc["connection"] != expected("Username-Password-Authentication") || doc["strategy"] != "auth0" || doc["strategy_type"] != expected("database") || doc["user_agent"] != expected("Outcome browser") || doc["client_name"] != logscrub.Marker) {
					t.Fatalf("resolved form attribution=%s", event.Body)
				}
				if i == 0 && tc.password != "s" && strings.Contains(string(event.Body), tc.password) {
					t.Fatalf("credential leaked: %s", event.Body)
				}
				if tc.action != "" && event.Type != "ss" {
					details, _ := doc["details"].(map[string]any)
					actions, _ := details["actions"].(map[string]any)
					ids, _ := actions["executions"].([]any)
					if len(ids) != 1 {
						t.Fatalf("execution links=%s", event.Body)
					}
				}
			}
			if !slices.Equal(codes, tc.want) {
				t.Fatalf("codes=%v want=%v", codes, tc.want)
			}
			stats, err := e.st.Logs().DailyStats(ctx, tn.ID, time.Now().UTC().Add(-24*time.Hour), time.Now().UTC().Add(24*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			var logins, signups int
			for _, day := range stats {
				logins += day.Logins
				signups += day.Signups
			}
			wantLogins, wantSignups := 0, 0
			for _, code := range tc.want {
				if code == "s" || code == "ssa" {
					wantLogins++
				}
				if code == "ss" {
					wantSignups++
				}
			}
			if logins != wantLogins || signups != wantSignups {
				t.Fatalf("stats logins=%d signups=%d", logins, signups)
			}
		})
	}
}
