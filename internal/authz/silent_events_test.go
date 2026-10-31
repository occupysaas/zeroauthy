package authz

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSilentAuthorizationOutcomeEvents(t *testing.T) {
	for _, tc := range []struct {
		name, body, oauthError string
		session                bool
		want                   []string
	}{
		{name: "no session", oauthError: "login_required", want: []string{"fsa"}},
		{name: "invalid session", oauthError: "login_required", want: []string{"fsa"}},
		{name: "disabled connection", session: true, oauthError: "login_required", want: []string{"fsa"}},
		{name: "consent", session: true, oauthError: "consent_required", want: []string{"fsa"}},
		{name: "interaction", session: true, oauthError: "interaction_required", want: []string{"fsa"}},
		{name: "action redirect", session: true, body: `api.redirect.sendUserTo('https://external.example/');`, oauthError: "interaction_required", want: []string{"actions_execution_failed", "fsa"}},
		{name: "action deny", session: true, body: `api.access.deny('refused');`, oauthError: "access_denied", want: []string{"f", "fsa"}},
		{name: "action throw", session: true, body: `throw Error('private failure');`, oauthError: "server_error", want: []string{"actions_execution_failed", "f", "fsa"}},
		{name: "session credential mask", session: true, oauthError: "login_required", want: []string{"fsa"}},
		{name: "issuance failure", session: true, oauthError: "server_error", want: []string{"fsa"}},
		{name: "success", session: true, want: []string{"ssa"}},
		{name: "ordinary login", want: []string{}},
		{name: "malformed", want: []string{}},
		{name: "pushed", oauthError: "login_required", want: []string{"fsa"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.body != "" {
				ae := newActionsEnv(t)
				e = ae.env
				ae.postLogin(t, "fails", tc.body)
			}
			recorder := logs.NewRecorder(e.st, logs.Config{}, slog.New(slog.DiscardHandler))
			next := e.srv
			e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(logs.WithRecorder(logscrub.WithCredentials(r.Context(), "q"), recorder)))
			})
			q := with(goodQuery(), "prompt", "none", "login_hint", "browser-user", "organization_name", "browser-org")
			var ck *http.Cookie
			if tc.session {
				ck = e.login(t, fixedNow().Add(-time.Minute))
			}
			switch tc.name {
			case "session credential mask":
				q.Set("max_age", "0")
				c, _ := e.st.Clients().Get(context.Background(), e.tenant.ID, "spa")
				c.Name = ck.Value
				if err := e.st.Clients().Update(context.Background(), c); err != nil {
					t.Fatal(err)
				}
			case "issuance failure":
				e.h.Store = failedIssueStore{e.st}
			case "invalid session":
				ck = &http.Cookie{Name: "za_session", Value: "invalid"}
			case "disabled connection":
				q = with(q, "client_id", "other-spa", "redirect_uri", "https://other.acme.test/cb")
			case "consent":
				q = url.Values{"client_id": {"partner-open"}, "redirect_uri": {"https://open.example/cb"}, "response_type": {"code"}, "audience": {"https://api.acme.test"}, "scope": {"read:things"}, "prompt": {"none"}}
			case "interaction":
				setOrgClient(t, e.st, e.tenant.ID, "spa", store.OrgUsageRequire, store.OrgBehaviorPreLoginPrompt)
			case "ordinary login":
				q.Del("prompt")
			case "malformed":
				q.Set("client_id", "missing")
			case "pushed":
				p := parParams()
				p["prompt"] = "none"
				q = parQuery("par-web", e.push(t, e.tenant.ID, "par-web", p, PARLifetime))
			}
			var response *httptest.ResponseRecorder
			if ck == nil {
				response = e.get(t, q)
			} else {
				response = e.get(t, q, ck)
			}
			if tc.oauthError != "" {
				loc := location(t, response)
				if loc.Query().Get("error") != tc.oauthError {
					t.Fatalf("error=%s", loc)
				}
			}
			if err := recorder.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			events, _, err := e.st.Logs().SearchLogs(context.Background(), e.tenant.ID, nil, store.LogPage{PerPage: 20, Ascending: true})
			if err != nil {
				t.Fatal(err)
			}
			codes := []string{}
			for _, event := range events {
				codes = append(codes, event.Type)
				var doc map[string]any
				_ = json.Unmarshal(event.Body, &doc)
				if event.ClientID == "" || doc["type"] != event.Type || doc["date"] == "" || doc["hostname"] != "acme.example.test" {
					t.Fatalf("metadata=%s", event.Body)
				}
				if tc.name == "session credential mask" && doc["client_name"] != logscrub.Marker {
					t.Fatalf("session credential=%s", event.Body)
				}
				if !tc.session && (event.UserID != "" || event.OrganizationID != "") {
					t.Fatalf("browser attribution=%s", event.Body)
				}
			}
			if !slices.Equal(codes, tc.want) {
				t.Fatalf("codes=%v want=%v", codes, tc.want)
			}
		})
	}
}

type failedIssueStore struct{ store.Store }

func (s failedIssueStore) AuthCodes() store.AuthCodes { return failedIssueCodes{s.Store.AuthCodes()} }

type failedIssueCodes struct{ store.AuthCodes }

func (s failedIssueCodes) Create(context.Context, *store.AuthCode) error {
	return errors.New("private issue error")
}
