package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestLogoutOutcomeEvents(t *testing.T) {
	for _, tc := range []struct {
		name, route, want               string
		session, fail, invalid, confirm bool
		failDelete                      bool
	}{
		{name: "v2 ended", route: "/v2/logout", session: true, want: "slo"},
		{name: "v2 idempotent", route: "/v2/logout", want: "slo"},
		{name: "v2 failure", route: "/v2/logout", session: true, fail: true, want: "flo"},
		{name: "v2 write failure", route: "/v2/logout", session: true, failDelete: true, want: "flo"},
		{name: "rp write failure", route: "/oidc/logout", session: true, failDelete: true, confirm: true, want: "flo"},
		{name: "v2 invalid", route: "/v2/logout", session: true, invalid: true},
		{name: "rp pending", route: "/oidc/logout", session: true},
		{name: "rp confirmed", route: "/oidc/logout", session: true, confirm: true, want: "slo"},
		{name: "rp idempotent", route: "/oidc/logout", want: "slo"},
		{name: "rp failure", route: "/oidc/logout", session: true, fail: true, want: "flo"},
		{name: "rp invalid", route: "/oidc/logout", session: true, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wrap func(store.Store) store.Store
			if tc.fail {
				wrap = func(s store.Store) store.Store { return failingSessionStore{s} }
			}
			if tc.failDelete {
				wrap = func(s store.Store) store.Store { return deleteFailureStore{s} }
			}
			e := newLogoutEnv(t, wrap)
			recorder := logs.NewRecorder(e.st, logs.Config{}, slog.New(slog.DiscardHandler))
			next := e.srv
			e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(logs.WithRecorder(logscrub.WithCredentials(r.Context(), "x"), recorder)))
			})
			var cookies []*http.Cookie
			if tc.session {
				ck, _ := e.login(t)
				cookies = append(cookies, ck)
			}
			q := url.Values{"client_id": {"spa"}}
			if tc.invalid {
				if tc.route == "/v2/logout" {
					q.Set("returnTo", "https://evil.test/?private=x")
				} else {
					q.Set("post_logout_redirect_uri", "https://evil.test/?private=x")
				}
			}
			response := e.do(t, "GET", tc.route+"?"+q.Encode(), nil, cookies...)
			if tc.confirm {
				m := csrfField.FindStringSubmatch(response.Body.String())
				if m == nil {
					t.Fatal("missing confirmation")
				}
				q.Set("confirm", "yes")
				q.Set("csrf", m[1])
				for _, c := range response.Result().Cookies() {
					if c.Name == logoutCSRFCookie {
						cookies = append(cookies, c)
					}
				}
				response = e.do(t, "POST", tc.route, q, cookies...)
			}
			if tc.invalid && response.Code != 400 {
				t.Fatalf("invalid=%d", response.Code)
			}
			if (tc.fail || tc.failDelete) && response.Code != 500 {
				t.Fatalf("failed=%d", response.Code)
			}
			if err := recorder.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			events, _, err := e.st.Logs().SearchLogs(context.Background(), "ten_a", nil, store.LogPage{PerPage: 20})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if len(events) != 0 {
					t.Fatalf("premature events=%+v", events)
				}
				return
			}
			if len(events) != 1 || events[0].Type != tc.want {
				t.Fatalf("events=%+v want=%s", events, tc.want)
			}
			event := events[0]
			var doc map[string]any
			_ = json.Unmarshal(event.Body, &doc)
			if event.ClientID != "spa" || doc["date"] == "" || doc["type"] != tc.want || event.ID == "" {
				t.Fatalf("metadata=%s", event.Body)
			}
			if tc.session && !tc.fail && !tc.failDelete && (event.UserID != "auth0|1" || doc["connection"] != "DB") {
				t.Fatalf("ended metadata=%s", event.Body)
			}
			if !tc.session && event.UserID != "" {
				t.Fatalf("invented user=%s", event.Body)
			}
			if strings.Contains(string(event.Body), "private=") || strings.Contains(string(event.Body), "database unavailable") {
				t.Fatalf("raw details=%s", event.Body)
			}
		})
	}
}

type deleteFailureStore struct{ store.Store }

func (s deleteFailureStore) Sessions() store.Sessions {
	return deleteFailureSessions{s.Store.Sessions()}
}

type deleteFailureSessions struct{ store.Sessions }

func (s deleteFailureSessions) Delete(context.Context, string, string) error {
	return errors.New("private failed write")
}

func TestLogoutRequestCredentialMasks(t *testing.T) {
	for _, route := range []string{"/v2/logout", "/oidc/logout"} {
		t.Run(route, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			recorder := logs.NewRecorder(e.st, logs.Config{}, slog.New(slog.DiscardHandler))
			next := e.srv
			e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(logs.WithRecorder(r.Context(), recorder)))
			})
			secret := "x"
			var cookies []*http.Cookie
			if route == "/v2/logout" {
				ck, _ := e.login(t)
				secret = ck.Value
				cookies = append(cookies, ck)
			}
			client, _ := e.st.Clients().Get(context.Background(), "ten_a", "spa")
			client.Name = secret
			if err := e.st.Clients().Update(context.Background(), client); err != nil {
				t.Fatal(err)
			}
			response := e.do(t, "GET", route+"?client_id=spa&logout_hint="+url.QueryEscape(secret), nil, cookies...)
			if response.Code != 302 && response.Code != 200 {
				t.Fatalf("status=%d", response.Code)
			}
			if err := recorder.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			events, _, _ := e.st.Logs().SearchLogs(context.Background(), "ten_a", nil, store.LogPage{PerPage: 20})
			if len(events) != 1 {
				t.Fatalf("events=%+v", events)
			}
			var doc map[string]any
			_ = json.Unmarshal(events[0].Body, &doc)
			if doc["client_name"] != logscrub.Marker || doc["type"] != "slo" || doc["date"] == "" {
				t.Fatalf("credential leak=%s", events[0].Body)
			}
		})
	}
}
