package login

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The post-login picker resolves client/connection before inserting membership.
func TestOrganizationPickerMembershipEventAttribution(t *testing.T) {
	e := newEnv(t)
	org, conn, user := organizationFixture(t, e, store.OrgBehaviorPostLoginPrompt, true, false)
	ctx := context.Background()
	client, err := e.st.Clients().Get(ctx, org.TenantID, "spa")
	if err != nil {
		t.Fatal(err)
	}
	client.Name = "Picker app"
	if err := e.st.Clients().Update(ctx, client); err != nil {
		t.Fatal(err)
	}
	capture := &eventRecorder{}
	e.h.Recorder = capture
	old := e.srv
	e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		old.ServeHTTP(w, r.WithContext(logs.WithRecorder(r.Context(), capture)))
	})
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {user.Email}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatal("completion", loc, rec.Body)
	}
	member, err := e.st.Organizations().IsMember(ctx, org.TenantID, org.ID, user.UserID)
	if err != nil || !member {
		t.Fatal(member, err)
	}
	var got *logs.Event
	for i := range capture.events {
		if capture.events[i].Type == "organization_member_added" {
			got = &capture.events[i]
		}
	}
	if got == nil || got.ClientID != "spa" || got.ClientName != "Picker app" || got.UserID != user.UserID || got.ConnectionID != conn.ID || got.Connection != conn.Name || got.OrganizationID != org.ID || got.Strategy != "auth0" {
		t.Fatalf("membership attribution: %+v; all=%+v", got, capture.events)
	}
}
