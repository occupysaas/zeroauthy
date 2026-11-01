package orglogin

import (
	"context"
	"errors"
	"testing"
)

// Failure after identity resolution must retain that identity, even on rollback.
func TestInvitationFailureEventAttribution(t *testing.T) {
	for _, reason := range []string{"unverified", "wrong email", "deleted role"} {
		t.Run(reason, func(t *testing.T) {
			st, in := acceptanceFixture(t)
			ctx := context.Background()
			user, err := st.Users().Get(ctx, in.TenantID, in.UserID)
			if err != nil {
				t.Fatal(err)
			}
			user.Name = "Invited Person"
			if reason == "unverified" {
				user.EmailVerified = false
			}
			if reason == "wrong email" {
				user.Email = "wrong@example.test"
			}
			if err := st.Users().Update(ctx, user); err != nil {
				t.Fatal(err)
			}
			if reason == "deleted role" {
				if err := st.RBAC().DeleteRole(ctx, in.TenantID, "role"); err != nil {
					t.Fatal(err)
				}
			}
			capture := &eventRecorder{}
			in.Recorder = capture
			_, err = AcceptInvitation(ctx, st, in)
			if err == nil || reason != "deleted role" && !errors.Is(err, ErrInvitationIdentity) {
				t.Fatalf("acceptance=%v", err)
			}
			if len(capture.events) != 1 {
				t.Fatalf("events=%+v", capture.events)
			}
			got := capture.events[0]
			clientName, orgName := "app", "org"
			if reason == "unverified" {
				clientName, orgName = "", ""
			}
			if got.Type != "fi" || got.TenantID != "t" || got.ClientID != "client" || got.ClientName != clientName || got.OrganizationID != in.OrganizationID || got.OrganizationName != orgName || got.UserID != "auth0|u" || got.UserName != "Invited Person" || got.ConnectionID != "con_0000000000000001" || got.Connection != "db" || got.Strategy != "auth0" || got.StrategyType != "database" {
				t.Fatalf("event=%+v", got)
			}
			member, err := st.Organizations().IsMember(ctx, in.TenantID, in.OrganizationID, in.UserID)
			if err != nil || member {
				t.Fatalf("membership=%v err=%v", member, err)
			}
		})
	}
}
