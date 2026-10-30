package dbconn

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"regexp"
	"strings"
	"testing"
)

func TestOrganizationPasswordChangeContext(t *testing.T) {
	ctx := context.Background()
	for _, scenario := range []string{"valid", "missing account", "missing org", "foreign org", "disabled", "null", "name"} {
		t.Run(scenario, func(t *testing.T) {
			e := newEnv(t)
			conn, err := e.st.Connections().GetByName(ctx, e.tenantID, "Username-Password-Authentication")
			if err != nil {
				t.Fatal(err)
			}
			org := &store.Organization{TenantID: e.tenantID, ID: "org_0000000000000014", Name: "reset-org", DisplayName: "Reset Team"}
			if err = e.st.Organizations().Create(ctx, org, []store.OrganizationConnection{{TenantID: e.tenantID, OrganizationID: org.ID, ConnectionID: conn.ID, ShowAsButton: true, IsEnabledSet: true, IsEnabled: scenario != "disabled", AssignMembershipOnLogin: true}}); err != nil {
				t.Fatal(err)
			}
			value := `"` + org.ID + `"`
			email := "alice@acme.test"
			want := 200
			switch scenario {
			case "missing account":
				email = "missing@acme.test"
			case "foreign org":
				if err := e.st.Tenants().Create(ctx, &store.Tenant{ID: "foreign", Name: "foreign"}); err != nil {
					t.Fatal(err)
				}
				foreign := &store.Organization{TenantID: "foreign", ID: "org_0000000000000088", Name: "foreign"}
				if err := e.st.Organizations().Create(ctx, foreign, nil); err != nil {
					t.Fatal(err)
				}
				value = `"` + foreign.ID + `"`
				want = 400
			case "missing org":
				value = `"org_0000000000000099"`
				want = 400
			case "disabled":
				want = 400
			case "null":
				value = "null"
				want = 400
				e.strict = false
			case "name":
				value = `"reset-org"`
				want = 400
			}
			code, _, body := e.post(t, "/dbconnections/change_password", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"`+email+`","organization":`+value+`}`)
			if code != want {
				t.Fatalf("status %d want %d: %s", code, want, body)
			}
			if want != 200 || scenario == "missing account" {
				if len(e.mail.sent) != 0 {
					t.Fatal("unexpected email")
				}
				return
			}
			if len(e.mail.sent) != 1 {
				t.Fatal("missing email")
			}
			if !strings.Contains(e.mail.sent[0].HTML, org.DisplayName) {
				t.Fatal("email branding missing")
			}
			token := regexp.MustCompile(`ticket=([A-Za-z0-9]+)`).FindStringSubmatch(e.mail.sent[0].Text)
			if len(token) != 2 {
				t.Fatal("missing link")
			}
			tk, err := e.st.PasswordResetTickets().GetByTokenHash(ctx, e.tenantID, secrets.HashToken(token[1]))
			if err != nil || tk.OrganizationID != org.ID {
				t.Fatalf("context lost: %+v %v", tk, err)
			}
			unknownCode, _, unknownBody := e.post(t, "/dbconnections/change_password", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"nobody@acme.test","organization":"`+org.ID+`"}`)
			if unknownCode != code || unknownBody != body || len(e.mail.sent) != 1 {
				t.Fatal("organization reset leaks account existence")
			}
			members, err := e.st.Organizations().Members(ctx, e.tenantID, org.ID, store.OrgPage{})
			if err != nil || len(members.Items) != 0 {
				t.Fatalf("membership changed: %+v %v", members, err)
			}
		})
	}
}
