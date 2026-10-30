package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestOrganizationPasswordChangeContext(t *testing.T) {
	for _, scenario := range []string{"valid", "missing", "foreign", "missing client", "missing connection", "disabled", "null", "result URL"} {
		t.Run(scenario, func(t *testing.T) {
			e := newUsersEnv(t)
			ctx := context.Background()
			u := e.mustCreate(t, map[string]any{"email": "reset@x.test"})
			org := &store.Organization{TenantID: e.tn.ID, ID: "org_0000000000000014", Name: "reset-org"}
			if err := e.st.Organizations().Create(ctx, org, []store.OrganizationConnection{{TenantID: e.tn.ID, OrganizationID: org.ID, ConnectionID: e.conn.ID, ShowAsButton: true, IsEnabledSet: true, IsEnabled: scenario != "disabled"}}); err != nil {
				t.Fatal(err)
			}
			body := map[string]any{"user_id": u["user_id"], "organization_id": org.ID}
			want := 201
			switch scenario {
			case "foreign":
				if err := e.st.Tenants().Create(ctx, &store.Tenant{ID: "foreign", Name: "foreign"}); err != nil {
					t.Fatal(err)
				}
				foreign := &store.Organization{TenantID: "foreign", ID: "org_0000000000000088", Name: "foreign"}
				if err := e.st.Organizations().Create(ctx, foreign, nil); err != nil {
					t.Fatal(err)
				}
				body["organization_id"] = foreign.ID
				want = 404
			case "missing client":
				body["client_id"] = "missing"
				want = 404
			case "missing connection":
				delete(body, "user_id")
				body["email"] = "reset@x.test"
				body["connection_id"] = "missing"
				want = 404
			case "missing":
				body["organization_id"] = "org_0000000000000099"
				want = 404
			case "disabled":
				want = 404
			case "null":
				body["organization_id"] = nil
				want = 400
			case "result URL":
				body["result_url"] = "https://app.test/done"
				want = 400
			}
			rec, out := e.passwordTicket(t, body)
			if rec.Code != want {
				t.Fatalf("got %d want %d: %s", rec.Code, want, rec.Body)
			}
			if want == 404 && out["errorCode"] != "not_found" {
				t.Fatalf("invalid reference code: %v", out)
			}
			if want == 201 {
				tk := e.resetTicket(t, out["ticket"].(string))
				if tk.OrganizationID != org.ID {
					t.Fatalf("lost context: %+v", tk)
				}
			}
		})
	}
}
