package oauth

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestOrganizationEntitlementRevocation(t *testing.T) {
	for _, stage := range []string{"code exchange", "refresh"} {
		for _, revoke := range []string{"remove", "disable", "activate"} {
			t.Run(stage+"/"+revoke, func(t *testing.T) {
				f := newOrganizationFixture(t)
				ctx := context.Background()
				f.org.IsAppEntitlementActive = revoke != "activate"
				if err := f.st.Organizations().Update(ctx, f.org); err != nil {
					t.Fatal(err)
				}
				if revoke != "activate" {
					if err := f.st.OrganizationsII().PutClients(ctx, f.tid, f.org.ID, []store.OrganizationClient{{ClientID: "rt-spa", UseForMemberAccess: true}}); err != nil {
						t.Fatal(err)
					}
				}
				raw := f.code(t, f.org.ID)
				if stage == "refresh" {
					rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: codeForm(raw, "rt-spa", "https://app.acme.test/cb", pkceVerifier)})
					if rec.Code != 200 {
						t.Fatalf("initial exchange %d %v", rec.Code, body)
					}
					raw = body["refresh_token"].(string)
				}
				switch revoke {
				case "remove":
					if err := f.st.OrganizationsII().DeleteClients(ctx, f.tid, f.org.ID, []string{"rt-spa"}); err != nil {
						t.Fatal(err)
					}
				case "disable":
					if err := f.st.OrganizationsII().PutClients(ctx, f.tid, f.org.ID, []store.OrganizationClient{{ClientID: "rt-spa", UseForMemberAccess: false}}); err != nil {
						t.Fatal(err)
					}
				case "activate":
					f.org.IsAppEntitlementActive = true
					if err := f.st.Organizations().Update(ctx, f.org); err != nil {
						t.Fatal(err)
					}
				}
				var status int
				var body map[string]any
				if stage == "refresh" {
					status, body = f.refresh(t, refreshForm("rt-spa", raw))
				} else {
					rec, b := f.call(t, false, tokenCall{host: "acme.example.test", form: codeForm(raw, "rt-spa", "https://app.acme.test/cb", pkceVerifier)})
					status, body = rec.Code, b
				}
				if status != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil {
					t.Fatalf("revoked %d %v", status, body)
				}
			})
		}
	}
}
