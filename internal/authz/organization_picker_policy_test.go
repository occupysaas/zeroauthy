package authz

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Counting a blocked organization before membership priority, uniqueness or
// truncation must not hide a route that admits the current application.
func TestOrganizationPickerClientPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		firstParty, auto, blockedOnly bool
		blocked                       int
		wantHosted                    bool
	}{
		{name: "allowed member and blocked member", blocked: 1},
		{name: "allowed auto and blocked member", auto: true, blocked: 1},
		{name: "twenty blocked members before allowed member", blocked: 20},
		{name: "blocked only", blocked: 1, blockedOnly: true},
		{name: "first party blocked only", firstParty: true, blocked: 1, blockedOnly: true},
		{name: "first party keeps both members", firstParty: true, blocked: 1, wantHosted: true},
	} {
		for _, silent := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/silent=%v", tc.name, silent), func(t *testing.T) {
				ctx := context.Background()
				e := newEnv(t)
				sess := e.session(t, e.login(t, fixedNow()))
				c, err := e.st.Clients().Get(ctx, e.tenant.ID, "spa")
				if err != nil {
					t.Fatal(err)
				}
				c.IsFirstParty = tc.firstParty
				c.OrganizationUsage = store.OrgUsageRequire
				c.OrganizationRequireBehavior = store.OrgBehaviorPostLoginPrompt
				if err = e.st.Clients().Update(ctx, c); err != nil {
					t.Fatal(err)
				}
				conn, err := e.st.Connections().GetByName(ctx, e.tenant.ID, sess.Connection)
				if err != nil {
					t.Fatal(err)
				}
				conn.IsDomainConnection = true
				if err = e.st.Connections().Update(ctx, conn); err != nil {
					t.Fatal(err)
				}
				link := func(o *store.Organization, auto bool) {
					t.Helper()
					if err := e.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: e.tenant.ID, OrganizationID: o.ID, ConnectionID: conn.ID, ShowAsButton: true, AssignMembershipOnLogin: auto}, true); err != nil {
						t.Fatal(err)
					}
					if !auto {
						if err := e.st.Organizations().AddMembers(ctx, e.tenant.ID, o.ID, []string{sess.UserID}); err != nil {
							t.Fatal(err)
						}
					}
				}
				wantID := ""
				if !tc.blockedOnly {
					allowed := addOrg(t, e.st, e.tenant.ID, "", "zz-allowed", "allow")
					link(allowed, tc.auto)
					wantID = allowed.ID
				}
				for i := 0; i < tc.blocked; i++ {
					o := addOrg(t, e.st, e.tenant.ID, "", fmt.Sprintf("aa-blocked-%02d", i), "block")
					link(o, false)
					if tc.blockedOnly && tc.firstParty {
						wantID = o.ID
					}
				}
				fr := flowReq{Request: Request{OrgMode: OrgPickAfter}}
				if silent {
					fr.Prompt = "none"
				}
				hosted, oerr := e.h.organizationSession(httptest.NewRecorder(), httptest.NewRequest("GET", "https://acme.example.test/authorize", nil), e.res(), c, &fr, sess)
				wantError := ""
				if tc.blockedOnly && !tc.firstParty {
					wantError = "access_denied"
					if silent {
						wantError = "interaction_required"
					}
				}
				if tc.wantHosted && silent {
					wantError = "interaction_required"
				}
				if wantError != "" {
					if oerr == nil || oerr.Code != wantError || hosted || fr.OrgID != "" {
						t.Fatalf("hosted=%v error=%v org=%q; want %s without binding", hosted, oerr, fr.OrgID, wantError)
					}
					return
				}
				if oerr != nil || hosted != tc.wantHosted {
					t.Fatalf("hosted=%v error=%v; want hosted=%v", hosted, oerr, tc.wantHosted)
				}
				if tc.wantHosted {
					if fr.OrgID != "" {
						t.Fatalf("ambiguous picker bound %q", fr.OrgID)
					}
					return
				}
				if fr.OrgID != wantID || fr.OrgMode != OrgFixed {
					t.Fatalf("binding=%q/%q; want %q/fixed", fr.OrgID, fr.OrgMode, wantID)
				}
				member, err := e.st.Organizations().IsMember(ctx, e.tenant.ID, wantID, sess.UserID)
				if err != nil || !member {
					t.Fatalf("selected membership=%v err=%v", member, err)
				}
			})
		}
	}
}
