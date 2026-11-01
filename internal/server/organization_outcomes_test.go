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

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestMountedOrganizationDenialEvents(t *testing.T) {
	for _, route := range []string{"authorize", "par"} {
		t.Run(route, func(t *testing.T) {
			var recorder *logs.AsyncRecorder
			seedText := strings.Replace(flowSeed, "    clients:", `    clients:
      - client_id: confidential
        client_secret: q
        app_type: regular_web
        name: q
        grant_types: [authorization_code]
        callbacks: ["https://app.flow.test/cb"]`, 1)
			e := newFlowEnvSeed(t, seedText, func(d *Deps) {
				recorder = logs.NewRecorder(d.Store, logs.Config{}, slog.New(slog.DiscardHandler))
				d.Recorder = recorder
			})
			ctx := context.Background()
			tn, _ := e.st.Tenants().GetByName(ctx, "flow")
			tn.PushedAuthorizationRequestsSupported = true
			if err := e.st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			client, _ := e.st.Clients().Get(ctx, tn.ID, "confidential")
			client.OrganizationUsage = store.OrgUsageAllow
			if err := e.st.Clients().Update(ctx, client); err != nil {
				t.Fatal(err)
			}
			org := &store.Organization{TenantID: tn.ID, ID: "org_0000000000000001", Name: "q", DisplayName: "q", ThirdPartyClientAccess: "block", IsAppEntitlementActive: true}
			if err := e.st.Organizations().Create(ctx, org, nil); err != nil {
				t.Fatal(err)
			}
			q := url.Values{"client_id": {"confidential"}, "redirect_uri": {"https://app.flow.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "organization": {org.ID}}
			if route == "par" {
				q.Set("client_secret", "q")
				req, _ := http.NewRequest("POST", e.base+"/oauth/par", strings.NewReader(q.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp, body := mustDo(t, e.client(t), req)
				if resp.StatusCode != 403 {
					t.Fatalf("par=%d %s", resp.StatusCode, body)
				}
			} else {
				resp, _ := fetch(t, e.client(t), e.base+"/authorize?"+q.Encode())
				if resp.StatusCode != 302 {
					t.Fatalf("authorize=%d", resp.StatusCode)
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
			for _, event := range events {
				codes = append(codes, event.Type)
				if event.Type == "organization_access_denied" {
					if event.ClientID != client.ClientID || event.OrganizationID != org.ID || event.UserID != "" {
						t.Fatalf("attribution=%s", event.Body)
					}
					var doc map[string]any
					_ = json.Unmarshal(event.Body, &doc)
					if route == "par" && (doc["client_name"] != logscrub.Marker || doc["organization_name"] != logscrub.Marker) {
						t.Fatalf("short PAR credential=%s", event.Body)
					}
				}
			}
			want := []string{"organization_access_denied"}
			if route == "par" {
				want = append(want, "fpar")
			}
			if !slices.Equal(codes, want) {
				t.Fatalf("codes=%v want=%v", codes, want)
			}
		})
	}
}
