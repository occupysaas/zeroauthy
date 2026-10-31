package authz

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type failingOrganizationEventStore struct {
	store.Store
	afterLookup bool
}

func (s failingOrganizationEventStore) Organizations() store.Organizations {
	return failingOrganizationEventRepo{s.Store.Organizations(), s.afterLookup}
}

type failingOrganizationEventRepo struct {
	store.Organizations
	afterLookup bool
}

func (s failingOrganizationEventRepo) Get(ctx context.Context, tid, id string) (*store.Organization, error) {
	if s.afterLookup {
		org, err := s.Organizations.Get(ctx, tid, id)
		if err == nil {
			org.IsAppEntitlementActive = true
		}
		return org, err
	}
	return nil, errors.New("private database error")
}
func (s failingOrganizationEventStore) CheckOrganizationsIISupport(context.Context) error {
	return store.ErrOrganizationsIIUnavailable
}
func (s failingOrganizationEventStore) OrganizationsIISupported() bool { return !s.afterLookup }

func TestOrganizationAccessDeniedEvents(t *testing.T) {
	for _, name := range []string{"third party", "member client", "allowed", "missing", "foreign", "usage deny", "lookup failure", "unavailable"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			org := addOrg(t, f.st, f.tenant.ID, "org_0000000000000001", "acme-q", "")
			c := &store.Client{TenantID: f.tenant.ID, ClientID: "client", Name: "app-q", IsFirstParty: true, OrganizationUsage: store.OrgUsageAllow}
			if err := f.st.Clients().Create(ctx, c); err != nil {
				t.Fatal(err)
			}
			raw := org.ID
			var st store.Store = f.st
			want := ""
			if name == "third party" {
				c.IsFirstParty = false
				want = "access_denied"
			}
			if name == "member client" {
				org.IsAppEntitlementActive = true
				if err := f.st.Organizations().Update(ctx, org); err != nil {
					t.Fatal(err)
				}
				want = "access_denied"
			}
			switch name {
			case "missing":
				raw = "org_0000000000000000"
				want = "invalid_request"
			case "foreign":
				other, _ := f.st.Tenants().GetByName(ctx, "globex")
				raw = addOrg(t, f.st, other.ID, "", "foreign", "").ID
				want = "invalid_request"
			case "usage deny":
				c.OrganizationUsage = store.OrgUsageDeny
				want = "invalid_request"
			case "lookup failure":
				st = failingOrganizationEventStore{Store: f.st}
				want = "server_error"
			case "unavailable":
				st = failingOrganizationEventStore{Store: f.st, afterLookup: true}
				want = "server_error"
			}
			recorder := logs.NewRecorder(f.st, logs.Config{}, slog.New(slog.DiscardHandler))
			ctx = logs.WithRecorder(logscrub.WithCredentials(ctx, "q"), recorder)
			_, e := ResolveOrganization(ctx, st, tenant.Resolved{Tenant: f.tenant, Host: "acme.example.test"}, c, raw)
			if want == "" && e != nil || want != "" && (e == nil || e.Code != want) {
				t.Fatalf("err=%+v want=%s", e, want)
			}
			if err := recorder.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			events, _, err := f.st.Logs().SearchLogs(context.Background(), f.tenant.ID, nil, store.LogPage{PerPage: 20})
			if err != nil {
				t.Fatal(err)
			}
			if want != "access_denied" {
				if len(events) != 0 {
					t.Fatalf("not a policy refusal=%+v", events)
				}
				return
			}
			if len(events) != 1 || events[0].Type != "organization_access_denied" || events[0].OrganizationID != org.ID || events[0].ClientID != c.ClientID || events[0].UserID != "" {
				t.Fatalf("events=%+v", events)
			}
			var doc map[string]any
			_ = json.Unmarshal(events[0].Body, &doc)
			if doc["organization_name"] != "acme-"+logscrub.Marker || doc["client_name"] != "app-"+logscrub.Marker || doc["date"] == "" || strings.Contains(string(events[0].Body), "private") {
				t.Fatalf("metadata=%s", events[0].Body)
			}
		})
	}
}
