package server

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestMicrosoftImportHTTP(t *testing.T) {
	var runner *jobs.Runner
	a := newJobsAPI(t, func(d *Deps) { d.JobNotify = func() { runner.Notify() } })
	runner = &jobs.Runner{Store: a.st, Workers: 1, LeaseFor: time.Second, Poll: time.Hour, Processors: map[store.JobType]jobs.Processor{store.JobUsersImport: jobs.Importer{}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runner.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	tid := a.tenantID()
	db, err := a.st.Connections().GetByName(ctx, tid, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	db.EnabledClients = []string{"users"}
	if err := a.st.Connections().Update(ctx, db); err != nil {
		t.Fatal(err)
	}
	const oid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const directory = "11111111-2222-3333-4444-555555555555"
	for _, c := range []*store.Connection{
		{TenantID: tid, ID: "personal", Name: "personal", Strategy: "windowslive"},
		{TenantID: tid, ID: "work", Name: "work", Strategy: "waad", Extra: map[string]any{"useCommonEndpoint": true}},
	} {
		if err := a.st.Connections().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	identities := []any{
		map[string]any{"connection": "personal", "provider": "windowslive", "user_id": "PersonalCase"},
		map[string]any{"connection": "work", "provider": "waad", "user_id": "work|" + directory + ":" + oid},
	}
	file, _ := json.Marshal([]any{map[string]any{"email": "migrated@example.test", "user_id": "migrated", "identities": identities}})
	rec, job := a.postImportAs(a.tokenFor("jobscreate"), map[string]string{"connection_id": db.ID, "users": string(file)})
	if rec.Code != 202 {
		t.Fatalf("import %d %s", rec.Code, rec.Body)
	}
	got := a.waitJob(job["id"].(string))
	summary := got["summary"].(map[string]any)
	if got["status"] != "completed" || summary["inserted"] != float64(1) || summary["failed"] != float64(0) {
		t.Fatalf("job %v", got)
	}
	rec, u := a.do("GET", usersBase+"/"+url.PathEscape("auth0|migrated"), nil)
	if rec.Code != 200 {
		t.Fatalf("user %d %s", rec.Code, rec.Body)
	}
	ids := u["identities"].([]any)
	if len(ids) != 3 || ids[1].(map[string]any)["provider"] != "windowslive" || ids[1].(map[string]any)["isSocial"] != true || ids[2].(map[string]any)["provider"] != "waad" || ids[2].(map[string]any)["isSocial"] != false {
		t.Fatalf("identities %v", ids)
	}
	for _, key := range []store.FederatedIdentityKey{{TenantID: tid, ConnectionID: "personal", Subject: "PersonalCase"}, {TenantID: tid, ConnectionID: "work", Subject: directory + ":" + oid}} {
		owner, err := a.st.Users().FindByIdentity(ctx, key.TenantID, key.ConnectionID, key.Subject)
		if err != nil || owner.UserID != "auth0|migrated" {
			t.Fatalf("owner %+v %v", owner, err)
		}
	}
	if err := federation.PreflightMicrosoftIdentities(ctx, a.st); err != nil {
		t.Fatal(err)
	}
}
