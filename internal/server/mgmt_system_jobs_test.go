package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSystemAPITenantJobs(t *testing.T) {
	h, st := newMgmtEnv(t)
	op, _ := operatorToken(t, st, "op@example.test")
	ctx := context.Background()
	acme, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(id string, typ store.JobType, status store.JobStatus, age time.Duration, params map[string]any, sum store.JobSummary) {
		t.Helper()
		j := &store.Job{
			TenantID: acme.ID, ID: id, Type: typ, Status: status, ConnectionID: "con_1", Connection: "db",
			Params: params, Input: []byte(`[{"email":"x@y.test","custom_password_hash":{"hash":{"value":"SECRETHASH"}}}]`),
			Summary: sum, CreatedAt: now.Add(-age), UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if err := st.Jobs().Create(ctx, j); err != nil {
			t.Fatal(err)
		}
	}
	mk("job_old", store.JobUsersImport, store.JobCompleted, 3*time.Hour, map[string]any{"weak_hashes": 2}, store.JobSummary{Inserted: 3, Total: 3})
	mk("job_mid", store.JobUsersExport, store.JobCompleted, 2*time.Hour, map[string]any{"format": "csv"}, store.JobSummary{})
	mk("job_new", store.JobUsersImport, store.JobFailed, time.Hour, map[string]any{"weak_hashes": 0}, store.JobSummary{Failed: 1, Total: 1})

	api := "https://" + mgmtSystemHost + "/api/system/tenants/acme/jobs"
	rec, out := sendRaw(h, "GET", api, op, nil)
	list, _ := out.([]any)
	if rec.Code != 200 || len(list) != 3 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	for i, id := range []string{"job_new", "job_mid", "job_old"} {
		if list[i].(map[string]any)["id"] != id {
			t.Errorf("order[%d] = %v, want %s", i, list[i].(map[string]any)["id"], id)
		}
	}
	oldJob := list[2].(map[string]any)
	if oldJob["weak_hashes"] != float64(2) || oldJob["summary"].(map[string]any)["inserted"] != float64(3) {
		t.Errorf("import = %v", oldJob)
	}
	if newJob := list[0].(map[string]any); newJob["summary"].(map[string]any)["failed"] != float64(1) || newJob["weak_hashes"] != float64(0) {
		t.Errorf("failed import = %v", newJob)
	}
	if exp := list[1].(map[string]any); exp["weak_hashes"] != nil || exp["location"] != nil {
		t.Errorf("export = %v", exp)
	}
	if strings.Contains(rec.Body.String(), "SECRETHASH") || strings.Contains(rec.Body.String(), "custom_password_hash") {
		t.Errorf("the input leaked: %s", rec.Body)
	}

	rec, out = sendRaw(h, "GET", api+"?include_totals=true&per_page=2&page=1", op, nil)
	m, _ := out.(map[string]any)
	if rec.Code != 200 || m["total"] != float64(3) || m["start"] != float64(2) || m["limit"] != float64(2) || len(m["jobs"].([]any)) != 1 {
		t.Errorf("paged = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendRaw(h, "GET", api+"?per_page=101", op, nil); rec.Code != 400 {
		t.Errorf("per_page 101 = %d", rec.Code)
	}
	if rec, out := sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants/nope/jobs", op, nil); rec.Code != 404 || errCode(out) != "inexistent_tenant" {
		t.Errorf("unknown tenant = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := sendRaw(h, "GET", "https://acme.example.test/api/system/tenants/acme/jobs", op, nil); rec.Code != 404 {
		t.Errorf("tenant host = %d", rec.Code)
	}
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	if rec, _ := sendRaw(h, "GET", api, admin, nil); rec.Code != 401 {
		t.Errorf("M2M token = %d", rec.Code)
	}
	if rec, _ := sendRaw(h, "GET", api, "", nil); rec.Code != 401 {
		t.Errorf("no token = %d", rec.Code)
	}
}
