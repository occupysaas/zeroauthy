package mgmt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var jobIDRe = regexp.MustCompile(`^job_[A-Za-z0-9]{16}$`)

func (e *usersEnv) postVerification(t *testing.T, body any, scopes ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	if scopes == nil {
		scopes = []string{"update:users"}
	}
	rec, out := e.do(t, m2mCaller(scopes...), "POST", "/api/v2/jobs/verification-email", body, e.h.CreateVerificationEmailJob)
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *usersEnv) getJob(t *testing.T, id string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.do(t, m2mCaller("read:users"), "GET", "/api/v2/jobs/"+id, nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetJob(w, r, id) })
	m, _ := out.(map[string]any)
	return rec, m
}

func (e *usersEnv) getJobErrors(t *testing.T, id string) (*httptest.ResponseRecorder, any) {
	t.Helper()
	return e.do(t, m2mCaller("read:users"), "GET", "/api/v2/jobs/"+id+"/errors", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetJobErrors(w, r, id) })
}

func (e *usersEnv) putJob(t *testing.T, j *store.Job) {
	t.Helper()
	if j.TenantID == "" {
		j.TenantID = e.tn.ID
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = now
	}
	if j.ExpiresAt.IsZero() {
		j.ExpiresAt = now.Add(24 * time.Hour)
	}
	if err := e.st.Jobs().Create(context.Background(), j); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationEmailJobCases(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "v@x.test"})
	uid := u["user_id"].(string)
	bare := strings.TrimPrefix(uid, "auth0|")
	conID := e.conn.ID
	social := &store.User{TenantID: e.tn.ID, UserID: "github|7", Email: "g@x.test", CreatedAt: now, UpdatedAt: now,
		Identities: []store.Identity{{Connection: "github", Provider: "github", UserID: "7"}}}
	if err := e.st.Users().Create(context.Background(), social); err != nil {
		t.Fatal(err)
	}
	noEmail := &store.User{TenantID: e.tn.ID, UserID: "auth0|aaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: now, UpdatedAt: now,
		Identities: []store.Identity{{Connection: dbConn, Provider: "auth0", UserID: "aaaaaaaaaaaaaaaaaaaaaaaa"}}}
	if err := e.st.Users().Create(context.Background(), noEmail); err != nil {
		t.Fatal(err)
	}
	client := e.mustCreateClient(t)

	ok := []struct {
		name string
		body map[string]any
	}{
		{"user only", map[string]any{"user_id": uid}},
		{"primary identity", map[string]any{"user_id": uid, "identity": map[string]any{"user_id": bare, "provider": "auth0"}}},
		{"identity with its connection", map[string]any{"user_id": uid, "identity": map[string]any{"user_id": bare, "provider": "auth0", "connection_id": conID}}},
		{"client", map[string]any{"user_id": uid, "client_id": client}},
	}
	for _, c := range ok {
		rec, out := e.postVerification(t, c.body)
		if rec.Code != 201 || out["type"] != "verification_email" || out["status"] != "pending" || !jobIDRe.MatchString(out["id"].(string)) || out["created_at"] == nil {
			t.Errorf("%s = %d %s", c.name, rec.Code, rec.Body)
		}
		for _, k := range []string{"percentage_done", "time_left_seconds", "summary", "status_details", "location"} {
			if _, has := out[k]; has {
				t.Errorf("%s: a new job has %s", c.name, k)
			}
		}
	}

	bad := []struct {
		name   string
		body   any
		scopes []string
		status int
		code   string
		msg    string
	}{
		{"unknown user", map[string]any{"user_id": "auth0|000000000000000000000000"}, nil, 400, "inexistent_user", "The user does not exist"},
		{"empty user_id", map[string]any{"user_id": ""}, nil, 400, "invalid_body",
			"Payload validation error: 'Object didn't pass validation for format user-id: ' on property user_id (user_id of the user to send the verification email to)."},
		{"malformed user_id", map[string]any{"user_id": "nope"}, nil, 400, "invalid_body",
			"Payload validation error: 'Object didn't pass validation for format user-id: nope' on property user_id (user_id of the user to send the verification email to)."},
		{"no user_id", map[string]any{}, nil, 400, "invalid_body", "Payload validation error: 'Missing required property: user_id'."},
		{"wrong type", map[string]any{"user_id": 5}, nil, 400, "invalid_body", "Payload validation error: 'Expected type string but found type number' on property user_id."},
		{"identity not on the user", map[string]any{"user_id": uid, "identity": map[string]any{"user_id": "other", "provider": "auth0"}}, nil, 400, "inexistent_identity",
			"The user exists, but does not contain the given identity"},
		{"identity of another connection", map[string]any{"user_id": uid, "identity": map[string]any{"user_id": bare, "provider": "auth0", "connection_id": "con_other"}}, nil, 400, "inexistent_identity",
			"The user exists, but does not contain the given identity"},
		{"unknown property", map[string]any{"user_id": uid, "foo": 1}, nil, 400, "invalid_body", "Payload validation error: 'Additional properties not allowed: foo'."},
		{"organization_id", map[string]any{"user_id": uid, "organization_id": "org_1"}, nil, 400, "invalid_body", "Payload validation error: 'Additional properties not allowed: organization_id'."},
		{"unknown identity property", map[string]any{"user_id": uid, "identity": map[string]any{"user_id": bare, "provider": "auth0", "x": 1}}, nil, 400, "invalid_body",
			"Payload validation error: 'Additional properties not allowed: x' on property identity."},
		{"unknown client", map[string]any{"user_id": uid, "client_id": "nope"}, nil, 400, "inexistent_client", "The client does not exist"},
		{"no email", map[string]any{"user_id": noEmail.UserID}, nil, 400, "operation_not_supported", "The user does not have an email address."},
		{"social identity", map[string]any{"user_id": "github|7", "identity": map[string]any{"user_id": "7", "provider": "github"}}, nil, 400, "operation_not_supported",
			"The identity is not in a database connection."},
		{"not an object", "[]", nil, 400, "invalid_body", "Payload validation error: the body must be a JSON object"},
	}
	for _, c := range bad {
		rec, out := e.postVerification(t, c.body, c.scopes...)
		if rec.Code != c.status || out["errorCode"] != c.code || out["message"] != c.msg {
			t.Errorf("%s = %d %s, want %d %s %q", c.name, rec.Code, rec.Body, c.status, c.code, c.msg)
		}
	}
	// Refused requests store no job.
	jobs, total, _ := e.st.Jobs().List(context.Background(), e.tn.ID, store.Page{Limit: 100})
	if total != len(ok) {
		t.Errorf("%d jobs stored (%d listed), want %d", total, len(jobs), len(ok))
	}
}

func (e *usersEnv) mustCreateClient(t *testing.T) string {
	t.Helper()
	c := &store.Client{TenantID: e.tn.ID, ClientID: "app1", Name: "App", AppType: "regular_web", CreatedAt: now}
	if err := e.st.Clients().Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c.ClientID
}

func TestCreateJobNotifies(t *testing.T) {
	e := newUsersEnv(t)
	n := 0
	e.h.Notify = func() { n++ }
	u := e.mustCreate(t, map[string]any{"email": "n@x.test"})
	if rec, _ := e.postVerification(t, map[string]any{"user_id": u["user_id"]}); rec.Code != 201 || n != 1 {
		t.Errorf("create = %d, notified %d times, want 201 and once", rec.Code, n)
	}
}

func TestGetJobShapes(t *testing.T) {
	e := newUsersEnv(t)
	e.putJob(t, &store.Job{ID: "job_pendingAAAAAAAAA", Type: store.JobUsersImport, Status: store.JobPending, ConnectionID: "con_x", Connection: dbConn, ExternalID: "ext-1"})
	e.putJob(t, &store.Job{ID: "job_runningAAAAAAAAA", Type: store.JobUsersImport, Status: store.JobProcessing, Progress: 3, Summary: store.JobSummary{Total: 10}})
	e.putJob(t, &store.Job{ID: "job_importOKAAAAAAAA", Type: store.JobUsersImport, Status: store.JobCompleted, Summary: store.JobSummary{Failed: 1, Updated: 2, Inserted: 3, Total: 6}})
	e.putJob(t, &store.Job{ID: "job_importBadAAAAAAA", Type: store.JobUsersImport, Status: store.JobFailed, StatusDetails: "Failed to parse users file JSON when importing users. Make sure it is valid JSON.",
		Summary: store.JobSummary{Total: 4}})
	e.putJob(t, &store.Job{ID: "job_exportOKAAAAAAAA", Type: store.JobUsersExport, Status: store.JobCompleted,
		Params: map[string]any{"format": "csv", "limit": float64(5), "fields": []any{map[string]any{"name": "email"}}}})
	e.putJob(t, &store.Job{ID: "job_verifyFailAAAAAA", Type: store.JobVerificationEmail, Status: store.JobFailed})

	type want struct {
		status string
		has    []string
		not    []string
	}
	for id, w := range map[string]want{
		"job_pendingAAAAAAAAA": {"pending", []string{"connection_id", "connection", "external_id", "created_at"}, []string{"summary", "status_details", "location", "percentage_done", "time_left_seconds"}},
		"job_runningAAAAAAAAA": {"pending", nil, []string{"summary", "percentage_done", "time_left_seconds", "status_details"}},
		"job_importOKAAAAAAAA": {"completed", []string{"summary"}, []string{"status_details", "location"}},
		"job_importBadAAAAAAA": {"failed", []string{"status_details"}, []string{"summary"}},
		"job_exportOKAAAAAAAA": {"completed", []string{"format", "limit", "fields"}, []string{"summary", "location"}},
		"job_verifyFailAAAAAA": {"failed", nil, []string{"status_details", "summary"}},
	} {
		rec, out := e.getJob(t, id)
		if rec.Code != 200 || out["status"] != w.status || out["id"] != id {
			t.Errorf("%s = %d %s, want status %s", id, rec.Code, rec.Body, w.status)
			continue
		}
		for _, k := range w.has {
			if _, ok := out[k]; !ok {
				t.Errorf("%s lacks %s: %s", id, k, rec.Body)
			}
		}
		for _, k := range w.not {
			if _, ok := out[k]; ok {
				t.Errorf("%s has %s: %s", id, k, rec.Body)
			}
		}
	}
	if _, out := e.getJob(t, "job_importOKAAAAAAAA"); out["summary"].(map[string]any)["inserted"] != float64(3) || out["type"] != "users_import" {
		t.Errorf("summary = %v", out)
	}
}

func TestJobLocationOnlyOnCompletedExports(t *testing.T) {
	exp := &store.Job{ID: "job_exportOKAAAAAAAA", Type: store.JobUsersExport, Status: store.JobCompleted, CreatedAt: now}
	if got := mgmt.JobJSON(exp, "https://x.test/f.gz")["location"]; got != "https://x.test/f.gz" {
		t.Errorf("completed export location = %v", got)
	}
	exp.Status = store.JobPending
	imp := &store.Job{ID: "job_importOKAAAAAAAA", Type: store.JobUsersImport, Status: store.JobCompleted, CreatedAt: now}
	for _, j := range []*store.Job{exp, imp} {
		if _, has := mgmt.JobJSON(j, "https://x.test/f.gz")["location"]; has {
			t.Errorf("%s %s has a location", j.Type, j.Status)
		}
	}
}

func TestGetJobIDAndExpiry(t *testing.T) {
	e := newUsersEnv(t)
	e.putJob(t, &store.Job{ID: "job_expiredAAAAAAAAA", Type: store.JobUsersExport, Status: store.JobPending, ExpiresAt: now.Add(-time.Hour)})
	for _, id := range []string{"job_x", "nope", "job_" + strings.Repeat("a", 17), "job_aaaaaaaaaaaaaaa!", "JOB_aaaaaaaaaaaaaaaa"} {
		for name, call := range map[string]func() (*httptest.ResponseRecorder, any){
			"job":    func() (*httptest.ResponseRecorder, any) { r, m := e.getJob(t, id); return r, m },
			"errors": func() (*httptest.ResponseRecorder, any) { return e.getJobErrors(t, id) },
		} {
			rec, out := call()
			m, _ := out.(map[string]any)
			want := "Path validation error: 'String does not match pattern ^job_[A-Za-z0-9]{16}$: " + id + "' on property id (ID of the job)."
			if rec.Code != 400 || m["errorCode"] != "invalid_uri" || m["message"] != want {
				t.Errorf("%s %q = %d %s", name, id, rec.Code, rec.Body)
			}
		}
	}
	for _, id := range []string{"job_unknownAAAAAAAAA", "job_expiredAAAAAAAAA"} {
		rec, out := e.getJob(t, id)
		if rec.Code != 404 || out["errorCode"] != "inexistent_job" || out["message"] != "The job does not exist" {
			t.Errorf("%s = %d %s", id, rec.Code, rec.Body)
		}
		if rec, _ := e.getJobErrors(t, id); rec.Code != 404 {
			t.Errorf("%s errors = %d", id, rec.Code)
		}
	}
}

func TestGetJobIsPerTenant(t *testing.T) {
	e := newUsersEnv(t)
	e.putJob(t, &store.Job{TenantID: "other-tenant", ID: "job_otherAAAAAAAAAAA", Type: store.JobUsersExport, Status: store.JobPending})
	if rec, _ := e.getJob(t, "job_otherAAAAAAAAAAA"); rec.Code != 404 {
		t.Errorf("another tenant's job = %d, want 404", rec.Code)
	}
}

func TestGetJobErrors(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	e.putJob(t, &store.Job{ID: "job_importOKAAAAAAAA", Type: store.JobUsersImport, Status: store.JobCompleted})
	e.putJob(t, &store.Job{ID: "job_importErrAAAAAAA", Type: store.JobUsersImport, Status: store.JobProcessing, LeaseOwner: "w", LeaseUntil: now.Add(time.Hour), Attempts: 1})
	if err := e.st.Jobs().Checkpoint(ctx, e.tn.ID, "job_importErrAAAAAAA", "w", 2, store.JobSummary{Total: 2, Failed: 2}, []store.JobError{
		{Index: 0, User: map[string]any{"email": "a"}, Errors: []store.JobErrorItem{{Code: "INVALID_FORMAT", Message: "bad", Path: "email"}}},
		{Index: 1, User: map[string]any{"x": 1}, Errors: []store.JobErrorItem{{Code: "NOT_PASSED", Message: "no"}}},
	}); err != nil {
		t.Fatal(err)
	}
	e.putJob(t, &store.Job{ID: "job_importFailAAAAAA", Type: store.JobUsersImport, Status: store.JobFailed, StatusDetails: "The users file must provide an array of users to upload using JSON format."})
	e.putJob(t, &store.Job{ID: "job_exportOKAAAAAAAA", Type: store.JobUsersExport, Status: store.JobCompleted})
	e.putJob(t, &store.Job{ID: "job_verifyOKAAAAAAAA", Type: store.JobVerificationEmail, Status: store.JobCompleted})
	e.putJob(t, &store.Job{ID: "job_verifyBadAAAAAAA", Type: store.JobVerificationEmail, Status: store.JobFailed})

	if rec, out := e.getJobErrors(t, "job_importOKAAAAAAAA"); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("clean import = %d %s (%v)", rec.Code, rec.Body, out)
	}
	rec, out := e.getJobErrors(t, "job_importErrAAAAAAA")
	list, _ := out.([]any)
	if rec.Code != 200 || len(list) != 2 {
		t.Fatalf("import errors = %d %s", rec.Code, rec.Body)
	}
	first := list[0].(map[string]any)
	item := first["errors"].([]any)[0].(map[string]any)
	if first["user"].(map[string]any)["email"] != "a" || item["code"] != "INVALID_FORMAT" || item["path"] != "email" {
		t.Errorf("first error = %v", first)
	}
	if _, has := list[1].(map[string]any)["errors"].([]any)[0].(map[string]any)["path"]; has {
		t.Errorf("an error without a path has one: %v", list[1])
	}
	for _, id := range []string{"job_exportOKAAAAAAAA", "job_verifyOKAAAAAAAA"} {
		if rec, _ := e.getJobErrors(t, id); rec.Code != 204 || rec.Body.Len() != 0 {
			t.Errorf("%s = %d %q, want 204 with no body", id, rec.Code, rec.Body)
		}
	}
	for _, id := range []string{"job_importFailAAAAAA", "job_verifyBadAAAAAAA"} {
		rec, out := e.getJobErrors(t, id)
		m, _ := out.(map[string]any)
		if rec.Code != 200 || m["id"] != id || m["status"] != "failed" {
			t.Errorf("%s = %d %s, want the job itself", id, rec.Code, rec.Body)
		}
	}
}
