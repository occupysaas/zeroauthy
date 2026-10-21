package mgmt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const (
	importConnID = "con_ImportsAAAAAAAAA"
	importBound  = "zaImportBoundary"
)

// part is one multipart form part; file parts carry a filename.
type part struct {
	name, value string
	file        bool
}

// importBody builds a multipart body with a fixed boundary.
func importBody(t *testing.T, parts ...part) []byte {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if err := w.SetBoundary(importBound); err != nil {
		t.Fatal(err)
	}
	for _, p := range parts {
		var pw io.Writer
		var err error
		if p.file {
			pw, err = w.CreateFormFile(p.name, "users.json")
		} else {
			pw, err = w.CreateFormField(p.name)
		}
		if err != nil {
			t.Fatal(err)
		}
		_, _ = pw.Write([]byte(p.value))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// postImport sends body to CreateUsersImportJob. contentLength -1 sends it
// without a length (chunked).
func (e *usersEnv) postImport(t *testing.T, body []byte, contentLength int64) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "https://login.acme.test/api/v2/jobs/users-imports", bytes.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+importBound)
	req.ContentLength = contentLength
	ctx := tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tn, Host: "login.acme.test"})
	req = req.WithContext(mgmt.WithCaller(ctx, m2mCaller("create:users")))
	rec := httptest.NewRecorder()
	e.h.CreateUsersImportJob(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func (e *usersEnv) importConnections(t *testing.T) {
	t.Helper()
	for _, c := range []*store.Connection{
		{ID: importConnID, Name: "Imports", Strategy: store.StrategyDatabase, EnabledClients: []string{"app1"}},
		{ID: "con_DisabledAAAAAAAA", Name: "Disabled", Strategy: store.StrategyDatabase},
		{ID: "con_SocialAAAAAAAAAA", Name: "github", Strategy: "github", EnabledClients: []string{"app1"}},
		{ID: "con_LegacyAAAAAAAAAA", Name: "Legacy", Strategy: store.StrategyDatabase, EnabledClients: []string{"app1"},
			EnabledDatabaseCustomization: true, CustomScripts: map[string]string{"login": "function login() {}"}},
		{ID: "con_ImportModeAAAAAA", Name: "Migrating", Strategy: store.StrategyDatabase, EnabledClients: []string{"app1"},
			EnabledDatabaseCustomization: true, ImportMode: true, CustomScripts: map[string]string{"login": "function login() {}"}},
	} {
		c.TenantID, c.CreatedAt = e.tn.ID, now
		if err := e.st.Connections().Create(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
}

func usersFile(v string) part          { return part{name: "users", value: v, file: true} }
func connPart(id string) part          { return part{name: "connection_id", value: id} }
func field(name, value string) part    { return part{name: name, value: value} }
func defaultImport(file string) []part { return []part{usersFile(file), connPart(importConnID)} }

// J1: each refused request, with Auth0's status, code and message; none
// stores a job.
func TestUsersImportCreateErrors(t *testing.T) {
	e := newUsersEnv(t)
	e.importConnections(t)
	file := `[{"email":"a@x.test"}]`
	for _, c := range []struct {
		name   string
		parts  []part
		status int
		code   string
		msg    string
	}{
		{"no users part", []part{connPart(importConnID)}, 400, "invalid_body", "Must provide 'users' file as multipart part."},
		{"no connection_id part", []part{usersFile(file)}, 400, "invalid_body", "Must provide 'connection_id' as multipart part."},
		{"empty file", []part{usersFile(""), connPart(importConnID)}, 400, "operation_not_supported", "Users file must not be empty."},
		{"malformed connection_id", []part{usersFile(file), connPart("con_short")}, 400, "invalid_body",
			"Payload validation error: 'String does not match pattern ^con_[A-Za-z0-9]{16}$' on property connection_id."},
		{"unknown connection", []part{usersFile(file), connPart("con_UnknownAAAAAAAAA")}, 400, "inexistent_connection", "The connection does not exist."},
		{"not a database", []part{usersFile(file), connPart("con_SocialAAAAAAAAAA")}, 400, "operation_not_supported", "Connection must be a database connection."},
		{"enabled for no application", []part{usersFile(file), connPart("con_DisabledAAAAAAAA")}, 400, "connection_is_disabled", "Connection must be enabled."},
		{"custom database without import mode", []part{usersFile(file), connPart("con_LegacyAAAAAAAAAA")}, 400, "operation_not_supported",
			"Custom Database Connections without import mode are not allowed."},
	} {
		body := importBody(t, c.parts...)
		rec, out := e.postImport(t, body, int64(len(body)))
		if rec.Code != c.status || out["errorCode"] != c.code || out["message"] != c.msg {
			t.Errorf("%s = %d %s, want %d %s %q", c.name, rec.Code, rec.Body, c.status, c.code, c.msg)
		}
	}
	// A body that is not multipart has no parts.
	req := httptest.NewRequest("POST", "https://login.acme.test/api/v2/jobs/users-imports", strings.NewReader(`{"users":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(mgmt.WithCaller(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tn, Host: "login.acme.test"}), m2mCaller("create:users")))
	rec := httptest.NewRecorder()
	e.h.CreateUsersImportJob(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "Must provide 'users' file as multipart part.") {
		t.Errorf("JSON body = %d %s", rec.Code, rec.Body)
	}
	if _, n, _ := e.st.Jobs().List(context.Background(), e.tn.ID, store.Page{}); n != 0 {
		t.Errorf("%d jobs stored by refused requests", n)
	}
}

// J1, J3: the 202 answer, the stored job, loose booleans and unknown parts.
func TestUsersImportCreate(t *testing.T) {
	e := newUsersEnv(t)
	e.importConnections(t)
	notified := 0
	e.h.Notify = func() { notified++ }
	weak := `{"email":"w@x.test","custom_password_hash":{"algorithm":"md5","hash":{"value":"5f4dcc3b5aa765d61d8327deb882cf99","encoding":"hex"}}}`
	body := importBody(t, usersFile("["+weak+"]"), connPart(importConnID), field("upsert", "maybe"),
		field("external_id", "batch-7"), field("colour", "blue"))
	rec, out := e.postImport(t, body, int64(len(body)))
	if rec.Code != 202 || out["type"] != "users_import" || out["status"] != "pending" || out["connection_id"] != importConnID ||
		out["connection"] != "Imports" || out["external_id"] != "batch-7" || !jobIDRe.MatchString(out["id"].(string)) || out["created_at"] == nil || len(out) != 7 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if notified != 1 {
		t.Errorf("notified %d times", notified)
	}
	j, err := e.st.Jobs().Get(context.Background(), e.tn.ID, out["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(j.Input) != "["+weak+"]" || j.Params[jobs.ParamUpsert] != false || j.Params[jobs.ParamSendCompletionEmail] != true || j.Params[jobs.ParamWeakHashes] != 1 {
		t.Errorf("job = input %q params %v", j.Input, j.Params)
	}
	if !strings.Contains(e.logs.String(), "management API: create users import job") || !strings.Contains(e.logs.String(), "actor=m2m") {
		t.Errorf("no audit line:\n%s", e.logs)
	}

	// upsert true, completion email off, a custom database in import mode.
	body = importBody(t, usersFile("[]"), connPart("con_ImportModeAAAAAA"), field("upsert", "TRUE"), field("send_completion_email", "false"))
	rec, out = e.postImport(t, body, int64(len(body)))
	if rec.Code != 202 {
		t.Fatalf("import mode = %d %s", rec.Code, rec.Body)
	}
	j, _ = e.st.Jobs().Get(context.Background(), e.tn.ID, out["id"].(string))
	if j.Params[jobs.ParamUpsert] != true || j.Params[jobs.ParamSendCompletionEmail] != false || j.Connection != "Migrating" {
		t.Errorf("job = %+v", j)
	}

}

// J3: a third import while two are active is 429 without errorCode;
// another tenant's imports and other job types do not count, and once one
// finishes a new one is accepted.
func TestUsersImportConcurrencyLimit(t *testing.T) {
	e := newUsersEnv(t)
	e.importConnections(t)
	ctx := context.Background()
	e.putJob(t, &store.Job{TenantID: "other", ID: "job_otherImportAAAAA", Type: store.JobUsersImport, Status: store.JobPending})
	e.putJob(t, &store.Job{TenantID: "other", ID: "job_otherImportBBBBB", Type: store.JobUsersImport, Status: store.JobPending})
	e.putJob(t, &store.Job{ID: "job_verifyAAAAAAAAAA", Type: store.JobVerificationEmail, Status: store.JobPending})
	body := importBody(t, defaultImport(`[]`)...)
	for i := range 2 {
		if rec, _ := e.postImport(t, body, int64(len(body))); rec.Code != 202 {
			t.Fatalf("import %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	rec, out := e.postImport(t, body, int64(len(body)))
	if rec.Code != 429 || out["error"] != "Too Many Requests" || out["statusCode"] != float64(429) ||
		out["message"] != "There are 2 active import users jobs, please wait until some of them are finished and try again" {
		t.Errorf("third import = %d %s", rec.Code, rec.Body)
	}
	if _, has := out["errorCode"]; has {
		t.Errorf("429 has an errorCode: %s", rec.Body)
	}
	// A running import still counts; a finished one does not.
	for {
		j, err := e.st.Jobs().Claim(ctx, "w", now.Add(time.Hour), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if j.TenantID != e.tn.ID || j.Type != store.JobUsersImport {
			continue
		}
		if rec, _ := e.postImport(t, body, int64(len(body))); rec.Code != 429 {
			t.Errorf("with one running = %d, want 429", rec.Code)
		}
		if err := e.st.Jobs().Finish(ctx, j.TenantID, j.ID, "w", store.JobCompleted, "", now); err != nil {
			t.Fatal(err)
		}
		break
	}
	if rec, _ := e.postImport(t, body, int64(len(body))); rec.Code != 202 {
		t.Errorf("after one finished = %d %s, want 202", rec.Code, rec.Body)
	}
}

// J1: the limit is on the whole body, multipart framing included: exactly
// 512000 bytes is accepted, one more is 413 without errorCode, whether the
// request declares its length or not. Malformed files are accepted (J2).
func TestUsersImportBodyLimit(t *testing.T) {
	e := newUsersEnv(t)
	e.importConnections(t)
	sized := func(total int) []byte {
		base := importBody(t, defaultImport("[]")...)
		pad := total - len(base)
		b := importBody(t, defaultImport("["+strings.Repeat(" ", pad)+"]")...)
		if len(b) != total {
			t.Fatalf("built %d bytes, want %d", len(b), total)
		}
		return b
	}
	ctx := context.Background()
	finishAll := func() {
		for {
			j, err := e.st.Jobs().Claim(ctx, "w", now.Add(time.Hour), time.Hour)
			if err != nil {
				return
			}
			_ = e.st.Jobs().Finish(ctx, j.TenantID, j.ID, "w", store.JobCompleted, "", now)
		}
	}
	for _, c := range []struct {
		name   string
		body   []byte
		length int64
		status int
	}{
		{"exactly 512000", sized(mgmt.MaxImportBody), mgmt.MaxImportBody, 202},
		{"exactly 512000, chunked", sized(mgmt.MaxImportBody), -1, 202},
		{"512001", sized(mgmt.MaxImportBody + 1), mgmt.MaxImportBody + 1, 413},
		{"512001, chunked", sized(mgmt.MaxImportBody + 1), -1, 413},
		{"far over, chunked", bytes.Repeat([]byte("x"), 2*mgmt.MaxImportBody), -1, 413},
	} {
		finishAll()
		rec, out := e.postImport(t, c.body, c.length)
		if rec.Code != c.status {
			t.Errorf("%s = %d %s, want %d", c.name, rec.Code, rec.Body, c.status)
			continue
		}
		if c.status == 413 {
			_, has := out["errorCode"]
			if has || out["error"] != "Request Entity Too Large" || out["message"] != "Payload content length greater than maximum allowed: 512000" {
				t.Errorf("%s body = %s", c.name, rec.Body)
			}
		}
	}
	for _, f := range []string{"not json", `{"email":"a@x.test"}`, "\xEF\xBB\xBF[]", "{\"email\":\"a@x.test\"}\n{\"email\":\"b@x.test\"}", "[1, null]"} {
		finishAll()
		body := importBody(t, defaultImport(f)...)
		if rec, _ := e.postImport(t, body, int64(len(body))); rec.Code != 202 {
			t.Errorf("file %q = %d %s, want 202", f, rec.Code, rec.Body)
		}
	}
}
