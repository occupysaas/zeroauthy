package mgmt_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const argonHash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"

type exportLease struct {
	e     *usersEnv
	j     *store.Job
	owner string
}

func (l exportLease) Owner() string { return l.owner }
func (l exportLease) Lost() bool    { return false }
func (l exportLease) Renew(ctx context.Context) error {
	return l.e.st.Jobs().Renew(ctx, l.j.TenantID, l.j.ID, l.owner, now.Add(time.Hour))
}

func (e *usersEnv) postExport(t *testing.T, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.do(t, m2mCaller("read:users"), "POST", "/api/v2/jobs/users-exports", body, e.h.CreateUsersExportJob)
	m, _ := out.(map[string]any)
	return rec, m
}

// runJob claims the next job and runs the exporter on it.
func (e *usersEnv) runJob(t *testing.T, x jobs.Exporter) {
	t.Helper()
	ctx := context.Background()
	j, err := e.st.Jobs().Claim(ctx, "w1", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if x.View == nil {
		x.View = mgmt.UserJSON
	}
	status, details, err := x.Run(ctx, e.st, j, exportLease{e, j, "w1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Jobs().Finish(ctx, j.TenantID, j.ID, "w1", status, details, now); err != nil {
		t.Fatal(err)
	}
}

// export creates an export with body, runs it and returns the decompressed
// file and the number of chunks it was stored in.
func (e *usersEnv) export(t *testing.T, body any, x jobs.Exporter) (string, string, int) {
	t.Helper()
	rec, out := e.postExport(t, body)
	if rec.Code != 200 {
		t.Fatalf("export create = %d %s", rec.Code, rec.Body)
	}
	id := out["id"].(string)
	e.runJob(t, x)
	chunks := 0
	var raw bytes.Buffer
	if err := e.st.Jobs().ReadFile(context.Background(), e.tn.ID, id, func(c []byte) error {
		chunks++
		raw.Write(c)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(&raw)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(plain), id, chunks
}

func (e *usersEnv) addUser(t *testing.T, u *store.User) {
	t.Helper()
	u.TenantID, u.CreatedAt, u.UpdatedAt = e.tn.ID, time.Date(2026, 1, 2, 3, 4, 5, 6000000, time.UTC), time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	if u.Identities == nil {
		bare := strings.TrimPrefix(u.UserID, "auth0|")
		u.Identities = []store.Identity{{Connection: dbConn, Provider: "auth0", UserID: bare, PasswordHash: argonHash}}
	}
	if err := e.st.Users().Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
}

const exportsConnID = "con_ExportsAAAAAAAAA"

// exportsConn adds a second database connection, "Exports".
func (e *usersEnv) exportsConn(t *testing.T) {
	t.Helper()
	c := &store.Connection{TenantID: e.tn.ID, ID: exportsConnID, Name: "Exports", Strategy: store.StrategyDatabase, CreatedAt: now}
	if err := e.st.Connections().Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func (e *usersEnv) addExportsUser(t *testing.T, id string) {
	t.Helper()
	e.addUser(t, &store.User{UserID: "auth0|" + id, Email: id + "@x.test",
		Identities: []store.Identity{{Connection: "Exports", Provider: "auth0", UserID: id}}})
}

func TestExportBodyErrors(t *testing.T) {
	e := newUsersEnv(t)
	many := make([]any, 31)
	for i := range many {
		many[i] = map[string]any{"name": "email"}
	}
	for name, c := range map[string]struct {
		body any
		msg  string
	}{
		"limit 0":  {map[string]any{"limit": 0}, "Payload validation error: 'Value 0 is less than minimum 1' on property limit (Limit the number of records)."},
		"31 field": {map[string]any{"fields": many}, "Payload validation error: 'Array is too long (31), maximum 30' on property fields (List of fields to be included in the CSV. Defaults to a predefined set of fields)."},
		"format":   {map[string]any{"format": "xml"}, "Payload validation error: 'Invalid value \"xml\"' on property format (Format of the file. Must be `json` or `csv`)."},
		"unknown":  {map[string]any{"foo": 1}, "Payload validation error: 'Additional properties not allowed: foo'."},
	} {
		rec, out := e.postExport(t, c.body)
		if rec.Code != 400 || out["errorCode"] != "invalid_body" || out["message"] != c.msg {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
		}
	}
	// 30 fields are fine; so is an unknown field name, and password_hash.
	if rec, _ := e.postExport(t, map[string]any{"fields": many[:30]}); rec.Code != 200 {
		t.Errorf("30 fields = %d %s", rec.Code, rec.Body)
	}
	rec, out := e.postExport(t, map[string]any{"connection_id": "con_NoSuchAAAAAAAAAA"})
	if rec.Code != 400 || out["errorCode"] != "inexistent_connection" {
		t.Errorf("unknown connection = %d %s", rec.Code, rec.Body)
	}
	if rec, _ := e.do(t, m2mCaller("read:users"), "POST", "/api/v2/jobs/users-exports", "", e.h.CreateUsersExportJob); rec.Code != 200 {
		t.Errorf("empty body = %d %s", rec.Code, rec.Body)
	}
}

func TestExportEchoAndDefaults(t *testing.T) {
	e := newUsersEnv(t)
	e.exportsConn(t)
	rec, out := e.postExport(t, map[string]any{})
	if rec.Code != 200 || out["format"] != "csv" || out["status"] != "pending" || out["type"] != "users_export" {
		t.Fatalf("{} = %d %s", rec.Code, rec.Body)
	}
	if _, has := out["connection_id"]; has {
		t.Error("an export of every connection echoes a connection")
	}
	rec, out = e.postExport(t, map[string]any{"connection_id": exportsConnID, "format": "json", "limit": 3,
		"fields": []any{map[string]any{"name": "email", "export_as": "mail"}}})
	if rec.Code != 200 || out["connection_id"] != exportsConnID || out["connection"] != "Exports" || out["format"] != "json" || out["limit"] != float64(3) {
		t.Fatalf("echo = %d %s", rec.Code, rec.Body)
	}
	if f := out["fields"].([]any); len(f) != 1 || f[0].(map[string]any)["export_as"] != "mail" {
		t.Errorf("fields = %v", out["fields"])
	}
}

func TestExportJSON(t *testing.T) {
	e := newUsersEnv(t)
	login := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	e.addUser(t, &store.User{UserID: "auth0|b", Email: "b@x.test", Name: "Bee", Nickname: "bee", EmailVerified: true,
		UserMetadata: map[string]any{"plan": "pro", "obj": map[string]any{"x": 1}, "n": 5}, LastLogin: &login, LoginsCount: 3, LastIP: "1.2.3.4"})
	e.addUser(t, &store.User{UserID: "auth0|a", Email: "a@x.test"})

	// Default keys: those with a value, in user_id order, no metadata.
	got, _, _ := e.export(t, map[string]any{"format": "json"}, jobs.Exporter{})
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 2 {
		t.Fatalf("rows = %q", got)
	}
	var a, b map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &a)
	_ = json.Unmarshal([]byte(lines[1]), &b)
	if a["user_id"] != "auth0|a" || b["user_id"] != "auth0|b" {
		t.Errorf("order: %s", got)
	}
	if b["email"] != "b@x.test" || b["name"] != "Bee" || b["identities.[0].connection"] != dbConn || b["logins_count"] != float64(3) ||
		b["created_at"] != "2026-01-02T03:04:05.006Z" || b["last_login"] == nil || b["email_verified"] != true {
		t.Errorf("row b = %v", b)
	}
	if _, has := a["name"]; has {
		t.Errorf("row a has a name: %v", a)
	}
	if _, has := b["user_metadata"]; has {
		t.Errorf("default keys hold metadata: %v", b)
	}

	// Fields, export_as, subfields, whole objects, unknown and hash names.
	got, _, _ = e.export(t, map[string]any{"format": "json", "fields": []any{
		map[string]any{"name": "user_id"},
		map[string]any{"name": "email", "export_as": "mail"},
		map[string]any{"name": "user_metadata.obj"},
		map[string]any{"name": "user_metadata.plan", "export_as": "plan"},
		map[string]any{"name": "user_metadata"},
		map[string]any{"name": "identities"},
		map[string]any{"name": "nope"},
		map[string]any{"name": "password_hash"},
	}}, jobs.Exporter{})
	lines = strings.Split(strings.TrimSpace(got), "\n")
	a, b = nil, nil
	_ = json.Unmarshal([]byte(lines[0]), &a)
	_ = json.Unmarshal([]byte(lines[1]), &b)
	if a["mail"] != "a@x.test" || a["user_metadata"] != nil && len(a["user_metadata"].(map[string]any)) != 0 {
		t.Errorf("row a = %v", a)
	}
	if _, has := a["user_metadata.obj"]; has {
		t.Errorf("user without metadata has the subfield: %v", a)
	}
	if b["user_metadata.obj"].(map[string]any)["x"] != float64(1) || b["plan"] != "pro" || b["user_metadata"].(map[string]any)["n"] != float64(5) {
		t.Errorf("row b = %v", b)
	}
	if ids := b["identities"].([]any); len(ids) != 1 || ids[0].(map[string]any)["connection"] != dbConn {
		t.Errorf("identities = %v", b["identities"])
	}
	for _, k := range []string{"nope", "password_hash"} {
		if _, has := b[k]; has {
			t.Errorf("row has %s", k)
		}
	}
	if len(lines) != 2 || strings.Contains(got, "argon2") {
		t.Errorf("hash in %s", got)
	}
}

func TestExportCSV(t *testing.T) {
	e := newUsersEnv(t)
	e.addUser(t, &store.User{UserID: "auth0|b", Email: "b@x.test", Name: `Bee "B", Jr`, Nickname: "=1+1", Blocked: true})
	e.addUser(t, &store.User{UserID: "auth0|a", Email: "a@x.test", EmailVerified: true})

	got, _, _ := e.export(t, map[string]any{}, jobs.Exporter{})
	want := "user_id,email,name,family_name,given_name,phone_number,nickname,username,last_ip,logins_count,created_at,updated_at,deleted_at,last_login,blocked,deleted,email_verified,phone_verified,identities.[0].connection\n" +
		`"'auth0|a","'a@x.test",,,,,,,,,2026-01-02T03:04:05.006Z,2026-02-03T04:05:06.000Z,,,,,true,,"'` + dbConn + "\"\n" +
		`"'auth0|b","'b@x.test","'Bee ""B"", Jr",,,,"'=1+1",,,,2026-01-02T03:04:05.006Z,2026-02-03T04:05:06.000Z,,,true,,false,,"'` + dbConn + "\"\n"
	if got != want {
		t.Errorf("csv =\n%s\nwant\n%s", got, want)
	}

	// One connection only, a limit, fields with export_as; whole
	// user_metadata and an object subfield are empty.
	e.exportsConn(t)
	e.addExportsUser(t, "c")
	e.addExportsUser(t, "d")
	e.addUser(t, &store.User{UserID: "github|7", Email: "g@x.test", UserMetadata: map[string]any{"k": 1},
		Identities: []store.Identity{{Connection: "github", Provider: "github", UserID: "7"}}})
	got, _, _ = e.export(t, map[string]any{"connection_id": exportsConnID, "limit": 1, "fields": []any{
		map[string]any{"name": "email", "export_as": "Mail"}, map[string]any{"name": "user_metadata"}, map[string]any{"name": "identities"},
	}}, jobs.Exporter{})
	if got != "Mail,user_metadata,identities\n\"'c@x.test\",,\n" {
		t.Errorf("limited csv = %q", got)
	}
	got, _, _ = e.export(t, map[string]any{"format": "csv", "fields": []any{map[string]any{"name": "user_id"}}}, jobs.Exporter{})
	if got != "user_id\n\"'auth0|a\"\n\"'auth0|b\"\n\"'auth0|c\"\n\"'auth0|d\"\n\"'github|7\"\n" {
		t.Errorf("all connections = %q", got)
	}
}

func TestExportCSVHostileValues(t *testing.T) {
	e := newUsersEnv(t)
	hostile := []string{"=cmd|' /C calc'!A0", "+1", "-1", "@SUM(A1)", `a"b`, "a,b", "line1\nline2", `"`, "'", " lead", "tab\tx", ""}
	meta := map[string]any{"n": 7, "f": 1.5, "t": true, "z": false, "o": map[string]any{"x": 1}, "arr": []any{1, 2}, "nil": nil}
	for i, s := range hostile {
		m := map[string]any{"s": s}
		for k, v := range meta {
			m[k] = v
		}
		e.addUser(t, &store.User{UserID: fmt.Sprintf("auth0|u%02d", i), Email: fmt.Sprintf("u%d@x.test", i), Name: s, UserMetadata: m})
	}
	fields := []any{map[string]any{"name": "user_id"}, map[string]any{"name": "name"}}
	for _, k := range []string{"s", "n", "f", "t", "z", "o", "arr", "nil", "missing"} {
		fields = append(fields, map[string]any{"name": "user_metadata." + k})
	}
	got, _, _ := e.export(t, map[string]any{"fields": fields}, jobs.Exporter{})
	rows, err := csv.NewReader(strings.NewReader(got)).ReadAll()
	if err != nil {
		t.Fatalf("csv does not parse: %v\n%s", err, got)
	}
	if len(rows) != len(hostile)+1 {
		t.Fatalf("rows = %d", len(rows))
	}
	for i, s := range hostile {
		r := rows[i+1]
		if len(r) != len(fields) {
			t.Fatalf("row %d has %d columns", i, len(r))
		}
		wantName := "'" + s
		if s == "" {
			wantName = "" // an empty name is no value
		}
		if r[1] != wantName || r[2] != "'"+s {
			t.Errorf("row %d strings = %q %q", i, r[1], r[2])
		}
		if strings.Join(r[3:], "|") != "7|1.5|true|false||||" {
			t.Errorf("row %d scalars = %q", i, r[3:])
		}
	}
	if !strings.Contains(got, "\n\"'auth0|u00\",\"'=cmd|' /C calc'!A0\"") {
		t.Errorf("formula not guarded in %q", got)
	}
}

func TestExportNeverHashes(t *testing.T) {
	e := newUsersEnv(t)
	imp := `{"algorithm":"sha256","hash":{"value":"IMPORTEDVECTORVALUE"}}`
	e.addUser(t, &store.User{UserID: "auth0|a", Email: "a@x.test", Name: "A",
		Identities: []store.Identity{{Connection: dbConn, Provider: "auth0", UserID: "a", ImportedHash: imp}}})
	e.addUser(t, &store.User{UserID: "auth0|b", Email: "b@x.test", Name: "B"})
	all := []any{}
	for _, n := range []string{"password_hash", "custom_password_hash", "identities", "identities.[0].password_hash", "identities.[0].ImportedHash", "passwordHash"} {
		all = append(all, map[string]any{"name": n})
	}
	for _, f := range []string{"json", "csv"} {
		for _, fields := range [][]any{nil, all} {
			body := map[string]any{"format": f}
			if fields != nil {
				body["fields"] = fields
			}
			got, _, _ := e.export(t, body, jobs.Exporter{})
			for _, bad := range []string{"$argon2id$", "IMPORTEDVECTORVALUE", "aGFzaGhhc2g", "sha256"} {
				if strings.Contains(got, bad) {
					t.Errorf("%s export holds %q:\n%s", f, bad, got)
				}
			}
		}
	}
	got, _, _ := e.export(t, map[string]any{"format": "json", "fields": []any{map[string]any{"name": "password_hash"}}}, jobs.Exporter{})
	if got != "{}\n{}\n" {
		t.Errorf("password_hash rows = %q", got)
	}
}

func TestExportSpansChunksAndRestarts(t *testing.T) {
	e := newUsersEnv(t)
	for i := range 1200 {
		e.addUser(t, &store.User{UserID: fmt.Sprintf("auth0|u%04d", i), Email: fmt.Sprintf("user%04d@x.test", i), Name: fmt.Sprintf("User %04d", i)})
	}
	got, id, chunks := e.export(t, map[string]any{"format": "json", "fields": []any{map[string]any{"name": "user_id"}, map[string]any{"name": "email"}}},
		jobs.Exporter{ChunkSize: 700, Page: 500})
	if chunks < 3 {
		t.Errorf("chunks = %d, want at least 3", chunks)
	}
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 1200 || lines[0] != `{"user_id":"auth0|u0000","email":"user0000@x.test"}` || lines[1199] != `{"user_id":"auth0|u1199","email":"user1199@x.test"}` {
		t.Errorf("rows = %d, first %q", len(lines), lines[0])
	}
	j, _ := e.st.Jobs().Get(context.Background(), e.tn.ID, id)
	if j.Status != store.JobCompleted || j.FileSize <= 700*2 {
		t.Errorf("job = %+v", j)
	}

	// A job claimed again after its worker stopped rewrites the file from
	// scratch, whatever the earlier attempt left.
	rec, out := e.postExport(t, map[string]any{"format": "json", "limit": 2, "fields": []any{map[string]any{"name": "user_id"}}})
	if rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	ctx := context.Background()
	j, err := e.st.Jobs().Claim(ctx, "w0", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		if err := e.st.Jobs().AppendFile(ctx, j.TenantID, j.ID, "w0", i, bytes.Repeat([]byte("stale"), 100)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := (jobs.Exporter{View: mgmt.UserJSON, ChunkSize: 700}).Run(ctx, e.st, j, exportLease{e, j, "w0"}); err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	_ = e.st.Jobs().ReadFile(ctx, j.TenantID, out["id"].(string), func(c []byte) error { raw.Write(c); return nil })
	zr, err := gzip.NewReader(&raw)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil || string(plain) != "{\"user_id\":\"auth0|u0000\"}\n{\"user_id\":\"auth0|u0001\"}\n" {
		t.Errorf("restarted file = %q, %v", plain, err)
	}
}

func TestExportLink(t *testing.T) {
	clock := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	l := mgmt.ExportLink{Key: bytes.Repeat([]byte{9}, 32), Now: func() time.Time { return clock }}
	raw := l.Sign("login.acme.test", "acme", "ten_a", "job_AAAAAAAAAAAAAAAA", "csv")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "login.acme.test" || u.Path != "/export/job_AAAAAAAAAAAAAAAA/acme.csv.gz" {
		t.Fatalf("link = %s, %v", raw, err)
	}
	expires, _ := strconv.ParseInt(u.Query().Get("expires"), 10, 64)
	sig := u.Query().Get("sig")
	if expires != clock.Add(60*time.Second).Unix() {
		t.Errorf("expires = %d", expires)
	}
	check := func() bool { return l.Check("ten_a", "job_AAAAAAAAAAAAAAAA", expires, sig) }
	if !check() {
		t.Error("a fresh link fails")
	}
	clock = clock.Add(60 * time.Second)
	if !check() {
		t.Error("the link fails at 60 s")
	}
	clock = clock.Add(time.Second)
	if check() {
		t.Error("the link works at 61 s")
	}
	clock = clock.Add(-61 * time.Second)
	for name, ok := range map[string]bool{
		"tenant":  l.Check("ten_b", "job_AAAAAAAAAAAAAAAA", expires, sig),
		"job":     l.Check("ten_a", "job_BBBBBBBBBBBBBBBB", expires, sig),
		"expires": l.Check("ten_a", "job_AAAAAAAAAAAAAAAA", expires+1, sig),
		"sig":     l.Check("ten_a", "job_AAAAAAAAAAAAAAAA", expires, sig[:len(sig)-2]+"AA"),
		"empty":   l.Check("ten_a", "job_AAAAAAAAAAAAAAAA", expires, ""),
		"junk":    l.Check("ten_a", "job_AAAAAAAAAAAAAAAA", expires, "%%%"),
		"key":     mgmt.ExportLink{Key: bytes.Repeat([]byte{8}, 32), Now: l.Now}.Check("ten_a", "job_AAAAAAAAAAAAAAAA", expires, sig),
	} {
		if ok {
			t.Errorf("a link with another %s passes", name)
		}
	}
}

func (e *usersEnv) download(t *testing.T, tn *store.Tenant, rawURL string) *httptest.ResponseRecorder {
	t.Helper()
	u, _ := url.Parse(rawURL)
	req := httptest.NewRequest("GET", rawURL, nil)
	req.RemoteAddr = "203.0.113.9:4321"
	rc := chi.NewRouteContext()
	parts := strings.Split(strings.TrimPrefix(u.Path, "/export/"), "/")
	rc.URLParams.Add("job", parts[0])
	rc.URLParams.Add("file", parts[1])
	ctx := tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: tn, Host: u.Host})
	req = req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rc))
	rec := httptest.NewRecorder()
	e.h.DownloadExport(rec, req)
	return rec
}

func TestExportDownload(t *testing.T) {
	e := newUsersEnv(t)
	clock := now
	e.h.Export = &mgmt.ExportLink{Key: bytes.Repeat([]byte{3}, 32), Now: func() time.Time { return clock }}
	e.addUser(t, &store.User{UserID: "auth0|a", Email: "a@x.test"})
	other, err := e.sysTenantCopy(t)
	if err != nil {
		t.Fatal(err)
	}

	rec, out := e.postExport(t, map[string]any{"format": "json"})
	id := out["id"].(string)
	// Not completed: no location, and no download.
	if _, has := out["location"]; has {
		t.Fatal("a new job has a location")
	}
	_, pending := e.getJob(t, id)
	if _, has := pending["location"]; has {
		t.Error("a pending export has a location")
	}
	e.runJob(t, jobs.Exporter{})

	// Every read of a completed export signs a new link.
	_, first := e.getJob(t, id)
	loc1, _ := first["location"].(string)
	clock = clock.Add(2 * time.Second)
	_, second := e.getJob(t, id)
	loc2, _ := second["location"].(string)
	if !strings.HasPrefix(loc1, "https://login.acme.test/export/"+id+"/acme.json.gz?expires=") || loc1 == loc2 {
		t.Fatalf("locations %q %q", loc1, loc2)
	}
	if rec, _ := e.getJobErrors(t, id); rec.Code != 204 {
		t.Errorf("export errors = %d", rec.Code)
	}

	dl := e.download(t, e.tn, loc2)
	if dl.Code != 200 || dl.Header().Get("Content-Type") != "application/gzip" || dl.Header().Get("Cache-Control") != "no-store" ||
		dl.Header().Get("Content-Disposition") != `attachment; filename="acme.json.gz"` {
		t.Fatalf("download = %d %v", dl.Code, dl.Header())
	}
	zr, err := gzip.NewReader(dl.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(zr)
	if !strings.Contains(string(body), `"user_id":"auth0|a"`) {
		t.Errorf("body = %s", body)
	}
	if !strings.Contains(e.logs.String(), "export download") || !strings.Contains(e.logs.String(), "203.0.113.9") || !strings.Contains(e.logs.String(), id) {
		t.Errorf("download not logged: %s", e.logs)
	}

	forbidden := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != 403 || strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s = %d %q", name, rec.Code, rec.Body)
		}
	}
	forbidden("other tenant", e.download(t, other, loc2))
	forbidden("tampered", e.download(t, e.tn, strings.Replace(loc2, "sig=", "sig=A", 1)))
	forbidden("wrong name", e.download(t, e.tn, strings.Replace(loc2, "acme.json.gz", "acme.csv.gz", 1)))
	forbidden("no query", e.download(t, e.tn, strings.SplitN(loc2, "?", 2)[0]))
	clock = clock.Add(61 * time.Second) // past loc2's 60 s
	forbidden("expired", e.download(t, e.tn, loc2))
	if rec := e.download(t, e.tn, loc2[:0]+e.h.Export.Sign("login.acme.test", "acme", e.tn.ID, id, "json")); rec.Code != 200 {
		t.Errorf("fresh link = %d", rec.Code)
	}

	// A link to a job that has not completed, and to a job of another type.
	rec, out = e.postExport(t, map[string]any{})
	forbidden("pending", e.download(t, e.tn, e.h.Export.Sign("login.acme.test", "acme", e.tn.ID, out["id"].(string), "csv")))
	forbidden("unknown job", e.download(t, e.tn, e.h.Export.Sign("login.acme.test", "acme", e.tn.ID, "job_ZZZZZZZZZZZZZZZZ", "csv")))
	_ = rec
}

func (e *usersEnv) sysTenantCopy(t *testing.T) (*store.Tenant, error) {
	t.Helper()
	tn := &store.Tenant{ID: "ten_other", Name: "other"}
	return tn, e.st.Tenants().Create(context.Background(), tn)
}

var _ = http.StatusOK
