package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/passhash"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const (
	impTenant = "ten_acme"
	impConnID = "con_AAAAAAAAAAAAAAAA"
	impConn   = "Imports"
	// bcryptHash is "$2a$10$…" of vectorPassword, a valid password_hash.
	bcryptHash = "$2a$10$abcdefghijklmnopqrstuutXuLMGzUDkLKWYZMwfQ1jZL/OanUDL2"
)

var impStart = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

// vector is one entry of passhash's generated test vectors.
type vector struct {
	Name     string         `json:"name"`
	Spec     map[string]any `json:"spec"`
	Password string         `json:"password"`
	Match    bool           `json:"match"`
}

var (
	vectorsOnce sync.Once
	vectors     map[string]vector
)

// vec returns the matching vector name from passhash's test data.
func vec(t *testing.T, name string) vector {
	t.Helper()
	vectorsOnce.Do(func() {
		vectors = map[string]vector{}
		for _, f := range []string{"../passhash/testdata/vectors.json", "../passhash/testdata/vectors-kdf.json"} {
			b, err := os.ReadFile(f)
			if err != nil {
				panic(err)
			}
			var vs []vector
			if err := json.Unmarshal(b, &vs); err != nil {
				panic(err)
			}
			for _, v := range vs {
				if v.Match {
					vectors[v.Name] = v
				}
			}
		}
	})
	v, ok := vectors[name]
	if !ok {
		t.Fatalf("no vector %q", name)
	}
	return v
}

// clone deep-copies a JSON value.
func clone(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// masked returns a copy of the record rec with the dotted paths set to
// "*****".
func masked(rec map[string]any, paths ...string) map[string]any {
	out := clone(rec).(map[string]any)
	for _, p := range paths {
		parts := strings.Split(p, ".")
		m := out
		for _, k := range parts[:len(parts)-1] {
			m = m[k].(map[string]any)
		}
		m[parts[len(parts)-1]] = "*****"
	}
	return out
}

type testLease struct {
	e     *impEnv
	j     *store.Job
	owner string
}

func (l *testLease) Owner() string { return l.owner }
func (l *testLease) Lost() bool    { return false }
func (l *testLease) Renew(ctx context.Context) error {
	return l.e.st.Jobs().Renew(ctx, l.j.TenantID, l.j.ID, l.owner, l.e.now.Add(time.Minute))
}

type sentMail struct {
	mu   sync.Mutex
	sent []email.Message
}

func (m *sentMail) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

type impEnv struct {
	t    *testing.T
	st   store.Store
	conn *store.Connection
	now  time.Time
	logs *bytes.Buffer
	mail *sentMail
	jobs int
}

func newImpEnv(t *testing.T, st store.Store) *impEnv {
	t.Helper()
	ctx := context.Background()
	e := &impEnv{t: t, st: st, now: impStart, logs: &bytes.Buffer{}, mail: &sentMail{}}
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: impTenant, Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	e.conn = &store.Connection{TenantID: impTenant, ID: impConnID, Name: impConn, Strategy: store.StrategyDatabase,
		EnabledClients: []string{"app"}, CreatedAt: impStart}
	if err := st.Connections().Create(ctx, e.conn); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *impEnv) importer() Importer {
	return Importer{Log: slog.New(slog.NewTextHandler(e.logs, nil)), Now: func() time.Time { return e.now }, Mailer: e.mail}
}

func fileOf(t *testing.T, records any) []byte {
	t.Helper()
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newJob stores a pending import of file into the env's connection.
func (e *impEnv) newJob(file []byte, params map[string]any) string {
	e.t.Helper()
	e.jobs++
	id := fmt.Sprintf("job_imp%013d", e.jobs)
	if params == nil {
		params = map[string]any{ParamUpsert: false, ParamSendCompletionEmail: false}
	}
	err := e.st.Jobs().Create(context.Background(), &store.Job{
		TenantID: impTenant, ID: id, Type: store.JobUsersImport, Status: store.JobPending,
		ConnectionID: e.conn.ID, Connection: e.conn.Name, Input: file, Params: params,
		CreatedAt: e.now, UpdatedAt: e.now, ExpiresAt: e.now.Add(24 * time.Hour),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

// claim claims the next job at e.now as owner.
func (e *impEnv) claim(owner string) (*store.Job, *testLease) {
	e.t.Helper()
	j, err := e.st.Jobs().Claim(context.Background(), owner, e.now, time.Minute)
	if err != nil {
		e.t.Fatalf("claim: %v", err)
	}
	return j, &testLease{e: e, j: j, owner: owner}
}

// finish runs p on the claimed job, finishes it with the result and
// returns the stored job and its errors.
func (e *impEnv) finish(p Importer, st store.Store, j *store.Job, l *testLease) (*store.Job, []store.JobError) {
	e.t.Helper()
	ctx := context.Background()
	status, details, err := p.Run(ctx, st, j, l)
	if err != nil {
		e.t.Fatalf("run: %v", err)
	}
	if err := e.st.Jobs().Finish(ctx, j.TenantID, j.ID, l.owner, status, details, e.now); err != nil {
		e.t.Fatal(err)
	}
	got, err := e.st.Jobs().Get(ctx, j.TenantID, j.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	errs, err := e.st.Jobs().Errors(ctx, j.TenantID, j.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return got, errs
}

// run imports file to the end.
func (e *impEnv) run(p Importer, file []byte, params map[string]any) (*store.Job, []store.JobError) {
	e.t.Helper()
	e.newJob(file, params)
	j, l := e.claim("w1")
	return e.finish(p, e.st, j, l)
}

func (e *impEnv) user(email string) *store.User {
	e.t.Helper()
	u, err := e.st.Users().FindByLogin(context.Background(), impTenant, impConn, email)
	if err != nil {
		e.t.Fatalf("find %s: %v", email, err)
	}
	return u
}

func (e *impEnv) mustCreate(u *store.User) {
	e.t.Helper()
	u.TenantID, u.CreatedAt, u.UpdatedAt = impTenant, impStart, impStart
	if err := e.st.Users().Create(context.Background(), u); err != nil {
		e.t.Fatal(err)
	}
}

func specOf(t *testing.T, spec map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(spec)
	s, errs := passhash.ParseCustom(b)
	if len(errs) > 0 {
		t.Fatalf("spec %s: %v", b, errs)
	}
	return s.Marshal()
}

func sameJSON(t *testing.T, what string, got, want any) {
	t.Helper()
	if g, ok := got.([]store.JobError); ok {
		if w, ok := want.([]store.JobError); ok && len(g) == len(w) {
			for i := range g {
				sameJSON(t, fmt.Sprintf("%s[%d]", what, i), g[i], w[i])
			}
			return
		}
	}
	g, _ := json.MarshalIndent(got, "", " ")
	w, _ := json.MarshalIndent(want, "", " ")
	if !bytes.Equal(g, w) {
		t.Errorf("%s:\ngot  %s\nwant %s", what, g, w)
	}
}

func jerr(i int, user any, items ...store.JobErrorItem) store.JobError {
	return store.JobError{Index: i, User: user, Errors: items}
}

func it(code, message, path string) store.JobErrorItem {
	return store.JobErrorItem{Code: code, Message: message, Path: path}
}

// A file mixing new users with a hash of every algorithm family, records
// with each error the importer raises, and upserts: the exact summary and
// errors (hashes masked), then the imported users sign in and are
// upgraded.
func TestImportMixedFile(t *testing.T) {
	forEachStore(t, testImportMixedFile)
}

func testImportMixedFile(t *testing.T, st store.Store) {
	ctx := context.Background()
	e := newImpEnv(t, st)
	hashVectors := []vector{
		vec(t, "md5/hex/salt-none"), vec(t, "sha256/hex/salt-prefix-utf8"), vec(t, "sha512/base64/salt-none"),
		vec(t, "hmac/sha256/key-utf8/salt-none"), vec(t, "ldap/SSHA"), vec(t, "pbkdf2/sha256"),
		vec(t, "scrypt/defaults-hex"), vec(t, "argon2/argon2id"), vec(t, "bcrypt/2b"),
	}
	sha1 := vec(t, "sha1/hex/salt-none")
	sha256 := vec(t, "sha256/hex/salt-prefix-utf8")
	md5 := hashVectors[0]
	hmacv := hashVectors[3]

	// Users already on the connection, for the upserts.
	old, err := secrets.Hash("old horse 1")
	if err != nil {
		t.Fatal(err)
	}
	e.mustCreate(&store.User{UserID: "auth0|pre1", Email: "pre1@x.test", Name: "pre1@x.test", Nickname: "pre1",
		Identities: []store.Identity{{Connection: impConn, Provider: "auth0", UserID: "pre1", ImportedHash: specOf(t, md5.Spec)}}})
	e.mustCreate(&store.User{UserID: "auth0|pre2", Email: "pre2@x.test",
		Identities: []store.Identity{{Connection: impConn, Provider: "auth0", UserID: "pre2", PasswordHash: old}}})
	e.mustCreate(&store.User{UserID: "auth0|pre3", Email: "pre3@x.test", Name: "Old", GivenName: "Keep", FamilyName: "OldF",
		UserMetadata: map[string]any{"a": 1.0, "b": 2.0}, AppMetadata: map[string]any{"plan": "x"},
		Identities: []store.Identity{{Connection: impConn, Provider: "auth0", UserID: "pre3", PasswordHash: old}}})

	type rec = map[string]any
	var records []any
	records = append(records, rec{"email": "Bcrypt@Example.test", "user_id": "custom-id-123", "password_hash": bcryptHash, "given_name": "Bea"}) // 0
	for i, v := range hashVectors {                                                                                                              // 1-9
		records = append(records, rec{"email": fmt.Sprintf("hash%d@x.test", i+1), "custom_password_hash": v.Spec})
	}
	cph := func(spec rec) rec { return rec{"custom_password_hash": spec} }
	withEmail := func(email string, r rec) rec { r["email"] = email; return r }
	scryptNoKeylen := rec{"algorithm": "scrypt", "hash": rec{"value": "00ff", "encoding": "hex"}, "salt": rec{"value": "pepper"}}
	argonSalt := rec{"algorithm": "argon2", "hash": rec{"value": "$argon2id$v=19$m=64,t=2,p=1$c29tZXNhbHQ$aGFzaA", "encoding": "utf8"}, "salt": rec{"value": "x"}}
	records = append(records,
		rec{"email": "not-an-email"}, // 10
		rec{"name": "No Email"},      // 11
		withEmail("enum@x.test", cph(rec{"algorithm": "foo", "hash": rec{"value": "abc"}})),                                        // 12
		withEmail("oneof@x.test", cph(rec{"algorithm": "sha256", "hash": rec{"value": "abc", "encoding": "utf8"}})),                // 13
		withEmail("keylen@x.test", cph(scryptNoKeylen)),                                                                            // 14
		withEmail("salt@x.test", cph(argonSalt)),                                                                                   // 15
		withEmail("hmac@x.test", cph(rec{"algorithm": "hmac", "hash": rec{"value": "00", "encoding": "hex", "digest": "sha256"}})), // 16
		rec{"email": "both@x.test", "password_hash": bcryptHash, "custom_password_hash": hmacv.Spec},                               // 17
		rec{"email": "cost@x.test", "password_hash": "$2a$12$" + bcryptHash[7:]},                                                   // 18
		rec{"email": "reserved@x.test", "app_metadata": rec{"blocked": true, "plan": "y"}},                                         // 19
		rec{"email": "HASH1@x.test"},                                                      // 20: duplicate of 1
		rec{"email": "other@x.test", "user_id": "custom-id-123"},                          // 21: duplicate user_id of 0
		rec{"email": "type@x.test", "email_verified": "yes"},                              // 22
		rec{"email": "long@x.test", "given_name": strings.Repeat("a", 301)},               // 23
		rec{"email": "pre1@x.test", "custom_password_hash": sha1.Spec, "name": "Pre One"}, // 24: upsert, hash replaced
		rec{"email": "pre2@x.test", "custom_password_hash": sha256.Spec},                  // 25: upsert, already signed in
		rec{"email": "pre3@x.test", "name": "New", "family_name": "NewF", "email_verified": true, // 26: upsert, profile
			"user_metadata": rec{"c": 3}, "app_metadata": rec{"tier": "gold"}, "blocked": true, "user_id": "ignored", "password_hash": bcryptHash},
		rec{"email": "mfa@x.test", "mfa_factors": []any{rec{"totp": rec{"secret": "2PRXZWZAYYDAWCD"}}}, "favourite_colour": "blue"}, // 27
		rec{"email": "nohash@x.test"}, // 28
		1,                             // 29
		rec{"email": "user@x.test", "username": "someone"},                                                               // 30
		withEmail("crypt@x.test", cph(rec{"algorithm": "ldap", "hash": rec{"value": "{CRYPT}abc", "encoding": "utf8"}})), // 31
		rec{"email": "name@x.test", "name": 5},                                                                           // 32
		rec{"email": "multi@x.test", "email_verified": "x", "blocked": "y"},                                              // 33
		rec{"email": "nul@x.test", "name": "a\x00b"},                                                                     // 34
	)
	file := fileOf(t, records)
	if n := WeakHashes(file); n != 2 { // md5 (1) and sha1 (24), both unsalted
		t.Errorf("WeakHashes = %d, want 2", n)
	}

	p := e.importer()
	p.Batch = 7
	j, errs := e.run(p, file, map[string]any{ParamUpsert: true, ParamSendCompletionEmail: false})

	if j.Status != store.JobCompleted || j.Summary != (store.JobSummary{Inserted: 12, Updated: 2, Failed: 21, Total: 35}) || j.Progress != 35 {
		t.Errorf("job = %s %+v progress %d, want completed 12/2/21/35", j.Status, j.Summary, j.Progress)
	}
	r := func(i int) map[string]any { return records[i].(map[string]any) }
	patternMsg := `Error in passwordHash property - String does not match pattern ^\$2[ab]?\$10+\$[./A-Za-z0-9]{53}$: *****`
	want := []store.JobError{
		jerr(10, r(10), it("INVALID_FORMAT", "Error in identities[0].profileData.email property - Object didn't pass validation for format email: not-an-email", "identities[0].profileData.email")),
		jerr(11, r(11), it("OBJECT_MISSING_REQUIRED_PROPERTY", "Missing required property: email", "")),
		jerr(12, masked(r(12), "custom_password_hash.hash.value"), it("ENUM_MISMATCH", "Error in custom_password_hash.algorithm property - No enum match for: foo", "custom_password_hash.algorithm")),
		jerr(13, masked(r(13), "custom_password_hash.hash.value"), it("ONE_OF_MISSING", "", "custom_password_hash")),
		jerr(14, masked(r(14), "custom_password_hash.hash.value", "custom_password_hash.salt.value"), it("OBJECT_MISSING_REQUIRED_PROPERTY", "Missing required property: keylen", "custom_password_hash")),
		jerr(15, masked(r(15), "custom_password_hash.hash.value", "custom_password_hash.salt.value"), it("OBJECT_ADDITIONAL_PROPERTIES", "Additional properties not allowed: salt", "custom_password_hash")),
		jerr(16, masked(r(16), "custom_password_hash.hash.value"), it("OBJECT_MISSING_REQUIRED_PROPERTY", "Missing required property: key", "custom_password_hash.hash")),
		jerr(17, masked(r(17), "password_hash", "custom_password_hash.hash.value", "custom_password_hash.hash.key.value"), it("NOT_PASSED", "Forbidden attribute in appUser: ", "")),
		jerr(18, masked(r(18), "password_hash"), it("PATTERN", patternMsg, "passwordHash")),
		jerr(19, r(19), it("NOT_PASSED", "Forbidden attribute in app_metadata: blocked", "blocked")),
		jerr(20, r(20), it("NON_UNIQUE_PROPERTY_VALUE", `Property "email" has non-unique value: hash1@x.test`, "")),
		jerr(21, r(21), it("DUPLICATED_USER", "A user with this [email|phone_number|username|user_id] was already provided.", "")),
		jerr(22, r(22), it("INVALID_TYPE", "Expected type boolean but found type string", "email_verified")),
		jerr(23, r(23), it("MAX_LENGTH", "String is too long (301 chars), maximum 300", "given_name")),
		jerr(25, masked(r(25), "custom_password_hash.hash.value", "custom_password_hash.salt.value"), it("CONFLICT", "A custom_password_hash was provided, but the user already has password hash defined.", "")),
		jerr(29, 1, it("INVALID_TYPE", "Expected type object but found type integer", "")),
		jerr(30, r(30), it("NOT_PASSED", "Cannot set username for connection without requires_username", "username")),
		jerr(31, masked(r(31), "custom_password_hash.hash.value"), it("ONE_OF_MISSING", "", "custom_password_hash")),
		jerr(32, r(32), it("INVALID_TYPE", "Expected type string but found type integer", "name")),
		jerr(33, r(33), it("INVALID_TYPE", "Expected type boolean but found type string", "email_verified"), it("INVALID_TYPE", "Expected type boolean but found type string", "blocked")),
		jerr(34, map[string]any{"email": "nul@x.test", "name": "a\uFFFDb"}, it("INVALID_FORMAT", "Strings must not contain NUL characters", "")),
	}
	sameJSON(t, "errors", errs, want)
	if strings.Contains(fmt.Sprint(errs), md5.Spec["hash"].(map[string]any)["value"].(string)) ||
		strings.Contains(fmt.Sprint(errs), "abcdefghijklmnopqrstuu") {
		t.Error("a job error shows a hash value")
	}
	if !strings.Contains(e.logs.String(), "weak_hashes=2") {
		t.Errorf("log lacks weak_hashes=2:\n%s", e.logs)
	}

	// Inserted users: the record's fields, user_metadata {}, the hash kept
	// for the first sign-in, which upgrades it to argon2id.
	u := e.user("bcrypt@example.test")
	if u.UserID != "auth0|custom-id-123" || u.Identities[0].UserID != "custom-id-123" || u.GivenName != "Bea" ||
		u.Name != "bcrypt@example.test" || u.Nickname != "bcrypt" || u.Picture == "" || u.UserMetadata == nil || len(u.UserMetadata) != 0 {
		t.Errorf("bcrypt user = %+v", u)
	}
	db := &identity.Database{Store: st, Now: func() time.Time { return e.now }}
	signIn := func(email, password string) {
		t.Helper()
		before := e.user(email).Identities[0]
		if before.ImportedHash == "" || before.PasswordHash != "" {
			t.Errorf("%s before sign-in: %+v", email, before)
		}
		if _, err := db.Login(ctx, e.conn, email, password); err != nil {
			t.Errorf("sign in %s: %v", email, err)
			return
		}
		after := e.user(email).Identities[0]
		if after.ImportedHash != "" || !strings.HasPrefix(after.PasswordHash, "$argon2id$") {
			t.Errorf("%s after sign-in: imported %q hash %q", email, after.ImportedHash, after.PasswordHash)
		}
	}
	signIn("bcrypt@example.test", vec(t, "bcrypt/2a").Password)
	for i, v := range hashVectors {
		signIn(fmt.Sprintf("hash%d@x.test", i+1), v.Password)
	}
	if _, err := db.Login(ctx, e.conn, "nohash@x.test", "anything 1"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Errorf("sign in without a hash: %v", err)
	}
	if u := e.user("mfa@x.test"); u.Email != "mfa@x.test" {
		t.Errorf("mfa user = %+v", u)
	}

	// Upserts (J4).
	pre1 := e.user("pre1@x.test")
	if pre1.Identities[0].ImportedHash != specOf(t, sha1.Spec) || pre1.Name != "Pre One" || pre1.Nickname != "pre1" {
		t.Errorf("pre1 = %+v", pre1)
	}
	if pre2 := e.user("pre2@x.test"); pre2.Identities[0].PasswordHash != old || pre2.Identities[0].ImportedHash != "" {
		t.Errorf("pre2 = %+v", pre2.Identities)
	}
	pre3 := e.user("pre3@x.test")
	if pre3.UserID != "auth0|pre3" || pre3.Name != "New" || pre3.GivenName != "Keep" || pre3.FamilyName != "NewF" || !pre3.EmailVerified ||
		pre3.Blocked || pre3.Identities[0].PasswordHash != old || pre3.Identities[0].ImportedHash != "" {
		t.Errorf("pre3 = %+v", pre3)
	}
	sameJSON(t, "pre3 metadata", []any{pre3.UserMetadata, pre3.AppMetadata}, []any{map[string]any{"c": 3}, map[string]any{"tier": "gold"}})

	// upsert false: an existing user is DUPLICATED_USER (U10).
	j, errs = e.run(e.importer(), fileOf(t, []any{rec{"email": "pre3@x.test", "name": "X"}, rec{"email": "fresh@x.test"}}), nil)
	if j.Summary != (store.JobSummary{Inserted: 1, Failed: 1, Total: 2}) {
		t.Errorf("upsert false summary = %+v", j.Summary)
	}
	sameJSON(t, "upsert false errors", errs, []store.JobError{
		jerr(0, rec{"email": "pre3@x.test", "name": "X"}, it("DUPLICATED_USER", "The user already exist and upsert parameter is false", "")),
	})
	if e.user("pre3@x.test").Name != "New" {
		t.Error("upsert false changed the user")
	}
}

// crashStore stops its worker at the start of batch crashAt (counting from
// 1): it cancels the worker's context and fails that batch's transaction,
// as if the process had died after the previous batch committed.
type crashStore struct {
	store.Store
	crashAt int
	cancel  context.CancelFunc
	n       int
}

func (c *crashStore) WithTx(ctx context.Context, fn func(tx store.Store) error) error {
	c.n++
	if c.n == c.crashAt {
		c.cancel()
		return ctx.Err()
	}
	return c.Store.WithTx(ctx, fn)
}

// Review Focus 2: the worker dies after the second batch; once its lease
// has expired a second worker claims the job and resumes at the
// checkpoint. Users of the committed batches are neither inserted twice
// nor reported as duplicates, and the summary counts every record once.
func TestImportResumesAfterLeaseExpiry(t *testing.T) {
	forEachStore(t, func(t *testing.T, st store.Store) {
		e := newImpEnv(t, st)
		var records []any
		for i := range 120 {
			records = append(records, map[string]any{"email": fmt.Sprintf("u%03d@x.test", i)})
		}
		records[60] = map[string]any{"email": "U010@x.test"} // a duplicate of a record in a committed batch
		e.newJob(fileOf(t, records), nil)

		j, l := e.claim("w1")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, _, err := e.importer().Run(ctx, &crashStore{Store: st, crashAt: 3, cancel: cancel}, j, l)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first worker: %v, want it stopped", err)
		}
		mid, err := st.Jobs().Get(context.Background(), impTenant, j.ID)
		if err != nil {
			t.Fatal(err)
		}
		if mid.Status != store.JobProcessing || mid.Progress != 100 || mid.Summary != (store.JobSummary{Inserted: 99, Failed: 1, Total: 100}) {
			t.Fatalf("after the crash: %s progress %d %+v", mid.Status, mid.Progress, mid.Summary)
		}

		// The lease runs out; a second worker takes the job over.
		e.now = e.now.Add(2 * time.Minute)
		j2, l2 := e.claim("w2")
		if j2.ID != j.ID || j2.Attempts != 2 || j2.Progress != 100 {
			t.Fatalf("second claim = %s attempts %d progress %d", j2.ID, j2.Attempts, j2.Progress)
		}
		done, errs := e.finish(e.importer(), st, j2, l2)
		if done.Status != store.JobCompleted || done.Summary != (store.JobSummary{Inserted: 119, Failed: 1, Total: 120}) {
			t.Errorf("job = %s %+v", done.Status, done.Summary)
		}
		sameJSON(t, "errors", errs, []store.JobError{
			jerr(60, records[60], it("NON_UNIQUE_PROPERTY_VALUE", `Property "email" has non-unique value: u010@x.test`, "")),
		})
		all, n, err := st.Users().List(context.Background(), impTenant, nil, store.UserSort{}, store.Page{})
		if err != nil {
			t.Fatal(err)
		}
		if n != 119 || len(all) != 119 {
			t.Errorf("%d users stored, want 119", n)
		}
	})
}

// Review Focus 5: files that are not a JSON array fail the job with J2's
// status_details; an empty array completes with nothing; entries that are
// not objects are INVALID_TYPE records. Never a stuck or 500 job.
func TestImportBadFiles(t *testing.T) {
	forEachStore(t, func(t *testing.T, st store.Store) {
		e := newImpEnv(t, st)
		for _, c := range []struct {
			name, file string
			status     store.JobStatus
			details    string
			summary    store.JobSummary
			errs       []store.JobError
		}{
			{"not JSON", "users, one per line", store.JobFailed, DetailsNotJSON, store.JobSummary{}, nil},
			{"BOM", "\xEF\xBB\xBF[]", store.JobFailed, DetailsNotJSON, store.JobSummary{}, nil},
			{"NDJSON", "{\"email\":\"a@x.test\"}\n{\"email\":\"b@x.test\"}\n", store.JobFailed, DetailsNotJSON, store.JobSummary{}, nil},
			{"truncated", `[{"email":"a@x.test"}`, store.JobFailed, DetailsNotJSON, store.JobSummary{}, nil},
			{"object", `{"email":"a@x.test"}`, store.JobFailed, DetailsNotArray, store.JobSummary{}, nil},
			{"string", `"users"`, store.JobFailed, DetailsNotArray, store.JobSummary{}, nil},
			{"null", `null`, store.JobFailed, DetailsNotArray, store.JobSummary{}, nil},
			{"empty array", " [ ]\n", store.JobCompleted, "", store.JobSummary{}, nil},
			{"not objects", `[1, "x", null, [], 2.5]`, store.JobCompleted, "", store.JobSummary{Failed: 5, Total: 5}, []store.JobError{
				jerr(0, 1, it("INVALID_TYPE", "Expected type object but found type integer", "")),
				jerr(1, "x", it("INVALID_TYPE", "Expected type object but found type string", "")),
				jerr(2, nil, it("INVALID_TYPE", "Expected type object but found type null", "")),
				jerr(3, []any{}, it("INVALID_TYPE", "Expected type object but found type array", "")),
				jerr(4, 2.5, it("INVALID_TYPE", "Expected type object but found type number", "")),
			}},
		} {
			t.Run(c.name, func(t *testing.T) {
				j, errs := e.run(e.importer(), []byte(c.file), nil)
				if j.Status != c.status || j.StatusDetails != c.details || j.Summary != c.summary || j.LeaseOwner != "" || j.Input != nil {
					t.Errorf("job = %s %q %+v lease %q", j.Status, j.StatusDetails, j.Summary, j.LeaseOwner)
				}
				if len(errs) != 0 || len(c.errs) != 0 {
					sameJSON(t, "errors", errs, c.errs)
				}
				if WeakHashes([]byte(c.file)) != 0 {
					t.Error("weak hashes counted in a bad file")
				}
			})
		}
	})
}

// The completion email goes to the operators who manage the tenant (by
// name or "*"), not to an operator of another tenant, when the job ends
// completed or failed; send_completion_email false sends none.
func TestImportCompletionEmail(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	e := newImpEnv(t, st)
	const sysID = "ten_system"
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: sysID, Name: tenant.SystemName}); err != nil {
		t.Fatal(err)
	}
	for _, op := range []struct {
		id, email string
		tenants   []string
	}{{"auth0|op1", "one@ops.test", []string{"acme"}}, {"auth0|op2", "two@ops.test", []string{store.OperatorAllTenants}}, {"auth0|op3", "three@ops.test", []string{"other"}}} {
		if err := st.Users().Create(ctx, &store.User{TenantID: sysID, UserID: op.id, Email: op.email, CreatedAt: impStart, UpdatedAt: impStart}); err != nil {
			t.Fatal(err)
		}
		if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: sysID, UserID: op.id, Tenants: op.tenants, CreatedAt: impStart, UpdatedAt: impStart}); err != nil {
			t.Fatal(err)
		}
	}
	to, err := Recipients(ctx, st, "acme")
	if err != nil || strings.Join(to, ",") != "one@ops.test,two@ops.test" {
		t.Errorf("Recipients = %v %v", to, err)
	}

	on := map[string]any{ParamUpsert: false, ParamSendCompletionEmail: true}
	j, _ := e.run(e.importer(), []byte(`[{"email":"a@x.test"},{"email":"bad"}]`), on)
	if len(e.mail.sent) != 2 {
		t.Fatalf("%d emails, want 2", len(e.mail.sent))
	}
	for i, addr := range []string{"one@ops.test", "two@ops.test"} {
		m := e.mail.sent[i]
		if m.To != addr || m.Subject != "User import "+j.ID+" on acme has finished" ||
			!strings.Contains(m.Text, "New users: 1. Updated users: 0. Records with errors: 1. Records in total: 2.") ||
			!strings.Contains(m.Text, impConn) || !strings.Contains(m.HTML, j.ID) {
			t.Errorf("email %d = %+v", i, m)
		}
	}

	e.mail.sent = nil
	j, _ = e.run(e.importer(), []byte(`{"not": "an array"}`), on)
	if len(e.mail.sent) != 2 || e.mail.sent[0].Subject != "User import "+j.ID+" on acme did not finish" ||
		!strings.Contains(e.mail.sent[0].Text, DetailsNotArray) {
		t.Errorf("failed-job emails = %+v", e.mail.sent)
	}

	// A store failure fails the job (the runner finishes it) and is
	// reported too.
	e.mail.sent = nil
	e.newJob([]byte(`[{"email":"c@x.test"}]`), on)
	j, l := e.claim("w1")
	if _, _, err := e.importer().Run(ctx, failingTx{st}, j, l); err == nil {
		t.Fatal("a store failure was swallowed")
	}
	if len(e.mail.sent) != 2 || !strings.Contains(e.mail.sent[0].Text, FailedDetails) {
		t.Errorf("store failure emails = %+v", e.mail.sent)
	}
	_ = st.Jobs().Finish(ctx, j.TenantID, j.ID, "w1", store.JobFailed, FailedDetails, e.now)

	e.mail.sent = nil
	e.run(e.importer(), []byte(`[{"email":"b@x.test"}]`), map[string]any{ParamSendCompletionEmail: false})
	if len(e.mail.sent) != 0 {
		t.Errorf("send_completion_email false sent %d emails", len(e.mail.sent))
	}
}

// failingTx is a store whose transactions fail.
type failingTx struct{ store.Store }

func (failingTx) WithTx(context.Context, func(store.Store) error) error {
	return errors.New("database down")
}

// A custom database in import mode: the importer never runs a script,
// and the imported user signs in locally, without one either.
func TestImportCustomDatabaseNeverCallsScripts(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	e := newImpEnv(t, st)
	e.conn.EnabledDatabaseCustomization, e.conn.ImportMode = true, true
	e.conn.CustomScripts = map[string]string{}
	for _, s := range store.ScriptNames {
		e.conn.CustomScripts[s] = "function " + s + "() {}"
	}
	if err := st.Connections().Update(ctx, e.conn); err != nil {
		t.Fatal(err)
	}
	funcs := map[string]func([]any) (any, error){}
	for _, s := range store.ScriptNames {
		funcs[s] = func([]any) (any, error) {
			t.Errorf("script %s was called", s)
			return nil, errors.New("no scripts here")
		}
	}
	fe := &customdb.FuncExecutor{Funcs: funcs}
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	v := vec(t, "pbkdf2/sha256")
	j, errs := e.run(e.importer(), fileOf(t, []any{map[string]any{"email": "legacy@x.test", "custom_password_hash": v.Spec}}), nil)
	if j.Summary != (store.JobSummary{Inserted: 1, Total: 1}) || len(errs) != 0 {
		t.Fatalf("job = %+v %v", j.Summary, errs)
	}
	db := &identity.Database{Store: st, Scripts: &customdb.Client{Exec: fe, Wrapper: w}}
	if _, err := db.Login(ctx, e.conn, "legacy@x.test", v.Password); err != nil {
		t.Errorf("sign in: %v", err)
	}
	if len(fe.Calls) != 0 {
		t.Errorf("scripts called: %+v", fe.Calls)
	}
}

// A connection deleted after the job was created fails every record.
func TestImportConnectionGone(t *testing.T) {
	st := memory.New()
	e := newImpEnv(t, st)
	e.newJob([]byte(`[{"email":"a@x.test"}]`), nil)
	if err := st.Connections().Delete(context.Background(), impTenant, impConnID); err != nil {
		t.Fatal(err)
	}
	j, l := e.claim("w1")
	done, errs := e.finish(e.importer(), st, j, l)
	if done.Summary != (store.JobSummary{Failed: 1, Total: 1}) || len(errs) != 1 || errs[0].Errors[0].Code != "CONNECTION_NOT_FOUND" {
		t.Errorf("job = %+v %+v", done.Summary, errs)
	}
}

// Ruling R11: on upsert, a custom_password_hash replaces an imported hash,
// sets one on a user that has no hash at all, and is a CONFLICT only for a
// user with a native password hash (one who signed in or set a password).
func TestImportUpsertCustomHash(t *testing.T) {
	forEachStore(t, func(t *testing.T, st store.Store) {
		ctx := context.Background()
		e := newImpEnv(t, st)
		md5, sha256 := vec(t, "md5/hex/salt-none"), vec(t, "sha256/hex/salt-prefix-utf8")
		native, err := secrets.Hash("native horse 1")
		if err != nil {
			t.Fatal(err)
		}
		e.mustCreate(&store.User{UserID: "auth0|imported", Email: "imported@x.test",
			Identities: []store.Identity{{Connection: impConn, Provider: "auth0", UserID: "imported", ImportedHash: specOf(t, md5.Spec)}}})
		e.mustCreate(&store.User{UserID: "auth0|native", Email: "native@x.test",
			Identities: []store.Identity{{Connection: impConn, Provider: "auth0", UserID: "native", PasswordHash: native}}})
		// A user imported without any hash.
		if j, _ := e.run(e.importer(), []byte(`[{"email":"hashless@x.test"}]`), nil); j.Summary.Inserted != 1 {
			t.Fatalf("hashless import = %+v", j.Summary)
		}

		records := []any{
			map[string]any{"email": "imported@x.test", "custom_password_hash": sha256.Spec},
			map[string]any{"email": "hashless@x.test", "custom_password_hash": sha256.Spec},
			map[string]any{"email": "native@x.test", "custom_password_hash": sha256.Spec},
		}
		j, errs := e.run(e.importer(), fileOf(t, records), map[string]any{ParamUpsert: true, ParamSendCompletionEmail: false})
		if j.Summary != (store.JobSummary{Updated: 2, Failed: 1, Total: 3}) {
			t.Errorf("summary = %+v", j.Summary)
		}
		sameJSON(t, "errors", errs, []store.JobError{
			jerr(2, masked(records[2].(map[string]any), "custom_password_hash.hash.value", "custom_password_hash.salt.value"),
				it("CONFLICT", "A custom_password_hash was provided, but the user already has password hash defined.", "")),
		})
		want := specOf(t, sha256.Spec)
		for _, email := range []string{"imported@x.test", "hashless@x.test"} {
			if id := e.user(email).Identities[0]; id.ImportedHash != want || id.PasswordHash != "" {
				t.Errorf("%s identity = %+v", email, id)
			}
		}
		if id := e.user("native@x.test").Identities[0]; id.PasswordHash != native || id.ImportedHash != "" {
			t.Errorf("native identity = %+v", id)
		}
		db := &identity.Database{Store: st, Now: func() time.Time { return e.now }}
		for _, email := range []string{"imported@x.test", "hashless@x.test"} {
			if _, err := db.Login(ctx, e.conn, email, sha256.Password); err != nil {
				t.Errorf("sign in %s with the new hash: %v", email, err)
			}
		}
		if _, err := db.Login(ctx, e.conn, "native@x.test", "native horse 1"); err != nil {
			t.Errorf("native password no longer works: %v", err)
		}
	})
}

// Hash values of the wrong type are masked whole in /errors.
func TestImportMasksWrongShapes(t *testing.T) {
	forEachStore(t, func(t *testing.T, st store.Store) {
		e := newImpEnv(t, st)
		file := `[
			{"email":"a@x.test","custom_password_hash":"$2b$10$abcdefghijklmnopqrstuutXuLMGzUDkLKWYZMwfQ1jZL/OanUDL2"},
			{"email":"b@x.test","custom_password_hash":["5f4dcc3b5aa765d61d8327deb882cf99"]},
			{"email":"c@x.test","custom_password_hash":{"algorithm":"md5","hash":"5f4dcc3b5aa765d61d8327deb882cf99"}},
			{"email":"d@x.test","custom_password_hash":{"algorithm":"md5","hash":{"value":"5f4dcc3b5aa765d61d8327deb882cf99","encoding":"hex"},"salt":"s3cr3t-salt"}},
			{"email":"e@x.test","custom_password_hash":{"algorithm":"hmac","hash":{"value":"5f4dcc3b5aa765d61d8327deb882cf99","encoding":"hex","digest":"sha256","key":"s3cr3t-key"}}},
			{"email":"f@x.test","password_hash":["$2b$10$abcdefghijklmnopqrstuutXuLMGzUDkLKWYZMwfQ1jZL/OanUDL2"]}
		]`
		j, errs := e.run(e.importer(), []byte(file), nil)
		if j.Summary != (store.JobSummary{Failed: 6, Total: 6}) || len(errs) != 6 {
			t.Fatalf("job = %+v, %d errors", j.Summary, len(errs))
		}
		want := []string{
			`{"custom_password_hash":"*****","email":"a@x.test"}`,
			`{"custom_password_hash":"*****","email":"b@x.test"}`,
			`{"custom_password_hash":{"algorithm":"md5","hash":"*****"},"email":"c@x.test"}`,
			`{"custom_password_hash":{"algorithm":"md5","hash":{"encoding":"hex","value":"*****"},"salt":"*****"},"email":"d@x.test"}`,
			`{"custom_password_hash":{"algorithm":"hmac","hash":{"digest":"sha256","encoding":"hex","key":"*****","value":"*****"}},"email":"e@x.test"}`,
			`{"email":"f@x.test","password_hash":"*****"}`,
		}
		for i, e := range errs {
			b, _ := json.Marshal(e.User)
			if string(b) != want[i] {
				t.Errorf("record %d echo = %s, want %s", e.Index, b, want[i])
			}
			all, _ := json.Marshal(e)
			for _, secret := range []string{"5f4dcc3b", "abcdefghijklmnop", "s3cr3t"} {
				if strings.Contains(string(all), secret) {
					t.Errorf("record %d shows %q: %s", e.Index, secret, all)
				}
			}
		}
	})
}
