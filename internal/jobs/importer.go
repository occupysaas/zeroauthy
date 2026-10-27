package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/passhash"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
)

// ImportBatch is how many records the importer commits in one
// transaction, with the job's checkpoint.
const ImportBatch = 50

// The status_details of an import whose file is not a JSON array (J2).
const (
	DetailsNotJSON  = "Failed to parse users file JSON when importing users. Make sure it is valid JSON."
	DetailsNotArray = "The users file must provide an array of users to upload using JSON format."
)

// The job Params an import create stores.
const (
	ParamUpsert              = "upsert"
	ParamSendCompletionEmail = "send_completion_email"
	// ParamWeakHashes is the number of records in the file whose
	// custom_password_hash is weak (passhash.Spec.Weak, spec §9).
	ParamWeakHashes = "weak_hashes"
)

// Auth0's messages for the record errors it was observed to give (J4, J5).
const (
	msgDuplicatedUser   = "The user already exist and upsert parameter is false"
	msgDuplicateInFile  = "A user with this [email|phone_number|username|user_id] was already provided."
	msgHashAlreadySet   = "A custom_password_hash was provided, but the user already has password hash defined."
	msgBothHashes       = "Forbidden attribute in appUser: "
	msgMissingEmail     = "Missing required property: email"
	pathEmail           = "identities[0].profileData.email"
	formatEmailMessage  = "Error in identities[0].profileData.email property - Object didn't pass validation for format email: "
	forbiddenAppMessage = "Forbidden attribute in app_metadata: "
)

// reservedAppMetadata are the app_metadata keys an import may not set.
var reservedAppMetadata = []string{
	"__tenant", "_id", "blocked", "clientID", "created_at", "email_verified", "email", "globalClientID",
	"global_client_id", "identities", "lastIP", "lastLogin", "loginsCount", "metadata",
	"multifactor_last_modified", "multifactor", "updated_at", "user_id",
}

// Importer runs users_import jobs: it reads the job's file (a JSON array of
// users in Auth0's import schema) and creates or, with upsert, updates the
// users of the job's database connection. Records are committed in batches
// of ImportBatch, each with the job's checkpoint, so a job claimed again
// after its worker stopped resumes after the last committed batch. Custom
// database scripts are never called: an import into a custom database
// (which must be in import mode) writes zeroauthy's own copy of the users.
type Importer struct {
	// Mailer sends the completion email to the tenant's operators; nil
	// sends none.
	Mailer email.Mailer
	Email  *email.Service
	Log    *slog.Logger
	Now    func() time.Time
	// Batch overrides ImportBatch when positive.
	Batch int
}

func (p Importer) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

func (p Importer) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func (p Importer) batch() int {
	if p.Batch > 0 {
		return p.Batch
	}
	return ImportBatch
}

// ParseImportFile reads an import file. It returns the records, or the
// status_details of a job whose file is not a JSON array (J2). A UTF-8 BOM
// and newline-delimited JSON are not JSON.
func ParseImportFile(input []byte) ([]json.RawMessage, string) {
	if !json.Valid(input) {
		return nil, DetailsNotJSON
	}
	if t := bytes.TrimLeft(input, " \t\r\n"); len(t) == 0 || t[0] != '[' {
		return nil, DetailsNotArray
	}
	var recs []json.RawMessage
	if err := json.Unmarshal(input, &recs); err != nil {
		return nil, DetailsNotJSON
	}
	return recs, ""
}

// WeakHashes counts the records of an import file whose
// custom_password_hash is valid and weak (passhash.Spec.Weak). A file that
// is not a JSON array has none.
func WeakHashes(input []byte) int {
	recs, details := ParseImportFile(input)
	if details != "" {
		return 0
	}
	n := 0
	for _, raw := range recs {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || m == nil {
			continue
		}
		cph, ok := m["custom_password_hash"]
		if _, both := m["password_hash"]; !ok || both {
			continue
		}
		if s, errs := passhash.ParseCustom(cph); len(errs) == 0 && s.Weak() {
			n++
		}
	}
	return n
}

// paramBool reads a boolean job param, def when absent or not a boolean.
func paramBool(j *store.Job, k string, def bool) bool {
	if v, ok := j.Params[k].(bool); ok {
		return v
	}
	return def
}

// Run implements Processor.
func (p Importer) Run(ctx context.Context, st store.Store, j *store.Job, lease Lease) (status store.JobStatus, details string, err error) {
	recs, details := ParseImportFile(j.Input)
	if details != "" {
		p.log().InfoContext(ctx, "jobs: user import failed", "tenant", j.TenantID, "job", j.ID, "details", details)
		p.notify(ctx, st, j, store.JobFailed, details, store.JobSummary{})
		return store.JobFailed, details, nil
	}
	defer func() {
		// The runner fails a job whose processor returned an error, unless
		// it is stopping or lost the lease (a write refused with
		// ErrConflict): the operators hear of it too.
		if err != nil && ctx.Err() == nil && !errors.Is(err, store.ErrConflict) && (lease == nil || !lease.Lost()) {
			p.notify(ctx, st, j, store.JobFailed, FailedDetails, store.JobSummary{})
		}
	}()

	plan := planImport(recs)
	upsert := paramBool(j, ParamUpsert, false)
	sum := j.Summary
	owner := ""
	if lease != nil {
		owner = lease.Owner()
	}
	for start := j.Progress; start < len(recs); start += p.batch() {
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		if start > j.Progress && lease != nil {
			if err := lease.Renew(ctx); err != nil {
				return "", "", fmt.Errorf("renew the lease: %w", err)
			}
		}
		end := min(start+p.batch(), len(recs))
		var next store.JobSummary
		err := st.WithTx(ctx, func(tx store.Store) error {
			next = sum
			conn, err := importConnection(ctx, tx, j)
			if err != nil {
				return err
			}
			var errs []store.JobError
			for i := start; i < end; i++ {
				out, items, err := p.record(ctx, tx, conn, plan, i, upsert)
				if err != nil {
					return fmt.Errorf("record %d: %w", i, err)
				}
				next.Total++
				switch out {
				case outInserted:
					next.Inserted++
				case outUpdated:
					next.Updated++
				default:
					next.Failed++
					errs = append(errs, store.JobError{Index: i, User: plan[i].echo(), Errors: items})
				}
			}
			return tx.Jobs().Checkpoint(ctx, j.TenantID, j.ID, owner, end, next, errs)
		})
		if err != nil {
			return "", "", err
		}
		sum = next
	}

	weak, err := p.importedWeak(ctx, st, j, plan)
	if err != nil {
		return "", "", err
	}
	p.log().InfoContext(ctx, "jobs: user import completed", "tenant", j.TenantID, "job", j.ID, "connection", j.Connection,
		"inserted", sum.Inserted, "updated", sum.Updated, "failed", sum.Failed, "total", sum.Total, "weak_hashes", weak)
	p.notify(ctx, st, j, store.JobCompleted, "", sum)
	return store.JobCompleted, "", nil
}

// importedWeak counts the records that were imported with a weak hash: a
// weak custom_password_hash on a record that did not fail.
func (p Importer) importedWeak(ctx context.Context, st store.Store, j *store.Job, plan []importRecord) (int, error) {
	errs, err := st.Jobs().Errors(ctx, j.TenantID, j.ID)
	if err != nil {
		return 0, err
	}
	failed := make(map[int]bool, len(errs))
	for _, e := range errs {
		failed[e.Index] = true
	}
	n := 0
	for i, r := range plan {
		if !failed[i] && r.weak {
			n++
		}
	}
	return n, nil
}

// importConnection is the job's connection, or nil when it no longer
// exists or no longer takes imports (every record then fails).
func importConnection(ctx context.Context, tx store.Store, j *store.Job) (*store.Connection, error) {
	conn, err := tx.Connections().Get(ctx, j.TenantID, j.ConnectionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if conn.Strategy != store.StrategyDatabase || identity.IsLegacy(conn) {
		return nil, nil
	}
	return conn, nil
}

type outcome int

const (
	outFailed outcome = iota
	outInserted
	outUpdated
)

// importRecord is one entry of the file, decoded once for the whole job.
type importRecord struct {
	raw any            // the entry as decoded
	obj map[string]any // raw when it is an object, else nil
	// email, userID and username are the record's values when they are
	// strings (email and username normalized), for the duplicate checks.
	email, userID, username string
	// dupEmail and dupOther mark a record whose email, or user_id or
	// username, an earlier record of the file already has.
	dupEmail, dupOther bool
	weak               bool // a valid, weak custom_password_hash
}

// echo is the record as a job error shows it: hashes masked, and NUL
// characters (which no store can hold) replaced.
func (r *importRecord) echo() any {
	if r.obj == nil {
		return storable(r.raw)
	}
	return storable((&passhash.Spec{}).Masked(r.obj))
}

// planImport decodes every record and finds the duplicates within the
// file: the first record with a given email, user_id or username is
// processed normally and every later one fails (J4).
func planImport(recs []json.RawMessage) []importRecord {
	plan := make([]importRecord, len(recs))
	emails, ids, usernames := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, raw := range recs {
		r := &plan[i]
		_ = json.Unmarshal(raw, &r.raw) // an element of a valid array
		r.obj, _ = r.raw.(map[string]any)
		if r.obj == nil {
			continue
		}
		if s, ok := r.obj["email"].(string); ok {
			r.email = loginid.Normalize(s)
		}
		r.userID, _ = r.obj["user_id"].(string)
		if s, ok := r.obj["username"].(string); ok {
			r.username = loginid.Normalize(s)
		}
		if r.email != "" {
			r.dupEmail = emails[r.email]
			emails[r.email] = true
		}
		if r.userID != "" {
			r.dupOther = ids[r.userID]
			ids[r.userID] = true
		}
		if r.username != "" {
			r.dupOther = r.dupOther || usernames[r.username]
			usernames[r.username] = true
		}
		if cph, ok := r.obj["custom_password_hash"]; ok {
			if _, both := r.obj["password_hash"]; !both {
				b, _ := json.Marshal(cph)
				if s, errs := passhash.ParseCustom(b); len(errs) == 0 {
					r.weak = s.Weak()
				}
			}
		}
	}
	return plan
}

// storable copies v with every NUL in a string or key replaced by U+FFFD.
func storable(v any) any {
	switch t := v.(type) {
	case string:
		return strings.ReplaceAll(t, "\x00", "�")
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = storable(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[strings.ReplaceAll(k, "\x00", "�")] = storable(e)
		}
		return out
	}
	return v
}

// hasNUL reports whether a string or key in v holds a NUL character.
func hasNUL(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.ContainsRune(t, 0)
	case []any:
		return slices.ContainsFunc(t, hasNUL)
	case map[string]any:
		for k, e := range t {
			if strings.ContainsRune(k, 0) || hasNUL(e) {
				return true
			}
		}
	}
	return false
}

// jsonType names v's JSON type the way Auth0's schema errors do: a whole
// number is an integer.
func jsonType(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		if t == math.Trunc(t) && !math.IsInf(t, 0) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	}
	return "object"
}

func item(code, message, path string) store.JobErrorItem {
	return store.JobErrorItem{Code: code, Message: message, Path: path}
}

func typeItem(want string, got any, path string) store.JobErrorItem {
	return item("INVALID_TYPE", "Expected type "+want+" but found type "+jsonType(got), path)
}

// fields is a record that passed the checks, normalized.
type fields struct {
	identities                            []store.Identity
	identityKeys                          []store.FederatedIdentityKey
	hasIdentities                         bool
	email, userID, username, phone        string
	name, givenName, familyName, nickname string
	picture                               string
	emailVerified, phoneVerified, blocked *bool
	userMetadata, appMetadata             map[string]any
	hasUserMetadata, hasAppMetadata       bool
	present                               map[string]bool
	spec                                  *passhash.Spec
	customHash                            bool // spec came from custom_password_hash
}

// check validates an object record against the import schema (U10, J5)
// and the user rules of conn. Unknown properties are ignored.
func check(conn *store.Connection, obj map[string]any) (*fields, []store.JobErrorItem) {
	var items []store.JobErrorItem
	f := &fields{present: map[string]bool{}}
	str := func(k string) (string, bool) {
		v, ok := obj[k]
		if !ok {
			return "", false
		}
		f.present[k] = true
		s, isStr := v.(string)
		if !isStr {
			items = append(items, typeItem("string", v, k))
			return "", false
		}
		return s, true
	}
	boolean := func(k string) *bool {
		v, ok := obj[k]
		if !ok {
			return nil
		}
		b, isBool := v.(bool)
		if !isBool {
			items = append(items, typeItem("boolean", v, k))
			return nil
		}
		return &b
	}
	object := func(k string) (map[string]any, bool) {
		v, ok := obj[k]
		if !ok {
			return nil, false
		}
		m, isObj := v.(map[string]any)
		if !isObj {
			items = append(items, typeItem("object", v, k))
			return nil, false
		}
		if err := userrules.CheckMetadata(k, m); err != nil {
			// Not observed on Auth0; zeroauthy's metadata rules (D-0043).
			items = append(items, item("INVALID_FORMAT", "Error in "+k+" property - "+err.Error(), k))
			return nil, false
		}
		return m, true
	}
	maxLen := func(k, s string, limit int) {
		if n := utf8.RuneCountInString(s); n > limit {
			items = append(items, item("MAX_LENGTH", fmt.Sprintf("String is too long (%d chars), maximum %d", n, limit), k))
		}
	}

	if hasNUL(obj) {
		// No store can hold a NUL character; not observed on Auth0.
		items = append(items, item("INVALID_FORMAT", "Strings must not contain NUL characters", ""))
	}
	if v, ok := obj["email"]; !ok {
		items = append(items, item("OBJECT_MISSING_REQUIRED_PROPERTY", msgMissingEmail, ""))
	} else if s, isStr := v.(string); !isStr {
		items = append(items, typeItem("string", v, "email"))
	} else if f.email = loginid.Normalize(s); identity.CheckEmail(f.email) != nil {
		items = append(items, item("INVALID_FORMAT", formatEmailMessage+s, pathEmail))
	}
	f.emailVerified = boolean("email_verified")

	if s, ok := str("username"); ok {
		f.username = loginid.Normalize(s)
		switch {
		case !conn.RequiresUsername:
			// userrules' rule for a connection without usernames; Auth0's
			// import answer was not observed.
			items = append(items, item("NOT_PASSED", "Cannot set username for connection without requires_username", "username"))
		default:
			if err := identity.CheckUsername(conn, f.username); err != nil {
				var pe *identity.PolicyError
				msg := err.Error()
				if errors.As(err, &pe) {
					msg = pe.Reason
				}
				items = append(items, item("INVALID_FORMAT", "Error in username property - "+msg, "username"))
			}
		}
	}
	for _, p := range []struct {
		k   string
		dst *string
	}{{"given_name", &f.givenName}, {"family_name", &f.familyName}, {"name", &f.name}, {"nickname", &f.nickname}} {
		if s, ok := str(p.k); ok {
			*p.dst = s
			maxLen(p.k, s, loginid.MaxProfileFieldRunes)
		}
	}
	if s, ok := str("picture"); ok {
		f.picture = s
		if !loginid.ValidPicture(s) {
			items = append(items, item("INVALID_FORMAT", "Error in picture property - Object didn't pass validation for format url: "+s, "picture"))
		}
	}
	if s, ok := str("user_id"); ok {
		f.userID = s
		n := utf8.RuneCountInString(s)
		switch {
		case n == 0:
			items = append(items, item("MIN_LENGTH", "String is too short (0 chars), minimum 1", "user_id"))
		case n > userrules.MaxUserIDLength:
			items = append(items, item("MAX_LENGTH", fmt.Sprintf("String is too long (%d chars), maximum %d", n, userrules.MaxUserIDLength), "user_id"))
		case strings.IndexFunc(s, unicode.IsSpace) >= 0:
			items = append(items, item("PATTERN", `String does not match pattern ^\S*$: `+s, "user_id"))
		}
	}
	f.blocked = boolean("blocked")
	if s, ok := str("phone_number"); ok {
		f.phone = s
		maxLen("phone_number", s, loginid.MaxProfileFieldRunes)
	}
	f.phoneVerified = boolean("phone_verified")

	f.appMetadata, f.hasAppMetadata = object("app_metadata")
	for _, k := range reservedAppMetadata {
		if _, ok := f.appMetadata[k]; ok {
			items = append(items, item("NOT_PASSED", forbiddenAppMessage+k, k))
		}
	}
	f.userMetadata, f.hasUserMetadata = object("user_metadata")

	ph, hasPH := obj["password_hash"]
	cph, hasCPH := obj["custom_password_hash"]
	switch {
	case hasPH && hasCPH:
		items = append(items, item("NOT_PASSED", msgBothHashes, ""))
	case hasPH:
		s, isStr := ph.(string)
		if !isStr {
			items = append(items, typeItem("string", ph, "passwordHash"))
			break
		}
		spec, errs := passhash.FromBcrypt(s)
		items = appendHashErrors(items, errs)
		f.spec = spec
	case hasCPH:
		b, _ := json.Marshal(cph)
		spec, errs := passhash.ParseCustom(b)
		items = appendHashErrors(items, errs)
		f.spec, f.customHash = spec, true
	}
	if v, ok := obj["mfa_factors"]; ok {
		// Accepted and ignored: zeroauthy has no MFA yet (D-0044).
		if _, isArr := v.([]any); !isArr {
			items = append(items, typeItem("array", v, "mfa_factors"))
		}
	}
	if raw, ok := obj["identities"]; ok {
		f.hasIdentities = true
		var identityItems []store.JobErrorItem
		f.identities, identityItems = secondaryImportIdentities(raw)
		items = append(items, identityItems...)
	}
	return f, items
}

func appendHashErrors(items []store.JobErrorItem, errs []passhash.FieldError) []store.JobErrorItem {
	for _, e := range errs {
		items = append(items, item(e.Code, e.Message, e.Path))
	}
	return items
}

// record imports record i inside the batch transaction tx. A failure of
// the record is outFailed with its error items; an error is a store
// failure that ends the job.
func (p Importer) record(ctx context.Context, tx store.Store, conn *store.Connection, plan []importRecord, i int, upsert bool) (outcome, []store.JobErrorItem, error) {
	r := &plan[i]
	fail := func(items ...store.JobErrorItem) (outcome, []store.JobErrorItem, error) { return outFailed, items, nil }
	if r.obj == nil {
		return fail(typeItem("object", r.raw, ""))
	}
	if conn == nil {
		// Our own message: the connection was deleted or changed after the
		// job was created.
		return fail(item("CONNECTION_NOT_FOUND", "The connection does not exist or no longer accepts imports.", ""))
	}
	f, items := check(conn, r.obj)
	if len(items) > 0 {
		return fail(items...)
	}
	switch {
	case r.dupEmail:
		return fail(item("NON_UNIQUE_PROPERTY_VALUE", fmt.Sprintf("Property \"email\" has non-unique value: %s", f.email), ""))
	case r.dupOther:
		return fail(item("DUPLICATED_USER", msgDuplicateInFile, ""))
	}

	if f.hasIdentities {
		items, err := validateImportIdentities(ctx, tx, conn.TenantID, f)
		if err != nil {
			return 0, nil, err
		}
		if len(items) > 0 {
			return fail(items...)
		}
	}
	existing, err := tx.Users().FindByLogin(ctx, conn.TenantID, conn.Name, f.email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return p.insert(ctx, tx, conn, f)
	case err != nil:
		return 0, nil, err
	case existing.Email != f.email || existing.OwnIdentityOn(conn.Name) == nil:
		// The email belongs to an identity linked to another user.
		return fail(item("CONFLICT_EMAIL", "The email is already used by another user of the connection", ""))
	case !upsert:
		return fail(item("DUPLICATED_USER", msgDuplicatedUser, ""))
	}
	return p.update(ctx, tx, conn, existing.UserID, f)
}

// insert creates a new user from f.
func (p Importer) insert(ctx context.Context, tx store.Store, conn *store.Connection, f *fields) (outcome, []store.JobErrorItem, error) {
	if f.username != "" {
		if _, err := tx.Users().FindByLogin(ctx, conn.TenantID, conn.Name, f.username); err == nil {
			return outFailed, []store.JobErrorItem{item("CONFLICT_USERNAME", "The username is already used by another user of the connection", "username")}, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return 0, nil, err
		}
	}
	ident := store.Identity{Connection: conn.Name, Provider: store.StrategyDatabase, UserID: f.userID}
	if ident.UserID == "" {
		ident.UserID = secrets.RandomHex(12)
	}
	userID := userrules.UserIDPrefix + ident.UserID
	if f.userID != "" {
		if _, err := tx.Users().Get(ctx, conn.TenantID, userID); err == nil {
			return outFailed, []store.JobErrorItem{item("CONFLICT", "A user with this user_id already exists: "+userID, "user_id")}, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return 0, nil, err
		}
	}
	if f.spec != nil {
		ident.ImportedHash = f.spec.Marshal()
	}
	// Without a hash the user has no password until it is reset (J6).
	deref := func(b *bool) bool { return b != nil && *b }
	now := p.now()
	u := &store.User{
		TenantID: conn.TenantID, UserID: userID, Email: f.email, EmailVerified: deref(f.emailVerified), Username: f.username,
		GivenName: f.givenName, FamilyName: f.familyName, Picture: f.picture, PhoneNumber: f.phone, PhoneVerified: deref(f.phoneVerified),
		Blocked: deref(f.blocked), UserMetadata: f.userMetadata, AppMetadata: f.appMetadata,
		Identities: []store.Identity{ident}, CreatedAt: now, UpdatedAt: now,
	}
	u.Identities = append(u.Identities, f.identities...)
	u.Name, u.Nickname = identity.DefaultNames(f.name, f.nickname, f.email, f.username)
	if u.Picture == "" {
		u.Picture = userrules.DefaultPicture(f.email)
	}
	if u.UserMetadata == nil {
		u.UserMetadata = map[string]any{} // imported users show {} (J4)
	}
	if err := tx.Users().Create(ctx, u); errors.Is(err, store.ErrConflict) {
		// A user created since the checks above.
		return outFailed, []store.JobErrorItem{item("CONFLICT", "The user already exists", "")}, nil
	} else if err != nil {
		return 0, nil, err
	}
	return outInserted, nil, nil
}

// update applies an upsert record to the existing user userID (J4): names,
// email_verified and the other profile fields the record has replace the
// stored ones, metadata objects are replaced whole, and blocked, user_id
// and password_hash are ignored. A custom_password_hash replaces the
// imported hash, or sets one on a user that has no hash at all; a user
// with a native password hash (who signed in, or set a password) is a
// CONFLICT (rulings R1, R11). The user row is locked here, and the sign-in
// upgrade is a compare-and-swap on the imported value, so exactly one of
// the two wins: if the upgrade committed first, PasswordHash is set and
// the record conflicts.
func (p Importer) update(ctx context.Context, tx store.Store, conn *store.Connection, userID string, f *fields) (outcome, []store.JobErrorItem, error) {
	u, err := tx.Users().GetForUpdate(ctx, conn.TenantID, userID)
	if err != nil {
		return 0, nil, err
	}
	if f.hasIdentities {
		matching, err := matchingImportIdentities(ctx, tx, u, f)
		if err != nil {
			return 0, nil, err
		}
		if !matching {
			return outFailed, []store.JobErrorItem{item("CONFLICT", "Upsert cannot change secondary identity ownership; use explicit account linking", "identities")}, nil
		}
	}
	id := u.OwnIdentityOn(conn.Name)
	if id == nil {
		return outFailed, []store.JobErrorItem{item("CONFLICT_EMAIL", "The email is already used by another user of the connection", "")}, nil
	}
	if f.customHash {
		if id.PasswordHash != "" {
			return outFailed, []store.JobErrorItem{item("CONFLICT", msgHashAlreadySet, "")}, nil
		}
		id.ImportedHash = f.spec.Marshal()
	}
	if f.username != "" && f.username != u.Username {
		if other, err := tx.Users().FindByLogin(ctx, conn.TenantID, conn.Name, f.username); err == nil && other.UserID != u.UserID {
			return outFailed, []store.JobErrorItem{item("CONFLICT_USERNAME", "The username is already used by another user of the connection", "username")}, nil
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return 0, nil, err
		}
	}
	opt := func(k string, v string) *string {
		if f.present[k] {
			return &v
		}
		return nil
	}
	patch := &userrules.Patch{
		Username: opt("username", f.username), PhoneNumber: opt("phone_number", f.phone),
		Name: opt("name", f.name), GivenName: opt("given_name", f.givenName), FamilyName: opt("family_name", f.familyName),
		Nickname: opt("nickname", f.nickname), Picture: opt("picture", f.picture),
		EmailVerified: f.emailVerified, PhoneVerified: f.phoneVerified,
	}
	userrules.ApplyPatch(u, patch)
	if f.hasUserMetadata {
		u.UserMetadata = maps.Clone(f.userMetadata)
	}
	if f.hasAppMetadata {
		u.AppMetadata = maps.Clone(f.appMetadata)
	}
	u.UpdatedAt = p.now()
	if err := tx.Users().Update(ctx, u); errors.Is(err, store.ErrConflict) {
		return outFailed, []store.JobErrorItem{item("CONFLICT", "The user conflicts with another user of the connection", "")}, nil
	} else if err != nil {
		return 0, nil, err
	}
	return outUpdated, nil, nil
}

// notify emails the tenant's operators that the import ended, when the
// job asked for it (send_completion_email, default true). A failure is
// logged; it never changes the job.
func (p Importer) notify(ctx context.Context, st store.Store, j *store.Job, status store.JobStatus, details string, sum store.JobSummary) {
	if (p.Mailer == nil && p.Email == nil) || !paramBool(j, ParamSendCompletionEmail, true) {
		return
	}
	// The job may be ending because ctx is done; the email still goes.
	ctx = context.WithoutCancel(ctx)
	fail := func(what string, err error) {
		p.log().ErrorContext(ctx, "jobs: import completion email: "+what, "err", err, "tenant", j.TenantID, "job", j.ID)
	}
	tn, err := st.Tenants().Get(ctx, j.TenantID)
	if err != nil {
		fail("load the tenant", err)
		return
	}
	to, err := Recipients(ctx, st, tn.Name)
	if err != nil {
		fail("load the operators", err)
		return
	}
	msg := email.ImportDoneMessage(i18n.Default(), email.ImportDone{
		Tenant: tn.Name, Job: j.ID, Connection: j.Connection, Failed: status == store.JobFailed, Details: details,
		Inserted: sum.Inserted, Updated: sum.Updated, FailedRecords: sum.Failed, Total: sum.Total,
	})
	for _, addr := range to {
		m := msg
		m.To = addr
		var sendErr error
		if p.Email != nil {
			sendErr = p.Email.SendMessage(ctx, j.TenantID, m)
		} else {
			sendErr = p.Mailer.Send(ctx, m)
		}
		if sendErr != nil {
			fail("send", sendErr)
		}
	}
}

// Recipients returns the email addresses, sorted and without repeats, of
// the operators who manage the tenant named name: those whose Tenants list
// it or "*" (spec §5.6, D-0044).
func Recipients(ctx context.Context, st store.Store, name string) ([]string, error) {
	sys, err := st.Tenants().GetByName(ctx, tenant.SystemName)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ops, err := st.Operators().List(ctx, sys.ID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, op := range ops {
		if !slices.Contains(op.Tenants, store.OperatorAllTenants) && !slices.Contains(op.Tenants, name) {
			continue
		}
		u, err := st.Users().Get(ctx, sys.ID, op.UserID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if u.Email != "" && !slices.Contains(out, u.Email) {
			out = append(out, u.Email)
		}
	}
	slices.Sort(out)
	return out, nil
}
