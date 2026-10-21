package mgmt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// JobLifetime is how long a job is kept: Auth0 deletes job data after 24
// hours (J9).
const JobLifetime = 24 * time.Hour

var jobIDPattern = regexp.MustCompile(`^job_[A-Za-z0-9]{16}$`)

var (
	// Every verification-email error is a 400 on Auth0 (J10), unlike the
	// tickets endpoints (D-0043), so these are not the ticket errors.
	errJobNotFound      = &Error{Status: http.StatusNotFound, Code: "inexistent_job", Message: "The job does not exist"}
	errVerifyUser       = &Error{Status: http.StatusBadRequest, Code: "inexistent_user", Message: "The user does not exist"}
	errVerifyIdentity   = &Error{Status: http.StatusBadRequest, Code: "inexistent_identity", Message: "The user exists, but does not contain the given identity"}
	errVerifyNotDB      = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "The identity is not in a database connection."}
	errJobIDUnavailable = errors.New("no free job ID")
)

func badJobID(id string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_uri",
		Message: fmt.Sprintf("Path validation error: 'String does not match pattern ^job_[A-Za-z0-9]{16}$: %s' on property id (ID of the job).", id)}
}

// NewJobID returns a job ID: job_ and 16 letters or digits.
func NewJobID() string { return "job_" + secrets.RandomString(16) }

// NewJob returns a pending job of type t for the tenant, created now,
// with a fresh ID and the lifetime JobLifetime. The create handlers store
// it with CreateJob.
func NewJob(tenantID string, t store.JobType, now time.Time) *store.Job {
	return &store.Job{
		TenantID: tenantID, ID: NewJobID(), Type: t, Status: store.JobPending,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(JobLifetime),
	}
}

// CreateJob stores j (choosing a new ID if the one it has is taken) and
// wakes a worker.
func (h *Handlers) CreateJob(r *http.Request, j *store.Job) error {
	for range 5 {
		err := h.Store.Jobs().Create(r.Context(), j)
		if err == nil {
			if h.Notify != nil {
				h.Notify()
			}
			return nil
		}
		if !errors.Is(err, store.ErrConflict) {
			return internalError(h, r, "create job", err)
		}
		j.ID = NewJobID()
	}
	return internalError(h, r, "create job", errJobIDUnavailable)
}

// JobJSON is j in Auth0's shape (J2, J3, J9). A job that is running reads
// pending, with no progress. location is the download link of a completed
// export ("" for any other job). Fields without a value are left out.
func JobJSON(j *store.Job, location string) map[string]any {
	status := j.Status
	if status == store.JobProcessing {
		status = store.JobPending
	}
	m := map[string]any{"id": j.ID, "type": string(j.Type), "status": string(status), "created_at": userTime(j.CreatedAt)}
	for k, v := range map[string]string{"connection_id": j.ConnectionID, "connection": j.Connection, "external_id": j.ExternalID} {
		if v != "" {
			m[k] = v
		}
	}
	if j.Type == store.JobUsersExport {
		for _, k := range []string{"format", "limit", "fields"} {
			if v, ok := j.Params[k]; ok {
				m[k] = v
			}
		}
	}
	switch {
	case j.Status == store.JobFailed && j.StatusDetails != "":
		m["status_details"] = j.StatusDetails
	case j.Status == store.JobCompleted && j.Type == store.JobUsersImport:
		m["summary"] = map[string]any{"failed": j.Summary.Failed, "updated": j.Summary.Updated, "inserted": j.Summary.Inserted, "total": j.Summary.Total}
	}
	if location != "" && j.Status == store.JobCompleted && j.Type == store.JobUsersExport {
		m["location"] = location
	}
	return m
}

// jobLocation is the download link of a completed export; exports add it
// with their download route.
func (h *Handlers) jobLocation(*http.Request, *store.Job) string { return "" }

// loadJob finds the tenant's job id. An expired job that the sweeper has
// not removed yet does not exist (J9).
func (h *Handlers) loadJob(r *http.Request, id string) (*store.Job, error) {
	if !jobIDPattern.MatchString(id) {
		return nil, badJobID(id)
	}
	j, err := h.Store.Jobs().Get(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errJobNotFound
	}
	if err != nil {
		return nil, internalError(h, r, "get job", err)
	}
	if h.now().After(j.ExpiresAt) {
		return nil, errJobNotFound
	}
	return j, nil
}

// GetJob serves GET /jobs/{id} (J3, J9).
func (h *Handlers) GetJob(w http.ResponseWriter, r *http.Request, id string) {
	j, err := h.loadJob(r, id)
	if err != nil {
		Fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, JobJSON(j, h.jobLocation(r, j)))
}

// GetJobErrors serves GET /jobs/{id}/errors (J9): the record errors of an
// import (an empty array when there are none), the job itself when it
// failed, and 204 for the jobs that have no errors to list.
func (h *Handlers) GetJobErrors(w http.ResponseWriter, r *http.Request, id string) {
	j, err := h.loadJob(r, id)
	if err != nil {
		Fail(w, err)
		return
	}
	switch {
	case j.Status == store.JobFailed:
		writeJSON(w, http.StatusOK, JobJSON(j, ""))
		return
	case j.Type != store.JobUsersImport:
		w.WriteHeader(http.StatusNoContent)
		return
	}
	errs, err := h.Store.Jobs().Errors(r.Context(), j.TenantID, j.ID)
	if err != nil {
		Fail(w, internalError(h, r, "get job errors", err))
		return
	}
	out := make([]map[string]any, len(errs))
	for i, e := range errs {
		items := make([]map[string]any, len(e.Errors))
		for k, it := range e.Errors {
			items[k] = map[string]any{"code": it.Code, "message": it.Message}
			if it.Path != "" {
				items[k]["path"] = it.Path
			}
		}
		out[i] = map[string]any{"user": e.User, "errors": items}
	}
	writeJSON(w, http.StatusOK, out)
}

// verificationEmailBody is a POST /jobs/verification-email body.
type verificationEmailBody struct {
	userID, clientID string
	identity         *struct{ userID, provider, connectionID string }
}

func readVerificationEmailBody(body map[string]json.RawMessage) (*verificationEmailBody, error) {
	if err := checkBodyText(body); err != nil {
		return nil, err
	}
	b := userBody{body}
	in := &verificationEmailBody{}
	for _, k := range slices.Sorted(maps.Keys(body)) {
		var err error
		switch k {
		case "user_id":
			in.userID, err = b.str(k)
		case "client_id":
			in.clientID, err = b.str(k)
		case "identity":
			in.identity, err = readVerificationIdentity(body[k])
		default:
			// organization_id included: there are no organizations.
			err = badBodyRaw(fmt.Sprintf("Payload validation error: 'Additional properties not allowed: %s'.", k))
		}
		if err != nil {
			return nil, err
		}
	}
	if _, ok := body["user_id"]; !ok {
		return nil, missingProperty("user_id")
	}
	if !validUserID(in.userID) {
		return nil, badBodyRaw("Payload validation error: 'Object didn't pass validation for format user-id: " + in.userID +
			"' on property user_id (user_id of the user to send the verification email to).")
	}
	return in, nil
}

func readVerificationIdentity(raw json.RawMessage) (*struct{ userID, provider, connectionID string }, error) {
	var v map[string]json.RawMessage
	if isNull(raw) || json.Unmarshal(raw, &v) != nil {
		return nil, wrongType("identity", "object", raw)
	}
	id := &struct{ userID, provider, connectionID string }{}
	b := userBody{v}
	for _, k := range slices.Sorted(maps.Keys(v)) {
		var err error
		switch k {
		case "user_id":
			id.userID, err = b.str(k)
		case "provider":
			id.provider, err = b.str(k)
		case "connection_id":
			id.connectionID, err = b.str(k)
		default:
			err = badBodyRaw(fmt.Sprintf("Payload validation error: 'Additional properties not allowed: %s' on property identity.", k))
		}
		if err != nil {
			return nil, err
		}
	}
	switch {
	case id.userID == "":
		return nil, badBodyRaw("Payload validation error: 'Missing required property: user_id' on property identity.")
	case id.provider == "":
		return nil, badBodyRaw("Payload validation error: 'Missing required property: provider' on property identity.")
	}
	return id, nil
}

// CreateVerificationEmailJob serves POST /jobs/verification-email (J10).
// The checks run now; a worker sends the email.
func (h *Handlers) CreateVerificationEmailJob(w http.ResponseWriter, r *http.Request) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	in, err := readVerificationEmailBody(body)
	if err != nil {
		Fail(w, err)
		return
	}
	ctx, tn := r.Context(), resolved(r)
	u, err := h.Store.Users().Get(ctx, tn.ID, in.userID)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errVerifyUser)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "load user", err))
		return
	}
	params := map[string]any{"user_id": u.UserID}
	if in.identity != nil {
		id, err := h.verificationIdentity(r, u, in.identity.userID, in.identity.provider, in.identity.connectionID)
		if err != nil {
			Fail(w, err)
			return
		}
		if id.Provider != store.StrategyDatabase {
			Fail(w, errVerifyNotDB)
			return
		}
		params["identity"] = map[string]any{"user_id": id.UserID, "provider": id.Provider, "connection": id.Connection}
	}
	if in.clientID != "" {
		_, err := h.Store.Clients().Get(ctx, tn.ID, in.clientID)
		if errors.Is(err, store.ErrNotFound) {
			Fail(w, errNoSuchClient)
			return
		}
		if err != nil {
			Fail(w, internalError(h, r, "load client", err))
			return
		}
		params["client_id"] = in.clientID
	}
	if u.Email == "" {
		Fail(w, errTicketNoEmail)
		return
	}
	j := NewJob(tn.ID, store.JobVerificationEmail, h.now())
	j.Params = params
	if err := h.CreateJob(r, j); err != nil {
		Fail(w, err)
		return
	}
	h.audit(r, "create verification email job", "job_id", j.ID, "user_id", u.UserID)
	writeJSON(w, http.StatusCreated, JobJSON(j, ""))
}

// verificationIdentity finds the user's identity named by the request;
// connectionID, when given, must be that identity's connection.
func (h *Handlers) verificationIdentity(r *http.Request, u *store.User, userID, provider, connectionID string) (*store.Identity, error) {
	for i := range u.Identities {
		id := &u.Identities[i]
		if id.Provider != provider || id.UserID != userID {
			continue
		}
		if connectionID != "" {
			c, err := h.Store.Connections().Get(r.Context(), u.TenantID, connectionID)
			if errors.Is(err, store.ErrNotFound) || (err == nil && c.Name != id.Connection) {
				return nil, errVerifyIdentity
			}
			if err != nil {
				return nil, internalError(h, r, "load connection", err)
			}
		}
		return id, nil
	}
	return nil, errVerifyIdentity
}

// MaxImportBody is the largest POST /jobs/users-imports request body,
// multipart framing included (J1).
const MaxImportBody = 512000

// MaxActiveImports is how many import jobs of one tenant may be pending or
// running at once (J3).
const MaxActiveImports = 2

var importConnectionID = regexp.MustCompile(`^con_[A-Za-z0-9]{16}$`)

var (
	errImportTooLarge = &Error{Status: http.StatusRequestEntityTooLarge,
		Message: fmt.Sprintf("Payload content length greater than maximum allowed: %d", MaxImportBody)}
	errImportTooMany = &Error{Status: http.StatusTooManyRequests,
		Message: fmt.Sprintf("There are %d active import users jobs, please wait until some of them are finished and try again", MaxActiveImports)}
	errImportNoUsers      = badBodyRaw("Must provide 'users' file as multipart part.")
	errImportNoConnection = badBodyRaw("Must provide 'connection_id' as multipart part.")
	errImportEmptyFile    = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "Users file must not be empty."}
	errImportConnectionID = badBodyRaw("Payload validation error: 'String does not match pattern ^con_[A-Za-z0-9]{16}$' on property connection_id.")
	errImportNotDatabase  = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "Connection must be a database connection."}
	errImportDisabled     = &Error{Status: http.StatusBadRequest, Code: "connection_is_disabled", Message: "Connection must be enabled."}
	errImportLegacy       = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "Custom Database Connections without import mode are not allowed."}
	errImportExternalID   = badBodyRaw("Payload validation error: strings must be valid UTF-8 without NUL characters.")
)

// readImportForm reads the parts of a multipart request body, keeping the
// first part of each name. A body that is not multipart, or whose framing
// breaks off, has the parts read before that; the rest of the body is
// still read, so that a body over the limit fails.
func readImportForm(r *http.Request) (map[string][]byte, error) {
	parts := map[string][]byte{}
	mr, err := r.MultipartReader()
	if err != nil {
		_, err := io.Copy(io.Discard, r.Body)
		return parts, err
	}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return parts, nil
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return nil, err
			}
			_, err := io.Copy(io.Discard, r.Body)
			return parts, err
		}
		data, err := io.ReadAll(part)
		if err != nil {
			return nil, err
		}
		if name := part.FormName(); name != "" {
			if _, seen := parts[name]; !seen {
				parts[name] = data
			}
		}
	}
}

// CreateUsersImportJob serves POST /jobs/users-imports (J1, J3): the checks
// run now, a worker imports the file (jobs.Importer).
func (h *Handlers) CreateUsersImportJob(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > MaxImportBody {
		Fail(w, errImportTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxImportBody)
	parts, err := readImportForm(r)
	if err != nil {
		// The multipart reader may hide the limit's error behind its own:
		// once over the limit, the body keeps answering it.
		_, rest := io.Copy(io.Discard, r.Body)
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) || errors.As(rest, &mbe) {
			Fail(w, errImportTooLarge)
			return
		}
		Fail(w, badBodyRaw("The request body could not be read."))
		return
	}
	users, hasUsers := parts["users"]
	connID, hasConn := parts["connection_id"]
	switch {
	case !hasUsers:
		Fail(w, errImportNoUsers)
		return
	case !hasConn:
		Fail(w, errImportNoConnection)
		return
	case len(users) == 0:
		Fail(w, errImportEmptyFile)
		return
	case !importConnectionID.Match(connID):
		Fail(w, errImportConnectionID)
		return
	}
	externalID := string(parts["external_id"])
	if !storableText(externalID) {
		Fail(w, errImportExternalID)
		return
	}
	ctx, tn := r.Context(), resolved(r)
	conn, err := h.Store.Connections().Get(ctx, tn.ID, string(connID))
	switch {
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errUserConnection)
		return
	case err != nil:
		Fail(w, internalError(h, r, "load connection", err))
		return
	case conn.Strategy != store.StrategyDatabase:
		Fail(w, errImportNotDatabase)
		return
	case len(conn.EnabledClients) == 0:
		Fail(w, errImportDisabled)
		return
	case identity.IsLegacy(conn):
		Fail(w, errImportLegacy)
		return
	}
	// Loose booleans, as on Auth0: anything but "true" is no upsert, and
	// anything but "false" sends the completion email.
	upsert := strings.EqualFold(strings.TrimSpace(string(parts["upsert"])), "true")
	sendEmail := true
	if v, ok := parts["send_completion_email"]; ok && strings.EqualFold(strings.TrimSpace(string(v)), "false") {
		sendEmail = false
	}
	j := NewJob(tn.ID, store.JobUsersImport, h.now())
	j.ConnectionID, j.Connection, j.ExternalID, j.Input = conn.ID, conn.Name, externalID, users
	j.Params = map[string]any{
		jobs.ParamUpsert: upsert, jobs.ParamSendCompletionEmail: sendEmail, jobs.ParamWeakHashes: jobs.WeakHashes(users),
	}
	if err := h.createImportJob(r, j); err != nil {
		Fail(w, err)
		return
	}
	h.audit(r, "create users import job", "job_id", j.ID, "connection", conn.Name, "upsert", upsert, "bytes", len(users))
	writeJSON(w, http.StatusAccepted, JobJSON(j, ""))
}

// createImportJob stores j unless the tenant already has MaxActiveImports
// active imports. The count and the write share a transaction, which
// serializes them on the memory and SQLite drivers; on PostgreSQL and MySQL
// two requests racing each other can both pass the count (the limit is a
// guard against overload, not a security boundary).
func (h *Handlers) createImportJob(r *http.Request, j *store.Job) error {
	ctx := r.Context()
	for range 5 {
		err := h.Store.WithTx(ctx, func(tx store.Store) error {
			n, err := tx.Jobs().CountActive(ctx, j.TenantID, store.JobUsersImport)
			if err != nil {
				return err
			}
			if n >= MaxActiveImports {
				return errImportTooMany
			}
			return tx.Jobs().Create(ctx, j)
		})
		switch {
		case err == nil:
			if h.Notify != nil {
				h.Notify()
			}
			return nil
		case errors.Is(err, errImportTooMany):
			return errImportTooMany
		case !errors.Is(err, store.ErrConflict):
			return internalError(h, r, "create job", err)
		}
		j.ID = NewJobID()
	}
	return internalError(h, r, "create job", errJobIDUnavailable)
}
