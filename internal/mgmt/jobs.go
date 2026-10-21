package mgmt

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// JobLifetime is how long a job is kept: Auth0 deletes job data after 24
// hours (J9).
const JobLifetime = 24 * time.Hour

var jobIDPattern = regexp.MustCompile(`^job_[A-Za-z0-9]{16}$`)

var (
	errJobNotFound      = &Error{Status: http.StatusNotFound, Code: "inexistent_job", Message: "The job does not exist"}
	errVerifyUser       = &Error{Status: http.StatusNotFound, Code: "inexistent_user", Message: "The user does not exist"}
	errVerifyIdentity   = &Error{Status: http.StatusNotFound, Code: "inexistent_identity", Message: "The user exists, but does not contain the given identity"}
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
	if err := h.checkTicketClient(r, in.clientID); err != nil {
		Fail(w, err)
		return
	}
	if in.clientID != "" {
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
