package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logstream"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var errLogStreamInvalid = badBody("invalid log stream configuration")

var errLogStreamConflict = &Error{Status: 409, Code: "conflict", Message: "The log stream changed concurrently"}

func streamDecode(raw json.RawMessage, out any) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errLogStreamInvalid
	}
	if json.Unmarshal(raw, out) != nil {
		return errLogStreamInvalid
	}
	return nil
}
func (h *Handlers) streamError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrInvalid):
		Fail(w, errLogStreamInvalid)
	case errors.Is(err, store.ErrConflict):
		Fail(w, errLogStreamConflict)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, &Error{Status: 404, Code: "not_found", Message: "Log stream not found"})
	default:
		h.logError(w, r, err)
	}
}

func (h *Handlers) streamView(s *store.LogStream) (map[string]any, error) {
	private, err := logstream.OpenSecrets(h.Wrapper, s)
	if err != nil {
		return nil, err
	}
	sink := map[string]any{}
	schema, ok := logrules.SinkSchema(s.Type)
	if !ok {
		return nil, store.ErrInvalid
	}
	for _, f := range schema.Fields {
		if f.Secret {
			if _, ok := private[f.Name]; ok {
				sink[f.Name] = logrules.Marker
			}
		} else if v, ok := s.Sink[f.Name]; ok {
			sink[f.Name] = v
		}
	}
	filters := make([]map[string]string, 0, len(s.Filters))
	for _, f := range s.Filters {
		filters = append(filters, map[string]string{"type": f.Type, "name": f.Name})
	}
	out := map[string]any{"id": s.ID, "name": s.Name, "type": s.Type, "status": s.Status, "sink": sink, "filters": filters, "isPriority": s.IsPriority}
	if s.PII != nil {
		out["pii_config"] = map[string]any{"log_fields": s.PII.LogFields, "method": s.PII.Method, "algorithm": s.PII.Algorithm}
	}
	return out, nil
}
func (h *Handlers) writeStream(w http.ResponseWriter, r *http.Request, s *store.LogStream, status int) {
	view, err := h.streamView(s)
	if err != nil {
		h.streamError(w, r, err)
		return
	}
	writeJSON(w, status, view)
}
func (h *Handlers) ListLogStreams(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	rows, err := repo.ListLogStreams(r.Context(), resolved(r).ID)
	if err != nil {
		h.streamError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		view, err := h.streamView(&rows[i])
		if err != nil {
			h.streamError(w, r, err)
			return
		}
		out = append(out, view)
	}
	writeJSON(w, 200, out)
}
func (h *Handlers) GetLogStream(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	s, err := repo.GetLogStream(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.streamError(w, r, err)
		return
	}
	h.writeStream(w, r, s, 200)
}
func (h *Handlers) CreateLogStream(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	raw, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	s := &store.LogStream{TenantID: resolved(r).ID, ID: "lst_" + secrets.RandomString(24), Status: "active", Sink: map[string]any{}}
	if err = streamDecode(raw["type"], &s.Type); err != nil {
		Fail(w, errLogStreamInvalid)
		return
	}
	if err = h.applyStream(s, raw, true); err != nil {
		h.streamError(w, r, err)
		return
	}
	if err = repo.CreateLogStream(r.Context(), s); err != nil {
		h.streamError(w, r, err)
		return
	}
	logDetails(r, "create log stream", "id", s.ID, "type", s.Type)
	h.writeStream(w, r, s, http.StatusOK)
}
func (h *Handlers) UpdateLogStream(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	raw, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		s, err := repo.GetLogStream(r.Context(), resolved(r).ID, id)
		if err != nil {
			h.streamError(w, r, err)
			return
		}
		if err = h.applyStream(s, raw, false); err != nil {
			h.streamError(w, r, err)
			return
		}
		if err = repo.UpdateLogStream(r.Context(), s, s.Version); errors.Is(err, store.ErrConflict) {
			continue
		} else if err != nil {
			h.streamError(w, r, err)
			return
		}
		logDetails(r, "update log stream", "id", s.ID, "type", s.Type)
		h.writeStream(w, r, s, 200)
		return
	}
	Fail(w, errLogStreamConflict)
}
func (h *Handlers) DeleteLogStream(w http.ResponseWriter, r *http.Request, id string) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	if err := repo.DeleteLogStream(r.Context(), resolved(r).ID, id); err != nil {
		h.streamError(w, r, err)
		return
	}
	logDetails(r, "delete log stream", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// applyStream rebuilds from the latest tenant-scoped candidate on retry.
func (h *Handlers) applyStream(s *store.LogStream, raw map[string]json.RawMessage, create bool) error {
	private, err := logstream.OpenSecrets(h.Wrapper, s)
	if err != nil {
		return err
	}
	if err = logstream.Configure(s, raw, create, h.LogsConfig.Streams.AllowInsecureHTTP, private); err != nil {
		return err
	}
	s.SealedSecrets, err = logstream.SealSecrets(h.Wrapper, s, private)
	return err
}
