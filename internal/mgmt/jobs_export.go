package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// maxExportFieldName is the longest name or export_as of an export field.
const maxExportFieldName = 100

const (
	descLimit  = "Limit the number of records"
	descFields = "List of fields to be included in the CSV. Defaults to a predefined set of fields"
	descFormat = "Format of the file. Must be `json` or `csv`"
)

// exportBody is a POST /jobs/users-exports body.
type exportBody struct {
	connectionID string
	format       string
	limit        int
	fields       []any // [{name, export_as?}], as stored in the job
}

func exportMessage(msg, prop, desc string) *Error {
	return badBodyRaw(fmt.Sprintf("Payload validation error: '%s' on property %s (%s).", msg, prop, desc))
}

func readExportBody(body map[string]json.RawMessage) (*exportBody, error) {
	if err := checkBodyText(body); err != nil {
		return nil, err
	}
	in := &exportBody{format: jobs.FormatCSV}
	var unknown []string
	for _, k := range slices.Sorted(maps.Keys(body)) {
		switch k {
		case "connection_id", "format", "limit", "fields":
		default:
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		return nil, badBodyRaw("Payload validation error: 'Additional properties not allowed: " + strings.Join(unknown, ",") + "'.")
	}
	b := userBody{body}
	if _, ok := body["connection_id"]; ok {
		s, err := b.str("connection_id")
		if err != nil {
			return nil, err
		}
		if !importConnectionID.MatchString(s) {
			return nil, badBodyRaw("Payload validation error: 'String does not match pattern ^con_[A-Za-z0-9]{16}$: " + s + "' on property connection_id.")
		}
		in.connectionID = s
	}
	if _, ok := body["format"]; ok {
		s, err := b.str("format")
		if err != nil {
			return nil, err
		}
		if s != jobs.FormatCSV && s != jobs.FormatJSON {
			return nil, exportMessage(fmt.Sprintf("Invalid value %q", s), "format", descFormat)
		}
		in.format = s
	}
	if raw, ok := body["limit"]; ok {
		var n json.Number
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if isNull(raw) || d.Decode(&n) != nil {
			return nil, wrongType("limit", "integer", raw)
		}
		v, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil {
			f, ferr := n.Float64()
			if ferr != nil || f != float64(int64(f)) {
				return nil, wrongType("limit", "integer", raw)
			}
			v = int64(f)
		}
		if v < 1 {
			return nil, exportMessage(fmt.Sprintf("Value %d is less than minimum 1", v), "limit", descLimit)
		}
		in.limit = int(min(v, 1<<31))
	}
	if raw, ok := body["fields"]; ok {
		var list []json.RawMessage
		if isNull(raw) || json.Unmarshal(raw, &list) != nil {
			return nil, wrongType("fields", "array", raw)
		}
		if len(list) > jobs.MaxExportFields {
			return nil, exportMessage(fmt.Sprintf("Array is too long (%d), maximum %d", len(list), jobs.MaxExportFields), "fields", descFields)
		}
		for i, it := range list {
			f, err := readExportField(i, it)
			if err != nil {
				return nil, err
			}
			in.fields = append(in.fields, f)
		}
	}
	return in, nil
}

func readExportField(i int, raw json.RawMessage) (map[string]any, error) {
	prop := fmt.Sprintf("fields[%d]", i)
	var m map[string]json.RawMessage
	if isNull(raw) || json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, wrongType(prop, "object", raw)
	}
	out := map[string]any{}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if k != "name" && k != "export_as" {
			return nil, badBodyRaw("Payload validation error: 'Additional properties not allowed: " + k + "' on property " + prop + ".")
		}
		var s string
		if isNull(m[k]) || json.Unmarshal(m[k], &s) != nil {
			return nil, wrongType(prop+"."+k, "string", m[k])
		}
		if n := utf8.RuneCountInString(s); n > maxExportFieldName {
			return nil, badBodyRaw(fmt.Sprintf("Payload validation error: 'String is too long (%d), maximum %d' on property %s.%s.", n, maxExportFieldName, prop, k))
		}
		out[k] = s
	}
	if _, ok := out["name"]; !ok {
		return nil, badBodyRaw("Payload validation error: 'Missing required property: name' on property " + prop + ".")
	}
	return out, nil
}

// decodeOptionalObject reads a JSON object body; an empty body is {}.
func decodeOptionalObject(r *http.Request) (map[string]json.RawMessage, error) {
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		return nil, badBody("the body is too large or unreadable")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(data, &body); err != nil || body == nil {
		return nil, badBody("the body must be a JSON object")
	}
	return body, nil
}

// CreateUsersExportJob serves POST /jobs/users-exports (J8). The checks run
// now; a worker writes the file (jobs.Exporter).
func (h *Handlers) CreateUsersExportJob(w http.ResponseWriter, r *http.Request) {
	body, err := decodeOptionalObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	in, err := readExportBody(body)
	if err != nil {
		Fail(w, err)
		return
	}
	ctx, tn := r.Context(), resolved(r)
	j := NewJob(tn.ID, store.JobUsersExport, h.now())
	if in.connectionID != "" {
		c, err := h.Store.Connections().Get(ctx, tn.ID, in.connectionID)
		if errors.Is(err, store.ErrNotFound) {
			Fail(w, errUserConnection)
			return
		}
		if err != nil {
			Fail(w, internalError(h, r, "load connection", err))
			return
		}
		j.ConnectionID, j.Connection = c.ID, c.Name
	}
	j.Params = map[string]any{jobs.ParamFormat: in.format}
	if in.limit > 0 {
		j.Params[jobs.ParamLimit] = in.limit
	}
	if in.fields != nil {
		j.Params[jobs.ParamFields] = in.fields
	}
	if err := h.CreateJob(r, j); err != nil {
		Fail(w, err)
		return
	}
	h.audit(r, "create users export job", "job_id", j.ID, "format", in.format, "connection", j.Connection)
	writeJSON(w, http.StatusOK, JobJSON(j, ""))
}

// DownloadExport serves GET /export/{job}/{file} on tenant hosts (D-0044):
// the file of a completed export, for the holder of a link that
// ExportLink.Sign made for this tenant and that has not expired. There is no
// token; every refusal is the same plain 403.
func (h *Handlers) DownloadExport(w http.ResponseWriter, r *http.Request) {
	deny := func(why string) {
		h.log().WarnContext(r.Context(), "export download refused", "why", why, "job", chi.URLParam(r, "job"),
			"remote", httpx.ClientIP(r, h.TrustProxyHeaders))
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
	res, ok := tenant.FromContext(r.Context())
	if !ok || res.Tenant == nil || h.Export == nil {
		deny("no tenant or no link key")
		return
	}
	jobID, file := chi.URLParam(r, "job"), chi.URLParam(r, "file")
	expires, err := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
	if err != nil || !h.Export.Check(res.Tenant.ID, jobID, expires, r.URL.Query().Get("sig")) {
		deny("bad or expired signature")
		return
	}
	j, err := h.Store.Jobs().Get(r.Context(), res.Tenant.ID, jobID)
	if errors.Is(err, store.ErrNotFound) {
		deny("no such job")
		return
	}
	if err != nil {
		h.log().ErrorContext(r.Context(), "export download: get job", "err", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	format := exportFormat(j)
	name := res.Tenant.Name + "." + format + ".gz"
	if j.Type != store.JobUsersExport || j.Status != store.JobCompleted || h.now().After(j.ExpiresAt) || file != name {
		deny("not a completed export of this file")
		return
	}
	h.log().InfoContext(r.Context(), "export download", "job", j.ID, "tenant", res.Tenant.Name,
		"remote", httpx.ClientIP(r, h.TrustProxyHeaders), "bytes", j.FileSize)
	hd := w.Header()
	hd.Set("Content-Type", "application/gzip")
	hd.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	hd.Set("Cache-Control", "no-store")
	hd.Set("Content-Length", strconv.FormatInt(j.FileSize, 10))
	if err := h.Store.Jobs().ReadFile(r.Context(), j.TenantID, j.ID, func(chunk []byte) error {
		_, err := w.Write(chunk)
		return err
	}); err != nil {
		h.log().WarnContext(r.Context(), "export download: read file", "err", err, "job", j.ID)
	}
}
