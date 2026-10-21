package jobs

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Export job Params (the request's options, J8). Format is always set.
const (
	ParamFormat = "format"
	ParamLimit  = "limit"
	ParamFields = "fields"
)

// Export formats.
const (
	FormatCSV  = "csv"
	FormatJSON = "json"
)

// ExportPage is how many users the exporter reads at a time.
const ExportPage = 500

// exportSlack is how many more users a page asks for than it writes, for the
// users of the previous page that the inclusive bound returns again.
const exportSlack = 4

// MaxExportFields is the most fields an export may name (J8).
const MaxExportFields = 30

// DefaultExportFields are the columns of a CSV export without fields (U11),
// and the keys a JSON export gives each user that has a value for them.
var DefaultExportFields = []string{
	"user_id", "email", "name", "family_name", "given_name", "phone_number", "nickname", "username", "last_ip",
	"logins_count", "created_at", "updated_at", "deleted_at", "last_login", "blocked", "deleted", "email_verified",
	"phone_verified", "identities.[0].connection",
}

// exportDates are the fields written bare in a CSV (Auth0's dates).
var exportDates = map[string]bool{"created_at": true, "updated_at": true, "last_login": true, "deleted_at": true}

// neverExported are field names that would be a password hash. The user view
// holds none, so they read as unknown fields; this keeps it so should a view
// ever gain one.
var neverExported = map[string]bool{"password_hash": true, "custom_password_hash": true}

// Exporter runs users_export jobs: it walks the tenant's users in user_id
// order (all, or those of one connection) and writes a gzipped CSV or
// newline-delimited JSON file in chunks of at most ChunkSize bytes. A job
// claimed again after its worker stopped restarts the file: chunk 0 starts
// it anew (store.Jobs.AppendFile).
type Exporter struct {
	// View is a user in Auth0's JSON shape, without any hash
	// (mgmt.UserJSON).
	View func(*store.User) map[string]any
	Log  *slog.Logger
	// ChunkSize overrides store.JobMaxChunk when positive (tests).
	ChunkSize int
	// Page overrides ExportPage when positive.
	Page int
}

func (p Exporter) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

func (p Exporter) chunkSize() int {
	if p.ChunkSize > 0 {
		return min(p.ChunkSize, store.JobMaxChunk)
	}
	return store.JobMaxChunk
}

func (p Exporter) page() int {
	if p.Page > 0 {
		return p.Page
	}
	return ExportPage
}

// exportField is one requested field.
type exportField struct{ name, key string }

func exportFields(params map[string]any) []exportField {
	raw, _ := params[ParamFields].([]any)
	var out []exportField
	for _, r := range raw {
		m, _ := r.(map[string]any)
		name, _ := m["name"].(string)
		as, _ := m["export_as"].(string)
		if as == "" {
			as = name
		}
		out = append(out, exportField{name, as})
	}
	if len(out) == 0 {
		for _, n := range DefaultExportFields {
			out = append(out, exportField{n, n})
		}
	}
	return out
}

// intParam reads a whole-number job param; 0 when absent.
func intParam(params map[string]any, k string) int {
	switch v := params[k].(type) {
	case int:
		return clampLimit(float64(v))
	case int64:
		return clampLimit(float64(v))
	case float64:
		return clampLimit(v)
	case json.Number:
		f, _ := v.Float64()
		return clampLimit(f)
	}
	return 0
}

// clampLimit keeps a stored limit, which may be any positive integer, within
// what int holds on every platform.
func clampLimit(v float64) int {
	if v < 1 {
		return 0
	}
	return int(min(v, math.MaxInt32))
}

// chunkWriter cuts what is written into chunks for AppendFile.
type chunkWriter struct {
	ctx            context.Context
	st             store.Store
	tenant, job    string
	owner          string
	size           int
	buf            []byte
	seq            int
	written, total int64
}

func (w *chunkWriter) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 {
		room := w.size - len(w.buf)
		take := min(room, len(b))
		w.buf = append(w.buf, b[:take]...)
		b = b[take:]
		if len(w.buf) == w.size {
			if err := w.flush(); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

func (w *chunkWriter) flush() error {
	if len(w.buf) == 0 && w.seq > 0 {
		return nil
	}
	if err := w.st.Jobs().AppendFile(w.ctx, w.tenant, w.job, w.owner, w.seq, w.buf); err != nil {
		return fmt.Errorf("write chunk %d: %w", w.seq, err)
	}
	w.seq++
	w.total += int64(len(w.buf))
	w.buf = w.buf[:0]
	return nil
}

// Run implements Processor.
func (p Exporter) Run(ctx context.Context, st store.Store, j *store.Job, lease Lease) (store.JobStatus, string, error) {
	format, _ := j.Params[ParamFormat].(string)
	if format != FormatJSON {
		format = FormatCSV
	}
	limit := intParam(j.Params, ParamLimit)
	fields := exportFields(j.Params)
	var base *store.UserQuery
	if j.Connection != "" {
		base = &store.UserQuery{Op: store.QueryTerm, Field: "identities.connection", Kind: store.KindString, Value: j.Connection}
	} else {
		base = &store.UserQuery{Op: store.QueryAll}
	}
	owner := ""
	if lease != nil {
		owner = lease.Owner()
	}
	cw := &chunkWriter{ctx: ctx, st: st, tenant: j.TenantID, job: j.ID, owner: owner, size: p.chunkSize()}
	zw := gzip.NewWriter(cw)

	var line bytes.Buffer
	if format == FormatCSV {
		for i, f := range fields {
			if i > 0 {
				line.WriteByte(',')
			}
			line.WriteString(csvHeader(f.key))
		}
		line.WriteByte('\n')
		if _, err := zw.Write(line.Bytes()); err != nil {
			return "", "", err
		}
	}

	count := 0
	last := "" // the last user_id written; the walk goes on after it
	for limit == 0 || count < limit {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		if count > 0 && lease != nil {
			if err := lease.Renew(ctx); err != nil {
				return "", "", fmt.Errorf("renew the lease: %w", err)
			}
		}
		n := p.page()
		if limit > 0 {
			n = min(n, limit-count)
		}
		// Keyset paging: a user created or deleted while the export runs
		// neither repeats nor hides another. The bound is inclusive and the
		// users already written are skipped, because the order compares
		// lowercased IDs and two IDs may differ by case only.
		pq := base
		if last != "" {
			after := store.UserQuery{Op: store.QueryRange, Field: "user_id", Kind: store.KindString, Lo: &last, LoIncl: true}
			pq = &store.UserQuery{Op: store.QueryAnd, Kids: []*store.UserQuery{base, &after}}
		}
		ask := n + exportSlack
		users, _, err := st.Users().List(ctx, j.TenantID, pq, store.UserSort{Field: "user_id"}, store.Page{Limit: ask})
		if err != nil {
			return "", "", fmt.Errorf("list users: %w", err)
		}
		written := 0
		for _, u := range users {
			if last != "" && strings.ToLower(u.UserID) == strings.ToLower(last) && u.UserID <= last {
				continue
			}
			if written == n {
				break
			}
			view, err := normalize(p.View(u))
			if err != nil {
				return "", "", err
			}
			line.Reset()
			if format == FormatCSV {
				writeCSVRow(&line, view, fields)
			} else if err := writeJSONRow(&line, view, fields); err != nil {
				return "", "", err
			}
			if _, err := zw.Write(line.Bytes()); err != nil {
				return "", "", err
			}
			last = u.UserID
			written++
		}
		count += written
		if written == 0 {
			if len(users) >= ask {
				return "", "", fmt.Errorf("export: %d users share the id %q ignoring case", len(users), last)
			}
			break
		}
		if len(users) < ask && written < n {
			break
		}
	}
	if err := zw.Close(); err != nil {
		return "", "", err
	}
	if err := cw.flush(); err != nil {
		return "", "", err
	}
	p.log().InfoContext(ctx, "jobs: user export completed", "tenant", j.TenantID, "job", j.ID, "format", format,
		"users", count, "bytes", cw.total, "chunks", cw.seq)
	return store.JobCompleted, "", nil
}

// normalize turns a view into plain JSON values with numbers kept exact.
func normalize(m map[string]any) (map[string]any, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// lookup reads a dotted field of a user view: keys step into objects and
// [n] into arrays (identities.[0].connection). The second result is false
// when the field has no value.
func lookup(view map[string]any, name string) (any, bool) {
	if neverExported[strings.ToLower(strings.SplitN(name, ".", 2)[0])] {
		return nil, false
	}
	var cur any = view
	for _, seg := range strings.Split(name, ".") {
		switch c := cur.(type) {
		case map[string]any:
			v, ok := c[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			if !strings.HasPrefix(seg, "[") || !strings.HasSuffix(seg, "]") {
				return nil, false
			}
			i, err := strconv.Atoi(seg[1 : len(seg)-1])
			if err != nil || i < 0 || i >= len(c) {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, cur != nil
}

// writeJSONRow writes one user as a JSON object on a line. Fields without a
// value are left out; a key named twice is written once.
func writeJSONRow(buf *bytes.Buffer, view map[string]any, fields []exportField) error {
	buf.WriteByte('{')
	seen := map[string]bool{}
	first := true
	for _, f := range fields {
		v, ok := lookup(view, f.name)
		if !ok && (f.name == "user_metadata" || f.name == "app_metadata") {
			v, ok = map[string]any{}, true // J8: a user without metadata has {}
		}
		if !ok || seen[f.key] {
			continue
		}
		seen[f.key] = true
		if !first {
			buf.WriteByte(',')
		}
		first = false
		k, err := jsonValue(f.key)
		if err != nil {
			return err
		}
		val, err := jsonValue(v)
		if err != nil {
			return err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(val)
	}
	buf.WriteString("}\n")
	return nil
}

// csvHeader quotes a column name only when it needs it.
func csvHeader(s string) string {
	if strings.ContainsAny(s, ",\"\r\n") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// writeCSVRow writes one user as a CSV row (J8, U11): strings are quoted
// with their inner quotes doubled and a leading ' (so that a spreadsheet
// does not run a formula), numbers, booleans and dates are bare, and
// objects, arrays and missing values are empty.
func writeCSVRow(buf *bytes.Buffer, view map[string]any, fields []exportField) {
	for i, f := range fields {
		if i > 0 {
			buf.WriteByte(',')
		}
		v, ok := lookup(view, f.name)
		if !ok {
			continue
		}
		switch x := v.(type) {
		case string:
			if exportDates[f.name] {
				buf.WriteString(x)
				continue
			}
			buf.WriteString(`"'` + strings.ReplaceAll(x, `"`, `""`) + `"`)
		case json.Number:
			buf.WriteString(x.String())
		case bool:
			buf.WriteString(strconv.FormatBool(x))
		}
	}
	buf.WriteByte('\n')
}

// jsonValue encodes v without HTML escaping.
func jsonValue(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
