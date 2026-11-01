package seed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logstream"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var streamEnvRef = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// validateLogStreams checks public configuration and reference syntax without
// reading the environment. Existing streams need no seed credentials on restart.
func validateLogStreams(in *Tenant) error {
	ids, names := map[string]bool{}, map[string]bool{}
	for _, entry := range in.LogStreams {
		id, _ := entry["id"].(string)
		name, _ := entry["name"].(string)
		if strings.TrimSpace(name) == "" || names[name] || id != "" && ids[id] {
			return errors.New("log streams require unique nonempty names and unique optional IDs")
		}
		names[name] = true
		if id != "" {
			ids[id] = true
		}
		if _, _, err := seedStreamCandidate(entry, false); err != nil {
			return fmt.Errorf("log stream %q: invalid configuration or secret environment reference", name)
		}
	}
	return nil
}

// seedStreamCandidate uses exactly the Management API schema. Only seed's id
// and initial status are additional create fields; credentials must be whole
// ${ENV} references, never plaintext or interpolation into another string.
func seedStreamCandidate(entry map[string]any, resolve bool) (*store.LogStream, map[string]any, error) {
	values := cloneYAMLMap(entry)
	id := ""
	if v, ok := values["id"]; ok {
		var valid bool
		id, valid = v.(string)
		if !valid || strings.TrimSpace(id) == "" {
			return nil, nil, store.ErrInvalid
		}
		delete(values, "id")
	}
	status := "active"
	if v, ok := values["status"]; ok {
		var valid bool
		status, valid = v.(string)
		if !valid || (status != "active" && status != "paused" && status != "suspended") {
			return nil, nil, store.ErrInvalid
		}
		delete(values, "status")
	}
	kind, _ := values["type"].(string)
	schema, ok := logrules.SinkSchema(kind)
	if !ok {
		return nil, nil, store.ErrInvalid
	}
	sink, ok := values["sink"].(map[string]any)
	if !ok {
		return nil, nil, store.ErrInvalid
	}
	for _, field := range schema.Fields {
		if !field.Secret {
			continue
		}
		value, present := sink[field.Name]
		if !present {
			continue
		}
		if field.Type == "array" {
			headers, ok := value.([]any)
			if !ok {
				return nil, nil, store.ErrInvalid
			}
			for _, v := range headers {
				header, ok := v.(map[string]any)
				if !ok {
					return nil, nil, store.ErrInvalid
				}
				text, err := streamEnvValue(header["value"], resolve, false)
				if err != nil {
					return nil, nil, err
				}
				header["value"] = text
			}
		} else {
			text, err := streamEnvValue(value, resolve, field.Name == "sumoSourceAddress")
			if err != nil {
				return nil, nil, err
			}
			sink[field.Name] = text
		}
	}
	b, err := json.Marshal(values)
	if err != nil {
		return nil, nil, store.ErrInvalid
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return nil, nil, store.ErrInvalid
	}
	s := &store.LogStream{ID: id, Name: "", Type: kind, Status: status, Sink: map[string]any{}}
	private := map[string]any{}
	// Seed follows the secure default; development HTTP endpoints can be
	// provisioned through the API with its explicit deployment override.
	if err = logstream.Configure(s, raw, true, false, private); err != nil {
		return nil, nil, err
	}
	return s, private, nil
}
func streamEnvValue(value any, resolve, url bool) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", store.ErrInvalid
	}
	match := streamEnvRef.FindStringSubmatch(text)
	if match == nil {
		return "", store.ErrInvalid
	}
	if !resolve {
		if url {
			return "https://seed.example.invalid/secret", nil
		}
		return "seed-env-secret", nil
	}
	secret, ok := os.LookupEnv(match[1])
	if !ok || strings.TrimSpace(secret) == "" {
		return "", errors.New("log stream secret environment variable is missing or empty")
	}
	return secret, nil
}

// Log streams are always create-only, including in legacy apply mode. An
// explicit ID is authoritative; without one the tenant's unique name is the
// natural key. Never look up credentials, overwrite edits or resume a stream
// that already exists.
func applyLogStreams(ctx context.Context, st store.Store, tid string, entries []map[string]any, now time.Time, w keys.Wrapper) error {
	if len(entries) == 0 {
		return nil
	}
	rows, err := st.Logs().ListLogStreams(ctx, tid)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		id, _ := entry["id"].(string)
		name, _ := entry["name"].(string)
		exists := false
		matches := 0
		for _, row := range rows {
			if id != "" && row.ID == id {
				exists = true
			}
			if row.Name == name {
				matches++
			}
		}
		if exists {
			continue
		}
		if id == "" && matches == 1 {
			continue
		}
		if matches > 0 {
			return errors.New("log stream identity is ambiguous or conflicts with an existing name")
		}
		s, private, err := seedStreamCandidate(entry, true)
		if err != nil {
			return fmt.Errorf("log stream %q: %w", name, err)
		}
		s.TenantID = tid
		s.CreatedAt = now
		s.UpdatedAt = now
		if s.ID == "" {
			s.ID = "lst_" + secrets.RandomString(24)
		}
		if s.SealedSecrets, err = logstream.SealSecrets(w, s, private); err != nil {
			return err
		}
		if err = st.Logs().CreateLogStream(ctx, s); err != nil {
			return err
		}
		rows = append(rows, *s)
	}
	return nil
}
