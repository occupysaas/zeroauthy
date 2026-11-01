package seed

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/eventstream"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var seedEventStreamID = regexp.MustCompile(eventrules.StreamIDPattern)

func validateEventStreams(in *Tenant) error {
	ids, names := map[string]bool{}, map[string]bool{}
	for _, entry := range in.EventStreams {
		id, _ := entry["id"].(string)
		name, _ := entry["name"].(string)
		if strings.TrimSpace(name) == "" || names[name] || id != "" && ids[id] {
			return errors.New("event streams require unique nonempty names and optional IDs")
		}
		names[name] = true
		ids[id] = true
		if _, _, err := seedEventStreamCandidate(entry, false); err != nil {
			return errors.New("invalid event stream configuration or secret environment reference")
		}
	}
	return nil
}

// Seed accepts the public create shape plus an optional stable ID and an
// action_name alternative to action_id. Public fields are never interpolated.
func seedEventStreamCandidate(entry map[string]any, resolve bool) (*store.EventStream, map[string]any, error) {
	values := cloneYAMLMap(entry)
	id := "est_" + secrets.RandomString(22)
	if v, ok := values["id"]; ok {
		var valid bool
		id, valid = v.(string)
		if !valid || !seedEventStreamID.MatchString(id) {
			return nil, nil, store.ErrInvalid
		}
		delete(values, "id")
	}
	dest, _ := values["destination"].(map[string]any)
	cfg, _ := dest["configuration"].(map[string]any)
	if dest["type"] == "action" {
		if name, ok := cfg["action_name"]; ok {
			if text, valid := name.(string); !valid || text == "" || cfg["action_id"] != nil {
				return nil, nil, store.ErrInvalid
			}
			delete(cfg, "action_name")
			cfg["action_id"] = name
		}
	}
	if dest["type"] == "webhook" {
		auth, _ := cfg["webhook_authorization"].(map[string]any)
		for _, key := range []string{"password", "token", "header_value"} {
			if value, ok := auth[key]; ok {
				secret, err := streamEnvValue(value, resolve, false)
				if err != nil {
					return nil, nil, errors.New("event stream secret environment reference missing or invalid")
				}
				auth[key] = secret
			}
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
	s := &store.EventStream{ID: id, Status: "enabled", Config: map[string]any{}}
	private := map[string]any{}
	if err = eventstream.Configure(s, raw, true, false, private); err != nil {
		return nil, nil, err
	}
	return s, private, nil
}

// The caller owns the transaction. Lock the tenant before quota, identity and
// checkpoint reads, matching Management API creation's tenant serialization.
func applyEventStreams(ctx context.Context, st store.Store, tid string, entries []map[string]any, now time.Time, w keys.Wrapper) error {
	if len(entries) == 0 {
		return nil
	}
	if _, err := st.Tenants().Get(ctx, tid); err != nil {
		return err
	}
	rows := []store.EventStream{}
	cursor := ""
	for {
		page, next, err := st.Events().ListEventStreams(ctx, tid, cursor, 100)
		if err != nil {
			return err
		}
		rows = append(rows, page...)
		if next == "" {
			break
		}
		cursor = next
	}
	for _, entry := range entries {
		id, _ := entry["id"].(string)
		name, _ := entry["name"].(string)
		exists, matches := false, 0
		for _, row := range rows {
			if id != "" && row.ID == id {
				exists = true
			}
			if row.Name == name {
				matches++
			}
		}
		if exists || id == "" && matches == 1 {
			continue
		}
		if matches > 0 {
			return errors.New("event stream identity conflicts with an existing name")
		}
		count, err := st.Events().CountEventStreams(ctx, tid)
		if err != nil {
			return err
		}
		if count >= eventrules.Limits.MaxStreams {
			return store.ErrConflict
		}
		s, private, err := seedEventStreamCandidate(entry, true)
		if err != nil {
			return errors.New("invalid event stream configuration or missing secret environment variable")
		}
		s.TenantID = tid
		s.CreatedAt = now
		s.UpdatedAt = now
		if s.DestType == "action" {
			destination, _ := entry["destination"].(map[string]any)
			cfg, _ := destination["configuration"].(map[string]any)
			var a *store.Action
			if name, ok := cfg["action_name"].(string); ok {
				a, err = st.Actions().GetActionByName(ctx, tid, name)
			} else {
				a, err = st.Actions().GetAction(ctx, tid, s.Config["action_id"].(string))
			}
			if err != nil {
				return err
			}
			if a.Trigger != "event-stream" {
				return store.ErrInvalid
			}
			s.Config["action_id"] = a.ID
		}
		s.SealedSecret, err = eventstream.SealSecrets(w, s, private)
		if err != nil {
			return err
		}
		s.Checkpoint, err = st.Events().LatestEventSeq(ctx, tid)
		if err != nil {
			return err
		}
		if err = st.Events().CreateEventStream(ctx, s); err != nil {
			return err
		}
		rows = append(rows, *s)
	}
	return nil
}
