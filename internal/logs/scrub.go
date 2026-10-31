package logs

import (
	"context"
	"maps"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

var eventFieldNames = func() map[string]bool {
	out := map[string]bool{}
	for _, field := range logrules.Inventory().LogFields {
		out[field.Name] = true
	}
	return out
}()

// ScrubEvent preserves the log protocol's fixed field names and generated
// metadata. Credential masks apply to input-derived values and dynamic names,
// including embedded JSON; a one-character password cannot rename "date".
// Callers supply authoritative type/date/log_id metadata before this boundary.
func ScrubEvent(ctx context.Context, doc map[string]any) map[string]any {
	out := map[string]any{}
	dynamic := map[string]any{}
	typ, _ := doc["type"].(string)
	for key, value := range doc {
		if !eventFieldNames[key] {
			dynamic[key] = value
			continue
		}
		switch {
		case key == "date" || key == "log_id":
			out[key] = value
		case key == "type" && eventDescriptions[typ] != "":
			out[key] = typ
		case key == "description" && value == eventDescriptions[typ] && eventDescriptions[typ] != "":
			out[key] = value
		case key == "details":
			out[key] = scrubDetails(ctx, value)
		default:
			out[key] = logscrub.ScrubValueContext(ctx, value)
		}
	}
	for key, value := range logscrub.ScrubValueContext(ctx, dynamic).(map[string]any) {
		if _, exists := out[key]; exists {
			out[key] = logscrub.Marker
		} else {
			out[key] = value
		}
	}
	return out
}

func scrubDetails(ctx context.Context, value any) any {
	details, ok := value.(map[string]any)
	if !ok {
		return logscrub.ScrubValueContext(ctx, value)
	}
	details = maps.Clone(details)
	actions, ok := details["actions"].(map[string]any)
	if !ok {
		return logscrub.ScrubValueContext(ctx, details)
	}
	delete(details, "actions")
	actions = maps.Clone(actions)
	executions, exists := actions["executions"]
	delete(actions, "executions")
	safe := logscrub.ScrubValueContext(ctx, details).(map[string]any)
	safeActions := logscrub.ScrubValueContext(ctx, actions).(map[string]any)
	if exists {
		safeActions["executions"] = logscrub.ScrubValueContext(ctx, executions)
	}
	safe["actions"] = safeActions
	return safe
}

// executionID is the server-generated Actions identifier format. These opaque
// links are protocol metadata, never script console text or request parameters.
func executionID(id string) bool {
	if len(id) != 28 || id[:4] != "exe_" {
		return false
	}
	for _, r := range id[4:] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func scrubExecutionIDs(ctx context.Context, value any) any {
	ids, ok := logscrub.ScrubValue(value).([]any)
	if !ok {
		return logscrub.ScrubValueContext(ctx, value)
	}
	for i, id := range ids {
		if text, ok := id.(string); !ok || !executionID(text) {
			ids[i] = logscrub.ScrubValueContext(ctx, id)
		}
	}
	return ids
}

// ScrubStoredEvent rechecks a recorder-produced document at an API boundary.
// The reserved executions field contains only server-generated links: source
// Details were scrubbed before explicit Event.ExecutionIDs were attached.
func ScrubStoredEvent(ctx context.Context, doc map[string]any) map[string]any {
	var executions any
	if details, ok := doc["details"].(map[string]any); ok {
		if actions, ok := details["actions"].(map[string]any); ok {
			executions = actions["executions"]
		}
	}
	safe := ScrubEvent(ctx, doc)
	if executions != nil {
		attachExecutionIDs(ctx, safe, executions)
	}
	return safe
}

func attachExecutionIDs(ctx context.Context, doc map[string]any, ids any) {
	details, ok := doc["details"].(map[string]any)
	if !ok {
		details = map[string]any{}
		doc["details"] = details
	}
	actions, ok := details["actions"].(map[string]any)
	if !ok {
		actions = map[string]any{}
		details["actions"] = actions
	}
	actions["executions"] = scrubExecutionIDs(ctx, ids)
}
