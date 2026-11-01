package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/resourceview"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var ErrNotEmitted = errors.New("event type or strategy is not emitted")

// Build creates an unstamped event from a shared response view, projected through
// the catalog's recursive allowlist. Customer metadata remains opaque user data.
func Build(ctx context.Context, tenant *store.Tenant, typ string, object, previous any, at time.Time) (store.TenantEvent, error) {
	var zero store.TenantEvent
	rule, ok := eventrules.Lookup(typ)
	if !ok || !rule.Emitted {
		return zero, ErrNotEmitted
	}
	if tenant == nil || tenant.ID == "" || tenant.CanonicalHost == "" {
		return zero, errors.New("event requires tenant canonical identity")
	}
	obj, err := response(object)
	if err != nil {
		return zero, err
	}
	if len(rule.Strategies) > 0 {
		strategy, _ := obj["strategy"].(string)
		if !slices.Contains(rule.Strategies, strategy) {
			return zero, ErrNotEmitted
		}
	}
	if strings.HasSuffix(typ, ".deleted") {
		obj["deleted_at"] = timestamp(at)
	}
	d := map[string]any{"object": project(obj, rule.Allowlist), "context": eventContext(ctx, tenant.ID)}
	if strings.HasSuffix(typ, ".updated") && previous != nil {
		p, err := response(previous)
		if err != nil {
			return zero, err
		}
		d["previous_object"] = project(p, rule.Allowlist)
	}
	id := NewEventID()
	body, err := json.Marshal(map[string]any{"specversion": "1.0", "type": typ, "source": "urn:auth0:" + tenant.CanonicalHost, "id": id, "time": timestamp(at), "a0tenant": tenant.ID, "data": d})
	if err != nil {
		return zero, err
	}
	return store.TenantEvent{TenantID: tenant.ID, ID: id, Type: typ, Time: at.UTC(), Body: body}, nil
}
func timestamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
func response(v any) (map[string]any, error) {
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
		return nil, errors.New("event object is nil")
	}
	switch x := v.(type) {
	case *store.User:
		v = resourceview.User(x)
	case store.User:
		v = resourceview.User(&x)
	case *store.Organization:
		v = resourceview.Organization(*x)
	case store.Organization:
		v = resourceview.Organization(x)
	case *store.Connection:
		m, err := resourceview.Connection(connrules.FromConnection(x), x.ID, true)
		if err != nil {
			return nil, err
		}
		v = m
	case store.Connection:
		return response(&x)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("event object: %w", err)
	}
	var m map[string]any
	if err = json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("event object: %w", err)
	}
	if m == nil {
		return nil, errors.New("event object must be an object")
	}
	return m, nil
}
func project(src map[string]any, paths []string) map[string]any {
	out := map[string]any{}
	children := map[string][]string{}
	for _, path := range paths {
		head, tail, nested := strings.Cut(path, ".")
		if nested {
			children[head] = append(children[head], tail)
		} else if v, ok := src[head]; ok {
			out[head] = v
		}
	}
	for head, paths := range children {
		key := strings.TrimSuffix(head, "[]")
		if strings.HasSuffix(head, "[]") {
			if vs, ok := src[key].([]any); ok {
				list := make([]any, 0, len(vs))
				for _, v := range vs {
					if m, ok := v.(map[string]any); ok {
						list = append(list, project(m, paths))
					}
				}
				out[key] = list
			}
		} else if m, ok := src[key].(map[string]any); ok {
			out[key] = project(m, paths)
		}
	}
	return out
}

// Stamp adds delivery extensions without changing the persisted event body.
// Invalid JSON is returned unchanged; persisted bodies are always valid JSON.
func Stamp(body []byte, streamID string, test bool) []byte {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil || m == nil {
		return append([]byte(nil), body...)
	}
	m["a0stream"] = streamID
	delete(m, "a0purpose")
	if test {
		m["a0purpose"] = "test"
	}
	out, err := json.Marshal(m)
	if err != nil {
		return append([]byte(nil), body...)
	}
	return out
}
