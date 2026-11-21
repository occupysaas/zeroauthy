// Package quotarules validates and renders the shared client, organization and tenant token quotas.
package quotarules

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ParseTokenQuota reads the public client/organization quota wrapper. Null
// removes an override; omitted enforcement defaults to true.
func ParseTokenQuota(raw any, path string) (*store.TokenQuota, error) {
	if raw == nil {
		return nil, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok || len(obj) != 1 {
		return nil, invalid(path, "must contain client_credentials")
	}
	v, ok := obj["client_credentials"]
	if !ok {
		return nil, invalid(path, "must contain client_credentials")
	}
	return parseQuota(v, path+".client_credentials")
}
func parseQuota(raw any, path string) (*store.TokenQuota, error) {
	obj, ok := raw.(map[string]any)
	if !ok || len(obj) == 0 {
		return nil, invalid(path, "must be a nonempty object")
	}
	q := &store.TokenQuota{Enforce: true}
	for k, v := range obj {
		switch k {
		case "enforce":
			b, ok := v.(bool)
			if !ok {
				return nil, invalid(path+"."+k, "must be a boolean")
			}
			q.Enforce = b
		case "per_hour", "per_day":
			n, ok := integer(v)
			if !ok || n < 1 || n > math.MaxInt32 {
				return nil, invalid(path+"."+k, "must be an integer from 1 to 2147483647")
			}
			if k == "per_hour" {
				q.PerHour = int(n)
			} else {
				q.PerDay = int(n)
			}
		default:
			return nil, invalid(path+"."+k, "unknown property")
		}
	}
	return q, nil
}

// ValidateTokenQuota checks typed specifications, which already applied defaults.
func ValidateTokenQuota(q *store.TokenQuota) error {
	if q == nil {
		return nil
	}
	if q.PerHour < 0 || q.PerDay < 0 || int64(q.PerHour) > math.MaxInt32 || int64(q.PerDay) > math.MaxInt32 {
		return fmt.Errorf("quota limits must be from 1 to 2147483647 when set")
	}
	return nil
}
func PublicTokenQuota(q *store.TokenQuota) any {
	if q == nil {
		return nil
	}
	body := map[string]any{"enforce": q.Enforce}
	if q.PerHour != 0 {
		body["per_hour"] = q.PerHour
	}
	if q.PerDay != 0 {
		body["per_day"] = q.PerDay
	}
	return map[string]any{"client_credentials": body}
}
func ParseDefaultTokenQuota(raw any) (*store.DefaultTokenQuota, error) {
	if raw == nil {
		return nil, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok || len(obj) == 0 {
		return nil, invalid("default_token_quota", "must be a nonempty object")
	}
	q := &store.DefaultTokenQuota{}
	for k, v := range obj {
		if k != "clients" && k != "organizations" {
			return nil, invalid("default_token_quota."+k, "unknown property")
		}
		wrapper, ok := v.(map[string]any)
		if !ok {
			return nil, invalid("default_token_quota."+k, "must contain client_credentials")
		}
		value, ok := wrapper["client_credentials"]
		if !ok {
			return nil, invalid("default_token_quota."+k, "must contain client_credentials")
		}
		parsed, err := parseQuota(value, "default_token_quota."+k+".client_credentials")
		if err != nil {
			return nil, err
		}
		if k == "clients" {
			q.Clients = parsed
		} else {
			q.Organizations = parsed
		}
	}
	return q, nil
}
func PublicDefaultTokenQuota(q *store.DefaultTokenQuota) any {
	if q == nil {
		return nil
	}
	body := map[string]any{}
	if q.Clients != nil {
		body["clients"] = PublicTokenQuota(q.Clients)
	}
	if q.Organizations != nil {
		body["organizations"] = PublicTokenQuota(q.Organizations)
	}
	return body
}

func invalid(path, message string) error { return fmt.Errorf("%s: %s", path, message) }
func integer(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		v, ok := new(big.Rat).SetString(string(n))
		if !ok || !v.IsInt() || !v.Num().IsInt64() {
			return 0, false
		}
		return v.Num().Int64(), true
	case float64:
		if n < 1 || n > math.MaxInt32 || math.Trunc(n) != n {
			return 0, false
		}
		return int64(n), true
	default:
		rv := reflect.ValueOf(v)
		if !rv.IsValid() {
			return 0, false
		}
		switch rv.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return rv.Int(), true
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if rv.Uint() > math.MaxInt64 {
				return 0, false
			}
			return int64(rv.Uint()), true
		}
		return 0, false
	}
}

// DefaultsOf preserves previously stored tenant configuration when the typed
// column has not yet been populated. A typed setting always wins over Extra.
func DefaultsOf(t *store.Tenant) (*store.DefaultTokenQuota, error) {
	if t.DefaultTokenQuota != nil {
		q := *t.DefaultTokenQuota
		if q.Clients != nil {
			v := *q.Clients
			q.Clients = &v
		}
		if q.Organizations != nil {
			v := *q.Organizations
			q.Organizations = &v
		}
		if err := ValidateTokenQuota(q.Clients); err != nil {
			return nil, err
		}
		if err := ValidateTokenQuota(q.Organizations); err != nil {
			return nil, err
		}
		return &q, nil
	}
	raw, ok := t.SettingsExtra["default_token_quota"]
	if !ok {
		return nil, nil
	}
	return ParseDefaultTokenQuota(raw)
}

// PatchTokenQuota retains omitted limits and enforcement. The supplied object
// must itself be valid and nonempty; null explicitly clears the override.
func PatchTokenQuota(current *store.TokenQuota, raw any, path string) (*store.TokenQuota, error) {
	parsed, err := ParseTokenQuota(raw, path)
	if err != nil || raw == nil || current == nil {
		return parsed, err
	}
	merged := PublicTokenQuota(current).(map[string]any)["client_credentials"].(map[string]any)
	for k, v := range raw.(map[string]any)["client_credentials"].(map[string]any) {
		merged[k] = v
	}
	return parseQuota(merged, path+".client_credentials")
}
func PatchDefaultTokenQuota(current *store.DefaultTokenQuota, raw any) (*store.DefaultTokenQuota, error) {
	parsed, err := ParseDefaultTokenQuota(raw)
	if err != nil || raw == nil || current == nil {
		return parsed, err
	}
	copy := *current
	if current.Clients != nil {
		v := *current.Clients
		copy.Clients = &v
	}
	if current.Organizations != nil {
		v := *current.Organizations
		copy.Organizations = &v
	}
	for k, v := range raw.(map[string]any) {
		prior := current.Clients
		if k == "organizations" {
			prior = current.Organizations
		}
		next, err := PatchTokenQuota(prior, v, "default_token_quota."+k)
		if err != nil {
			return nil, err
		}
		if k == "clients" {
			copy.Clients = next
		} else {
			copy.Organizations = next
		}
	}
	return &copy, nil
}
