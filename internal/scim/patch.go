package scim

import (
	"errors"
	"strings"
)

// PatchRequest is an RFC 7644 §3.5.2 PatchOp message.
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one operation. Op is matched case-insensitively (Entra
// sends "Replace").
type PatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

// maxPatchOperations bounds one request.
const maxPatchOperations = 1000

var errPatch = errors.New("scim: invalid patch")

// ActiveValue reads active leniently: a JSON boolean or "true"/"false" in
// any case (Entra sends strings).
func ActiveValue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return true
}

// memberValues lists the value of each member element.
func memberValues(res map[string]any) []string {
	v, _ := lookup(res, "members")
	list, _ := v.([]any)
	var out []string
	for _, el := range list {
		if m, ok := el.(map[string]any); ok {
			if s, ok := m["value"].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// valueKey identifies an element of a multi-valued attribute by its value.
func valueKey(el any) (string, bool) {
	m, ok := el.(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := lookup(m, "value")
	s, isStr := v.(string)
	return s, ok && isStr
}

// actualKey returns the existing key matching k case-insensitively, or k.
func actualKey(m map[string]any, k string) string {
	for key := range m {
		if strings.EqualFold(key, k) {
			return key
		}
	}
	return k
}

// merge sets each member of src into dst, merging nested objects.
func merge(dst, src map[string]any) {
	for k, v := range src {
		k = actualKey(dst, k)
		if sv, ok := v.(map[string]any); ok {
			if dv, ok := dst[k].(map[string]any); ok {
				merge(dv, sv)
				continue
			}
		}
		dst[k] = v
	}
}

// ApplyPatch applies operations to a resource object in place.
func ApplyPatch(res map[string]any, ops []PatchOperation) error {
	if len(ops) == 0 || len(ops) > maxPatchOperations {
		return errPatch
	}
	for _, op := range ops {
		kind := strings.ToLower(op.Op)
		if kind != "add" && kind != "replace" && kind != "remove" {
			return errPatch
		}
		if op.Path == "" {
			obj, ok := op.Value.(map[string]any)
			if kind == "remove" || !ok {
				return errPatch
			}
			merge(res, obj)
			continue
		}
		p, err := ParsePath(op.Path)
		if err != nil {
			return errPatch
		}
		c := container(res, p, kind != "remove")
		if kind == "remove" {
			if c != nil {
				removePath(c, p, op.Value)
			}
			continue
		}
		if op.Value == nil {
			return errPatch
		}
		key := actualKey(c, p.Attr)
		if kind == "add" && p.Filter == nil && p.Sub == "" {
			if add, ok := op.Value.([]any); ok {
				existing, _ := c[key].([]any)
				seen := map[string]bool{}
				for _, el := range existing {
					if k, ok := valueKey(el); ok {
						seen[k] = true
					}
				}
				for _, el := range add {
					if k, ok := valueKey(el); ok && seen[k] {
						continue
					} else if ok {
						seen[k] = true
					}
					existing = append(existing, el)
				}
				c[key] = existing
				continue
			}
			if obj, ok := op.Value.(map[string]any); ok {
				if cur, ok := c[key].(map[string]any); ok {
					merge(cur, obj)
					continue
				}
			}
		}
		p.Attr = key
		Set(res, p, op.Value)
	}
	return nil
}

// removePath removes p from its container c. A value list on a plain
// multi-valued attribute removes the elements with those values.
func removePath(c map[string]any, p Path, value any) {
	key := actualKey(c, p.Attr)
	cur, exists := c[key]
	if !exists {
		return
	}
	list, isList := cur.([]any)
	switch {
	case p.Filter != nil && isList:
		var kept []any
		for _, el := range list {
			m, ok := el.(map[string]any)
			if fv, has := lookup(m, p.Filter.Path); ok && has && equalValue(p.Filter.Value, fv) {
				if p.Sub != "" {
					delete(m, actualKey(m, p.Sub))
					kept = append(kept, m)
				}
				continue
			}
			kept = append(kept, el)
		}
		c[key] = kept
	case p.Sub != "":
		if m, ok := cur.(map[string]any); ok {
			delete(m, actualKey(m, p.Sub))
		}
	case isList && value != nil:
		drop := map[string]bool{}
		if vals, ok := value.([]any); ok {
			for _, el := range vals {
				if k, ok := valueKey(el); ok {
					drop[k] = true
				}
			}
		}
		var kept []any
		for _, el := range list {
			if k, ok := valueKey(el); ok && drop[k] {
				continue
			}
			kept = append(kept, el)
		}
		c[key] = kept
	default:
		delete(c, key)
	}
}
