// Package rbacrules validates role and assignment inputs shared by all writers.
package rbacrules

import (
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"unicode"
	"unicode/utf8"
)

func NormalizeRole(r *store.Role) []error {
	var out []error
	if r == nil {
		return []error{fmt.Errorf("role is required")}
	}
	if n := utf8.RuneCountInString(r.Name); n < 1 || n > 128 || strings.TrimSpace(r.Name) == "" {
		out = append(out, fmt.Errorf("name must contain 1 to 128 characters"))
	}
	if utf8.RuneCountInString(r.Description) > 255 {
		out = append(out, fmt.Errorf("description must contain at most 255 characters"))
	}
	if strings.ContainsFunc(r.Name, unicode.IsControl) || strings.ContainsFunc(r.Description, unicode.IsControl) {
		out = append(out, fmt.Errorf("role fields must not contain control characters"))
	}
	return out
}
func ValidatePermissionKeys(keys []store.PermissionKey) []error {
	if len(keys) < 1 || len(keys) > 100 {
		return []error{fmt.Errorf("permissions must contain 1 to 100 items")}
	}
	for _, k := range keys {
		if k.ResourceServerIdentifier == "" || k.PermissionName == "" || strings.ContainsAny(k.PermissionName, " \t\r\n") {
			return []error{fmt.Errorf("invalid permission")}
		}
	}
	return nil
}
func NormalizePage(p *store.RBACPage) error {
	if p.PerPage == 0 {
		p.PerPage = 50
	}
	if p.Take == 0 {
		p.Take = 50
	}
	if p.Page < 0 || p.PerPage < 1 || p.PerPage > 100 || p.Take < 1 || p.Take > 100 || p.From != "" && p.Page != 0 {
		return fmt.Errorf("invalid pagination")
	}
	return nil
}
