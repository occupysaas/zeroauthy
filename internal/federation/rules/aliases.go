package rules

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

func validDNS(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !microsoftDNSLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func ParseDomainAliases(v any) ([]string, error) {
	var values []string
	switch v := v.(type) {
	case []string:
		values = v
	case []any:
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("domain_aliases must contain strings")
			}
			values = append(values, s)
		}
	default:
		return nil, fmt.Errorf("domain_aliases must be an array")
	}
	if len(values) > 1000 {
		return nil, fmt.Errorf("domain_aliases permits at most 1000 domains")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, s := range values {
		s = strings.ToLower(s)
		u, err := url.Parse(s)
		isURI := err == nil && u.IsAbs() && u.Host != "" && u.User == nil && u.Fragment == ""
		if utf8.RuneCountInString(s) > 256 || !cleanText(s) || (!validDNS(s) && !isURI) {
			return nil, fmt.Errorf("domain_aliases entries must be DNS names or URIs of at most 256 characters")
		}
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}
	return result, nil
}
