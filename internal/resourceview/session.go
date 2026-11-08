package resourceview

import "github.com/zeroauthy/zeroauthy/internal/store"

// SessionAuthMethods renders recorded proofs with the Management API names.
// Sessions created before method recording retain their password projection.
func SessionAuthMethods(s *store.LoginSession) []map[string]any {
	methods := s.AuthMethods
	if len(methods) == 0 {
		methods = []store.AuthMethod{{Name: "pwd", At: s.AuthenticatedAt}}
	}
	out := make([]map[string]any, 0, len(methods))
	for _, m := range methods {
		v := map[string]any{"name": m.Name, "timestamp": userTime(m.At)}
		if m.Type != "" {
			v["type"] = m.Type
		}
		out = append(out, v)
	}
	return out
}
