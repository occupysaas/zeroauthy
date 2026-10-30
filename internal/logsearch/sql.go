package logsearch

import "github.com/zeroauthy/zeroauthy/internal/store"

// SQL is the Task 4 temporary match-all translator. Task 7 replaces this
// implementation with dialect-specific parameterized AST predicates. Validation
// already fails closed for malformed ASTs; query parity is not yet provided.
func SQL(q *store.LogQuery, dialect string) (string, []any, error) {
	if err := Validate(q); err != nil {
		return "", nil, err
	}
	return "1=1", nil, nil
}
