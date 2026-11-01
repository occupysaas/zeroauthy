package logsearch

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
)

// BodyFields extracts only inventory JSON string fields using Go's JSON string
// semantics. UseNumber avoids imposing floating-point bounds on unrelated data;
// decoding also consistently replaces invalid Unicode escape sequences.
// Empty, missing and non-string fields remain distinct in the returned map.
func BodyFields(body []byte) map[string]string {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&doc) != nil {
		return nil
	}
	fields := map[string]string{}
	for _, f := range logrules.Fields() {
		if f.Storage == "json-string" {
			if v, ok := doc[strings.TrimPrefix(f.Column, "body.")].(string); ok {
				fields[f.Name] = v
			}
		}
	}
	return fields
}
