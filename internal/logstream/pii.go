package logstream

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Cache the immutable frozen field inventory once, rather than parsing the
// entire documentation contract for every delivered event.
var piiFields = func() map[string]bool {
	fields := map[string]bool{}
	for _, field := range logrules.Inventory().StreamContract["pii_fields"].([]any) {
		fields[field.(string)] = true
	}
	return fields
}()

func outgoing(ctx context.Context, body []byte, pii *store.LogStreamPII) (json.RawMessage, error) {
	if len(body) == 0 {
		body = []byte(`{}`)
	}
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	v := logs.ScrubStoredEvent(ctx, doc)
	if pii == nil || len(pii.LogFields) == 0 {
		return json.Marshal(v)
	}
	fields := map[string]bool{}
	for _, f := range pii.LogFields {
		if piiFields[f] {
			fields[f] = true
			fields[logscrub.MaskText(ctx, f)] = true
		}
	}
	var visit func(any)
	visit = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, value := range x {
				if fields[k] {
					if pii.Method == "hash" {
						text, ok := value.(string)
						if !ok {
							b, _ := json.Marshal(value)
							text = string(b)
						}
						x[k] = hashPII(text)
					} else {
						x[k] = logrules.Marker
					}
				} else {
					visit(value)
				}
			}
		case []any:
			for _, value := range x {
				visit(value)
			}
		}
	}
	visit(v)
	return json.Marshal(v)
}
