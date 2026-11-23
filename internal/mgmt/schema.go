package mgmt

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/zeroauthy/zeroauthy/api"
)

// Request bodies whose Auth0 schemas carry many constraints (Plan 37c
// Phase B: self-service and connection profiles, SSO tickets) are checked
// against the embedded Management contract itself, so the rules cannot
// drift from it. kin-openapi was already a direct dependency (contract
// tests); the document is loaded once, on first use.

var (
	contractOnce sync.Once
	contractDoc  *openapi3.T
	contractErr  error
)

func managementContract() (*openapi3.T, error) {
	contractOnce.Do(func() {
		l := openapi3.NewLoader()
		l.IsExternalRefsAllowed = false
		contractDoc, contractErr = l.LoadFromData(api.ManagementYAML)
	})
	return contractDoc, contractErr
}

// checkSchema validates a decoded JSON value against a component schema of
// the Management contract and returns a 400 naming the first violation.
func checkSchema(name string, raw json.RawMessage) error {
	doc, err := managementContract()
	if err != nil {
		return err
	}
	ref, ok := doc.Components.Schemas[name]
	if !ok || ref.Value == nil {
		return errors.New("mgmt: unknown contract schema " + name)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return badBody("the body is not valid JSON")
	}
	if err := ref.Value.VisitJSON(v); err != nil {
		var se *openapi3.SchemaError
		if errors.As(err, &se) {
			field := strings.Join(se.JSONPointer(), ".")
			if field == "" {
				return badBody("%s", se.Reason)
			}
			return badBody("%s: %s", field, se.Reason)
		}
		return badBody("%s", err.Error())
	}
	return nil
}
