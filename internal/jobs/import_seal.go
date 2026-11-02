package jobs

import (
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const ParamInputSealed = "input_sealed_v1"

// ImportInputNeedsSealing parses property names, including escaped JSON keys.
// Malformed input is sealed too: it cannot safely be classified as secret-free.
func ImportInputNeedsSealing(raw []byte) bool {
	var rows []map[string]json.RawMessage
	if json.Unmarshal(raw, &rows) != nil {
		return true
	}
	for _, row := range rows {
		if _, ok := row["mfa_factors"]; ok {
			return true
		}
	}
	return false
}
func SealImportInput(w keys.Wrapper, j *store.Job) error {
	blob, err := keys.SealBound(w, "users-import/v1", []string{j.TenantID, j.ID}, j.Input)
	if err != nil {
		return err
	}
	j.Input = blob
	j.Params[ParamInputSealed] = true
	return nil
}
func openImportInput(w keys.Wrapper, j *store.Job) ([]byte, error) {
	if !paramBool(j, ParamInputSealed, false) {
		return j.Input, nil
	}
	return keys.OpenBound(w, "users-import/v1", []string{j.TenantID, j.ID}, j.Input)
}
