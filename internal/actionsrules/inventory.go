package actionsrules

import (
	_ "embed"
	"encoding/json"
)

//go:embed inventory.json
var inventoryJSON []byte

// OperationContract records the public wire surface and its provenance.
// Evidence is "documented", "observed" or "local".
type OperationContract struct {
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	RequiredScopes []string `json:"required_scopes"`
	RequestShape   string   `json:"request_shape"`
	ResponseShape  string   `json:"response_shape"`
	SuccessStatus  int      `json:"success_status"`
	ErrorStatuses  []int    `json:"error_statuses"`
	Limits         []string `json:"limits"`
	SourceURL      string   `json:"source_url"`
	Evidence       string   `json:"evidence"`
}

// APIMember classifies one trigger api member as supported, empty or unsupported.
type APIMember struct {
	Name     string `json:"name"`
	Support  string `json:"support"`
	Evidence string `json:"evidence"`
	Note     string `json:"note,omitempty"`
}

type TriggerContract struct {
	ID        string      `json:"id"`
	Version   string      `json:"version,omitempty"`
	Event     []string    `json:"event"`
	API       []APIMember `json:"api"`
	SourceURL string      `json:"source_url"`
}

type compatibilityInventory struct {
	Operations   []OperationContract `json:"operations"`
	Triggers     []TriggerContract   `json:"triggers"`
	Limits       map[string]int      `json:"limits"`
	LimitSources map[string]string   `json:"limit_sources"`
}

// Catalog is the frozen Plan 27 contract inventory.
type Catalog struct {
	Operations   []OperationContract
	Triggers     []TriggerContract
	Limits       map[string]int
	LimitSources map[string]string
}

// Inventory returns independent values decoded from the embedded JSON.
func Inventory() Catalog {
	var r compatibilityInventory
	if err := json.Unmarshal(inventoryJSON, &r); err != nil {
		panic("actionsrules: invalid embedded inventory: " + err.Error())
	}
	return Catalog(r)
}
