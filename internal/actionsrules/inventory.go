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
	ID              string      `json:"id"`
	Handler         string      `json:"handler"`
	ContinueHandler string      `json:"continue_handler,omitempty"`
	Blocking        bool        `json:"blocking"`
	Version         string      `json:"version,omitempty"`
	Event           []string    `json:"event"`
	API             []APIMember `json:"api"`
	SourceURL       string      `json:"source_url"`
}

// DeferredTrigger records an advertised upstream trigger whose caller is out of scope.
// Plan is a roadmap plan number, or "deferred" when no plan is assigned.
type DeferredTrigger struct {
	ID   string `json:"id"`
	Plan string `json:"plan"`
}

type compatibilityInventory struct {
	DeferredTriggers []DeferredTrigger   `json:"deferred_triggers"`
	Operations       []OperationContract `json:"operations"`
	Triggers         []TriggerContract   `json:"triggers"`
	Limits           map[string]int      `json:"limits"`
	LimitSources     map[string]string   `json:"limit_sources"`
}

// Catalog is the frozen Actions compatibility contract inventory.
type Catalog struct {
	DeferredTriggers []DeferredTrigger
	Operations       []OperationContract
	Triggers         []TriggerContract
	Limits           map[string]int
	LimitSources     map[string]string
}

// Inventory returns independent values decoded from the embedded JSON.
func Inventory() Catalog {
	var r compatibilityInventory
	if err := json.Unmarshal(inventoryJSON, &r); err != nil {
		panic("actionsrules: invalid embedded inventory: " + err.Error())
	}
	return Catalog(r)
}
