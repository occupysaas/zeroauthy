package rbacrules

import (
	_ "embed"
	"encoding/json"
)

//go:embed inventory.json
var inventoryJSON []byte

// OperationContract records the public wire surface and its provenance.
type OperationContract struct {
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	RequiredScopes []string `json:"required_scopes"`
	// ScopeMatch is "all" (every required scope) or "any_set" (every scope of
	// at least one AcceptedScopeSets entry; RequiredScopes is then the OAS list).
	ScopeMatch        string     `json:"scope_match"`
	AcceptedScopeSets [][]string `json:"accepted_scope_sets,omitempty"`
	RequestShape      string     `json:"request_shape"`
	ResponseShape     string     `json:"response_shape"`
	Pagination        string     `json:"pagination"`
	SuccessStatus     int        `json:"success_status"`
	ErrorStatuses     []int      `json:"error_statuses"`
	Limits            []string   `json:"limits"`
	SourceURL         string     `json:"source_url"`
	Evidence          string     `json:"evidence"`
}

type RuleContract struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Evidence  string `json:"evidence"`
	SourceURL string `json:"source_url,omitempty"`
	Decision  string `json:"decision,omitempty"`
}

type ContractMetadata struct {
	Dialects []string       `json:"dialects"`
	Deferred []string       `json:"deferred"`
	Rules    []RuleContract `json:"rules"`
}

type compatibilityInventory struct {
	Operations []OperationContract `json:"operations"`
	Metadata   ContractMetadata    `json:"metadata"`
}

func readInventory() compatibilityInventory {
	var result compatibilityInventory
	if err := json.Unmarshal(inventoryJSON, &result); err != nil {
		panic("rbacrules: invalid embedded inventory: " + err.Error())
	}
	return result
}

// Inventory returns independent contract values; callers cannot mutate the frozen inventory.
func Inventory() []OperationContract      { return readInventory().Operations }
func InventoryMetadata() ContractMetadata { return readInventory().Metadata }
