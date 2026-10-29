package orgrules

import (
	_ "embed"
	"encoding/json"
)

//go:embed inventory.json
var inventoryJSON []byte

// ObservationSource is the provenance value for facts taken from the
// separate observer session's notes (CLEAN_ROOM.md firewalled observation).
const ObservationSource = "docs/compat/observations/organizations.md"

// OperationContract records the public wire surface and its provenance.
// ScopeMatch is "all" or "any". ConditionalScopes are needed only for the
// optional input the request shape names (for example enabled_connections on
// create or fields=roles on the member list). Evidence is "documented" or
// "observed"; Lifecycle is the public release stage ("GA" or "EA").
type OperationContract struct {
	Method            string   `json:"method"`
	Path              string   `json:"path"`
	RequiredScopes    []string `json:"required_scopes"`
	ScopeMatch        string   `json:"scope_match"`
	ConditionalScopes []string `json:"conditional_scopes,omitempty"`
	RequestShape      string   `json:"request_shape"`
	ResponseShape     string   `json:"response_shape"`
	Pagination        string   `json:"pagination"`
	SuccessStatus     int      `json:"success_status"`
	ErrorStatuses     []int    `json:"error_statuses"`
	Limits            []string `json:"limits"`
	SourceURL         string   `json:"source_url"`
	Evidence          string   `json:"evidence"`
	Lifecycle         string   `json:"lifecycle"`
}

// DeferredItem is an upstream surface that Plan 29 does not implement.
// Plan is the roadmap plan that owns it.
type DeferredItem struct {
	Name   string `json:"name"`
	Plan   string `json:"plan"`
	Source string `json:"source"`
}

// FieldContract freezes one client or tenant field that Plan 29 makes live.
type FieldContract struct {
	Object    string   `json:"object"`
	Name      string   `json:"name"`
	Values    []string `json:"values"`
	Default   string   `json:"default"`
	Rules     []string `json:"rules"`
	Evidence  string   `json:"evidence"`
	SourceURL string   `json:"source_url,omitempty"`
	Decision  string   `json:"decision,omitempty"`
}

// LimitContract is one numeric limit. Source is a public URL, D-0055 for a
// local decision, or ObservationSource.
type LimitContract struct {
	Name   string `json:"name"`
	Value  int    `json:"value"`
	Source string `json:"source"`
}

// DecisionItem is one spec §2 "not documented publicly" item (1-10) as frozen
// by D-0055. Status is "observed", "partly_observed" or "unavailable";
// LocalDefault is the local decision that covers whatever was not observed.
type DecisionItem struct {
	Item         int    `json:"item"`
	Topic        string `json:"topic"`
	Status       string `json:"status"`
	Evidence     string `json:"evidence"`
	Value        string `json:"value"`
	LocalDefault string `json:"local_default,omitempty"`
	Source       string `json:"source"`
	Decision     string `json:"decision"`
}

// RuleContract is one frozen behavior rule. Evidence is "documented",
// "observed" or "local-decision".
type RuleContract struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Evidence  string `json:"evidence"`
	SourceURL string `json:"source_url,omitempty"`
	Decision  string `json:"decision,omitempty"`
}

// ToolProvenance records what a pinned open-source client exposes.
type ToolProvenance struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Repo    string   `json:"repo"`
	Files   []string `json:"files"`
	Exposes string   `json:"exposes"`
}

type ContractMetadata struct {
	Fields    []FieldContract  `json:"fields"`
	Limits    []LimitContract  `json:"limits"`
	Decisions []DecisionItem   `json:"decisions"`
	Rules     []RuleContract   `json:"rules"`
	Tools     []ToolProvenance `json:"tools"`
}

type compatibilityInventory struct {
	Operations []OperationContract `json:"operations"`
	Deferred   []DeferredItem      `json:"deferred"`
	Metadata   ContractMetadata    `json:"metadata"`
}

func readInventory() compatibilityInventory {
	var result compatibilityInventory
	if err := json.Unmarshal(inventoryJSON, &result); err != nil {
		panic("orgrules: invalid embedded inventory: " + err.Error())
	}
	return result
}

// Inventory returns independent contract values; callers cannot mutate the frozen inventory.
func Inventory() []OperationContract      { return readInventory().Operations }
func Deferred() []DeferredItem            { return readInventory().Deferred }
func InventoryMetadata() ContractMetadata { return readInventory().Metadata }
