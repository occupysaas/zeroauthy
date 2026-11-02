// Package logrules freezes Plan 31's public documentation contract. It contains
// no runtime emitter, parser, delivery implementation or store dependency.
package logrules

import (
	_ "embed"
	"encoding/json"
	"slices"
)

// Marker is the local, deliberately visible replacement for hidden log values.
// Public documentation does not establish a universal upstream marker (D-0057).
const Marker = "[REDACTED]"

//go:embed inventory.json
var inventoryJSON []byte

// Code describes a documented event. Emitted means a Plan 31 implementation
// target, not that Task 1 already records it. Plan names the implementation or
// deferred review owner; StatsKind is empty for events that do not increment stats.
type Code struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Emitted     bool      `json:"emitted"`
	Plan        int       `json:"plan"`
	Status      string    `json:"status,omitempty"`
	Owner       string    `json:"owner,omitempty"`
	StatsKind   string    `json:"stats_kind"`
	Source      string    `json:"source"`
	Origin      string    `json:"origin"`
	Note        string    `json:"note"`
	Triggers    []Trigger `json:"triggers"`
}

// Trigger identifies an existing outcome boundary for a later emission task.
type Trigger struct {
	File     string `json:"file"`
	Function string `json:"function"`
	When     string `json:"when"`
}

// Field maps a case-sensitive Lucene name to a storage field. Column is a
// physical column when Storage is "column"; "body.name" denotes a JSON string
// extraction which the SQL compiler must translate for its dialect, not raw SQL.
type Field struct {
	Name    string `json:"name"`
	Column  string `json:"column"`
	Storage string `json:"storage"`
	Type    string `json:"type"`
	Bare    bool   `json:"bare"`
	Source  string `json:"source"`
}

type LogField struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Source   string `json:"source"`
	Omission string `json:"omission"`
}

type Parameter struct {
	Name string `json:"name"`
	Type string `json:"type"`
	In   string `json:"in"`
	Rule string `json:"rule"`
}

type Route struct {
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Source        string            `json:"source"`
	Scopes        []string          `json:"scopes"`
	ScopeMatch    string            `json:"scope_match"`
	Parameters    []Parameter       `json:"parameters"`
	Envelope      string            `json:"envelope"`
	SuccessStatus int               `json:"success_status"`
	Body          string            `json:"body"`
	Errors        map[string]string `json:"errors"`
}

// SinkField is a strict typed field. Secret applies to the entire value,
// including credential-bearing URLs and the custom-headers array.
type SinkField struct {
	Name          string         `json:"name"`
	Type          string         `json:"type"`
	Required      bool           `json:"required"`
	Secret        bool           `json:"secret"`
	Values        []string       `json:"values,omitempty"`
	Pattern       string         `json:"pattern,omitempty"`
	SourcePattern string         `json:"source_pattern,omitempty"`
	LocalRule     string         `json:"local_rule,omitempty"`
	Items         map[string]any `json:"items,omitempty"`
}

type Sink struct {
	Type               string      `json:"type"`
	Source             string      `json:"source"`
	DeliverySource     string      `json:"delivery_source"`
	Delivery           string      `json:"delivery"`
	Delivered          bool        `json:"delivered"`
	Fields             []SinkField `json:"fields"`
	UnknownFields      string      `json:"unknown_fields"`
	SecretRead         string      `json:"secret_read"`
	SecretPatchOmitted string      `json:"secret_patch_omitted"`
}

// Contract contains the complete documentation inventory. Maps carrying longer
// prose rules keep those local decisions inspectable without implying executable
// policy; later tasks enforce and test them at their runtime boundaries.
type Contract struct {
	Version        int                 `json:"version"`
	ReviewedAt     string              `json:"reviewed_at"`
	Decision       string              `json:"decision"`
	Marker         string              `json:"marker"`
	IDPattern      string              `json:"id_pattern"`
	Limits         map[string]int      `json:"limits"`
	Categories     []string            `json:"categories"`
	Codes          []Code              `json:"codes"`
	Fields         []Field             `json:"fields"`
	LogFields      []LogField          `json:"log_fields"`
	Allowlists     map[string][]string `json:"allowlists"`
	Privacy        map[string]string   `json:"privacy"`
	Routes         []Route             `json:"routes"`
	Sinks          []Sink              `json:"sinks"`
	StreamContract map[string]any      `json:"stream_contract"`
	Gaps           []string            `json:"gaps"`
}

var frozen = Inventory()

// Inventory returns an independent snapshot; callers cannot change shared rules.
func Inventory() Contract {
	var result Contract
	if err := json.Unmarshal(inventoryJSON, &result); err != nil {
		panic("logrules: invalid embedded inventory: " + err.Error())
	}
	return result
}

// Codes returns independent code rows in lexical order by type.
func Codes() []Code {
	result := slices.Clone(frozen.Codes)
	for i := range result {
		result[i].Triggers = slices.Clone(result[i].Triggers)
	}
	return result
}

// Fields returns the supported search fields, including bare-term membership.
func Fields() []Field { return slices.Clone(frozen.Fields) }

// SinkSchema returns an independent schema and whether the type is recognized.
func SinkSchema(typ string) (Sink, bool) {
	// This is a configuration boundary, so parse a fresh snapshot to deep-copy
	// nested item schemas and enum slices without exposing mutable policy.
	for _, sink := range Inventory().Sinks {
		if sink.Type == typ {
			return sink, true
		}
	}
	return Sink{}, false
}

// BodyAllowlist returns explicit dotted paths for a resource family. Unknown
// families use the deny-all default; permitting an object never permits its keys.
func BodyAllowlist(resource string) []string {
	paths, ok := frozen.Allowlists[resource]
	if !ok {
		paths = frozen.Allowlists["default"]
	}
	return slices.Clone(paths)
}
