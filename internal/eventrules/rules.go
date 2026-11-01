// Package eventrules holds the public documentation contract for tenant events.
package eventrules

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const StreamIDPattern = `^est_[A-Za-z0-9]{22}$`
const EventIDPattern = `^evt_[A-Za-z0-9]{22}$`

type LimitSchema struct {
	TakeDefault         int   `json:"take_default"`
	TakeMax             int   `json:"take_max"`
	MaxStreams          int   `json:"max_streams"`
	MaxConnections      int   `json:"max_connections"`
	RetentionDays       int   `json:"retention_days"`
	RetentionMinDays    int   `json:"retention_min_days"`
	RingSize            int   `json:"ring_size"`
	Attempts            int   `json:"attempts"`
	TimeoutSeconds      int   `json:"timeout_seconds"`
	SettleSeconds       int   `json:"settle_seconds"`
	ConsecutiveFailures int   `json:"consecutive_failures"`
	TotalFailures       int   `json:"total_failures"`
	HeartbeatSeconds    int   `json:"heartbeat_seconds"`
	OffsetSeconds       int   `json:"offset_seconds"`
	CycleSeconds        int   `json:"cycle_seconds"`
	SSERetryMS          int   `json:"sse_retry_ms"`
	RetrySeconds        []int `json:"retry_seconds"`
}

var Limits = Inventory().Limits

type Type struct {
	Name        string   `json:"name"`
	Emitted     bool     `json:"emitted"`
	Plan        int      `json:"plan"`
	Allowlist   []string `json:"allowlist"`
	Strategies  []string `json:"strategies"`
	StoreMethod string   `json:"store_method"`
}
type RouteSchema struct {
	Operation, Method, Path, Source string
	ScopeMode                       string `json:"scope_mode"`
	Scopes                          []string
	Parameters                      []map[string]any
	Body                            map[string]any
	Errors                          map[string]string
}
type DestSchema struct {
	Type         string
	PublicFields []string `json:"public_fields"`
	SecretFields []string `json:"secret_fields"`
}
type Contract struct {
	Types        []Type
	Routes       []RouteSchema
	Destinations []DestSchema
	Gaps         []string
	Limits       LimitSchema
	SSE          map[string]any
}

//go:embed inventory.json
var inventory []byte

//go:embed catalog.json
var catalogJSON []byte

func Inventory() Contract {
	var c Contract
	if err := json.Unmarshal(inventory, &c); err != nil {
		panic(err)
	}
	return c
}
func Types() []Type { return Inventory().Types }
func Route(op string) RouteSchema {
	for _, r := range Inventory().Routes {
		if r.Operation == op {
			return r
		}
	}
	return RouteSchema{}
}
func Destination(typ string) DestSchema {
	for _, d := range Inventory().Destinations {
		if d.Type == typ {
			return d
		}
	}
	return DestSchema{}
}
func Lookup(typ string) (Type, bool) {
	for _, t := range Types() {
		if t.Name == typ {
			return t, true
		}
	}
	return Type{}, false
}

type catalog struct {
	Schemas  map[string]map[string]any
	Examples map[string]json.RawMessage
}

func loadCatalog() catalog {
	var c catalog
	if err := json.Unmarshal(catalogJSON, &c); err != nil {
		panic(err)
	}
	return c
}

var frozenCatalog = loadCatalog()
var validators = compileCatalog()

func compileCatalog() map[string]*jsonschema.Schema {
	result := map[string]*jsonschema.Schema{}
	for name, schema := range frozenCatalog.Schemas {
		compiler := jsonschema.NewCompiler()
		url := "urn:zeroauthy:events:" + name
		if err := compiler.AddResource(url, schema); err != nil {
			panic(err)
		}
		s, err := compiler.Compile(url)
		if err != nil {
			panic(err)
		}
		result[name] = s
	}
	return result
}
func Example(typ string) []byte { return append([]byte(nil), frozenCatalog.Examples[typ]...) }
func ObjectSchema(typ string) map[string]any {
	s := loadCatalog().Schemas[typ]
	if s == nil {
		return nil
	}
	return s["properties"].(map[string]any)["data"].(map[string]any)["properties"].(map[string]any)["object"].(map[string]any)
}
func ValidateEvent(body []byte) error {
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	typ, _ := v["type"].(string)
	s := validators[typ]
	if s == nil {
		return fmt.Errorf("unsupported event type %q", typ)
	}
	return s.Validate(v)
}
