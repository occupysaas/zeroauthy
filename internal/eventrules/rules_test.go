package eventrules

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestEventsInventory(t *testing.T) {
	types := Types()
	if len(types) != 25 {
		t.Fatalf("catalog has %d types", len(types))
	}
	for _, typ := range types {
		if len(typ.Allowlist) == 0 || (!typ.Emitted && typ.Plan != 38) || (typ.Emitted && typ.StoreMethod == "") {
			t.Errorf("incomplete type %+v", typ)
		}
		if len(typ.Name) >= 11 && typ.Name[:11] == "connection." && !slices.Equal(typ.Strategies, []string{"oidc", "okta", "samlp", "pingfederate", "adfs", "ad", "google-apps", "waad"}) {
			t.Fatal(typ.Strategies)
		}
	}
	for _, op := range []string{"ListEventStreams", "CreateEventStream", "GetEventStream", "UpdateEventStream", "DeleteEventStream", "TestEventStream", "ListEventDeliveries", "GetEventDelivery", "RedeliverEvents", "RedeliverEvent", "SubscribeEvents"} {
		r := Route(op)
		if r.Source == "" || len(r.Scopes) == 0 || len(r.Errors) == 0 || r.Body == nil || r.Parameters == nil || r.ScopeMode != "any" {
			t.Errorf("incomplete route %s: %+v", op, r)
		}
		for _, p := range r.Parameters {
			schema, _ := p["schema"].(map[string]any)
			if p["name"] == "take" && (schema["default"] != float64(50) || schema["maximum"] != float64(100)) {
				t.Errorf("%s pagination constraints: %v", op, schema)
			}
			if p["name"] == "id" && schema["pattern"] != StreamIDPattern {
				t.Errorf("%s stream ID pattern", op)
			}
			if p["name"] == "event_id" && schema["pattern"] != EventIDPattern {
				t.Errorf("%s event ID pattern", op)
			}
		}

	}
	d := Destination("webhook")
	for _, key := range []string{"password", "token", "header_value"} {
		if !slices.Contains(d.SecretFields, key) {
			t.Errorf("unmarked secret %s", key)
		}
	}
	if Limits.TakeMax != 100 || Limits.TakeDefault != 50 || StreamIDPattern != "^est_[A-Za-z0-9]{22}$" || EventIDPattern != "^evt_[A-Za-z0-9]{22}$" {
		t.Fatal("pagination or ID contract")
	}
}
func TestFrozenLimits(t *testing.T) {
	if Limits.RetentionMinDays != 1 || Limits.SSERetryMS != 2000 || !slices.Equal(Limits.RetrySeconds, []int{1, 2, 4}) {
		t.Fatalf("incomplete limits: %+v", Limits)
	}
	if len(Inventory().Gaps) != 8 || Inventory().SSE["content_type"] != "text/event-stream" {
		t.Fatal("missing gaps or SSE contract")
	}
}

func TestCatalogValidates(t *testing.T) {
	b := Example("user.created")
	if err := ValidateEvent(b); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	v["unexpected"] = true
	b, _ = json.Marshal(v)
	if ValidateEvent(b) == nil {
		t.Fatal("accepted extra CloudEvent property")
	}
}

func TestCatalogEmittedExamples(t *testing.T) {
	for _, typ := range Types() {
		if !typ.Emitted {
			continue
		}
		t.Run(typ.Name, func(t *testing.T) {
			if err := ValidateEvent(Example(typ.Name)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCatalogRejectsInvalidEvents(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"id prefix", func(v map[string]any) { v["id"] = "prefixevt_vjFVP5pVdfvsfRKatshkVV" }},
		{"id suffix", func(v map[string]any) { v["id"] = "evt_vjFVP5pVdfvsfRKatshkVVx" }},
		{"stream id", func(v map[string]any) { v["a0stream"] = "est_vjFVP5pVdfvsfRKatshkVVx" }},
		{"version", func(v map[string]any) { v["specversion"] = "0.3" }},
		{"unknown type", func(v map[string]any) { v["type"] = "user.invented" }},
		{"missing data", func(v map[string]any) { delete(v, "data") }},
		{"password hash", func(v map[string]any) {
			v["data"].(map[string]any)["object"].(map[string]any)["password_hash"] = "secret"
		}},
		{"identity token", func(v map[string]any) {
			v["data"].(map[string]any)["object"].(map[string]any)["identities"].([]any)[0].(map[string]any)["access_token"] = "secret"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v map[string]any
			if err := json.Unmarshal(Example("user.created"), &v); err != nil {
				t.Fatal(err)
			}
			tc.mutate(v)
			b, _ := json.Marshal(v)
			if ValidateEvent(b) == nil {
				t.Fatal("accepted invalid event")
			}
		})
	}
	for _, b := range []string{"null", "[]", "{", `{"type":42}`} {
		if ValidateEvent([]byte(b)) == nil {
			t.Errorf("accepted %s", b)
		}
	}
}
