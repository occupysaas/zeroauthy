package seed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/eventstream"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const eventStreamSeed = `tenants:
- name: acme
  event_streams:
  - id: est_abcdefghijklmnopqrstuv
    name: Audit webhook
    status: disabled
    subscriptions: [{event_type: user.created}]
    destination:
      type: webhook
      configuration:
        webhook_endpoint: https://events.example.invalid/intake
        webhook_authorization: {method: bearer, token: '${SEED_EVENT_TOKEN}'}
`

func TestSeedEventStreamsCreateOnly(t *testing.T) {
	for _, mode := range []Mode{ModeApply, ModeCreateOnly} {
		t.Run(string(mode), func(t *testing.T) {
			t.Setenv("SEED_EVENT_TOKEN", "private-event-token")
			ctx := context.Background()
			st := memory.New()
			w := testWrapper(t)
			f, err := Parse([]byte(eventStreamSeed))
			if err != nil {
				t.Fatal(err)
			}
			f.Mode = mode
			if err = Apply(ctx, st, f, fixedNow, w); err != nil {
				t.Fatal(err)
			}
			tn, _ := st.Tenants().GetByName(ctx, "acme")
			rows, _, err := st.Events().ListEventStreams(ctx, tn.ID, "", 100)
			if err != nil || len(rows) != 1 {
				t.Fatalf("stream missing: count=%d err=%v", len(rows), err)
			}
			s := rows[0]
			if s.Status != "disabled" || s.Subscriptions[0] != "user.created" {
				t.Fatal("configuration lost")
			}
			s.Name = "Console rename"
			s.Status = "enabled"
			s.Checkpoint = 42
			if err = st.Events().UpdateEventStream(ctx, &s, s.Version); err != nil {
				t.Fatal(err)
			}
			before, _, _ := st.Events().ListEventStreams(ctx, tn.ID, "", 100)
			t.Setenv("SEED_EVENT_TOKEN", "")
			if err = Apply(ctx, st, f, fixedNow, w); err != nil {
				t.Fatal(err)
			}
			after, _, _ := st.Events().ListEventStreams(ctx, tn.ID, "", 100)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("reapply changed stream state or secrets")
			}
			// Without an explicit ID, the unique tenant name remains create-only.
			f, err = Parse([]byte(strings.Replace(eventStreamSeed, "  - id: est_abcdefghijklmnopqrstuv\n    name: Audit webhook", "  - name: Console rename", 1)))
			if err != nil {
				t.Fatal(err)
			}

			if err = Apply(ctx, st, f, fixedNow, w); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSeedEventStreamSecretsFromEnv(t *testing.T) {
	for _, tc := range []struct{ method, field, public string }{{"bearer", "token", ""}, {"basic", "password", ", username: receiver"}, {"custom_header", "header_value", ", header_key: X-Event-Key"}} {
		t.Run(tc.method, func(t *testing.T) {
			text := strings.Replace(eventStreamSeed, "method: bearer, token:", "method: "+tc.method+tc.public+", "+tc.field+":", 1)
			f, err := Parse([]byte(text))
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("SEED_EVENT_TOKEN", "private-event-secret")
			ctx := context.Background()
			st := memory.New()
			w := testWrapper(t)
			if err = Apply(ctx, st, f, fixedNow, w); err != nil {
				t.Fatal(err)
			}
			tn, _ := st.Tenants().GetByName(ctx, "acme")
			s, err := st.Events().GetEventStream(ctx, tn.ID, "est_abcdefghijklmnopqrstuv")
			if err != nil {
				t.Fatal(err)
			}
			private, err := eventstream.OpenSecrets(w, s)
			if err != nil || private[tc.field] != "private-event-secret" {
				t.Fatal("secret not sealed/resolved")
			}
			if bytes.Contains(s.SealedSecret, []byte("private-event-secret")) || strings.Contains(string(mustJSON(t, s.Config)), "private-event-secret") {
				t.Fatal("plaintext persisted")
			}
			t.Setenv("SEED_EVENT_TOKEN", "")
			empty := memory.New()
			if err = Apply(ctx, empty, f, fixedNow, w); err == nil {
				t.Fatal("empty env accepted")
			}
			if _, err = empty.Tenants().GetByName(ctx, "acme"); err != store.ErrNotFound {
				t.Fatal("failed creation not atomic")
			}
			for _, bad := range []string{"literal-private-secret", "prefix-${SECRET}"} {
				if _, err = Parse([]byte(strings.Replace(text, "${SEED_EVENT_TOKEN}", bad, 1))); err == nil {
					t.Fatal("literal/interpolated secret accepted")
				}
			}
		})
	}
}

func TestSeedEventStreamsActionReferences(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	f, err := Parse([]byte(`tenants: [{name: acme}]`))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if err = st.Tenants().Create(ctx, &store.Tenant{ID: "foreign", Name: "foreign"}); err != nil {
		t.Fatal(err)
	}
	for _, a := range []store.Action{{TenantID: tn.ID, ID: "act_receiver", Name: "Receive events", Trigger: "event-stream"}, {TenantID: tn.ID, ID: "act_login", Name: "Login", Trigger: "post-login"}, {TenantID: "foreign", ID: "act_foreign", Name: "Foreign", Trigger: "event-stream"}} {
		if err = st.Actions().CreateAction(ctx, &a); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		ref   string
		valid bool
	}{{"action_name: Receive events", true}, {"action_id: act_receiver", true}, {"action_id: act_foreign", false}, {"action_name: Foreign", false}, {"action_id: act_login", false}, {"action_name: Login", false}} {
		text := `tenants: [{name: acme, event_streams: [{name: Events, subscriptions: [{event_type: user.created}], destination: {type: action, configuration: {` + tc.ref + `}}}]}]`
		f, err = Parse([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		err = Apply(ctx, st, f, fixedNow, w)
		if (err == nil) != tc.valid {
			t.Fatalf("reference %s: %v", tc.ref, err)
		}
		rows, _, _ := st.Events().ListEventStreams(ctx, tn.ID, "", 100)
		if tc.valid {
			if len(rows) != 1 || rows[0].Config["action_id"] != "act_receiver" {
				t.Fatal("Action reference did not resolve within tenant")
			}
			if err = st.Events().DeleteEventStream(ctx, tn.ID, rows[0].ID); err != nil {
				t.Fatal(err)
			}
		} else if len(rows) != 0 {
			t.Fatal("invalid reference created stream")
		}
	}
}

func TestSeedEventStreamsQuotaCheckpointAndTenantIsolation(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	t.Setenv("SEED_EVENT_TOKEN", "private-event-token")
	f, err := Parse([]byte(`tenants: [{name: acme}, {name: other}]`))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	other, _ := st.Tenants().GetByName(ctx, "other")
	if err = st.Events().AppendEvents(ctx, []store.TenantEvent{{TenantID: tn.ID, ID: "evt_history", Type: "user.created", Body: []byte(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	f, err = Parse([]byte(eventStreamSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	s, err := st.Events().GetEventStream(ctx, tn.ID, "est_abcdefghijklmnopqrstuv")
	if err != nil || s.Checkpoint != 1 {
		t.Fatal("seed replayed historical events")
	}
	f, err = Parse([]byte(strings.Replace(eventStreamSeed, "name: acme", "name: other", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	s2, err := st.Events().GetEventStream(ctx, other.ID, s.ID)
	if err != nil || s2.Checkpoint != 0 {
		t.Fatal("stream crossed tenant checkpoint")
	}
	s2.SealedSecret = s.SealedSecret
	if _, err = eventstream.OpenSecrets(w, s2); err == nil {
		t.Fatal("secret not tenant bound")
	}
	for i := 1; i < eventrules.Limits.MaxStreams; i++ {
		if err = st.Events().CreateEventStream(ctx, &store.EventStream{TenantID: tn.ID, ID: fmt.Sprintf("extra-%d", i), Name: fmt.Sprintf("Extra %d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	f, err = Parse([]byte(strings.Replace(eventStreamSeed, "id: est_abcdefghijklmnopqrstuv", "id: est_1234567890123456789012", 1)))
	if err != nil {
		t.Fatal(err)
	}
	f.Tenants[0].EventStreams[0]["name"] = "Over quota"
	if err = Apply(ctx, st, f, fixedNow, w); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("quota error=%v", err)
	}
	count, _ := st.Events().CountEventStreams(ctx, tn.ID)
	if count != eventrules.Limits.MaxStreams {
		t.Fatal("quota creation partially committed")
	}
}

func TestSeedEventStreamsAfterSeedActions(t *testing.T) {
	text := `tenants:
- name: acme
  actions:
  - name: Receive
    supported_triggers: [{id: event-stream, version: v1}]
    code: exports.onExecuteEventStream = async () => {};
    deploy: true
  event_streams:
  - name: Events
    subscriptions: [{event_type: user.created}]
    destination: {type: action, configuration: {action_name: Receive}}
`
	f, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	ae := actionstest.NewOffline(t, st, w)
	for range 2 {
		if err = ApplyWithActions(ctx, st, f, fixedNow, w, ae.Engine); err != nil {
			t.Fatal(err)
		}
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	a, err := st.Actions().GetActionByName(ctx, tn.ID, "Receive")
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.Events().ListEventStreams(ctx, tn.ID, "", 100)
	if err != nil || len(rows) != 1 || rows[0].Config["action_id"] != a.ID || a.DeployedVersionID == "" {
		t.Fatal("stream not created after seed Action build/deploy")
	}
}

func TestSeedEventStreamValidation(t *testing.T) {
	for name, text := range map[string]string{
		"missing secret":          strings.Replace(eventStreamSeed, ", token: '${SEED_EVENT_TOKEN}'", "", 1),
		"wrong method credential": strings.Replace(eventStreamSeed, "token:", "password:", 1),
		"http":                    strings.Replace(eventStreamSeed, "https://events.", "http://events.", 1),
		"bad id":                  strings.Replace(eventStreamSeed, "est_abcdefghijklmnopqrstuv", "wrong", 1),
		"unknown field":           strings.Replace(eventStreamSeed, "status: disabled", "status: disabled\n    checkpoint: 100", 1),
		"unknown event":           strings.Replace(eventStreamSeed, "user.created", "password.changed", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(text)); err == nil {
				t.Fatal("invalid seed accepted")
			}
		})
	}
}
