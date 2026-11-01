package seed

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logstream"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const logStreamSeed = `tenants:
- name: acme
  log_streams:
  - id: lst_seed
    name: Audit HTTP
    type: http
    status: paused
    sink:
      httpEndpoint: https://logs.example.invalid/intake
      httpContentFormat: JSONARRAY
      httpAuthorization: ${SEED_STREAM_AUTH}
      httpCustomHeaders: [{header: X-Private, value: '${SEED_STREAM_HEADER}'}]
    filters: [{type: category, name: auth.login.success}]
    pii_config: {log_fields: [email], method: hash, algorithm: xxhash}
    isPriority: true
  - name: Audit Datadog
    type: datadog
    sink: {datadogRegion: eu, datadogApiKey: '${SEED_STREAM_KEY}'}
  - name: Cloud
    type: eventbridge
    status: active
    sink: {awsAccountId: '123456789012', awsRegion: us-east-1}
`

func seedLogStreamEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SEED_STREAM_AUTH", "Bearer private-stream-auth")
	t.Setenv("SEED_STREAM_HEADER", "private-header-value")
	t.Setenv("SEED_STREAM_KEY", "private-datadog-key")
}
func TestSeedLogStreamsCreateOnly(t *testing.T) {
	for _, mode := range []Mode{ModeApply, ModeCreateOnly} {
		t.Run(string(mode), func(t *testing.T) {
			seedLogStreamEnv(t)
			ctx := context.Background()
			st := memory.New()
			w := testWrapper(t)
			f, err := Parse([]byte(logStreamSeed))
			if err != nil {
				t.Fatal(err)
			}
			f.Mode = mode
			if err = Apply(ctx, st, f, fixedNow, w); err != nil {
				t.Fatal(err)
			}
			tn, _ := st.Tenants().GetByName(ctx, "acme")
			rows, err := st.Logs().ListLogStreams(ctx, tn.ID)
			if err != nil || len(rows) != 3 {
				t.Fatalf("streams=%+v err=%v", rows, err)
			}
			s, err := st.Logs().GetLogStream(ctx, tn.ID, "lst_seed")
			if err != nil {
				t.Fatal(err)
			}
			if s.Status != "paused" || s.Name != "Audit HTTP" || !s.IsPriority || len(s.Filters) != 1 || s.PII == nil || s.PII.Method != "hash" {
				t.Fatalf("configuration lost: %+v", s)
			}
			for _, row := range rows {
				if row.Type == "eventbridge" && row.Status != "suspended" {
					t.Fatal("cloud stream must remain suspended")
				}
			}
			s.Name = "Console rename"
			s.Status = "suspended"
			s.Sink["httpEndpoint"] = "https://edited.example.invalid/"
			if err = st.Logs().UpdateLogStream(ctx, s, s.Version); err != nil {
				t.Fatal(err)
			}
			before, _ := st.Logs().ListLogStreams(ctx, tn.ID)
			// Existing IDs and unique names are skipped before environment lookup.
			t.Setenv("SEED_STREAM_AUTH", "")
			t.Setenv("SEED_STREAM_HEADER", "")
			t.Setenv("SEED_STREAM_KEY", "")
			if err = Apply(ctx, st, f, fixedNow, w); err != nil {
				t.Fatal(err)
			}
			after, _ := st.Logs().ListLogStreams(ctx, tn.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("reapply overwrote configuration, rotated secrets or resumed: before=%+v after=%+v", before, after)
			}
			// The same stable ID in another tenant is a distinct stream.
			seedLogStreamEnv(t)
			other, err := Parse([]byte(strings.Replace(logStreamSeed, "name: acme", "name: other", 1)))
			if err != nil {
				t.Fatal(err)
			}
			if err = Apply(ctx, st, other, fixedNow, w); err != nil {
				t.Fatal(err)
			}
			tn2, _ := st.Tenants().GetByName(ctx, "other")
			if _, err = st.Logs().GetLogStream(ctx, tn2.ID, "lst_seed"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestSeedLogStreamSecretsFromEnv(t *testing.T) {
	seedLogStreamEnv(t)
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	f, err := Parse([]byte(logStreamSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	rows, _ := st.Logs().ListLogStreams(ctx, tn.ID)
	for _, s := range rows {
		private, err := logstream.OpenSecrets(w, &s)
		if err != nil {
			t.Fatal(err)
		}
		switch s.Type {
		case "http":
			if private["httpAuthorization"] != "Bearer private-stream-auth" || !strings.Contains(string(mustJSON(t, private["httpCustomHeaders"])), "private-header-value") {
				t.Fatal("HTTP secrets not resolved")
			}
		case "datadog":
			if private["datadogApiKey"] != "private-datadog-key" {
				t.Fatal("Datadog secret not resolved")
			}
		}
		public := string(mustJSON(t, s.Sink))
		if strings.Contains(public, "private-") || bytes.Contains(s.SealedSecrets, []byte("private-")) {
			t.Fatal("plaintext credential persisted")
		}
		if len(s.SealedSecrets) > 0 {
			for _, field := range []string{"tenant", "id", "type"} {
				copy := s
				switch field {
				case "tenant":
					copy.TenantID += "x"
				case "id":
					copy.ID += "x"
				case "type":
					copy.Type = "segment"
				}
				if _, err = logstream.OpenSecrets(w, &copy); err == nil {
					t.Fatalf("secret binding missing for %s", field)
				}
			}
		}
	}
	t.Setenv("SEED_STREAM_KEY", "")
	empty := memory.New()
	err = Apply(ctx, empty, f, fixedNow, w)
	if err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatalf("missing env must fail safely: %v", err)
	}
	if _, err = empty.Tenants().GetByName(ctx, "acme"); err != store.ErrNotFound {
		t.Fatalf("failed seed was not atomic: %v", err)
	}
}
func TestSeedLogStreamValidation(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":        "{name: x, type: http, bogus: true, sink: {httpEndpoint: 'https://example.invalid'}}",
		"sink":           "{name: x, type: http, sink: {httpEndpoint: 'https://example.invalid', bogus: true}}",
		"plain secret":   "{name: x, type: datadog, sink: {datadogRegion: eu, datadogApiKey: plaintext-secret}}",
		"embedded env":   "{name: x, type: datadog, sink: {datadogRegion: eu, datadogApiKey: 'prefix-${KEY}'}}",
		"missing secret": "{name: x, type: datadog, sink: {datadogRegion: eu}}",
		"region":         "{name: x, type: datadog, sink: {datadogRegion: invalid, datadogApiKey: '${KEY}'}}",
		"insecure":       "{name: x, type: http, sink: {httpEndpoint: 'http://example.invalid'}}",
		"filter":         "{name: x, type: http, sink: {httpEndpoint: 'https://example.invalid'}, filters: [{type: category, name: wrong}]}",
		"pii":            "{name: x, type: http, sink: {httpEndpoint: 'https://example.invalid'}, pii_config: {log_fields: [password]}}",
		"duplicate name": "{name: x, type: http, sink: {httpEndpoint: 'https://example.invalid'}}, {name: x, type: http, sink: {httpEndpoint: 'https://example.invalid'}}",
		"duplicate id":   "{id: same, name: x, type: http, sink: {httpEndpoint: 'https://example.invalid'}}, {id: same, name: y, type: http, sink: {httpEndpoint: 'https://example.invalid'}}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte("tenants: [{name: acme, log_streams: [" + body + "]}]")); err == nil {
				t.Fatal("invalid stream accepted")
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSeedLogStreamOtherSinkSchemas(t *testing.T) {
	for _, tc := range []struct{ kind, sink, env, secretField string }{
		{"splunk", `{splunkDomain: logs.example.invalid, splunkPort: '8088', splunkSecure: true, splunkToken: '${STREAM_SECRET}'}`, "private-splunk-token", "splunkToken"},
		{"sumo", `{sumoSourceAddress: '${STREAM_SECRET}'}`, "https://logs.example.invalid/private-sumo-url", "sumoSourceAddress"},
		{"segment", `{segmentWriteKey: '${STREAM_SECRET}'}`, "private-segment-key", "segmentWriteKey"},
		{"mixpanel", `{mixpanelRegion: eu, mixpanelProjectId: '123', mixpanelServiceAccountUsername: account, mixpanelServiceAccountPassword: '${STREAM_SECRET}'}`, "private-mixpanel-password", "mixpanelServiceAccountPassword"},
		{"eventgrid", `{azureSubscriptionId: 12345678-1234-1234-1234-123456789abc, azureRegion: eastus, azureResourceGroup: audit}`, "", ""},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			t.Setenv("STREAM_SECRET", tc.env)
			ctx := context.Background()
			st := memory.New()
			w := testWrapper(t)
			f, err := Parse([]byte("tenants: [{name: acme, log_streams: [{name: Audit, type: " + tc.kind + ", sink: " + tc.sink + "}]}]"))
			if err != nil {
				t.Fatal(err)
			}
			if err = Apply(ctx, st, f, fixedNow, w); err != nil {
				t.Fatal(err)
			}
			tenant, _ := st.Tenants().GetByName(ctx, "acme")
			rows, err := st.Logs().ListLogStreams(ctx, tenant.ID)
			if err != nil || len(rows) != 1 {
				t.Fatalf("stream missing: %v", err)
			}
			s := rows[0]
			if tc.secretField != "" {
				private, err := logstream.OpenSecrets(w, &s)
				if err != nil || private[tc.secretField] != tc.env {
					t.Fatal("secret not resolved/sealed")
				}
				if _, ok := s.Sink[tc.secretField]; ok {
					t.Fatal("secret stored in public sink")
				}
			} else if s.Status != "suspended" {
				t.Fatal("cloud delivery must be suspended")
			}
		})
	}
}

func TestSeedLogStreamAmbiguousExistingName(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	f, err := Parse([]byte(`tenants: [{name: acme, log_streams: [{name: Audit, type: http, sink: {httpEndpoint: 'https://logs.example.invalid'}}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tenant, _ := st.Tenants().GetByName(ctx, "acme")
	duplicate := &store.LogStream{TenantID: tenant.ID, ID: "another", Name: "Audit", Type: "http", Status: "paused", Sink: map[string]any{"httpEndpoint": "https://logs.example.invalid"}}
	if err = st.Logs().CreateLogStream(ctx, duplicate); err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err == nil {
		t.Fatal("ambiguous natural name accepted")
	}
	rows, _ := st.Logs().ListLogStreams(ctx, tenant.ID)
	if len(rows) != 2 {
		t.Fatal("ambiguity created another stream")
	}
}
