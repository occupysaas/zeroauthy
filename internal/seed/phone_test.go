package seed

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const phoneSeed = `tenants:
- name: acme
  connections:
  - {name: email, strategy: email, options: {}}
  - {name: sms, strategy: sms, options: {provider: twilio, twilio_sid: AC00000000000000000000000000000000, from: '+14155550100', twilio_token: '${PHONE_TOKEN}'}}
  phone_provider:
    name: twilio
    configuration: {sid: AC00000000000000000000000000000000, default_from: '+14155550100', delivery_methods: [text, voice]}
    credentials: {auth_token: '${PHONE_TOKEN}'}
  phone_templates:
  - type: otp_verify
    content: {syntax: liquid, from: Example, body: {text: 'Code {{ code }}', voice: 'Code {{ code }}'}}
  guardian:
    phone_settings: {otp_length: 7, otp_expiration_time: 330}
    phone_selected_provider: {provider: twilio}
    phone_message_types: {message_types: [sms, voice]}
`

func TestSeedPasswordlessPhone(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	t.Setenv("PHONE_TOKEN", "0123456789abcdef0123456789abcdef")
	f, err := Parse([]byte(phoneSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	ps, err := st.Phone().ListPhoneProviders(ctx, tn.ID)
	if err != nil || len(ps) != 1 {
		t.Fatalf("providers=%v err=%v", ps, err)
	}
	raw, err := keys.OpenBound(w, phone.ProviderCredentialsLabel, phone.ProviderCredentialsAAD(tn.ID, "twilio"), ps[0].SealedCredentials)
	if err != nil || !strings.Contains(string(raw), "0123456789abcdef0123456789abcdef") {
		t.Fatalf("credentials unavailable: %v", err)
	}
	c, _ := st.Connections().GetByName(ctx, tn.ID, "sms")
	cfg, err := keys.OpenConnectionConfig(w, tn.ID, c.ID, c.ConfigurationSealed)
	if err != nil || cfg["twilio_token"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("connection credential unavailable: %v", err)
	}
	b, _ := json.Marshal(c.Extra)
	if strings.Contains(string(b), "0123456789abcdef0123456789abcdef") || strings.Contains(string(b), "PHONE_TOKEN") {
		t.Fatal("credential leaked into public options")
	}
	ts, err := st.Phone().ListPhoneTemplates(ctx, tn.ID)
	if err != nil || len(ts) != 1 || ts[0].Type != "otp_verify" {
		t.Fatalf("templates=%v %v", ts, err)
	}
	g, _ := st.MFA().GetGuardian(ctx, tn.ID)
	if !strings.Contains(string(g.Stored["/guardian/factors/phone/settings"]), "330") {
		t.Fatalf("Guardian settings=%v", g.Stored)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	again, _ := st.Phone().ListPhoneProviders(ctx, tn.ID)
	if len(again) != 1 || again[0].ID != ps[0].ID {
		t.Fatal("provider identity changed")
	}
}

func TestSeedPhoneSecretReferences(t *testing.T) {
	for _, value := range []string{"plaintext", "prefix-${PHONE_TOKEN}"} {
		if _, err := Parse([]byte(strings.ReplaceAll(phoneSeed, "${PHONE_TOKEN}", value))); err == nil {
			t.Fatalf("accepted secret %q", value)
		}
	}
	t.Setenv("PHONE_TOKEN", "")
	f, err := Parse([]byte(phoneSeed))
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	if err = Apply(context.Background(), st, f, fixedNow, testWrapper(t)); err == nil {
		t.Fatal("accepted missing secret")
	}
}

func TestSeedPhoneIdentifierPrecheck(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	f, err := Parse([]byte(`tenants: [{name: acme, connections: [{name: db, strategy: auth0}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	for _, id := range []string{"a", "b"} {
		if err = st.Users().Create(ctx, &store.User{TenantID: tn.ID, UserID: id, PhoneNumber: "+14155550100", Identities: []store.Identity{{Connection: "db", Provider: "auth0", UserID: id}}}); err != nil {
			t.Fatal(err)
		}
	}
	f, err = Parse([]byte(`tenants: [{name: acme, connections: [{name: db, strategy: auth0, options: {attributes: {phone_number: {identifier: {active: true}}}}}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err == nil {
		t.Fatal("enabled ambiguous phone identifier")
	}
}

func TestExampleActionsCompile(t *testing.T) {
	b, err := os.ReadFile("../../docs/phone-providers.md")
	if err != nil {
		t.Fatal(err)
	}
	examples := regexp.MustCompile("(?s)```javascript\\n(.*?)\\n```").FindAllStringSubmatch(string(b), -1)
	if len(examples) != 3 {
		t.Fatalf("got %d examples, want 3", len(examples))
	}
	for i, example := range examples {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			st := memory.New()
			w := testWrapper(t)
			ae := actionstest.NewOffline(t, st, w)
			f, err := Parse([]byte("tenants: [{name: acme}]"))
			if err != nil {
				t.Fatal(err)
			}
			f.Tenants[0].Actions = []Action{{Name: "example", Code: example[1], SupportedTriggers: []ActionTrigger{{ID: "custom-phone-provider", Version: "v1"}}, Deploy: true}}
			if err = ApplyWithActions(context.Background(), st, f, fixedNow, w, ae.Engine); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSeedPhoneGuardianCredentials(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	t.Setenv("GUARDIAN_TOKEN", "fixture-secret")
	f, err := Parse([]byte(`tenants: [{name: acme, guardian: {phone_providers: {twilio: {sid: fixture, from: '+14155550100', auth_token: '${GUARDIAN_TOKEN}'}}}}]`))
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	g, _ := st.MFA().GetGuardian(ctx, tn.ID)
	path := "/guardian/factors/phone/providers/twilio"
	plain, err := keys.OpenBound(w, "guardian-provider/v1", []string{tn.ID, path}, g.SealedSecrets[path])
	if err != nil || !strings.Contains(string(plain), "fixture-secret") {
		t.Fatalf("sealed Guardian credentials missing: %v", err)
	}
	if strings.Contains(string(g.Stored[path]), "fixture-secret") || strings.Contains(string(g.Stored[path]), "auth_token") {
		t.Fatal("Guardian credential leaked")
	}
	f.Mode = ModeCreateOnly
	t.Setenv("GUARDIAN_TOKEN", "changed")
	if err = Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	after, _ := st.MFA().GetGuardian(ctx, tn.ID)
	if after.Version != g.Version {
		t.Fatal("create_only changed Guardian")
	}
}

func TestSeedPhoneInvalidConfiguration(t *testing.T) {
	for _, yaml := range []string{
		`tenants: [{name: acme, phone_provider: {name: sns, configuration: {region: us-east-1, delivery_methods: [voice]}, credentials: {access_key_id: '${AWS_KEY}', secret_access_key: '${AWS_SECRET}'}}}]`,
		`tenants: [{name: acme, phone_templates: [{type: otp_verify, content: {syntax: unsafe}}]}]`,
		`tenants: [{name: acme, phone_templates: [{type: otp_verify, content: {body: {text: '{% if %}'}}}]}]`,
		`tenants: [{name: acme, guardian: {phone_settings: {otp_length: 2, otp_expiration_time: 300}}}]`,
		`tenants: [{name: acme, guardian: {phone_providers: {unknown: {}}}}]`,
	} {
		if _, err := Parse([]byte(yaml)); err == nil {
			t.Fatalf("accepted invalid phone seed: %s", yaml)
		}
	}
}

func TestSeedCustomPhoneProviderWithAction(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	ae := actionstest.NewOffline(t, st, w)
	f, err := Parse([]byte(`tenants:
- name: acme
  phone_provider: {name: custom, configuration: {delivery_methods: [text]}, credentials: {}}
  actions:
  - name: phone
    supported_triggers: [{id: custom-phone-provider, version: v1}]
    code: exports.onExecuteCustomPhoneProvider = async () => {};
    deploy: true
  triggers:
    custom-phone-provider:
      bindings: [{ref: {type: action_name, value: phone}, display_name: Phone}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if err = ApplyWithActions(ctx, st, f, fixedNow, w, ae.Engine); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	ps, err := st.Phone().ListPhoneProviders(ctx, tn.ID)
	if err != nil || len(ps) != 1 || ps[0].Name != "custom" {
		t.Fatalf("provider=%v %v", ps, err)
	}
}
