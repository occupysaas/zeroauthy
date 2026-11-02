package seed

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestSeedGuardian(t *testing.T) { testSeedGuardian(t, memory.New()) }

func testSeedGuardian(t *testing.T, st store.Store) {
	ctx := context.Background()
	apply := func(yaml string, mode Mode) {
		t.Helper()
		f, err := Parse([]byte(yaml))
		if err != nil {
			t.Fatal(err)
		}
		f.Mode = mode
		if err = Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
			t.Fatal(err)
		}
	}
	const initial = `tenants: [{name: acme, guardian: {factors: {otp: true, email: true, recovery-code: true, webauthn-platform: true, push-notification: true}, policies: [all-applications]}}, {name: other}]`
	apply(initial, ModeApply)
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	get := func() *store.GuardianSettings {
		t.Helper()
		g, err := st.MFA().GetGuardian(ctx, tn.ID)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := get()
	if !g.Factors["otp"] || !g.Factors["email"] || !g.Factors["webauthn-platform"] || !g.Factors["push-notification"] || g.Factors["sms"] || !reflect.DeepEqual(g.Policies, []string{"all-applications"}) {
		t.Fatalf("Guardian = %+v", g)
	}
	apply(initial, ModeApply)
	if after := get(); !reflect.DeepEqual(g, after) {
		t.Fatal("identical seed changed Guardian state/version")
	}
	// Stored provider data and sealed envelopes belong to their API routes.
	g.Stored = map[string]json.RawMessage{"/guardian/settings": json.RawMessage(`{"display_remember_me_checkbox":true}`)}
	g.SealedSecrets = map[string][]byte{"provider": {1, 2, 3}}
	if err := st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	g = get()
	for _, omitted := range []string{`tenants: [{name: acme}]`, `tenants: [{name: acme, guardian: {}}]`, `tenants: [{name: acme, guardian: {factors: {}}}]`} {
		apply(omitted, ModeApply)
		if after := get(); !reflect.DeepEqual(g, after) {
			t.Fatal("omitted Guardian fields changed state/version")
		}
	}
	apply(`tenants: [{name: acme, guardian: {factors: {otp: false}, policies: []}}]`, ModeApply)
	after := get()
	if after.Factors["otp"] || !after.Factors["email"] || len(after.Policies) != 0 || after.Version != g.Version+1 || !reflect.DeepEqual(g.Stored, after.Stored) || !reflect.DeepEqual(g.SealedSecrets, after.SealedSecrets) {
		t.Fatalf("patch lost state: %+v", after)
	}
	failed, err := Parse([]byte(initial))
	if err != nil {
		t.Fatal(err)
	}
	failed.Tenants[0].Clients = []Client{{ClientID: "boom"}}
	if err = Apply(ctx, failingStore{st}, failed, fixedNow, testWrapper(t)); err == nil {
		t.Fatal("want injected failure after Guardian update")
	}
	if !reflect.DeepEqual(after, get()) {
		t.Fatal("failed seed changed existing Guardian configuration/version")
	}
	apply(initial, ModeCreateOnly)
	if !reflect.DeepEqual(after, get()) {
		t.Fatal("create_only overwrote existing Guardian")
	}
	other, _ := st.Tenants().GetByName(ctx, "other")
	og, err := st.MFA().GetGuardian(ctx, other.ID)
	if err != nil || og.Factors["email"] || len(og.Policies) != 0 {
		t.Fatalf("cross-tenant mutation: %+v %v", og, err)
	}
}

func TestSeedGuardianUnknownFactor(t *testing.T) {
	_, err := Parse([]byte(`tenants: [{name: acme, guardian: {factors: {unknown: true}}}]`))
	if err == nil || !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("want invalid seed naming unknown factor, got %v", err)
	}
}

func TestSeedGuardianValidation(t *testing.T) {
	for _, guardian := range []string{`null`, `{factors: null}`, `{policies: null}`, `{factors: {otp: "true"}}`, `{factors: {otp: 1}}`, `{policies: [never]}`, `{policies: [all-applications, confidence-score]}`, `{policies: [all-applications, all-applications]}`, `{unexpected: true}`} {
		t.Run(guardian, func(t *testing.T) {
			if _, err := Parse([]byte(`tenants: [{name: acme, guardian: ` + guardian + `}]`)); err == nil {
				t.Fatal("invalid Guardian seed accepted")
			}
		})
	}
	for _, policy := range []string{`[]`, `[all-applications]`, `[confidence-score]`} {
		if _, err := Parse([]byte(`tenants: [{name: acme, guardian: {policies: ` + policy + `}}]`)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSeedGuardianRollback(t *testing.T) { testSeedGuardianRollback(t, memory.New()) }

func testSeedGuardianRollback(t *testing.T, st store.Store) {
	ctx := context.Background()
	f, err := Parse([]byte(`tenants: [{name: acme, guardian: {factors: {otp: true}, policies: [all-applications]}}]`))
	if err != nil {
		t.Fatal(err)
	}
	// The established failing client store returns a real transaction error
	// after Guardian is written, so the whole tenant must roll back.
	f.Tenants[0].Clients = []Client{{ClientID: "boom"}}
	if err = Apply(ctx, failingStore{st}, f, fixedNow, testWrapper(t)); err == nil {
		t.Fatal("want failure")
	}
	if _, err = st.Tenants().GetByName(ctx, "acme"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("tenant survived rollback")
	}
}
