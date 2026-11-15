package seed

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// publicKeyPEM returns the SPKI PEM of a fresh 2048-bit RSA key, indented
// for a YAML block scalar.
func publicKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
}

func indent(s, prefix string) string {
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix)
}

// noCredentialsStore is a plugin store that did not negotiate
// client_credentials.v1.
type noCredentialsStore struct{ store.Store }

func (noCredentialsStore) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}
func (s noCredentialsStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(noCredentialsStore{tx}) })
}

func credentialsSeed(a, b string) string {
	return fmt.Sprintf(`tenants:
  - name: acme
    clients:
      - client_id: svc
        name: Service
        app_type: non_interactive
        credentials:
          - name: primary
            alg: PS256
            kid: primary-key-0001
            pem: |
%s
          - name: secondary
            pem: |
%s
        client_authentication_methods:
          private_key_jwt:
            credentials: [primary, secondary]
        signed_request_object:
          required: true
          credentials: [secondary]
        token_exchange:
          allow_any_profile_of_type: [custom_authentication]
`, indent(a, "              "), indent(b, "              "))
}

func TestSeedClientCredentials(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	pemA, pemB := publicKeyPEM(t), publicKeyPEM(t)
	doc := credentialsSeed(pemA, pemB)
	if err := applySeed(t, st, doc, ModeApply); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	c, err := st.Clients().Get(ctx, tn.ID, "svc")
	if err != nil {
		t.Fatal(err)
	}
	creds, _ := st.ClientCredentials().List(ctx, tn.ID, "svc")
	if len(creds) != 2 {
		t.Fatalf("credentials = %d, want 2", len(creds))
	}
	byName := map[string]*store.ClientCredential{}
	for _, cr := range creds {
		byName[cr.Name] = cr
	}
	p, s := byName["primary"], byName["secondary"]
	if p.Alg != "PS256" || p.KID != "primary-key-0001" || s.Alg != "RS256" || s.KID != s.Thumbprint || s.KID == "" {
		t.Fatalf("stored credentials: %+v %+v", p, s)
	}
	if c.TokenEndpointAuthMethod != "" || len(c.PrivateKeyJWTCredentials) != 2 ||
		c.PrivateKeyJWTCredentials[0] != p.ID || c.PrivateKeyJWTCredentials[1] != s.ID {
		t.Fatalf("private_key_jwt = %q %v", c.TokenEndpointAuthMethod, c.PrivateKeyJWTCredentials)
	}
	if so := c.SignedRequestObject; so == nil || !so.Required || len(so.Credentials) != 1 || so.Credentials[0] != s.ID {
		t.Fatalf("signed_request_object = %+v", so)
	}
	if len(c.TokenExchangeTypes) != 1 || c.TokenExchangeTypes[0] != "custom_authentication" {
		t.Fatalf("token_exchange = %v", c.TokenExchangeTypes)
	}

	// Idempotent: the same seed keeps the credential ids.
	if err := applySeed(t, st, doc, ModeApply); err != nil {
		t.Fatal(err)
	}
	again, _ := st.ClientCredentials().List(ctx, tn.ID, "svc")
	if len(again) != 2 || again[0].ID != creds[0].ID || again[1].ID != creds[1].ID {
		t.Fatalf("a re-apply replaced credentials: %+v", again)
	}

	// A key deleted through the API comes back; the seed owns the client.
	if err := st.ClientCredentials().Delete(ctx, tn.ID, "svc", s.ID); err != nil {
		t.Fatal(err)
	}
	if err := applySeed(t, st, doc, ModeApply); err != nil {
		t.Fatal(err)
	}
	c, _ = st.Clients().Get(ctx, tn.ID, "svc")
	again, _ = st.ClientCredentials().List(ctx, tn.ID, "svc")
	if len(again) != 2 || len(c.PrivateKeyJWTCredentials) != 2 || c.SignedRequestObject.Credentials[0] == s.ID {
		t.Fatalf("re-apply did not restore the key: %+v %+v", again, c)
	}

	// A seed that drops a key and changes the other deletes and replaces them.
	pemC := publicKeyPEM(t)
	changed := strings.Replace(credentialsSeed(pemC, pemB), "credentials: [primary, secondary]", "credentials: [primary]", 1)
	changed = strings.Replace(changed, "credentials: [secondary]", "credentials: [primary]", 1)
	changed = changed[:strings.Index(changed, "          - name: secondary")] + changed[strings.Index(changed, "        client_authentication_methods"):]
	if err := applySeed(t, st, changed, ModeApply); err != nil {
		t.Fatal(err)
	}
	c, _ = st.Clients().Get(ctx, tn.ID, "svc")
	left, _ := st.ClientCredentials().List(ctx, tn.ID, "svc")
	if len(left) != 1 || left[0].Name != "primary" || len(c.PrivateKeyJWTCredentials) != 1 || c.PrivateKeyJWTCredentials[0] != left[0].ID {
		t.Fatalf("after dropping a key: %+v %+v", left, c.PrivateKeyJWTCredentials)
	}

	// A seed without the settings detaches them and keeps the stored keys.
	bare := "tenants:\n  - name: acme\n    clients:\n      - {client_id: svc, name: Service, app_type: non_interactive, client_secret: a-long-enough-secret}\n"
	if err := applySeed(t, st, bare, ModeApply); err != nil {
		t.Fatal(err)
	}
	c, _ = st.Clients().Get(ctx, tn.ID, "svc")
	kept, _ := st.ClientCredentials().List(ctx, tn.ID, "svc")
	if c.PrivateKeyJWTCredentials != nil || c.SignedRequestObject != nil || c.TokenExchangeTypes != nil || len(kept) != 1 {
		t.Fatalf("omitted settings: %+v keys=%d", c, len(kept))
	}
	if c.TokenEndpointAuthMethod != store.AuthMethodClientSecretPost {
		t.Fatalf("auth method = %q", c.TokenEndpointAuthMethod)
	}
}

func TestSeedClientCredentialsCreateOnly(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	pemA, pemB := publicKeyPEM(t), publicKeyPEM(t)
	if err := applySeed(t, st, credentialsSeed(pemA, pemB), ModeCreateOnly); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	before, _ := st.ClientCredentials().List(ctx, tn.ID, "svc")
	if len(before) != 2 {
		t.Fatalf("create-only did not create the credentials: %d", len(before))
	}
	if err := st.ClientCredentials().Delete(ctx, tn.ID, "svc", before[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := applySeed(t, st, credentialsSeed(publicKeyPEM(t), pemB), ModeCreateOnly); err != nil {
		t.Fatal(err)
	}
	after, _ := st.ClientCredentials().List(ctx, tn.ID, "svc")
	if len(after) != 1 || after[0].ID != before[1].ID {
		t.Fatalf("create-only changed an existing client's credentials: %+v", after)
	}
}

func TestSeedClientCredentialsValidation(t *testing.T) {
	pemA, pemB := publicKeyPEM(t), publicKeyPEM(t)
	base := credentialsSeed(pemA, pemB)
	three := strings.Replace(base, "        client_authentication_methods", "          - name: third\n            pem: |\n"+indent(publicKeyPEM(t), "              ")+"\n        client_authentication_methods", 1)
	for name, tc := range map[string]struct{ doc, want string }{
		"three credentials": {three, "at most 2"},
		"unknown reference": {strings.Replace(base, "credentials: [secondary]", "credentials: [nothing]", 1), "nothing"},
		"bad kid":           {strings.Replace(base, "primary-key-0001", "short", 1), "kid"},
		"bad alg":           {strings.Replace(base, "alg: PS256", "alg: HS256", 1), "alg"},
		"not a key":         {strings.Replace(base, "BEGIN PUBLIC KEY", "BEGIN NOTHING", 1), "pem"},
		"explicit method":   {strings.Replace(base, "app_type: non_interactive", "app_type: non_interactive\n        token_endpoint_auth_method: client_secret_post", 1), "token_endpoint_auth_method"},
		"duplicate name":    {strings.Replace(base, "name: secondary", "name: primary", 1), "duplicate"},
		"third party":       {strings.Replace(base, "app_type: non_interactive", "app_type: non_interactive\n        is_first_party: false", 1), "first-party"},
		"bad exchange type": {strings.Replace(base, "[custom_authentication]", "[other]", 1), "custom_authentication"},
		"unreferenced name": {strings.Replace(base, "          - name: secondary", "          - name: ''", 1), "name"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestSeedClientCredentialsNeedCapability(t *testing.T) {
	ctx := context.Background()
	for name, doc := range map[string]string{
		"credentials": credentialsSeed(publicKeyPEM(t), publicKeyPEM(t)),
		"hs256":       `tenants: [{name: acme, resource_servers: [{identifier: "https://api.acme.test", signing_alg: HS256}]}]`,
		"profiles": `tenants:
  - name: acme
    token_exchange_profiles:
      - {name: legacy, subject_token_type: "urn:acme:legacy", action: exchange}
`,
		"token exchange": `tenants: [{name: acme, clients: [{client_id: svc, name: S, app_type: non_interactive, client_secret: a-long-enough-secret, token_exchange: {allow_any_profile_of_type: [custom_authentication]}}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			mem := memory.New()
			f, err := Parse([]byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			err = ApplyWithActions(ctx, noCredentialsStore{mem}, f, fixedNow, testWrapper(t), nil)
			if !errors.Is(err, store.ErrClientCredentialsUnavailable) || !strings.Contains(err.Error(), "client_credentials.v1") {
				t.Fatalf("err = %v", err)
			}
			if _, err = mem.Tenants().GetByName(ctx, "acme"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("a refused seed still wrote the tenant")
			}
		})
	}
	// A seed that uses none of it applies to the same store.
	if err := applySeed(t, noCredentialsStore{memory.New()}, `tenants: [{name: acme, clients: [{client_id: a, name: A, app_type: non_interactive, client_secret: a-long-enough-secret}]}]`, ModeApply); err != nil {
		t.Fatal(err)
	}
}

func TestSeedAPISigning(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	api := func(extra string) string {
		return `tenants: [{name: acme, resource_servers: [{identifier: "https://api.acme.test", name: API` + extra + `}]}]`
	}
	get := func() *store.ResourceServer {
		t.Helper()
		tn, _ := st.Tenants().GetByName(ctx, "acme")
		rs, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://api.acme.test")
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}
	secret := func(rs *store.ResourceServer) string {
		t.Helper()
		b, err := keys.OpenAPISigningSecret(w, rs.TenantID, rs.ID, rs.SigningSecretSealed)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	if err := applySeed(t, st, api(", signing_alg: HS256"), ModeApply); err != nil {
		t.Fatal(err)
	}
	rs := get()
	generated := secret(rs)
	if rs.SigningAlg != "HS256" || len(generated) != 43 {
		t.Fatalf("generated: %q %q", rs.SigningAlg, generated)
	}
	// A re-apply keeps the generated secret.
	if err := applySeed(t, st, api(", signing_alg: HS256"), ModeApply); err != nil {
		t.Fatal(err)
	}
	if rs = get(); rs.SigningAlg != "HS256" || secret(rs) != generated {
		t.Fatal("a re-apply rotated or lost the HS256 secret")
	}
	// A supplied secret replaces it, and an unchanged one is not resealed.
	if err := applySeed(t, st, api(", signing_alg: HS256, signing_secret: sixteen-chars-ok"), ModeApply); err != nil {
		t.Fatal(err)
	}
	rs = get()
	sealed := rs.SigningSecretSealed
	if secret(rs) != "sixteen-chars-ok" {
		t.Fatal("the supplied secret was not applied")
	}
	if err := applySeed(t, st, api(", signing_alg: HS256, signing_secret: sixteen-chars-ok"), ModeApply); err != nil {
		t.Fatal(err)
	}
	if string(get().SigningSecretSealed) != string(sealed) {
		t.Fatal("an unchanged secret was sealed again")
	}
	// PS256 clears the secret; the default is RS256.
	if err := applySeed(t, st, api(", signing_alg: PS256"), ModeApply); err != nil {
		t.Fatal(err)
	}
	if rs = get(); rs.SigningAlg != "PS256" || len(rs.SigningSecretSealed) != 0 {
		t.Fatalf("PS256: %+v", rs)
	}
	if err := applySeed(t, st, api(""), ModeApply); err != nil {
		t.Fatal(err)
	}
	if rs = get(); rs.SigningAlg != "RS256" {
		t.Fatalf("default: %q", rs.SigningAlg)
	}

	for name, tc := range map[string]struct{ extra, want string }{
		"unknown alg":       {", signing_alg: ES256", "signing_alg"},
		"short secret":      {", signing_alg: HS256, signing_secret: short", "16"},
		"secret without":    {", signing_secret: sixteen-chars-ok", "HS256"},
		"secret with PS256": {", signing_alg: PS256, signing_secret: sixteen-chars-ok", "HS256"},
	} {
		if _, err := Parse([]byte(api(tc.extra))); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want mention of %q", name, err, tc.want)
		}
	}
}

const exchangeActionSeed = `tenants:
  - name: acme
    actions:
      - name: exchange
        supported_triggers: [{id: custom-token-exchange, version: v1}]
        code: exports.onExecuteCustomTokenExchange = async () => {};
        dependencies: []
        deploy: true
      - name: undeployed
        supported_triggers: [{id: custom-token-exchange, version: v1}]
        code: exports.onExecuteCustomTokenExchange = async () => {};
        dependencies: []
        deploy: false
    token_exchange_profiles:
      - {name: Legacy tokens, subject_token_type: "urn:acme:legacy", action: exchange}
`

func TestSeedTokenExchangeProfiles(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	ae := actionstest.NewOffline(t, st, w)
	apply := func(doc string, mode Mode) error {
		t.Helper()
		f, err := Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		f.Mode = mode
		return ApplyWithActions(ctx, st, f, fixedNow, w, ae.Engine)
	}
	if err := apply(exchangeActionSeed, ModeApply); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	act, _ := st.Actions().GetActionByName(ctx, tn.ID, "exchange")
	p, err := st.ClientCredentials().GetProfileByType(ctx, tn.ID, "urn:acme:legacy")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Legacy tokens" || p.ActionID != act.ID || p.Type != "custom_authentication" || !strings.HasPrefix(p.ID, "tep_") || len(p.ID) != 26 {
		t.Fatalf("profile = %+v", p)
	}
	// Idempotent.
	if err := apply(exchangeActionSeed, ModeApply); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.ClientCredentials().GetProfileByType(ctx, tn.ID, "urn:acme:legacy"); again.ID != p.ID {
		t.Fatal("a re-apply replaced the profile")
	}
	// Apply mode renames; create-only leaves the stored profile alone.
	renamed := strings.Replace(exchangeActionSeed, "Legacy tokens", "Old tokens", 1)
	if err := apply(renamed, ModeCreateOnly); err != nil {
		t.Fatal(err)
	}
	if q, _ := st.ClientCredentials().GetProfile(ctx, tn.ID, p.ID); q.Name != "Legacy tokens" {
		t.Fatalf("create-only renamed the profile: %q", q.Name)
	}
	if err := apply(renamed, ModeApply); err != nil {
		t.Fatal(err)
	}
	if q, _ := st.ClientCredentials().GetProfile(ctx, tn.ID, p.ID); q.Name != "Old tokens" || q.ID != p.ID {
		t.Fatalf("apply did not rename the profile: %+v", q)
	}
	// A new profile is created in either mode.
	more := renamed + "      - {name: Partner tokens, subject_token_type: \"https://partner.example/token\", action: exchange}\n"
	if err := apply(more, ModeCreateOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClientCredentials().GetProfileByType(ctx, tn.ID, "https://partner.example/token"); err != nil {
		t.Fatal(err)
	}
	// The legacy entry point cannot apply profiles.
	f, _ := Parse([]byte(exchangeActionSeed))
	if err := Apply(ctx, memory.New(), f, fixedNow, w); err == nil || !strings.Contains(err.Error(), "ApplyWithActions") {
		t.Fatalf("Apply = %v", err)
	}
}

func TestSeedTokenExchangeProfilesRefuse(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	ae := actionstest.NewOffline(t, st, w)
	line := func(entry string) string {
		return strings.Replace(exchangeActionSeed, `      - {name: Legacy tokens, subject_token_type: "urn:acme:legacy", action: exchange}`, "      - "+entry, 1)
	}
	for name, tc := range map[string]struct{ entry, want string }{
		"reserved prefix": {`{name: Legacy, subject_token_type: "urn:auth0:x-token", action: exchange}`, "reserved"},
		"short name":      {`{name: ab, subject_token_type: "urn:acme:legacy", action: exchange}`, "name"},
		"bad scheme":      {`{name: Legacy, subject_token_type: "http://acme.example/t", action: exchange}`, "https://"},
		"no action":       {`{name: Legacy, subject_token_type: "urn:acme:legacy"}`, "action"},
		"bad type":        {`{name: Legacy, type: other, subject_token_type: "urn:acme:legacy", action: exchange}`, "custom_authentication"},
		"wrong trigger":   {`{name: Legacy, subject_token_type: "urn:acme:legacy", action: exchange2}`, "custom-token-exchange"},
		"not deployed":    {`{name: Legacy, subject_token_type: "urn:acme:legacy", action: undeployed}`, "deploy"},
	} {
		t.Run(name, func(t *testing.T) {
			doc := line(tc.entry)
			if name == "wrong trigger" {
				doc = strings.Replace(doc, "      - name: undeployed", "      - name: exchange2\n        supported_triggers: [{id: post-login, version: v3}]\n        code: exports.onExecutePostLogin = async () => {};\n        dependencies: []\n        deploy: true\n      - name: undeployed", 1)
			}
			_, err := Parse([]byte(doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
	dup := line(`{name: One one, subject_token_type: "urn:acme:legacy", action: exchange}`) + "      - {name: Two two, subject_token_type: \"urn:acme:legacy\", action: exchange}\n"
	if _, err := Parse([]byte(dup)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate subject_token_type: %v", err)
	}
	// An Action the seed does not define must exist and qualify at apply time.
	missing, err := Parse([]byte(`tenants: [{name: acme, token_exchange_profiles: [{name: Legacy, subject_token_type: "urn:acme:legacy", action: ghost}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyWithActions(ctx, st, missing, fixedNow, w, ae.Engine); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("missing Action: %v", err)
	}
}
