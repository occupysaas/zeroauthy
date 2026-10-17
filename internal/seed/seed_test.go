package seed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const sample = `
tenants:
  - name: acme
    friendly_name: Acme
    domains: ["Login.Acme.TEST", "localhost:8443"]
    default_audience: https://api.acme.test
    resource_servers:
      - identifier: https://api.acme.test
        name: Acme API
        token_lifetime: 3600
        scopes:
          - {value: "read:things", description: "Read things"}
          - {value: "write:things", description: "Write things"}
    clients:
      - client_id: m2m
        name: Backend
        app_type: non_interactive
        client_secret: first-secret
        grant_types: [client_credentials]
      - client_id: spa
        name: Web
        app_type: spa
        callbacks: ["https://app.acme.test/callback"]
    client_grants:
      - client_id: m2m
        audience: https://api.acme.test
        scopes: ["read:things"]
`

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }

func TestApply(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}

	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tn.Domains, ",") != "login.acme.test,localhost:8443" {
		t.Errorf("domains not normalized: %v", tn.Domains)
	}
	if tn.DefaultAudience != "https://api.acme.test" || !strings.HasPrefix(tn.ID, "ten_") {
		t.Errorf("tenant = %+v", tn)
	}

	rs, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://api.acme.test")
	if err != nil || rs.TokenLifetime != 3600 || len(rs.Scopes) != 2 || rs.SigningAlg != "RS256" {
		t.Fatalf("resource server = %+v, %v", rs, err)
	}

	m2m, err := st.Clients().Get(ctx, tn.ID, "m2m")
	if err != nil {
		t.Fatal(err)
	}
	if m2m.TokenEndpointAuthMethod != store.AuthMethodClientSecretPost {
		t.Errorf("default auth method for non_interactive = %q", m2m.TokenEndpointAuthMethod)
	}
	if len(m2m.Secrets) != 1 {
		t.Fatalf("secrets = %d", len(m2m.Secrets))
	}
	if ok, _ := secrets.Verify(m2m.Secrets[0].Hash, "first-secret"); !ok {
		t.Error("stored hash does not verify against seed secret")
	}

	spa, _ := st.Clients().Get(ctx, tn.ID, "spa")
	if spa.TokenEndpointAuthMethod != store.AuthMethodNone || len(spa.Secrets) != 0 {
		t.Errorf("spa = %+v", spa)
	}

	g, err := st.ClientGrants().Find(ctx, tn.ID, "m2m", "https://api.acme.test", store.SubjectTypeClient)
	if err != nil || strings.Join(g.Scopes, " ") != "read:things" {
		t.Fatalf("grant = %+v, %v", g, err)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, _ := Parse([]byte(sample))
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn1, _ := st.Tenants().GetByName(ctx, "acme")
	c1, _ := st.Clients().Get(ctx, tn1.ID, "m2m")
	rs1, _ := st.ResourceServers().GetByIdentifier(ctx, tn1.ID, "https://api.acme.test")

	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn2, _ := st.Tenants().GetByName(ctx, "acme")
	c2, _ := st.Clients().Get(ctx, tn2.ID, "m2m")
	rs2, _ := st.ResourceServers().GetByIdentifier(ctx, tn2.ID, "https://api.acme.test")
	if tn1.ID != tn2.ID || rs1.ID != rs2.ID || c1.Secrets[0].Hash != c2.Secrets[0].Hash {
		t.Fatal("second Apply changed IDs or re-hashed an unchanged secret")
	}

	changed, _ := Parse([]byte(strings.Replace(sample, "first-secret", "second-secret", 1)))
	if err := Apply(ctx, st, changed, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	c3, _ := st.Clients().Get(ctx, tn2.ID, "m2m")
	if ok, _ := secrets.Verify(c3.Secrets[0].Hash, "second-secret"); !ok || len(c3.Secrets) != 1 {
		t.Fatal("changed secret was not applied")
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"bad callback escape":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://a.test/cb%zz"]}]}]`, "not a valid URL"},
		"relative callback":         {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["/cb"]}]}]`, "absolute"},
		"callback fragment":         {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://a.test/cb#x"]}]}]`, "fragment"},
		"https without host":        {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https:/cb"]}]}]`, "no host"},
		"bad logout url":            {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, allowed_logout_urls: ["https://a.test/%zz"]}]}]`, "not a valid URL"},
		"bad locale":                {`tenants: [{name: a, enabled_locales: ["not a tag"]}]`, "not a valid language tag"},
		"text for disabled":         {`tenants: [{name: a, custom_text: {login: {fr: {login: {title: x}}}}}]`, "not an enabled locale"},
		"unknown text key":          {`tenants: [{name: a, custom_text: {zeroauthy: {en: {error: {nope: x}}}}}]`, "unknown key"},
		"empty text":                {`tenants: [{name: a, custom_text: {login: {en: {login: {buttonText: }}}}}]`, "is empty"},
		"foreign variable":          {`tenants: [{name: a, custom_text: {login: {en: {login: {title: "Hi ${userName}"}}}}}]`, "${userName}"},
		"unknown default dir":       {`tenants: [{name: a, default_directory: Nope}]`, "default_directory"},
		"non-db default dir":        {`tenants: [{name: a, connections: [{name: G, strategy: google-oauth2}], default_directory: G}]`, "default_directory \"G\" must be a database connection"},
		"bad tenant logout url":     {`tenants: [{name: a, allowed_logout_urls: ["bye"]}]`, "absolute"},
		"bad rotation type":         {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {rotation_type: sometimes}}]}]`, "rotation_type"},
		"bad expiration type":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {expiration_type: never}}]}]`, "expiration_type"},
		"rotation needs expiry":     {`tenants: [{name: a, clients: [{client_id: c, app_type: regular_web, client_secret: s, refresh_token: {rotation_type: rotating, expiration_type: non-expiring}}]}]`, "requires expiration_type expiring"},
		"spa non-expiring":          {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {rotation_type: non-rotating, expiration_type: non-expiring}}]}]`, "single-page"},
		"negative leeway":           {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {leeway: -1}}]}]`, "must not be negative"},
		"idle exceeds absolute":     {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {token_lifetime: 60, idle_token_lifetime: 120}}]}]`, "must not exceed"},
		"first-party with mode":     {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, third_party_security_mode: strict}]}]`, `third_party_security_mode is only for third-party`},
		"bad mode":                  {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, third_party_security_mode: loose}]}]`, `third_party_security_mode "loose"`},
		"bad redirection policy":    {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, redirection_policy: sometimes}]}]`, `redirection_policy "sometimes"`},
		"third-party password":      {`tenants: [{name: a, clients: [{client_id: c, app_type: regular_web, client_secret: s, is_first_party: false, third_party_security_mode: permissive, grant_types: [password]}]}]`, `grant type "password" is not available to third-party applications`},
		"strict implicit-free list": {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, grant_types: [authorization_code, "urn:ietf:params:oauth:grant-type:device_code"]}]}]`, `not available to strict third-party applications`},
		"strict non-expiring":       {`tenants: [{name: a, clients: [{client_id: c, app_type: regular_web, client_secret: s, is_first_party: false, grant_types: [authorization_code, refresh_token], refresh_token: {rotation_type: non-rotating, expiration_type: non-expiring}}]}]`, `strict third-party applications require expiring refresh tokens`},
		"strict public m2m":         {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, grant_types: [client_credentials]}]}]`, `client_credentials requires a confidential client`},
		"bad user policy":           {`tenants: [{name: a, resource_servers: [{identifier: "https://x", subject_type_authorization: {user: {policy: maybe}}}]}]`, `subject_type_authorization.user.policy "maybe"`},
		"client allow_all":          {`tenants: [{name: a, resource_servers: [{identifier: "https://x", subject_type_authorization: {client: {policy: allow_all}}}]}]`, `subject_type_authorization.client.policy "allow_all"`},
		"bad subject type":          {`tenants: [{name: a, resource_servers: [{identifier: "https://x"}], clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://x", subject_type: robot}]}]`, `subject_type "robot"`},
		"third-party enabled":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, callbacks: ["https://c.test/cb"]}], connections: [{name: db, enabled_clients: [c]}]}]`, `third-party application "c" cannot be enabled on a connection; use is_domain_connection`},
		"dup grant same subject":    {`tenants: [{name: a, resource_servers: [{identifier: "https://x"}], clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://x", subject_type: user}, {client_id: c, audience: "https://x", subject_type: user}]}]`, `duplicate client grant`},
		"unknown field":             {`tenants: [{name: a, domainz: [x]}]`, "domainz"},
		"no name":                   {`tenants: [{domains: [x]}]`, "name is required"},
		"uppercase name":            {`tenants: [{name: Acme}]`, "valid DNS label"},
		"dotted name":               {`tenants: [{name: a.b}]`, "valid DNS label"},
		"leading hyphen name":       {`tenants: [{name: -a}]`, "valid DNS label"},
		"long name":                 {`tenants: [{name: ` + strings.Repeat("a", 64) + `}]`, "valid DNS label"},
		"empty domain":              {`tenants: [{name: a, domains: [""]}]`, "empty domain"},
		"dup domain across":         {`tenants: [{name: a, domains: [x.test]}, {name: b, domains: ["X.test:443"]}]`, `domain "X.test:443"`},
		"dup domain within":         {`tenants: [{name: a, domains: [x.test, x.test.]}]`, "duplicate domain"},
		"dup tenant":                {`tenants: [{name: a}, {name: a}]`, `duplicate tenant "a"`},
		"bad app type":              {`tenants: [{name: a, clients: [{client_id: c, app_type: robot}]}]`, `app_type "robot"`},
		"secret missing":            {`tenants: [{name: a, clients: [{client_id: c, app_type: non_interactive}]}]`, "client_secret is required"},
		"secret on public":          {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, client_secret: x}]}]`, "must not have a client_secret"},
		"grant unknown client":      {`tenants: [{name: a, resource_servers: [{identifier: "https://x"}], client_grants: [{client_id: nope, audience: "https://x"}]}]`, `unknown client "nope"`},
		"grant unknown api":         {`tenants: [{name: a, clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://nope"}]}]`, `unknown audience "https://nope"`},
		"grant undefined scope":     {`tenants: [{name: a, resource_servers: [{identifier: "https://x", scopes: [{value: r}]}], clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://x", scopes: [w]}]}]`, `scope "w"`},
		"wildcard over TLD":         {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://*.com/cb"]}]}]`, "wildcard"},
		"wildcard bare label":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://*.localhost:3000/cb"]}]}]`, "wildcard"},
		"wildcard empty host":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://*./cb"]}]}]`, "wildcard"},
		"par without tenant":        {`tenants: [{name: a, clients: [{client_id: c, app_type: regular_web, client_secret: s, require_pushed_authorization_requests: true}]}]`, `require_pushed_authorization_requests needs the tenant's pushed_authorization_requests_supported`},
		"par on public client":      {`tenants: [{name: a, pushed_authorization_requests_supported: true, clients: [{client_id: c, app_type: spa, require_pushed_authorization_requests: true}]}]`, `require_pushed_authorization_requests is only for confidential applications`},
		"par on third party":        {`tenants: [{name: a, pushed_authorization_requests_supported: true, clients: [{client_id: c, app_type: regular_web, client_secret: s, is_first_party: false, third_party_security_mode: permissive, require_pushed_authorization_requests: true}]}]`, `third-party applications cannot use pushed authorization requests`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

const sampleWithUsers = `
tenants:
  - name: acme
    domains: [acme.test]
    default_directory: Username-Password-Authentication
    session_lifetime: 3600
    idle_session_lifetime: 600
    branding: {logo_url: "https://cdn.acme.test/logo.png", primary_color: "#1A73E8"}
    clients:
      - {client_id: spa, app_type: spa, id_token_lifetime: 1200, callbacks: ["https://app.acme.test/"]}
    connections:
      - name: Username-Password-Authentication
        enabled_clients: [spa]
        password_policy: {min_length: 10}
    users:
      - connection: Username-Password-Authentication
        email: " Alice@Acme.TEST "
        password: "alice password 1"
        email_verified: true
        name: Alice
`

func TestApplyConnectionsAndUsers(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(sampleWithUsers))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if tn.SessionLifetime != 3600 || tn.IdleSessionLifetime != 600 || tn.Branding.PrimaryColor != "#1a73e8" || tn.Branding.LogoURL != "https://cdn.acme.test/logo.png" || tn.DefaultDirectory != "Username-Password-Authentication" {
		t.Errorf("tenant settings = %+v", tn)
	}
	c, _ := st.Clients().Get(ctx, tn.ID, "spa")
	if c.IDTokenLifetime != 1200 {
		t.Errorf("id_token_lifetime = %d", c.IDTokenLifetime)
	}
	conn, err := st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	if err != nil || conn.Strategy != store.StrategyDatabase || conn.PasswordPolicy.MinLength != 10 || len(conn.EnabledClients) != 1 {
		t.Fatalf("connection = %+v, %v", conn, err)
	}
	u, err := st.Users().FindByLogin(ctx, tn.ID, conn.Name, "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if !u.EmailVerified || u.Name != "Alice" || u.Nickname != "alice" || !strings.HasPrefix(u.UserID, "auth0|") {
		t.Errorf("user = %+v", u)
	}
	if ok, _ := secrets.Verify(u.Identities[0].PasswordHash, "alice password 1"); !ok {
		t.Error("seeded password does not verify")
	}

	// Idempotent: same user ID and hash on re-apply; a changed password is re-hashed.
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	u2, _ := st.Users().FindByLogin(ctx, tn.ID, conn.Name, "alice@acme.test")
	if u2.UserID != u.UserID || u2.Identities[0].PasswordHash != u.Identities[0].PasswordHash {
		t.Fatal("re-apply changed the user")
	}
	f2, _ := Parse([]byte(strings.Replace(sampleWithUsers, "alice password 1", "alice password 2", 1)))
	if err := Apply(ctx, st, f2, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	u3, _ := st.Users().FindByLogin(ctx, tn.ID, conn.Name, "alice@acme.test")
	if ok, _ := secrets.Verify(u3.Identities[0].PasswordHash, "alice password 2"); !ok || u3.UserID != u.UserID {
		t.Fatal("changed password not applied in place")
	}
}

func TestValidateConnectionsAndUsers(t *testing.T) {
	base := `tenants: [{name: a, clients: [{client_id: spa, app_type: spa}], connections: [%s], users: [%s]}]`
	conn := `{name: DB, enabled_clients: [spa]}`
	cases := map[string]struct{ conns, users, want string }{
		"unknown strategy":   {`{name: DB, strategy: google-oauth2}`, ``, `strategy "google-oauth2"`},
		"unknown client":     {`{name: DB, enabled_clients: [nope]}`, ``, `unknown client "nope"`},
		"dup connection":     {conn + `, ` + conn, ``, `duplicate connection "DB"`},
		"bad policy":         {`{name: DB, password_policy: {require_character_classes: 5}}`, ``, "require_character_classes"},
		"user unknown conn":  {conn, `{connection: Nope, email: a@b.test, password: "long enough 1"}`, `unknown connection "Nope"`},
		"user bad email":     {conn, `{connection: DB, email: nope, password: "long enough 1"}`, "valid email"},
		"user long email":    {conn, `{connection: DB, email: ` + strings.Repeat("e", 250) + `@b.test, password: "long enough 1"}`, "valid email"},
		"user weak password": {conn, `{connection: DB, email: a@b.test, password: short}`, "at least 8"},
		"user dup email":     {conn, `{connection: DB, email: a@b.test, password: "long enough 1"}, {connection: DB, email: A@B.test, password: "long enough 2"}`, `duplicate user "a@b.test"`},
		"username required":  {`{name: DB, requires_username: true}`, `{connection: DB, email: a@b.test, password: "long enough 1"}`, "username is required"},
		"username with at":   {conn, `{connection: DB, email: a@b.test, username: "a@b.test", password: "long enough 1"}`, "username"},
		"dup username":       {conn, `{connection: DB, email: a@b.test, username: alice, password: "long enough 1"}, {connection: DB, email: c@b.test, username: ALICE, password: "long enough 2"}`, `duplicate username "alice" on connection "DB"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(fmt.Sprintf(base, tc.conns, tc.users)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	for name, branding := range map[string]string{
		"http logo": `{logo_url: "http://x.test/l.png"}`,
		"bad color": `{primary_color: "blue"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(`tenants: [{name: a, branding: ` + branding + `}]`))
			if err == nil || !strings.Contains(err.Error(), "branding") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestWildcardCallbackAccepted(t *testing.T) {
	_, err := Parse([]byte(`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://*.preview.acme.test/cb", "https://*.acme.test:8443/cb?x=1", "com.example.app:/cb"]}]}]`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyRefreshTokenPolicyAndLogoutURLs(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(`
tenants:
  - name: acme
    allowed_logout_urls: ["https://acme.test/bye"]
    clients:
      - {client_id: spa, app_type: spa, callbacks: ["com.example.app:/cb"]}
      - {client_id: web, app_type: regular_web, client_secret: s}
      - client_id: tuned
        app_type: regular_web
        client_secret: s
        allowed_logout_urls: ["https://web.acme.test/bye"]
        refresh_token: {rotation_type: rotating, leeway: 10, token_lifetime: 86400, idle_token_lifetime: 3600}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if len(tn.AllowedLogoutURLs) != 1 || tn.AllowedLogoutURLs[0] != "https://acme.test/bye" {
		t.Errorf("tenant allowed_logout_urls = %v", tn.AllowedLogoutURLs)
	}
	want := map[string]store.RefreshTokenPolicy{
		"spa":   {Rotating: true, Expiring: true},
		"web":   {Rotating: false, Expiring: false},
		"tuned": {Rotating: true, Expiring: true, Leeway: 10, TokenLifetime: 86400, IdleTokenLifetime: 3600},
	}
	for id, w := range want {
		c, err := st.Clients().Get(ctx, tn.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		if c.RefreshToken != w {
			t.Errorf("%s refresh_token = %+v, want %+v", id, c.RefreshToken, w)
		}
	}
}

func TestStrictThirdPartyDefaultsToExpiringRefreshTokens(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(`
tenants:
  - name: acme
    clients:
      - {client_id: partner, app_type: regular_web, client_secret: s, is_first_party: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	c, err := st.Clients().Get(ctx, tn.ID, "partner")
	if err != nil {
		t.Fatal(err)
	}
	if !c.RefreshToken.Expiring {
		t.Errorf("refresh_token = %+v, want expiring", c.RefreshToken)
	}
}

func TestApplyLocalesAndCustomText(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(`
tenants:
  - name: acme
    enabled_locales: [en, fr]
    custom_text:
      login:
        fr:
          login:
            title: "Connexion à ${companyName}"
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if len(tn.EnabledLocales) != 2 || tn.EnabledLocales[1] != "fr" ||
		tn.CustomText["login"]["fr"]["login"]["title"] != "Connexion à ${companyName}" {
		t.Fatalf("tenant = %+v", tn)
	}
}

// failingStore makes Clients().Create fail for client ID "boom".
type failingStore struct{ store.Store }

func (f failingStore) Clients() store.Clients { return failingClients{f.Store.Clients()} }

// WithTx must wrap the transaction store too: Apply uses the tx handed to it,
// so without this the injected failure would never fire inside the transaction.
func (f failingStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return f.Store.WithTx(ctx, func(tx store.Store) error { return fn(failingStore{tx}) })
}

type failingClients struct{ store.Clients }

func (c failingClients) Create(ctx context.Context, cl *store.Client) error {
	if cl.ClientID == "boom" {
		return fmt.Errorf("injected failure")
	}
	return c.Clients.Create(ctx, cl)
}

func TestApplyIsTransactional(t *testing.T) {
	const doc = `
tenants:
  - name: acme
    clients:
      - {client_id: ok, name: Ok, app_type: spa, callbacks: ["https://app.acme.test/cb"]}
  - name: globex
    clients:
      - {client_id: boom, name: Boom, app_type: spa, callbacks: ["https://app.globex.test/cb"]}
`
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, failingStore{st}, f, fixedNow, nil); err == nil {
		t.Fatal("Apply succeeded despite injected failure")
	}
	if _, err := st.Tenants().GetByName(ctx, "acme"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant acme survived the failed Apply: %v", err)
	}
}

// conflictStore makes Tenants().Create fail with store.ErrConflict for the
// first `conflicts` calls, as when another replica inserted the tenant first.
type conflictStore struct {
	store.Store
	calls, conflicts *int
}

func (c conflictStore) Tenants() store.Tenants {
	return conflictTenants{c.Store.Tenants(), c.calls, c.conflicts}
}

func (c conflictStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return c.Store.WithTx(ctx, func(tx store.Store) error { return fn(conflictStore{tx, c.calls, c.conflicts}) })
}

type conflictTenants struct {
	store.Tenants
	calls, conflicts *int
}

func (t conflictTenants) Create(ctx context.Context, tn *store.Tenant) error {
	*t.calls++
	if *t.calls <= *t.conflicts {
		return store.ErrConflict
	}
	return t.Tenants.Create(ctx, tn)
}

func TestApplyRetriesOnceOnConflict(t *testing.T) {
	ctx := context.Background()
	f, err := Parse([]byte("tenants:\n  - name: acme\n"))
	if err != nil {
		t.Fatal(err)
	}

	st := memory.New()
	calls, conflicts := 0, 1
	if err := Apply(ctx, conflictStore{st, &calls, &conflicts}, f, fixedNow, nil); err != nil {
		t.Fatalf("Apply after one conflict: %v", err)
	}
	if calls != 2 {
		t.Errorf("Tenants().Create calls = %d, want 2", calls)
	}
	if _, err := st.Tenants().GetByName(ctx, "acme"); err != nil {
		t.Fatalf("tenant not created on retry: %v", err)
	}

	st = memory.New()
	calls, conflicts = 0, 5
	if err := Apply(ctx, conflictStore{st, &calls, &conflicts}, f, fixedNow, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("persistent conflict: err = %v, want ErrConflict", err)
	}
	if calls != 2 {
		t.Errorf("persistent conflict: Create calls = %d, want 2 (one retry)", calls)
	}
}

const legacyDoc = `
tenants:
  - name: acme
    clients:
      - {client_id: app, name: App, app_type: spa, callbacks: ["https://app.acme.test/cb"]}
    connections:
      - name: legacy
        enabled_clients: [app]
        enabledDatabaseCustomization: true
        import_mode: true
        set_user_root_attributes: on_first_login
        customScripts:
          login: |
            function login(email, password, callback) { callback(null, null); }
          get_user: |
            function getUser(email, callback) { callback(null, null); }
        configuration:
          API_URL: https://legacy.example
          API_TOKEN: s3cret
`

func testWrapper(t *testing.T) keys.Wrapper {
	t.Helper()
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestApplyCustomDatabase(t *testing.T) {
	ctx := context.Background()
	st, w := memory.New(), testWrapper(t)
	f, err := Parse([]byte(legacyDoc))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	c, err := st.Connections().GetByName(ctx, tn.ID, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if !c.EnabledDatabaseCustomization || !c.ImportMode || c.SetUserRootAttributes != store.RootAttributesOnFirstLogin {
		t.Errorf("flags not stored: %+v", c)
	}
	if len(c.CustomScripts) != 2 || !strings.Contains(c.CustomScripts["login"], "function login") {
		t.Errorf("scripts = %v", c.CustomScripts)
	}
	if c.ConfigurationSealed == nil {
		t.Fatal("configuration not sealed")
	}
	got, err := keys.OpenConnectionConfig(w, tn.ID, c.ID, c.ConfigurationSealed)
	if err != nil || got["API_TOKEN"] != "s3cret" || got["API_URL"] != "https://legacy.example" {
		t.Fatalf("opened = %v, %v", got, err)
	}

	// (b) re-apply with a changed token keeps the ID and re-seals.
	f2, err := Parse([]byte(strings.Replace(legacyDoc, "s3cret", "rotated", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f2, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	c2, _ := st.Connections().GetByName(ctx, tn.ID, "legacy")
	if c2.ID != c.ID {
		t.Fatalf("connection ID changed: %s -> %s", c.ID, c2.ID)
	}
	got, err = keys.OpenConnectionConfig(w, tn.ID, c2.ID, c2.ConfigurationSealed)
	if err != nil || got["API_TOKEN"] != "rotated" {
		t.Fatalf("after re-apply: %v, %v", got, err)
	}
}

func TestApplyPlainConnectionHasNoSealedConfig(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte("tenants:\n  - name: acme\n    connections:\n      - name: db\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	c, _ := st.Connections().GetByName(ctx, tn.ID, "db")
	if c.ConfigurationSealed != nil || c.EnabledDatabaseCustomization {
		t.Errorf("plain connection has custom db state: %+v", c)
	}
}

func TestCustomDatabaseValidation(t *testing.T) {
	conn := func(body string) string {
		return "tenants:\n  - name: acme\n    connections:\n      - name: legacy\n" + body
	}
	login := "        customScripts: {login: \"function login(e,p,cb){cb(null,null)}\"}\n"
	long := strings.Repeat("a", 102401)
	manyKeys := ""
	for i := 0; i < 65; i++ {
		manyKeys += fmt.Sprintf("          K%d: v\n", i)
	}
	cases := []struct{ name, doc, want string }{
		{"unknown script", conn("        enabledDatabaseCustomization: true\n        customScripts: {login: x, bogus: y}\n"), `unknown customScripts key "bogus"`},
		{"script too large", conn("        enabledDatabaseCustomization: true\n        customScripts: {login: " + long + "}\n"), "larger than 102400 bytes"},
		{"scripts without flag", conn(login), "require enabledDatabaseCustomization"},
		{"configuration without flag", conn("        configuration: {A: b}\n"), "require enabledDatabaseCustomization"},
		{"flag without login", conn("        enabledDatabaseCustomization: true\n        customScripts: {get_user: x}\n"), "requires a login script"},
		{"bad root attributes", conn("        set_user_root_attributes: sometimes\n"), "set_user_root_attributes"},
		{"bad config key", conn("        enabledDatabaseCustomization: true\n" + login + "        configuration: {\"bad-key\": v}\n"), `configuration key "bad-key"`},
		{"config value too large", conn("        enabledDatabaseCustomization: true\n" + login + "        configuration: {A: " + strings.Repeat("v", 4097) + "}\n"), "larger than 4096 bytes"},
		{"too many keys", conn("        enabledDatabaseCustomization: true\n" + login + "        configuration:\n" + manyKeys), "at most 64"},
		{"legacy users", conn("        enabledDatabaseCustomization: true\n"+login) +
			"    users:\n      - {connection: legacy, email: a@b.test, password: Passw0rd!x}\n", "is a legacy custom database; users live in the legacy store"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}

	// import mode allows seeded users.
	ok := conn("        enabledDatabaseCustomization: true\n        import_mode: true\n"+login) +
		"    users:\n      - {connection: legacy, email: a@b.test, password: Passw0rd!x}\n"
	if _, err := Parse([]byte(ok)); err != nil {
		t.Errorf("import-mode users rejected: %v", err)
	}
}

func TestApplyConsentFields(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(`
tenants:
  - name: a
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    use_scope_descriptions_for_consent: true
    resource_servers:
      - identifier: https://x
        skip_consent_for_verifiable_first_party_clients: false
        subject_type_authorization: {user: {policy: require_client_grant}}
        scopes: [{value: read}]
    clients:
      - {client_id: first, app_type: spa, callbacks: ["https://f.test/cb"]}
      - {client_id: third, app_type: spa, is_first_party: false, callbacks: ["https://t.test/cb"], skip_non_verifiable_callback_uri_confirmation_prompt: false}
      - {client_id: m2m, app_type: non_interactive, client_secret: s}
    client_grants:
      - {client_id: third, audience: https://x, subject_type: user, scopes: [read]}
      - {client_id: m2m, audience: https://x, scopes: [read]}
    connections:
      - {name: db, is_domain_connection: true, enabled_clients: [first]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, nil, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "a")
	if !tn.SkipNonVerifiableCallbackURIConfirmationPrompt || !tn.UseScopeDescriptionsForConsent {
		t.Errorf("tenant flags: %+v", tn)
	}
	first, _ := st.Clients().Get(ctx, tn.ID, "first")
	if !first.IsFirstParty || first.ThirdPartySecurityMode != "" || first.RedirectionPolicy != store.RedirectionPolicyAllowAlways || first.SkipNonVerifiableCallbackURIConfirmationPrompt != nil {
		t.Errorf("first: %+v", first)
	}
	third, _ := st.Clients().Get(ctx, tn.ID, "third")
	if third.IsFirstParty || third.ThirdPartySecurityMode != store.SecurityModeStrict ||
		third.RedirectionPolicy != store.RedirectionPolicyOpenRedirectProtection ||
		third.SkipNonVerifiableCallbackURIConfirmationPrompt == nil || *third.SkipNonVerifiableCallbackURIConfirmationPrompt {
		t.Errorf("third: %+v", third)
	}
	rs, _ := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://x")
	if rs.SkipConsentForVerifiableFirstPartyClients || rs.SubjectTypeAuthorization != (store.SubjectTypeAuthorization{User: store.PolicyRequireClientGrant, Client: store.PolicyRequireClientGrant}) {
		t.Errorf("rs: %+v", rs)
	}
	if _, err := st.ClientGrants().Find(ctx, tn.ID, "third", "https://x", store.SubjectTypeUser); err != nil {
		t.Errorf("user grant: %v", err)
	}
	if _, err := st.ClientGrants().Find(ctx, tn.ID, "m2m", "https://x", store.SubjectTypeClient); err != nil {
		t.Errorf("client grant (default subject type): %v", err)
	}
	conn, _ := st.Connections().GetByName(ctx, tn.ID, "db")
	if !conn.IsDomainConnection {
		t.Errorf("connection: %+v", conn)
	}
}

func TestApplyRefusesPartyChange(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	first, _ := Parse([]byte(`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://c.test/cb"]}]}]`))
	if err := Apply(ctx, st, first, nil, nil); err != nil {
		t.Fatal(err)
	}
	third, _ := Parse([]byte(`tenants: [{name: a, clients: [{client_id: c, app_type: spa, is_first_party: false, callbacks: ["https://c.test/cb"]}]}]`))
	err := Apply(ctx, st, third, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot change after creation") {
		t.Fatalf("err = %v", err)
	}
}

func TestOmittedSkipConsentAppliesAsFalse(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(`tenants: [{name: a, resource_servers: [{identifier: "https://x"}, {identifier: "https://y", skip_consent_for_verifiable_first_party_clients: true}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, nil, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "a")
	x, _ := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://x")
	y, _ := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://y")
	if x.SkipConsentForVerifiableFirstPartyClients || !y.SkipConsentForVerifiableFirstPartyClients {
		t.Errorf("x=%v y=%v", x.SkipConsentForVerifiableFirstPartyClients, y.SkipConsentForVerifiableFirstPartyClients)
	}
	if x.SubjectTypeAuthorization != (store.SubjectTypeAuthorization{User: store.PolicyAllowAll, Client: store.PolicyRequireClientGrant}) {
		t.Errorf("default policies: %+v", x.SubjectTypeAuthorization)
	}
}

func TestApplyPARFields(t *testing.T) {
	const doc = `
tenants:
  - name: acme
    pushed_authorization_requests_supported: true
    clients:
      - {client_id: web, app_type: regular_web, client_secret: s, require_pushed_authorization_requests: true}
      - {client_id: other, app_type: regular_web, client_secret: s}
`
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil || !tn.PushedAuthorizationRequestsSupported {
		t.Fatalf("tenant = %+v, %v", tn, err)
	}
	for id, want := range map[string]bool{"web": true, "other": false} {
		c, err := st.Clients().Get(ctx, tn.ID, id)
		if err != nil || c.RequirePushedAuthorizationRequests != want {
			t.Fatalf("%s: RequirePushedAuthorizationRequests = %v, %v; want %v", id, c.RequirePushedAuthorizationRequests, err, want)
		}
	}

	// Applying again with the settings removed turns them off.
	f, err = Parse([]byte(strings.ReplaceAll(strings.ReplaceAll(doc, "pushed_authorization_requests_supported: true", ""), ", require_pushed_authorization_requests: true", "")))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ = st.Tenants().GetByName(ctx, "acme")
	c, _ := st.Clients().Get(ctx, tn.ID, "web")
	if tn.PushedAuthorizationRequestsSupported || c.RequirePushedAuthorizationRequests {
		t.Fatalf("settings not cleared: tenant %v client %v", tn.PushedAuthorizationRequestsSupported, c.RequirePushedAuthorizationRequests)
	}
}
