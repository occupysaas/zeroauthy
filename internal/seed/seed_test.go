package seed

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

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
	if err := Apply(ctx, st, f, fixedNow); err != nil {
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

	g, err := st.ClientGrants().Find(ctx, tn.ID, "m2m", "https://api.acme.test")
	if err != nil || strings.Join(g.Scopes, " ") != "read:things" {
		t.Fatalf("grant = %+v, %v", g, err)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, _ := Parse([]byte(sample))
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn1, _ := st.Tenants().GetByName(ctx, "acme")
	c1, _ := st.Clients().Get(ctx, tn1.ID, "m2m")
	rs1, _ := st.ResourceServers().GetByIdentifier(ctx, tn1.ID, "https://api.acme.test")

	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn2, _ := st.Tenants().GetByName(ctx, "acme")
	c2, _ := st.Clients().Get(ctx, tn2.ID, "m2m")
	rs2, _ := st.ResourceServers().GetByIdentifier(ctx, tn2.ID, "https://api.acme.test")
	if tn1.ID != tn2.ID || rs1.ID != rs2.ID || c1.Secrets[0].Hash != c2.Secrets[0].Hash {
		t.Fatal("second Apply changed IDs or re-hashed an unchanged secret")
	}

	changed, _ := Parse([]byte(strings.Replace(sample, "first-secret", "second-secret", 1)))
	if err := Apply(ctx, st, changed, fixedNow); err != nil {
		t.Fatal(err)
	}
	c3, _ := st.Clients().Get(ctx, tn2.ID, "m2m")
	if ok, _ := secrets.Verify(c3.Secrets[0].Hash, "second-secret"); !ok || len(c3.Secrets) != 1 {
		t.Fatal("changed secret was not applied")
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"bad callback escape":   {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://a.test/cb%zz"]}]}]`, "not a valid URL"},
		"relative callback":     {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["/cb"]}]}]`, "absolute"},
		"callback fragment":     {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://a.test/cb#x"]}]}]`, "fragment"},
		"https without host":    {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https:/cb"]}]}]`, "no host"},
		"bad logout url":        {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, allowed_logout_urls: ["https://a.test/%zz"]}]}]`, "not a valid URL"},
		"bad locale":            {`tenants: [{name: a, enabled_locales: ["not a tag"]}]`, "not a valid language tag"},
		"text for disabled":     {`tenants: [{name: a, custom_text: {login: {fr: {login: {title: x}}}}}]`, "not an enabled locale"},
		"unknown text key":      {`tenants: [{name: a, custom_text: {zeroauthy: {en: {error: {nope: x}}}}}]`, "unknown key"},
		"empty text":            {`tenants: [{name: a, custom_text: {login: {en: {login: {buttonText: }}}}}]`, "is empty"},
		"foreign variable":      {`tenants: [{name: a, custom_text: {login: {en: {login: {title: "Hi ${userName}"}}}}}]`, "${userName}"},
		"bad tenant logout url": {`tenants: [{name: a, allowed_logout_urls: ["bye"]}]`, "absolute"},
		"bad rotation type":     {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {rotation_type: sometimes}}]}]`, "rotation_type"},
		"bad expiration type":   {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {expiration_type: never}}]}]`, "expiration_type"},
		"rotation needs expiry": {`tenants: [{name: a, clients: [{client_id: c, app_type: regular_web, client_secret: s, refresh_token: {rotation_type: rotating, expiration_type: non-expiring}}]}]`, "requires expiration_type expiring"},
		"spa non-expiring":      {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {rotation_type: non-rotating, expiration_type: non-expiring}}]}]`, "single-page"},
		"negative leeway":       {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {leeway: -1}}]}]`, "must not be negative"},
		"idle exceeds absolute": {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, refresh_token: {token_lifetime: 60, idle_token_lifetime: 120}}]}]`, "must not exceed"},
		"unknown field":         {`tenants: [{name: a, domainz: [x]}]`, "domainz"},
		"no name":               {`tenants: [{domains: [x]}]`, "name is required"},
		"uppercase name":        {`tenants: [{name: Acme}]`, "valid DNS label"},
		"dotted name":           {`tenants: [{name: a.b}]`, "valid DNS label"},
		"leading hyphen name":   {`tenants: [{name: -a}]`, "valid DNS label"},
		"long name":             {`tenants: [{name: ` + strings.Repeat("a", 64) + `}]`, "valid DNS label"},
		"empty domain":          {`tenants: [{name: a, domains: [""]}]`, "empty domain"},
		"dup domain across":     {`tenants: [{name: a, domains: [x.test]}, {name: b, domains: ["X.test:443"]}]`, `domain "X.test:443"`},
		"dup domain within":     {`tenants: [{name: a, domains: [x.test, x.test.]}]`, "duplicate domain"},
		"dup tenant":            {`tenants: [{name: a}, {name: a}]`, `duplicate tenant "a"`},
		"bad app type":          {`tenants: [{name: a, clients: [{client_id: c, app_type: robot}]}]`, `app_type "robot"`},
		"secret missing":        {`tenants: [{name: a, clients: [{client_id: c, app_type: non_interactive}]}]`, "client_secret is required"},
		"secret on public":      {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, client_secret: x}]}]`, "must not have a client_secret"},
		"grant unknown client":  {`tenants: [{name: a, resource_servers: [{identifier: "https://x"}], client_grants: [{client_id: nope, audience: "https://x"}]}]`, `unknown client "nope"`},
		"grant unknown api":     {`tenants: [{name: a, clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://nope"}]}]`, `unknown audience "https://nope"`},
		"grant undefined scope": {`tenants: [{name: a, resource_servers: [{identifier: "https://x", scopes: [{value: r}]}], clients: [{client_id: c, app_type: non_interactive, client_secret: s}], client_grants: [{client_id: c, audience: "https://x", scopes: [w]}]}]`, `scope "w"`},
		"wildcard over TLD":     {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://*.com/cb"]}]}]`, "wildcard"},
		"wildcard bare label":   {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://*.localhost:3000/cb"]}]}]`, "wildcard"},
		"wildcard empty host":   {`tenants: [{name: a, clients: [{client_id: c, app_type: spa, callbacks: ["https://*./cb"]}]}]`, "wildcard"},
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
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if tn.SessionLifetime != 3600 || tn.IdleSessionLifetime != 600 || tn.Branding.PrimaryColor != "#1a73e8" || tn.Branding.LogoURL != "https://cdn.acme.test/logo.png" {
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
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	u2, _ := st.Users().FindByLogin(ctx, tn.ID, conn.Name, "alice@acme.test")
	if u2.UserID != u.UserID || u2.Identities[0].PasswordHash != u.Identities[0].PasswordHash {
		t.Fatal("re-apply changed the user")
	}
	f2, _ := Parse([]byte(strings.Replace(sampleWithUsers, "alice password 1", "alice password 2", 1)))
	if err := Apply(ctx, st, f2, fixedNow); err != nil {
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
	if err := Apply(ctx, st, f, fixedNow); err != nil {
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
	if err := Apply(ctx, st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if len(tn.EnabledLocales) != 2 || tn.EnabledLocales[1] != "fr" ||
		tn.CustomText["login"]["fr"]["login"]["title"] != "Connexion à ${companyName}" {
		t.Fatalf("tenant = %+v", tn)
	}
}
