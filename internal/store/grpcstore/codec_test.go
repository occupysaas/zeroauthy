package grpcstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

var nanoTime = time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)

func ptr[T any](v T) *T { return &v }

// roundTrip asserts in survives toPB, a real protobuf marshal/unmarshal
// (presence must survive the wire, not just the in-memory message), and
// fromPB. P is the protobuf message type, T the domain type.
func roundTrip[P any, PP interface {
	*P
	proto.Message
}, T any](t *testing.T, name string, in *T, to func(*T) (PP, error), from func(PP) (*T, error)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		if name == "full" {
			assertNoZeroFields(t, "", reflect.ValueOf(in))
		}
		pb, err := to(in)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(in, mustFrom(t, from, pb)); diff != "" {
			t.Fatalf("in-memory round trip (-in +out):\n%s", diff)
		}
		raw, err := proto.Marshal(pb)
		if err != nil {
			t.Fatal(err)
		}
		wire := PP(new(P))
		if err := proto.Unmarshal(raw, wire); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(in, mustFrom(t, from, wire)); diff != "" {
			t.Fatalf("wire round trip (-in +out):\n%s", diff)
		}
	})
}

// assertNoZeroFields fails for every zero-valued field reachable from v,
// descending into pointers, structs, slice elements and map values. A "full"
// fixture passing it exercises every field, so a field added to the store
// types cannot escape the round-trip tests unnoticed. Elements of one slice
// or map may differ (a fixture lists a bare element beside a full one): a
// field counts as exercised when some element sets it.
func assertNoZeroFields(t *testing.T, path string, v reflect.Value) {
	t.Helper()
	for _, p := range zeroPaths(path, v) {
		t.Errorf("full fixture: %s is zero, nil or empty", p)
	}
}

func zeroPaths(path string, v reflect.Value) []string {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return []string{path}
		}
		return zeroPaths(path, v.Elem())
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			if v.IsZero() {
				return []string{path}
			}
			return nil
		}
		var out []string
		for i := 0; i < v.NumField(); i++ {
			out = append(out, zeroPaths(path+"."+v.Type().Field(i).Name, v.Field(i))...)
		}
		return out
	case reflect.Slice, reflect.Map:
		if v.Len() == 0 {
			return []string{path}
		}
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var elems []reflect.Value
		if v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				elems = append(elems, v.Index(i))
			}
		} else {
			for _, k := range v.MapKeys() {
				elems = append(elems, v.MapIndex(k))
			}
		}
		// Zero paths common to every element are the unexercised fields.
		var common map[string]bool
		for _, e := range elems {
			cur := map[string]bool{}
			for _, p := range zeroPaths(path+"[]", e) {
				if common == nil || common[p] {
					cur[p] = true
				}
			}
			common = cur
		}
		var out []string
		for p := range common {
			out = append(out, p)
		}
		sort.Strings(out)
		return out
	default:
		if v.IsZero() {
			return []string{path}
		}
		return nil
	}
}

func mustFrom[PP any, T any](t *testing.T, from func(PP) (*T, error), pb PP) *T {
	t.Helper()
	out, err := from(pb)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTenantRoundTrip(t *testing.T) {

	roundTrip(t, "full", &store.Tenant{
		SupportEmail: "support@example.com", SupportURL: "https://example.com", PictureURL: "https://example.com/logo",
		SettingsExtra: map[string]any{"flags": map[string]any{"enable_sso": true}}, SettingsPresence: map[string]bool{"device_flow.mask": true},
		ProtectionSettings: fullProtectionSettings(), ProtectionSettingsInitialized: true,
		EphemeralSessionLifetime: 7200, IdleEphemeralSessionLifetime: 3600, SessionCookieMode: "non-persistent",
		CanonicalHost: "canonical.example", ID: "ten", Name: "acme", FriendlyName: "Acme", Domains: []string{"a.example.test", "b.example.test"},
		DefaultAudience: "https://api", AllowedLogoutURLs: []string{"https://x/out"}, EnabledLocales: []string{"en", "de"},
		CustomText:      store.CustomText{"login": {"en": {"login": {"title": "Hi", "description": "Welcome"}}, "de": {"login": {"title": "Hallo"}}}},
		SessionLifetime: 3600, IdleSessionLifetime: 1800,
		Branding:         store.Branding{LogoURL: "https://l/logo.png", PrimaryColor: "#112233"},
		DefaultDirectory: "Username-Password-Authentication", CreatedAt: nanoTime,
		SkipNonVerifiableCallbackURIConfirmationPrompt: true, UseScopeDescriptionsForConsent: true,
		PushedAuthorizationRequestsSupported: true,
		DeviceFlowCharset:                    "digits", DeviceFlowMask: "###-###",
		Reserved: true, Seeded: true, Origin: store.OriginAPI, IdentityEpoch: 7,
	}, tenantToPB, tenantFromPB)
	roundTrip(t, "empty", &store.Tenant{Domains: []string{}, AllowedLogoutURLs: []string{}, EnabledLocales: []string{}, CustomText: store.CustomText{}, SettingsExtra: map[string]any{}, SettingsPresence: map[string]bool{}, ProtectionSettings: store.ProtectionSettings{CAPTCHA: store.CAPTCHAPolicy{SimpleCaptcha: map[string]any{}}}}, tenantToPB, tenantFromPB)
	roundTrip(t, "zero", &store.Tenant{}, tenantToPB, tenantFromPB)
}

func TestClientRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.Client{
		TenantID: "ten", ClientID: "cid", Name: "App", AppType: store.AppTypeRegularWeb,
		Secrets: []store.ClientSecret{
			{Hash: "h1", CreatedAt: nanoTime},
			{Hash: "h2", CreatedAt: nanoTime, ExpiresAt: ptr(nanoTime.Add(time.Hour))},
			{Sealed: []byte{0x00, 0xff, 0x80}, CreatedAt: nanoTime},
		},
		TokenEndpointAuthMethod: store.AuthMethodClientSecretPost,
		GrantTypes:              []string{"authorization_code"}, Callbacks: []string{"https://cb"},
		AllowedLogoutURLs: []string{"https://out"}, WebOrigins: []string{"https://web"}, AllowedOrigins: []string{"https://ao"},
		IDTokenLifetime: 36000,
		RefreshToken:    store.RefreshTokenPolicy{Rotating: true, Leeway: 5, Expiring: true, TokenLifetime: 100, IdleTokenLifetime: 50},
		CreatedAt:       nanoTime,
		IsFirstParty:    true, ThirdPartySecurityMode: store.SecurityModeStrict,
		RedirectionPolicy: store.RedirectionPolicyAllowAlways,
		SkipNonVerifiableCallbackURIConfirmationPrompt: ptr(true),
		RequirePushedAuthorizationRequests:             true,
		Origin:                                         store.OriginAPI,
	}, clientToPB, clientFromPB)
	roundTrip(t, "third party", &store.Client{
		TenantID: "ten", ClientID: "tp", ThirdPartySecurityMode: store.SecurityModePermissive,
		SkipNonVerifiableCallbackURIConfirmationPrompt: ptr(false),
	}, clientToPB, clientFromPB)
	roundTrip(t, "empty", &store.Client{
		Secrets: []store.ClientSecret{}, GrantTypes: []string{}, Callbacks: []string{},
		AllowedLogoutURLs: []string{}, WebOrigins: []string{}, AllowedOrigins: []string{},
	}, clientToPB, clientFromPB)
	roundTrip(t, "zero", &store.Client{}, clientToPB, clientFromPB)
}

func TestResourceServerRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.ResourceServer{
		TenantID: "ten", ID: "rs", Identifier: "https://api", Name: "API",
		EnforcePolicies: true, TokenDialect: "rfc9068_profile_authz",
		Scopes:     []store.Scope{{Value: "read", Description: "Read"}, {Value: "write"}},
		SigningAlg: "RS256", TokenLifetime: 7200, TokenLifetimeForWeb: 3600, AllowOfflineAccess: true, CreatedAt: nanoTime,
		SkipConsentForVerifiableFirstPartyClients: true,
		SubjectTypeAuthorization:                  store.SubjectTypeAuthorization{User: store.PolicyAllowAll, Client: store.PolicyRequireClientGrant},
		IsSystem:                                  true,
		Origin:                                    store.OriginAPI,
	}, resourceServerToPB, resourceServerFromPB)
	roundTrip(t, "skip off", &store.ResourceServer{
		SubjectTypeAuthorization: store.SubjectTypeAuthorization{User: store.PolicyDenyAll},
	}, resourceServerToPB, resourceServerFromPB)
	roundTrip(t, "empty", &store.ResourceServer{Scopes: []store.Scope{}}, resourceServerToPB, resourceServerFromPB)
	roundTrip(t, "zero", &store.ResourceServer{}, resourceServerToPB, resourceServerFromPB)
}

func TestClientGrantRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.ClientGrant{
		TenantID: "ten", ID: "g", ClientID: "cid", Audience: "https://api", Scopes: []string{"a", "b"}, CreatedAt: nanoTime,
		SubjectType: store.SubjectTypeUser, Origin: store.OriginAPI, AllowAllScopes: true,
	}, clientGrantToPB, clientGrantFromPB)
	roundTrip(t, "empty", &store.ClientGrant{Scopes: []string{}, SubjectType: store.SubjectTypeClient}, clientGrantToPB, clientGrantFromPB)
	roundTrip(t, "zero", &store.ClientGrant{SubjectType: store.SubjectTypeClient}, clientGrantToPB, clientGrantFromPB)
}

func TestUserGrantRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.UserGrant{
		TenantID: "ten", ID: "ug", ClientID: "cid", UserID: "u1", Audience: "https://api",
		Scopes: []string{"a", "b"}, CreatedAt: nanoTime, UpdatedAt: nanoTime.Add(time.Hour),
	}, userGrantToPB, userGrantFromPB)
	roundTrip(t, "empty", &store.UserGrant{Scopes: []string{}}, userGrantToPB, userGrantFromPB)
	roundTrip(t, "zero", &store.UserGrant{}, userGrantToPB, userGrantFromPB)
	if pb, err := userGrantToPB(nil); pb != nil || err != nil {
		t.Fatalf("userGrantToPB(nil) = %v, %v", pb, err)
	}
	if g, err := userGrantFromPB(nil); g != nil || err != nil {
		t.Fatalf("userGrantFromPB(nil) = %v, %v", g, err)
	}
}

// A plugin built before the consent fields leaves them absent. Absence must
// keep today's behaviour: a first-party client, an API that skips consent
// for it, and a client-credentials grant.
func TestCodecDefaultsForOldPlugins(t *testing.T) {
	c, err := clientFromPB(&storev1.Client{TenantId: "t", ClientId: "c", CreatedAt: tsToPB(time.Unix(0, 0))})
	if err != nil || !c.IsFirstParty || c.SkipNonVerifiableCallbackURIConfirmationPrompt != nil {
		t.Fatalf("client: %+v %v", c, err)
	}
	rs, err := resourceServerFromPB(&storev1.ResourceServer{TenantId: "t", Id: "r", CreatedAt: tsToPB(time.Unix(0, 0))})
	if err != nil || !rs.SkipConsentForVerifiableFirstPartyClients {
		t.Fatalf("resource server: %+v %v", rs, err)
	}
	g, err := clientGrantFromPB(&storev1.ClientGrant{TenantId: "t", Id: "g", CreatedAt: tsToPB(time.Unix(0, 0))})
	if err != nil || g.SubjectType != store.SubjectTypeClient {
		t.Fatalf("grant: %+v %v", g, err)
	}
}

func TestSigningKeyRoundTrip(t *testing.T) {
	since, until, revoked := nanoTime.Add(time.Minute), nanoTime.Add(time.Hour), nanoTime.Add(2*time.Hour)
	roundTrip(t, "full", &store.SigningKey{
		TenantID: "ten", KID: "k1", Alg: "RS256", Status: store.KeyCurrent,
		PrivateKey: []byte{0, 1, 2, 255}, PublicJWK: []byte(`{"kty":"RSA"}`), CreatedAt: nanoTime,
		CertificateDER: []byte{4, 5, 6}, CurrentSince: &since, CurrentUntil: &until, RevokedAt: &revoked,
	}, signingKeyToPB, signingKeyFromPB)
	roundTrip(t, "empty", &store.SigningKey{PrivateKey: []byte{}, PublicJWK: []byte{}}, signingKeyToPB, signingKeyFromPB)
	roundTrip(t, "zero", &store.SigningKey{}, signingKeyToPB, signingKeyFromPB)
}

func TestConnectionRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.Connection{
		TenantID: "ten", ID: "c1", Name: "Username-Password-Authentication", Strategy: store.StrategyDatabase,
		EnabledClients: []string{"cid1", "cid2"}, DisableSignup: true, RequiresUsername: true,
		PasswordOptions: store.PasswordOptions{
			Complexity: store.PasswordComplexity{
				MinLength: 12, CharacterTypes: []string{"uppercase", "number"}, CharacterTypeRule: store.CharacterTypeRuleAll,
				IdenticalCharacters: store.PasswordBlock, SequentialCharacters: store.PasswordAllow,
				MaxLengthExceeded: store.MaxLengthTruncate, MinCharacterClasses: 2,
			},
			History:     store.PasswordHistory{Active: true, Size: 4},
			Dictionary:  store.PasswordDictionary{Active: true, Default: store.DictionaryEn10k, Custom: []string{"acme"}},
			ProfileData: store.PasswordProfileData{Active: true, BlockedFields: []string{"name"}},
		},
		BruteForceProtection: true, UsernameMin: 3, UsernameMax: 40, Origin: store.OriginAPI,
		FederationRevision: 4, FederationSecretsSealed: []byte("sealed-credentials"),
		Extra:                        map[string]any{"a": map[string]any{"b": []any{"c", float64(1)}}},
		CreatedAt:                    nanoTime,
		EnabledDatabaseCustomization: true, ImportMode: true,
		CustomScripts:         map[string]string{store.ScriptLogin: "function login() {}", store.ScriptCreate: ""},
		ConfigurationSealed:   []byte{0x01, 0x00, 0xff},
		SetUserRootAttributes: store.RootAttributesOnFirstLogin,
		IsDomainConnection:    true,
	}, connectionToPB, connectionFromPB)
	// An empty (non-nil) script map stays distinct from nil.
	roundTrip(t, "empty scripts", &store.Connection{CustomScripts: map[string]string{}}, connectionToPB, connectionFromPB)
	roundTrip(t, "empty", &store.Connection{EnabledClients: []string{}}, connectionToPB, connectionFromPB)
	// Empty lists and an empty Extra stay distinct from nil.
	roundTrip(t, "empty options", &store.Connection{
		PasswordOptions: store.PasswordOptions{
			Complexity:  store.PasswordComplexity{CharacterTypes: []string{}},
			Dictionary:  store.PasswordDictionary{Custom: []string{}},
			ProfileData: store.PasswordProfileData{BlockedFields: []string{}},
		},
		Extra: map[string]any{},
	}, connectionToPB, connectionFromPB)
	roundTrip(t, "zero", &store.Connection{}, connectionToPB, connectionFromPB)
}

// Empty sealed bytes are not distinguishable from nil: they normalize to nil
// on the wire, as they do in the SQL drivers (stored as NULL).
func TestConnectionEmptySealedNormalizesToNil(t *testing.T) {
	pb, err := connectionToPB(&store.Connection{ConfigurationSealed: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if pb.ConfigurationSealed != nil {
		t.Fatalf("sealed = %v, want absent", pb.ConfigurationSealed)
	}
	got, err := connectionFromPB(&storev1.Connection{ConfigurationSealed: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigurationSealed != nil {
		t.Fatalf("sealed = %v, want nil", got.ConfigurationSealed)
	}
}

func TestUserRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.User{
		TenantID: "ten", UserID: "auth0|u1", Email: "a@example.test", EmailVerified: true,
		Username: "alice", Name: "Alice", Nickname: "al", Picture: "https://p.example/a.png",
		GivenName: "A", FamilyName: "L",
		// JSON numbers decode as float64, as in the SQL drivers (D-0020).
		UserMetadata: map[string]any{"plan": "pro", "seats": float64(3), "tags": []any{"x", "y"}, "nested": map[string]any{"k": true}, "none": nil},
		AppMetadata:  map[string]any{"plan": "gold", "n": float64(3), "roles": []any{"a"}},
		Blocked:      true,
		Identities: []store.Identity{{Connection: "db", Provider: "auth0", UserID: "u1", PasswordHash: "$argon2id$..."},
			{Connection: "db", Provider: "auth0", UserID: "u2", PasswordHash: "$argon2id$2", ProfileData: map[string]any{"email": "b@example.test", "email_verified": false}},
			{Connection: "other", Provider: "auth0", UserID: "u3", ImportedHash: `{"alg":"bcrypt","hash":"$2b$10$x"}`, ProfileData: map[string]any{}}},
		LastPasswordReset: ptr(nanoTime.Add(-time.Hour)), LastLogin: ptr(nanoTime), LoginsCount: 7, CreatedAt: nanoTime,
		PhoneNumber: "+14155550100", PhoneVerified: true, LastIP: "2001:db8::1", Version: 5, UpdatedAt: nanoTime.Add(time.Second),
	}, userToPB, userFromPB)
	roundTrip(t, "empty", &store.User{UserMetadata: map[string]any{}, AppMetadata: map[string]any{}, Identities: []store.Identity{}}, userToPB, userFromPB)
	roundTrip(t, "zero", &store.User{}, userToPB, userFromPB)
}

func TestSessionRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.LoginSession{
		Origin:   "https://login.example",
		TenantID: "ten", ID: "sid", TokenHash: "th", UserID: "auth0|u1", Connection: "db", CookieMode: "non-persistent",
		AuthenticatedAt: nanoTime, ClientIDs: []string{"c1", "c2"},
		ExpiresAt: nanoTime.Add(time.Hour), IdleExpiresAt: nanoTime.Add(time.Minute), CreatedAt: nanoTime,
		UpdatedAt: nanoTime.Add(time.Second), LastInteractedAt: nanoTime.Add(2 * time.Second),
		InitialIP: "203.0.113.7", InitialUserAgent: "ua-1", LastIP: "198.51.100.9", LastUserAgent: "ua-2",
	}, sessionToPB, sessionFromPB)
	roundTrip(t, "empty", &store.LoginSession{ClientIDs: []string{}}, sessionToPB, sessionFromPB)
	roundTrip(t, "zero", &store.LoginSession{}, sessionToPB, sessionFromPB)
}

func TestAuthTransactionRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.AuthTransaction{
		Origin:   "https://login.example",
		TenantID: "ten", ID: "st", CookieHash: "ch", CSRFToken: "csrf", ClientID: "cid",
		Params:      map[string]string{"scope": "openid profile", "state": "xyz", "empty": ""},
		HostedState: store.HostedLoginState{Step: "password", Identifier: "ada@example.test", ConnectionID: "db", PromptFields: map[string]string{"ulp-team": "blue"}, FormFields: map[string]string{"ulp-team": "text"}, Revision: 1, FormConfigRevision: 2, FormScreen: "login-password", FormLanguage: "en"},
		ExpiresAt:   nanoTime.Add(time.Hour), CreatedAt: nanoTime,
	}, authTransactionToPB, authTransactionFromPB)
	roundTrip(t, "empty", &store.AuthTransaction{Params: map[string]string{}}, authTransactionToPB, authTransactionFromPB)
	roundTrip(t, "zero", &store.AuthTransaction{}, authTransactionToPB, authTransactionFromPB)
}

func TestAuthCodeRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.AuthCode{
		Origin:   "https://login.example",
		TenantID: "ten", CodeHash: "ch", ClientID: "cid", RedirectURI: "https://cb", UserID: "auth0|u1",
		SessionID: "sid", Scopes: []string{"openid", "email"}, Audience: "https://api", Nonce: "n",
		CodeChallenge: "cc", CodeChallengeMethod: "S256", AuthTime: nanoTime,
		ExpiresAt: nanoTime.Add(time.Minute), CreatedAt: nanoTime,
		UsedAt: ptr(nanoTime.Add(time.Second)), ReplayedAt: ptr(nanoTime.Add(2 * time.Second)),
		ActionEffects: []byte{0, 0xff, 'x'},
	}, authCodeToPB, authCodeFromPB)
	roundTrip(t, "empty", &store.AuthCode{Scopes: []string{}}, authCodeToPB, authCodeFromPB)
	roundTrip(t, "zero", &store.AuthCode{}, authCodeToPB, authCodeFromPB)
}

func TestRefreshTokenRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.RefreshToken{
		Origin:   "https://login.example",
		TenantID: "ten", ID: "rt", TokenHash: "th", FamilyID: "fam", ClientID: "cid", UserID: "auth0|u1",
		SessionID: "sid", Scopes: []string{"openid", "offline_access"}, Audience: "https://api",
		AuthTime: nanoTime, Rotating: true, ExpiresAt: nanoTime.Add(time.Hour), IdleExpiresAt: nanoTime.Add(time.Minute),
		RotatedAt: ptr(nanoTime.Add(time.Second)), RevokedAt: ptr(nanoTime.Add(2 * time.Second)), CreatedAt: nanoTime,
	}, refreshTokenToPB, refreshTokenFromPB)
	roundTrip(t, "empty", &store.RefreshToken{Scopes: []string{}}, refreshTokenToPB, refreshTokenFromPB)
	roundTrip(t, "zero", &store.RefreshToken{}, refreshTokenToPB, refreshTokenFromPB)
}

func TestPasswordResetTicketRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.PasswordResetTicket{
		Origin:   "https://login.example",
		TenantID: "ten", ID: "tk", TokenHash: "th", UserID: "auth0|u1", Connection: "db", ClientID: "cid",
		Lang: "de", ExpiresAt: nanoTime.Add(time.Hour), UsedAt: ptr(nanoTime.Add(time.Second)), CreatedAt: nanoTime,
		ChallengePassedAt: ptr(nanoTime), ChallengeResultURL: "https://app.test/challenged",
		ResultURL: "https://app.test/done", IncludeEmailInRedirect: true, MarkEmailVerified: true,
	}, passwordResetTicketToPB, passwordResetTicketFromPB)
	roundTrip(t, "zero", &store.PasswordResetTicket{}, passwordResetTicketToPB, passwordResetTicketFromPB)
}

func TestEmailVerificationTicketRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.EmailVerificationTicket{
		Origin:   "https://login.example",
		TenantID: "ten", ID: "tk", TokenHash: "th", UserID: "auth0|u1", Connection: "db", ClientID: "cid",
		Lang: "de", ExpiresAt: nanoTime.Add(time.Hour), UsedAt: ptr(nanoTime.Add(time.Second)), CreatedAt: nanoTime,
		ResultURL: "https://app.test/done", IncludeEmailInRedirect: true, Email: "a@b.test",
	}, emailVerificationTicketToPB, emailVerificationTicketFromPB)
	roundTrip(t, "zero", &store.EmailVerificationTicket{}, emailVerificationTicketToPB, emailVerificationTicketFromPB)
}

func TestOperatorRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.Operator{
		TenantID: "ten", UserID: "auth0|u1", Tenants: []string{"acme", "globex"},
		CreatedAt: nanoTime, UpdatedAt: nanoTime.Add(time.Second),
	}, operatorToPB, operatorFromPB)
	roundTrip(t, "empty", &store.Operator{Tenants: []string{}}, operatorToPB, operatorFromPB)
	roundTrip(t, "zero", &store.Operator{}, operatorToPB, operatorFromPB)
}

func TestNilEntities(t *testing.T) {
	if pb, err := userToPB(nil); pb != nil || err != nil {
		t.Fatalf("userToPB(nil) = %v, %v", pb, err)
	}
	if u, err := userFromPB(nil); u != nil || err != nil {
		t.Fatalf("userFromPB(nil) = %v, %v", u, err)
	}
	if pb, err := tenantToPB(nil); pb != nil || err != nil {
		t.Fatalf("tenantToPB(nil) = %v, %v", pb, err)
	}
	if k, err := signingKeyFromPB(nil); k != nil || err != nil {
		t.Fatalf("signingKeyFromPB(nil) = %v, %v", k, err)
	}
}

func TestInvalidInputs(t *testing.T) {
	bad := &timestamppb.Timestamp{Seconds: 1 << 60}
	if _, err := userFromPB(&storev1.User{LastPasswordReset: bad}); err == nil {
		t.Fatal("invalid password reset timestamp accepted")
	}
	if _, err := passwordResetTicketFromPB(&storev1.PasswordResetTicket{ChallengePassedAt: bad}); err == nil {
		t.Fatal("invalid challenge pass timestamp accepted")
	}
	if _, err := userFromPB(&storev1.User{CreatedAt: bad}); err == nil {
		t.Fatal("invalid timestamp accepted")
	}
	if _, err := clientFromPB(&storev1.Client{Secrets: &storev1.ClientSecretList{
		Values: []*storev1.ClientSecret{{Hash: "h", ExpiresAt: bad}}}}); err == nil {
		t.Fatal("invalid secret timestamp accepted")
	}
	for name, sec := range map[string]*storev1.ClientSecret{
		"neither": {},
		"both":    {Hash: "h", Sealed: []byte{1}},
	} {
		if _, err := clientFromPB(&storev1.Client{Secrets: &storev1.ClientSecretList{
			Values: []*storev1.ClientSecret{sec}}}); err == nil {
			t.Errorf("client secret with %s of hash and sealed accepted", name)
		}
	}
	if _, err := userFromPB(&storev1.User{UserMetadataJson: []byte("{")}); err == nil {
		t.Fatal("bad metadata JSON accepted")
	}
	if _, err := tenantFromPB(&storev1.Tenant{CustomTextJson: []byte("[")}); err == nil {
		t.Fatal("bad custom text JSON accepted")
	}
	if _, err := userToPB(&store.User{UserMetadata: map[string]any{"f": func() {}}}); err == nil {
		t.Fatal("unmarshalable metadata accepted")
	}
}

func TestTimeHelpers(t *testing.T) {
	if !tsFromPB(tsToPB(time.Time{})).IsZero() {
		t.Fatal("zero time did not round-trip")
	}
	if tsFromPB(nil).IsZero() != true {
		t.Fatal("nil timestamp is not zero time")
	}
	if optTSFromPB(nil) != nil || optTSToPB(nil) != nil {
		t.Fatal("nil optional time not preserved")
	}
	loc := time.FixedZone("X", 5*3600)
	in := time.Date(2026, 3, 4, 5, 6, 7, 89, loc)
	out := tsFromPB(tsToPB(in))
	if !out.Equal(in) || out.Location() != time.UTC {
		t.Fatalf("got %v want %v in UTC", out, in)
	}
	if got := optTSFromPB(optTSToPB(&in)); got == nil || !got.Equal(in) || got.Location() != time.UTC {
		t.Fatalf("optional: got %v", got)
	}
}

func TestErrorMapping(t *testing.T) {
	// Every sentinel travels as itself and never matches another.
	sentinels := []error{store.ErrNotFound, store.ErrConflict, store.ErrAlreadyUsed, store.ErrPrecondition, store.ErrOrganizationsUnavailable}
	for _, e := range sentinels {
		for _, in := range []error{e, fmt.Errorf("wrapped: %w", e)} {
			got := errFromPB(errToPB(in))
			for _, s := range sentinels {
				if errors.Is(in, s) != errors.Is(got, s) {
					t.Fatalf("%v → %v: errors.Is(%v) differs", in, got, s)
				}
			}
		}
	}
	if got := errFromPB(errToPB(nil)); got != nil {
		t.Fatalf("nil → %v", got)
	}
	other := errFromPB(errToPB(errors.New("next key must have status next")))
	if other == nil || other.Error() != "next key must have status next" {
		t.Fatalf("other error = %v", other)
	}
}

func TestPushedAuthRequestCodecRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.PushedAuthRequest{TenantID: "ten", IDHash: "h", ClientID: "cid", Origin: "https://login.example", Params: map[string]string{"state": "s"}, ExpiresAt: nanoTime.Add(time.Minute), CreatedAt: nanoTime, UsedAt: &nanoTime}, pushedAuthRequestToPB, pushedAuthRequestFromPB)
	roundTrip(t, "zero", &store.PushedAuthRequest{}, pushedAuthRequestToPB, pushedAuthRequestFromPB)
	used := time.Date(2026, 1, 2, 3, 4, 5, 6000, time.UTC)
	for _, in := range []*store.PushedAuthRequest{
		{TenantID: "t", IDHash: "h", ClientID: "c", Params: map[string]string{"state": "s", "ext-a": "b"},
			ExpiresAt: used.Add(30 * time.Second), CreatedAt: used.Add(-time.Second)},
		{TenantID: "t", IDHash: "h", ClientID: "c", Params: map[string]string{},
			ExpiresAt: used, CreatedAt: used, UsedAt: &used},
	} {
		pb, err := pushedAuthRequestToPB(in)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pushedAuthRequestFromPB(pb)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(out, in) {
			t.Fatalf("round trip: got %+v, want %+v", out, in)
		}
	}
}

// Plugins built before fields 16 (tenant) and 19 (client) never set them:
// PAR stays off and is never required.
func TestPARFieldsDefaultOffForOldPlugins(t *testing.T) {
	tn, err := tenantFromPB(&storev1.Tenant{Id: "t", Name: "t"})
	if err != nil || tn.PushedAuthorizationRequestsSupported {
		t.Fatalf("tenant = %+v, %v", tn, err)
	}
	c, err := clientFromPB(&storev1.Client{TenantId: "t", ClientId: "c"})
	if err != nil || c.RequirePushedAuthorizationRequests {
		t.Fatalf("client = %+v, %v", c, err)
	}
}

func TestDeviceCodeCodecRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.DeviceCode{
		Origin:   "https://login.example",
		TenantID: "ten", DeviceCodeHash: "dh", UserCodeHash: "uh", ClientID: "c",
		Scopes: []string{"openid", "email"}, Audience: "https://api", Status: store.DeviceCodeApproved,
		UserID: "u", GrantedScopes: []string{"openid"},
		LastPolledAt: &nanoTime, ExpiredReportedAt: &nanoTime, ExpiresAt: nanoTime, CreatedAt: nanoTime,
		ActionEffects: []byte{0, 0xff, 'x'},
	}, deviceCodeToPB, deviceCodeFromPB)
	roundTrip(t, "pending", &store.DeviceCode{
		TenantID: "ten", DeviceCodeHash: "dh", UserCodeHash: "uh", ClientID: "c",
		Status: store.DeviceCodePending, ExpiresAt: nanoTime, CreatedAt: nanoTime,
	}, deviceCodeToPB, deviceCodeFromPB)
}

func TestDevicePollOutcomeFromPB(t *testing.T) {
	for _, o := range []store.DevicePollOutcome{store.PollPending, store.PollSlowDown, store.PollApproved, store.PollDenied, store.PollExpired, store.PollInvalid} {
		if got, err := devicePollOutcomeFromPB(string(o)); err != nil || got != o {
			t.Fatalf("%q = %q, %v", o, got, err)
		}
	}
	for _, bad := range []string{"", "Approved", "bogus"} {
		if _, err := devicePollOutcomeFromPB(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// A plugin older than Plan 15 stores only the legacy password_policy, so
// that is what a connection read back from it carries.
func TestConnectionLegacyPasswordPolicy(t *testing.T) {
	for classes, want := range map[int64]store.PasswordComplexity{
		0: {MinLength: 12},
		2: {MinLength: 12, MinCharacterClasses: 2},
		3: {MinLength: 12, CharacterTypes: store.CharacterTypes, CharacterTypeRule: store.CharacterTypeRuleThreeOfFour},
		4: {MinLength: 12, CharacterTypes: store.CharacterTypes, CharacterTypeRule: store.CharacterTypeRuleAll},
	} {
		c, err := connectionFromPB(&storev1.Connection{
			CreatedAt:      tsToPB(time.Unix(0, 0)),
			PasswordPolicy: &storev1.PasswordPolicy{MinLength: 12, RequireCharacterClasses: classes},
		})
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, c.PasswordOptions.Complexity); diff != "" {
			t.Errorf("classes %d (-want +got):\n%s", classes, diff)
		}
	}
}

// A plugin older than Plan 15 sends no brute-force field either; protection
// is on for the connections it stores, as it was before the option existed.
func TestConnectionLegacyKeepsBruteForceProtection(t *testing.T) {
	c, err := connectionFromPB(&storev1.Connection{CreatedAt: tsToPB(time.Unix(0, 0))})
	if err != nil {
		t.Fatal(err)
	}
	if !c.BruteForceProtection {
		t.Fatal("brute-force protection off for a connection from an old plugin")
	}
	c, err = connectionFromPB(&storev1.Connection{CreatedAt: tsToPB(time.Unix(0, 0)), PasswordOptions: &storev1.PasswordOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	if c.BruteForceProtection {
		t.Fatal("an explicit off was turned on")
	}
}

// And such a plugin keeps the minimum length and class count it understands.
func TestConnectionWritesLegacyPasswordPolicy(t *testing.T) {
	for want, c := range map[int64]store.PasswordComplexity{
		0: {MinLength: 12},
		1: {MinLength: 12, MinCharacterClasses: 1},
		3: store.LegacyComplexity(12, 3),
		4: store.LegacyComplexity(12, 4),
	} {
		pb, err := connectionToPB(&store.Connection{PasswordOptions: store.PasswordOptions{Complexity: c}})
		if err != nil {
			t.Fatal(err)
		}
		if got := pb.PasswordPolicy; got.MinLength != 12 || got.RequireCharacterClasses != want {
			t.Errorf("%+v: policy = %+v, want 12 and %d", c, got, want)
		}
	}
}

func TestUserQueryRoundTrip(t *testing.T) {
	lo := "2026-01-01"
	q := &store.UserQuery{Op: store.QueryAnd, Kids: []*store.UserQuery{
		{Op: store.QueryRange, Field: "created_at", Kind: store.KindDate, Lo: &lo, LoIncl: true},
		{Op: store.QueryNot, Kids: []*store.UserQuery{{Op: store.QueryWildcard, Field: "email", Value: `a\**`}}},
		{Op: store.QueryTerm, Field: "app_metadata.plan", Kind: store.KindNumber, Value: "2"},
		{Op: store.QueryExists, Field: "last_login"},
	}}
	roundTrip(t, "UserQuery", q,
		func(q *store.UserQuery) (*storev1.UserQuery, error) { return userQueryToPB(q), nil },
		func(pb *storev1.UserQuery) (*store.UserQuery, error) { return userQueryFromPB(pb), nil })
	if userQueryToPB(nil) != nil || userQueryFromPB(nil) != nil {
		t.Fatal("a nil query must stay nil")
	}
}

func TestJobRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.Job{
		TenantID: "ten", ID: "job_1", Type: store.JobUsersImport, Status: store.JobProcessing,
		ConnectionID: "con_1", Connection: "Database", ExternalID: "ext",
		Params: map[string]any{"upsert": true, "n": float64(3), "selected_origin": "https://login.example", "nested": map[string]any{"a": []any{"x", nil}}},
		Input:  []byte(`[{"email":"a@example.test"}]`), Progress: 2,
		Summary:       store.JobSummary{Failed: 1, Updated: 2, Inserted: 3, Total: 6},
		StatusDetails: "details", Attempts: 2, LeaseOwner: "w1", LeaseUntil: nanoTime.Add(time.Minute),
		FirstClaimedAt: nanoTime, CreatedAt: nanoTime.Add(-time.Hour), UpdatedAt: nanoTime.Add(time.Second),
		ExpiresAt: nanoTime.Add(24 * time.Hour), FileSize: 1 << 33,
	}, jobToPB, jobFromPB)
	roundTrip(t, "empty", &store.Job{Params: map[string]any{}}, jobToPB, jobFromPB)
	roundTrip(t, "zero", &store.Job{}, jobToPB, jobFromPB)
}

func TestJobErrorRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.JobError{
		Index: 41, User: map[string]any{"email": "a@example.test", "nested": map[string]any{"k": []any{"v"}}},
		Errors: []store.JobErrorItem{{Code: "DUPLICATED_USER", Message: "The user already exists.", Path: "email"}, {Code: "X"}},
	}, jobErrorToPB, jobErrorFromPB)
	roundTrip(t, "empty", &store.JobError{User: map[string]any{}, Errors: []store.JobErrorItem{}}, jobErrorToPB, jobErrorFromPB)
	roundTrip(t, "zero", &store.JobError{}, jobErrorToPB, jobErrorFromPB)
	// A file entry that is not an object is echoed as itself (J2).
	roundTrip(t, "number", &store.JobError{Index: 1, User: float64(1)}, jobErrorToPB, jobErrorFromPB)
	roundTrip(t, "string", &store.JobError{Index: 2, User: "x"}, jobErrorToPB, jobErrorFromPB)
}

// Every policy field is populated so the existing reflective completeness guard
// detects future fields missing from the plugin round-trip contract.
func fullProtectionSettings() store.ProtectionSettings {
	return store.ProtectionSettings{
		BruteForce:           store.BruteForcePolicy{Enabled: true, Shields: []string{"block"}, Allowlist: []string{"::1"}, Mode: "count_per_identifier", MaxAttempts: 7, FormSubmissionMode: "auto"},
		SuspiciousIP:         store.SuspiciousIPPolicy{Enabled: true, Shields: []string{"block"}, Allowlist: []string{"192.0.2.0/24"}, Stage: store.SuspiciousIPStages{PreLogin: store.ProtectionRate{MaxAttempts: 9, Rate: 864000}, PreUserRegistration: store.ProtectionRate{MaxAttempts: 8, Rate: 1728000}, PreCustomTokenExchange: store.ProtectionRate{MaxAttempts: 7, Rate: 8640000}}},
		BreachedPassword:     store.BreachedPasswordPolicy{Enabled: true, Shields: []string{"block"}, AdminNotificationFrequency: []string{"daily"}, Method: "standard", Stage: store.BreachedPasswordStages{PreUserRegistration: store.ProtectionShields{Shields: []string{"block"}}, PreChangePassword: store.ProtectionShields{Shields: []string{"block"}}}},
		Bot:                  store.BotPolicy{BotDetectionLevel: "high", ChallengePasswordPolicy: "always", ChallengePasswordlessPolicy: "when_risky", ChallengePasswordResetPolicy: "always", Allowlist: []string{"::1"}, MonitoringModeEnabled: true},
		CAPTCHA:              store.CAPTCHAPolicy{ActiveProviderID: "hcaptcha", Arkose: store.ArkoseProvider{CAPTCHAProvider: store.CAPTCHAProvider{SiteKey: "site", Secret: "test-secret"}, ClientSubdomain: "client", VerifySubdomain: "verify", FailOpen: true}, AuthChallenge: store.AuthChallengeProvider{FailOpen: true}, HCaptcha: store.CAPTCHAProvider{SiteKey: "site", Secret: "test-secret"}, FriendlyCaptcha: store.CAPTCHAProvider{SiteKey: "site", Secret: "test-secret"}, RecaptchaV2: store.CAPTCHAProvider{SiteKey: "site", Secret: "test-secret"}, RecaptchaEnterprise: store.RecaptchaEnterpriseProvider{SiteKey: "site", APIKey: "test-key", ProjectID: "project"}, SimpleCaptcha: map[string]any{"extension": true}},
		LegacyLockoutSeconds: 900, LegacyIPMaxAttempts: 100,
	}
}

func TestTenantSettingsLargeNumberRoundTrip(t *testing.T) {
	in, err := tenantrules.Apply(&store.Tenant{}, map[string]any{"security_headers": map[string]any{"content_security_policy": map[string]any{"reporting_infrastructure": map[string]any{"report_to": map[string]any{"max_age": json.Number("9007199254740993")}}}}})
	if err != nil {
		t.Fatal(err)
	}
	in.ProtectionSettings.CAPTCHA.SimpleCaptcha = map[string]any{"large": json.Number("9007199254740993")}
	roundTrip(t, "large settings integers", in, tenantToPB, tenantFromPB)
}

func TestHostedLoginConfigRoundTrip(t *testing.T) {
	template := `<html><head>{% auth0:head %}</head><body>{% auth0:widget %}</body></html>`
	full := &store.HostedLoginConfig{TenantID: "ten", Revision: 3, Branding: map[string]any{"colors": map[string]any{"primary": "#112233"}}, Template: &template, Themes: map[string]map[string]any{"abc": {"colors": map[string]any{"primary_button": "#445566"}}}, DefaultThemeID: "abc", Prompts: map[string]any{"identifier_first": true}, CustomText: store.CustomText{"login": {"en": {"login": {"title": "Welcome"}}}}, Partials: map[string]map[string]map[string]string{"login": {"login": {"form-content-start": "<p>Hi</p>"}}}}
	roundTrip(t, "full", full, hostedLoginConfigToPB, hostedLoginConfigFromPB)
	roundTrip(t, "empty", &store.HostedLoginConfig{Branding: map[string]any{}}, hostedLoginConfigToPB, hostedLoginConfigFromPB)
	roundTrip(t, "zero", &store.HostedLoginConfig{}, hostedLoginConfigToPB, hostedLoginConfigFromPB)
}
