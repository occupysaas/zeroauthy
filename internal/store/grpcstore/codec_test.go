package grpcstore

import (
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
		ID: "ten", Name: "acme", FriendlyName: "Acme", Domains: []string{"a.example.test", "b.example.test"},
		DefaultAudience: "https://api", AllowedLogoutURLs: []string{"https://x/out"}, EnabledLocales: []string{"en", "de"},
		CustomText:      store.CustomText{"login": {"en": {"login": {"title": "Hi", "description": "Welcome"}}, "de": {"login": {"title": "Hallo"}}}},
		SessionLifetime: 3600, IdleSessionLifetime: 1800,
		Branding:         store.Branding{LogoURL: "https://l/logo.png", PrimaryColor: "#112233"},
		DefaultDirectory: "Username-Password-Authentication", CreatedAt: nanoTime,
		SkipNonVerifiableCallbackURIConfirmationPrompt: true, UseScopeDescriptionsForConsent: true,
		PushedAuthorizationRequestsSupported: true,
		DeviceFlowCharset:                    "digits", DeviceFlowMask: "###-###",
	}, tenantToPB, tenantFromPB)
	roundTrip(t, "empty", &store.Tenant{Domains: []string{}, AllowedLogoutURLs: []string{}, EnabledLocales: []string{}, CustomText: store.CustomText{}}, tenantToPB, tenantFromPB)
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
		Scopes:     []store.Scope{{Value: "read", Description: "Read"}, {Value: "write"}},
		SigningAlg: "RS256", TokenLifetime: 7200, AllowOfflineAccess: true, CreatedAt: nanoTime,
		SkipConsentForVerifiableFirstPartyClients: true,
		SubjectTypeAuthorization:                  store.SubjectTypeAuthorization{User: store.PolicyAllowAll, Client: store.PolicyRequireClientGrant},
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
		SubjectType: store.SubjectTypeUser,
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
	roundTrip(t, "full", &store.SigningKey{
		TenantID: "ten", KID: "k1", Alg: "RS256", Status: store.KeyCurrent,
		PrivateKey: []byte{0, 1, 2, 255}, PublicJWK: []byte(`{"kty":"RSA"}`), CreatedAt: nanoTime,
	}, signingKeyToPB, signingKeyFromPB)
	roundTrip(t, "empty", &store.SigningKey{PrivateKey: []byte{}, PublicJWK: []byte{}}, signingKeyToPB, signingKeyFromPB)
	roundTrip(t, "zero", &store.SigningKey{}, signingKeyToPB, signingKeyFromPB)
}

func TestConnectionRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.Connection{
		TenantID: "ten", ID: "c1", Name: "Username-Password-Authentication", Strategy: store.StrategyDatabase,
		EnabledClients: []string{"cid1", "cid2"}, DisableSignup: true, RequiresUsername: true,
		PasswordPolicy: store.PasswordPolicy{MinLength: 12, RequireCharacterClasses: 3}, CreatedAt: nanoTime,
		EnabledDatabaseCustomization: true, ImportMode: true,
		CustomScripts:         map[string]string{store.ScriptLogin: "function login() {}", store.ScriptCreate: ""},
		ConfigurationSealed:   []byte{0x01, 0x00, 0xff},
		SetUserRootAttributes: store.RootAttributesOnFirstLogin,
		IsDomainConnection:    true,
	}, connectionToPB, connectionFromPB)
	// An empty (non-nil) script map stays distinct from nil.
	roundTrip(t, "empty scripts", &store.Connection{CustomScripts: map[string]string{}}, connectionToPB, connectionFromPB)
	roundTrip(t, "empty", &store.Connection{EnabledClients: []string{}}, connectionToPB, connectionFromPB)
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
		Identities:   []store.Identity{{Connection: "db", Provider: "auth0", UserID: "u1", PasswordHash: "$argon2id$..."}},
		LastLogin:    ptr(nanoTime), LoginsCount: 7, CreatedAt: nanoTime, UpdatedAt: nanoTime.Add(time.Second),
	}, userToPB, userFromPB)
	roundTrip(t, "empty", &store.User{UserMetadata: map[string]any{}, AppMetadata: map[string]any{}, Identities: []store.Identity{}}, userToPB, userFromPB)
	roundTrip(t, "zero", &store.User{}, userToPB, userFromPB)
}

func TestSessionRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.LoginSession{
		TenantID: "ten", ID: "sid", TokenHash: "th", UserID: "auth0|u1", Connection: "db",
		AuthenticatedAt: nanoTime, ClientIDs: []string{"c1", "c2"},
		ExpiresAt: nanoTime.Add(time.Hour), IdleExpiresAt: nanoTime.Add(time.Minute), CreatedAt: nanoTime,
	}, sessionToPB, sessionFromPB)
	roundTrip(t, "empty", &store.LoginSession{ClientIDs: []string{}}, sessionToPB, sessionFromPB)
	roundTrip(t, "zero", &store.LoginSession{}, sessionToPB, sessionFromPB)
}

func TestAuthTransactionRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.AuthTransaction{
		TenantID: "ten", ID: "st", CookieHash: "ch", CSRFToken: "csrf", ClientID: "cid",
		Params:    map[string]string{"scope": "openid profile", "state": "xyz", "empty": ""},
		ExpiresAt: nanoTime.Add(time.Hour), CreatedAt: nanoTime,
	}, authTransactionToPB, authTransactionFromPB)
	roundTrip(t, "empty", &store.AuthTransaction{Params: map[string]string{}}, authTransactionToPB, authTransactionFromPB)
	roundTrip(t, "zero", &store.AuthTransaction{}, authTransactionToPB, authTransactionFromPB)
}

func TestAuthCodeRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.AuthCode{
		TenantID: "ten", CodeHash: "ch", ClientID: "cid", RedirectURI: "https://cb", UserID: "auth0|u1",
		SessionID: "sid", Scopes: []string{"openid", "email"}, Audience: "https://api", Nonce: "n",
		CodeChallenge: "cc", CodeChallengeMethod: "S256", AuthTime: nanoTime,
		ExpiresAt: nanoTime.Add(time.Minute), CreatedAt: nanoTime,
		UsedAt: ptr(nanoTime.Add(time.Second)), ReplayedAt: ptr(nanoTime.Add(2 * time.Second)),
	}, authCodeToPB, authCodeFromPB)
	roundTrip(t, "empty", &store.AuthCode{Scopes: []string{}}, authCodeToPB, authCodeFromPB)
	roundTrip(t, "zero", &store.AuthCode{}, authCodeToPB, authCodeFromPB)
}

func TestRefreshTokenRoundTrip(t *testing.T) {
	roundTrip(t, "full", &store.RefreshToken{
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
		TenantID: "ten", ID: "tk", TokenHash: "th", UserID: "auth0|u1", Connection: "db", ClientID: "cid",
		Lang: "de", ExpiresAt: nanoTime.Add(time.Hour), UsedAt: ptr(nanoTime.Add(time.Second)), CreatedAt: nanoTime,
	}, passwordResetTicketToPB, passwordResetTicketFromPB)
	roundTrip(t, "zero", &store.PasswordResetTicket{}, passwordResetTicketToPB, passwordResetTicketFromPB)
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
	for _, e := range []error{nil, store.ErrNotFound, store.ErrConflict, store.ErrAlreadyUsed,
		fmt.Errorf("wrapped: %w", store.ErrConflict)} {
		got := errFromPB(errToPB(e))
		if e == nil {
			if got != nil {
				t.Fatalf("nil → %v", got)
			}
			continue
		}
		for _, sentinel := range []error{store.ErrNotFound, store.ErrConflict, store.ErrAlreadyUsed} {
			if errors.Is(e, sentinel) != errors.Is(got, sentinel) {
				t.Fatalf("%v → %v: errors.Is(%v) differs", e, got, sentinel)
			}
		}
	}
	other := errFromPB(errToPB(errors.New("next key must have status next")))
	if other == nil || other.Error() != "next key must have status next" {
		t.Fatalf("other error = %v", other)
	}
}

func TestPushedAuthRequestCodecRoundTrip(t *testing.T) {
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
		TenantID: "ten", DeviceCodeHash: "dh", UserCodeHash: "uh", ClientID: "c",
		Scopes: []string{"openid", "email"}, Audience: "https://api", Status: store.DeviceCodeApproved,
		UserID: "u", GrantedScopes: []string{"openid"},
		LastPolledAt: &nanoTime, ExpiredReportedAt: &nanoTime, ExpiresAt: nanoTime, CreatedAt: nanoTime,
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
