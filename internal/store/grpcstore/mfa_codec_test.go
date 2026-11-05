package grpcstore

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/protobuf/proto"
)

// Every public record field must be populated and survive an actual protobuf
// encoding in both directions. copyMFA also rejects unmatched fields at runtime.
func TestMFARecordWireRoundTripsAllFields(t *testing.T) {
	at := time.Date(2026, 11, 2, 12, 34, 56, 123456789, time.UTC)
	cases := []struct {
		name   string
		source any
		wire   proto.Message
	}{
		{"guardian", &store.GuardianSettings{TenantID: "tenant", Factors: map[string]bool{"otp": true}, Policies: []string{"all-applications"}, Stored: map[string]json.RawMessage{"route": json.RawMessage(`{"value":1}`)}, SealedSecrets: map[string][]byte{"route": []byte("sealed")}, Version: 4}, &storev1.MFAGuardian{}},
		{"authenticator", &store.Authenticator{TenantID: "tenant", UserID: "user", ID: "id", Type: "totp", Name: "name", Confirmed: true, Preferred: true, SealedSecret: []byte("sealed"), LastStep: 123, CodeHash: "hash", Email: "a@example.test", Phone: "123", PhoneMethod: "sms", PublicData: []byte(`{"transports":["usb"]}`), CredentialID: []byte("credential"), PublicKey: []byte("key"), RPID: "example.test", SignCount: 7, CreatedAt: at, LastAuthAt: at}, &storev1.MFAAuthenticator{}},
		{"token", &store.MFAToken{TenantID: "tenant", Hash: "hash", ClientID: "client", UserID: "user", Connection: "connection", Request: json.RawMessage(`{"scope":"x"}`), ExpiresAt: at}, &storev1.MFATokenMsg{}},
		{"challenge", &store.MFAChallenge{TenantID: "tenant", ID: "id", UserID: "user", AuthenticatorID: "factor", Kind: "email", CodeHash: "hash", Challenge: []byte("challenge"), Binding: []byte(`{"purpose":"passkey-login"}`), Attempts: 2, ExpiresAt: at}, &storev1.MFAChallengeMsg{}},
		{"ticket", &store.EnrollmentTicket{TenantID: "tenant", Hash: "hash", UserID: "user", Factor: "otp", AllowMultiple: true, ExpiresAt: at}, &storev1.MFAEnrollmentTicket{}},
		{"browser", &store.MFABrowser{TenantID: "tenant", Hash: "hash", UserID: "user", Kind: "remember", Epoch: 2, ExpiresAt: at}, &storev1.MFABrowserMsg{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := reflect.ValueOf(tc.source).Elem()
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).IsZero() {
					t.Errorf("fixture does not populate %s", v.Type().Field(i).Name)
				}
			}
			if err := copyMFA(tc.wire, tc.source); err != nil {
				t.Fatal(err)
			}
			b, err := proto.Marshal(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			wire := reflect.New(reflect.TypeOf(tc.wire).Elem()).Interface().(proto.Message)
			if err = proto.Unmarshal(b, wire); err != nil {
				t.Fatal(err)
			}
			got := reflect.New(v.Type()).Interface()
			if err = copyMFA(got, wire); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.source) {
				t.Fatalf("round trip\ngot: %#v\nwant: %#v", got, tc.source)
			}
		})
	}
}
