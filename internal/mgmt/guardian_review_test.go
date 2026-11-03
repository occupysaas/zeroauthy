package mgmt_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type noUserScanStore struct{ store.Store }
type noUserScanUsers struct{ store.Users }

func (s noUserScanStore) Users() store.Users { return noUserScanUsers{s.Store.Users()} }
func (s noUserScanStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(noUserScanStore{tx}) })
}
func (noUserScanUsers) List(context.Context, string, *store.UserQuery, store.UserSort, store.Page) ([]*store.User, int, error) {
	return nil, 0, errors.New("guardian enrollment scanned tenant users")
}

// Review I6: Guardian enrollment lookup uses an indexed store lookup by
// enrollment ID rather than walking every user in the tenant.
func TestGuardianEnrollmentDoesNotScanUsers(t *testing.T) {
	e, uid := mfaUser(t)
	_, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "email", "email": "mfa@example.test"}, "")
	id := strings.Split(out.(map[string]any)["id"].(string), "|")[1]
	e.h.Store = noUserScanStore{e.st}
	r, got := mfaCall(t, e.clientsEnv, "GetGuardianEnrollment", id, "", nil, "")
	if r.Code != 200 || got.(map[string]any)["id"] != id {
		t.Fatalf("get %d %s", r.Code, r.Body)
	}
	if r, _ = mfaCall(t, e.clientsEnv, "GetGuardianEnrollment", "dev_missing", "", nil, ""); r.Code != 404 {
		t.Fatalf("missing %d %s", r.Code, r.Body)
	}
	if r, _ = mfaCall(t, e.clientsEnv, "DeleteGuardianEnrollment", id, "", nil, ""); r.Code != 204 {
		t.Fatalf("delete %d %s", r.Code, r.Body)
	}
	if r, _ = mfaCall(t, e.clientsEnv, "GetGuardianEnrollment", id, "", nil, ""); r.Code != 404 {
		t.Fatalf("deleted %d %s", r.Code, r.Body)
	}
}

// Review M5: a Management API totp_secret in lower case or with padding is
// normalized rather than rejected.
func TestAuthMethodTOTPSecretNormalized(t *testing.T) {
	e, uid := mfaUser(t)
	for _, secret := range []string{"jbswy3dpehpk3pxp", "JBSW Y3DP EHPK 3PXP", "MZXW6==="} {
		r, _ := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "totp", "totp_secret": secret}, "")
		if r.Code != 201 {
			t.Fatalf("%q: %d %s", secret, r.Code, r.Body)
		}
	}
}
