package mgmt_test

import (
	"context"
	"strings"
	"testing"
)

func TestImportMFAInputSealedAtIngress(t *testing.T) {
	e := newUsersEnv(t)
	e.importConnections(t)
	payload := `[{"email":"mfa@example.test","mfa_factors":[{"totp":{"secret":"JBSWY3DPEHPK3PXP"}}]}]`
	r, out := e.postImport(t, importBody(t, part{name: "connection_id", value: importConnID}, part{name: "users", value: payload, file: true}), -1)
	if r.Code != 202 {
		t.Fatal(r.Body)
	}
	j, err := e.st.Jobs().Get(context.Background(), e.tn.ID, out["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(j.Input), "JBSWY3DPEHPK3PXP") {
		t.Fatal("MFA secret persisted in job input")
	}
}
