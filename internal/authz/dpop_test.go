package authz

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"strings"
	"testing"
)

func TestDPoPRequestBinding(t *testing.T) {
	e := newEnv(t)
	jkt := strings.Repeat("a", 43)
	q := with(goodQuery(), "dpop_jkt", jkt)
	req := ParseRequest(q)
	if req.Params()["dpop_jkt"] != jkt {
		t.Fatal("binding dropped")
	}
	_, failure, _ := ValidateRequest(context.Background(), e.st, e.tenant, &req)
	if failure != nil {
		t.Fatalf("valid %v", failure)
	}
	q.Set("dpop_jkt", "invalid")
	req = ParseRequest(q)
	_, failure, _ = ValidateRequest(context.Background(), e.st, e.tenant, &req)
	if failure == nil || failure.Code != "invalid_request" {
		t.Fatal("malformed binding accepted")
	}
}

func TestDPoPAuthorizationBinding(t *testing.T) {
	e := newEnv(t)
	jkt := strings.Repeat("a", 43)
	loc := location(t, e.get(t, with(goodQuery(), "dpop_jkt", jkt)))
	txn, err := e.st.AuthTransactions().Get(t.Context(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil || txn.DPoPJKT != jkt || txn.Params["dpop_jkt"] != jkt {
		t.Fatal("transaction lost binding")
	}
	ck := e.login(t, fixedNow())
	loc = location(t, e.get(t, with(goodQuery(), "dpop_jkt", jkt), ck))
	ac, err := e.st.AuthCodes().Get(t.Context(), e.tenant.ID, secrets.HashToken(loc.Query().Get("code")))
	if err != nil || ac.DPoPJKT != jkt {
		t.Fatal("code lost binding")
	}
}
func TestDPoPJARBinding(t *testing.T) {
	e := newJAREnv(t, false)
	jkt := strings.Repeat("b", 43)
	obj := signJAR(t, jarKey(t, "rsa2048.priv.pem"), jarClaims("dpop_jkt", jkt))
	p := e.txnParams(t, location(t, e.get(t, jarQuery(obj))))
	if p["dpop_jkt"] != jkt {
		t.Fatal("JAR lost binding")
	}
}
