package server

import (
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"strings"
	"testing"
)

func TestBreachCheckerCapabilityActual(t *testing.T) {
	h, st := newMgmtEnvWith(t, func(d *Deps) {
		d.Protection = &protection.Service{Store: d.Store, BreachChecker: protection.NewRangeChecker(nil)}
	})
	op, _ := operatorToken(t, st, "capability@example.test")
	rec, _ := sendJSON(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants", op, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"breached_password_checker":{"available":true}`) {
		t.Fatalf("actual checker unavailable: %d %s", rec.Code, rec.Body)
	}
}
