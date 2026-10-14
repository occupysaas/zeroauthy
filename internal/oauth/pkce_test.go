package oauth

import "testing"

func TestVerifyPKCE(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 Appendix B
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !verifyPKCE("S256", challenge, verifier) {
		t.Fatal("RFC 7636 test vector rejected")
	}
	for name, v := range map[string]string{
		"wrong":     "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX",
		"too short": "abc",
		"bad chars": verifier[:42] + "!",
		"empty":     "",
	} {
		if verifyPKCE("S256", challenge, v) {
			t.Errorf("%s verifier accepted", name)
		}
	}
	if verifyPKCE("plain", verifier, verifier) {
		t.Error("plain method accepted")
	}
}
