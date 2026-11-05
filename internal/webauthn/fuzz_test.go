package webauthn

import "testing"

func FuzzParseCredentialJSON(f *testing.F) {
	f.Add([]byte(`{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA","userHandle":null}}`))
	f.Add([]byte(`{"id":"AQ==","rawId":"AQ","response":{"attestationObject":"oA"}}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseCredentialJSON(b) })
}

func FuzzParseAuthData(f *testing.F) {
	base := make([]byte, 37)
	f.Add(base)
	at := append(append([]byte{}, base...), make([]byte, 16)...)
	at[32] = flagAT | flagUP
	at = append(at, 0, 1, 9, 0xa1, 0x01, 0x02)
	f.Add(at)
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseAuthData(b) })
}
