package config

import "testing"

func TestTrustedFingerprintConfig(t *testing.T) {
	c, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__BASE_DOMAIN=example.test", "ZEROAUTHY_TRUSTED_JA3_HEADER=X-JA3", "ZEROAUTHY_TRUSTED_JA4_HEADER=X-JA4"})
	if err != nil {
		t.Fatal(err)
	}
	if c.TrustedJA3Header != "X-JA3" || c.TrustedJA4Header != "X-JA4" {
		t.Fatal(c)
	}
}
