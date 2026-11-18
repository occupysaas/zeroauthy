package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	appleTestTeam = "TEAM123456"
	appleTestKID  = "KEY1234567"
	appleTestSub  = "test.example.services"
)

func appleTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Verification goes through the public key and decodes only authenticated claims.
func appleSecretClaims(t *testing.T, token string, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	obj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(obj.Signatures) != 1 {
		t.Fatalf("client secret is not a single ES256 JWS: %v", err)
	}
	if obj.Signatures[0].Header.Algorithm != "ES256" || obj.Signatures[0].Header.KeyID != appleTestKID {
		t.Fatal("client secret headers differ from algorithm and key ID")
	}
	payload, err := obj.Verify(&key.PublicKey)
	if err != nil {
		t.Fatalf("client secret signature verification failed: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestAppleClientSecretShape(t *testing.T) {
	key := appleTestKey(t)
	now := time.Date(2026, 11, 16, 12, 0, 0, 123456789, time.FixedZone("local", -5*60*60))
	for _, sub := range []string{appleTestSub, "test.example.ios"} {
		t.Run(sub, func(t *testing.T) {
			token, err := appleClientSecret(appleTestTeam, appleTestKID, sub, key, now)
			if err != nil {
				t.Fatal(err)
			}
			claims := appleSecretClaims(t, token, key)
			if claims["iss"] != appleTestTeam || claims["sub"] != sub || claims["aud"] != "https://appleid.apple.com" ||
				claims["iat"] != float64(now.Unix()) || claims["exp"] != float64(now.Unix()+300) {
				t.Fatal("client secret claims differ from the Apple contract")
			}
		})
	}
	wrong := appleTestKey(t)
	token, err := appleClientSecret(appleTestTeam, appleTestKID, appleTestSub, key, now)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := obj.Verify(&wrong.PublicKey); err == nil {
		t.Fatal("unrelated signing key verified the secret")
	}
}

func TestAppleClientSecretInvalidKey(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]*ecdsa.PrivateKey{"nil": nil, "empty": {}, "P384": p384} {
		t.Run(name, func(t *testing.T) {
			token, err := appleClientSecret(appleTestTeam, appleTestKID, appleTestSub, key, fixedTime)
			if token != "" || !errors.Is(err, ErrInvalidConfig) {
				t.Fatal("invalid Apple key was not refused with a safe configuration error")
			}
			if strings.Contains(err.Error(), appleTestSub) {
				t.Fatal("configuration error includes request data")
			}
		})
	}
}

func TestAppleSecretCache(t *testing.T) {
	key := appleTestKey(t)
	now := fixedTime
	ps := NewProviders(NetworkPolicy{}, func() time.Time { return now })
	cache := CacheKey{TenantID: "tenant", ConnectionID: "apple", Revision: 1}
	get := func() string {
		t.Helper()
		token, err := ps.appleClientSecret(cache, appleTestTeam, appleTestKID, appleTestSub, key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	first := get()
	now = now.Add(4*time.Minute - time.Second)
	if get() != first {
		t.Fatal("secret was not reused within four minutes")
	}
	// Expiry is exclusive: exactly four minutes causes a fresh signature.
	now = now.Add(time.Second)
	second := get()
	if second == first {
		t.Fatal("secret was reused at four minutes")
	}
	claims := appleSecretClaims(t, second, key)
	if claims["iat"] != float64(now.Unix()) {
		t.Fatal("renewed secret has stale issuance time")
	}
	now = now.Add(4*time.Minute + time.Second)
	if get() == second {
		t.Fatal("expired secret was reused")
	}
}

func TestAppleSecretCacheRevision(t *testing.T) {
	key, rotated := appleTestKey(t), appleTestKey(t)
	ps := NewProviders(NetworkPolicy{}, func() time.Time { return fixedTime })
	cache := CacheKey{TenantID: "tenant", ConnectionID: "apple", Revision: 1}
	first, err := ps.appleClientSecret(cache, appleTestTeam, appleTestKID, appleTestSub, key)
	if err != nil {
		t.Fatal(err)
	}
	cache.Revision++
	second, err := ps.appleClientSecret(cache, appleTestTeam, appleTestKID, appleTestSub, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("new revision reused old signing credentials")
	}
	appleSecretClaims(t, second, rotated)
	obj, err := jose.ParseSigned(second, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := obj.Verify(&key.PublicKey); err == nil {
		t.Fatal("new revision is still signed by the old key")
	}
}

func TestAppleSecretCacheIsolation(t *testing.T) {
	for _, dimension := range []string{"tenant", "connection", "subject", "team", "kid"} {
		t.Run(dimension, func(t *testing.T) {
			key := appleTestKey(t)
			ps := NewProviders(NetworkPolicy{}, func() time.Time { return fixedTime })
			cache := CacheKey{TenantID: "tenant", ConnectionID: "apple", Revision: 1}
			first, err := ps.appleClientSecret(cache, appleTestTeam, appleTestKID, appleTestSub, key)
			if err != nil {
				t.Fatal(err)
			}
			team, kid, sub := appleTestTeam, appleTestKID, appleTestSub
			switch dimension {
			case "tenant":
				cache.TenantID = "other"
			case "connection":
				cache.ConnectionID = "other"
			case "subject":
				sub = "test.example.ios"
			case "team":
				team = "OTHER12345"
			case "kid":
				kid = "OTHER12345"
			}
			second, err := ps.appleClientSecret(cache, team, kid, sub, key)
			if err != nil {
				t.Fatal(err)
			}
			if second == first {
				t.Fatalf("%s change reused a different context's secret", dimension)
			}
		})
	}
}

func TestAppleSecretCacheConcurrent(t *testing.T) {
	key := appleTestKey(t)
	ps := NewProviders(NetworkPolicy{}, func() time.Time { return fixedTime })
	cache := CacheKey{TenantID: "tenant", ConnectionID: "apple", Revision: 1}
	var wg sync.WaitGroup
	results := make(chan string, 32)
	for range 32 {
		wg.Go(func() {
			token, err := ps.appleClientSecret(cache, appleTestTeam, appleTestKID, appleTestSub, key)
			if err != nil {
				t.Error("concurrent secret generation failed")
				return
			}
			results <- token
		})
	}
	wg.Wait()
	close(results)
	first, n := "", 0
	for token := range results {
		n++
		if first == "" {
			first = token
		}
		if token != first {
			t.Fatal("burst generated multiple secrets for one context")
		}
	}
	if n != 32 {
		t.Fatalf("only %d concurrent calls succeeded", n)
	}
}
