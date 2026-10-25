package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func newManager(t *testing.T) (*Manager, store.Store) {
	t.Helper()
	st := memory.New()
	w, err := NewLocalWrapper(testMasterKey(7))
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(st.SigningKeys(), w), st
}

func kids(set jose.JSONWebKeySet) []string {
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.KeyID)
	}
	return out
}

func TestEnsureIsIdempotent(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	ks, _ := st.SigningKeys().List(ctx, "ten_a")
	if len(ks) != 2 || ks[0].Status != store.KeyCurrent || ks[1].Status != store.KeyNext {
		t.Fatalf("keys after Ensure: %+v", ks)
	}
	for _, k := range ks {
		if k.Alg != "RS256" || len(k.KID) != 43 { // base64url SHA-256 thumbprint
			t.Errorf("key %q alg %q", k.KID, k.Alg)
		}
	}
}

func TestJWKSFollowsRotation(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	ks, _ := st.SigningKeys().List(ctx, "ten_a")
	cur, next := ks[0].KID, ks[1].KID

	set, err := m.JWKS(ctx, "ten_a")
	if err != nil {
		t.Fatal(err)
	}
	if got := kids(set); len(got) != 2 || got[0] != cur || got[1] != next {
		t.Fatalf("JWKS kids = %v, want [%s %s]", got, cur, next)
	}
	for _, k := range set.Keys {
		if !k.IsPublic() || k.Use != "sig" || k.Algorithm != "RS256" {
			t.Fatalf("bad published key %+v", k)
		}
	}

	if err := m.Rotate(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	set, _ = m.JWKS(ctx, "ten_a")
	got := kids(set)
	if len(got) != 3 || got[0] != next || got[2] != cur {
		t.Fatalf("after rotate kids = %v; want next promoted first and old current last", got)
	}

	if err := m.Rotate(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	set, err = m.JWKS(ctx, "ten_a")
	if err != nil {
		t.Fatal(err)
	}
	got = kids(set)
	if len(got) != 4 {
		t.Fatalf("after second rotate kids = %v; want current, next and both retained previous keys", got)
	}
	if got[2] != cur || got[3] != next {
		t.Fatalf("after second rotate previous keys = %v; want retained keys [%s %s]", got[2:], cur, next)
	}
}

func TestSignVerifiesWithPublishedKey(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	if _, err := m.Sign(ctx, "ten_a", map[string]any{"sub": "x"}); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("Sign before Ensure: err = %v, want ErrNoSigningKey", err)
	}
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Sign(ctx, "ten_a", map[string]any{"sub": "user-1", "exp": time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	h := tok.Headers[0]
	if h.ExtraHeaders["typ"] != "JWT" {
		t.Errorf("typ = %v", h.ExtraHeaders["typ"])
	}
	set, _ := m.JWKS(ctx, "ten_a")
	if h.KeyID != set.Keys[0].KeyID {
		t.Fatalf("signed with kid %q, current is %q", h.KeyID, set.Keys[0].KeyID)
	}
	var claims map[string]any
	if err := tok.Claims(set.Key(h.KeyID)[0].Key, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestKeysAreTenantScoped(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(ctx, "ten_b"); err != nil {
		t.Fatal(err)
	}
	a, err := m.JWKS(ctx, "ten_a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.JWKS(ctx, "ten_b")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Keys) != 2 || len(b.Keys) != 2 {
		t.Fatalf("published key counts = %d, %d; want 2, 2", len(a.Keys), len(b.Keys))
	}
	for _, ka := range kids(a) {
		for _, kb := range kids(b) {
			if ka == kb {
				t.Fatal("tenants share a key")
			}
		}
	}
}

func TestVerify(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(ctx, "ten_b"); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Sign(ctx, "ten_a", map[string]any{"sub": "u1"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := m.Verify(ctx, "ten_a", raw, &got); err != nil || got["sub"] != "u1" {
		t.Fatalf("Verify = %v, %v", got, err)
	}
	if err := m.Verify(ctx, "ten_b", raw, &got); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("cross-tenant Verify err = %v", err)
	}
	if err := m.Verify(ctx, "ten_a", raw[:len(raw)-4]+"AAAA", &got); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered Verify err = %v", err)
	}
	if err := m.Verify(ctx, "ten_a", "not.a.jwt", &got); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("garbage Verify err = %v", err)
	}
	// Still valid after one rotation (key becomes "previous").
	if err := m.Rotate(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(ctx, "ten_a", raw, &got); err != nil {
		t.Fatalf("Verify after rotation: %v", err)
	}
}

// Verify accepts RS256 only: neither alg=none nor an HMAC token that names a
// published kid may pass.
func TestVerifyRejectsOtherAlgorithms(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	set, err := m.JWKS(ctx, "ten_a")
	if err != nil {
		t.Fatal(err)
	}
	kid := set.Keys[0].KeyID
	b64 := base64.RawURLEncoding.EncodeToString

	none := b64([]byte(`{"alg":"none","typ":"JWT","kid":"`+kid+`"}`)) + "." + b64([]byte(`{"sub":"u1"}`)) + "."

	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	hs, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, opts)
	if err != nil {
		t.Fatal(err)
	}
	hs256, err := jwt.Signed(hs).Claims(map[string]any{"sub": "u1"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	for name, raw := range map[string]string{"none": none, "HS256": hs256} {
		var got map[string]any
		if err := m.Verify(ctx, "ten_a", raw, &got); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: Verify err = %v, claims %v", name, err, got)
		}
	}
	noKidKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	noKidSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: noKidKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	noKid, err := jwt.Signed(noKidSigner).Claims(map[string]any{"sub": "u1"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(ctx, "ten_a", noKid, nil); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("missing kid accepted: %v", err)
	}
}

func keyStatuses(t *testing.T, st store.Store, tenantID string) map[store.KeyStatus]int {
	t.Helper()
	ks, err := st.SigningKeys().List(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[store.KeyStatus]int{}
	for _, k := range ks {
		out[k.Status]++
	}
	return out
}

func TestEnsureRepairsMissingNext(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	k, err := m.generate("ten_a", store.KeyCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SigningKeys().Create(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	got := keyStatuses(t, st, "ten_a")
	if len(got) != 2 || got[store.KeyCurrent] != 1 || got[store.KeyNext] != 1 {
		t.Fatalf("statuses after Ensure: %v", got)
	}
}

func TestEnsureRepairsMissingCurrent(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	k, err := m.generate("ten_a", store.KeyNext)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SigningKeys().Create(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	got := keyStatuses(t, st, "ten_a")
	if len(got) != 2 || got[store.KeyCurrent] != 1 || got[store.KeyNext] != 1 {
		t.Fatalf("statuses after Ensure: %v", got)
	}
}

func TestEnsureLeavesCompleteSetAlone(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	before, _ := st.SigningKeys().List(ctx, "ten_a")
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	after, _ := st.SigningKeys().List(ctx, "ten_a")
	if len(before) != 2 || len(after) != 2 {
		t.Fatalf("before %d after %d keys", len(before), len(after))
	}
	for i := range before {
		if before[i].KID != after[i].KID || before[i].Status != after[i].Status {
			t.Fatalf("key %d changed: %+v -> %+v", i, before[i], after[i])
		}
	}
}

func TestEnsureConcurrentManagers(t *testing.T) {
	m1, st := newManager(t)
	w, err := NewLocalWrapper(testMasterKey(7))
	if err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(st.SigningKeys(), w)
	ctx := context.Background()
	errs := make(chan error, 2)
	for _, m := range []*Manager{m1, m2} {
		go func() { errs <- m.Ensure(ctx, "ten_a") }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	got := keyStatuses(t, st, "ten_a")
	if len(got) != 2 || got[store.KeyCurrent] != 1 || got[store.KeyNext] != 1 {
		t.Fatalf("statuses after concurrent Ensure: %v", got)
	}
}
