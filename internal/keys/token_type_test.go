package keys

import (
	"context"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"testing"
)

func TestRBACSigningType(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"JWT", "at+jwt", "JWT", "at+jwt"} {
		raw, err := m.SignWithType(ctx, "ten_a", map[string]any{"sub": "user"}, typ)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Headers[0].ExtraHeaders[jose.HeaderType] != typ {
			t.Fatalf("typ = %v, want %s", parsed.Headers[0].ExtraHeaders[jose.HeaderType], typ)
		}
		var claims map[string]any
		if err := m.Verify(ctx, "ten_a", raw, &claims); err != nil || claims["sub"] != "user" {
			t.Fatalf("verification: %#v %v", claims, err)
		}
	}
	for _, typ := range []string{"", "jwt", "application/jwt", "HS256"} {
		if _, err := m.SignWithType(ctx, "ten_a", map[string]any{}, typ); err == nil {
			t.Fatalf("accepted token type %q", typ)
		}
	}
}
