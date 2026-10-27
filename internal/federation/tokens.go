package federation

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// tokensLabel versions the sealed token record; the AAD binds it to the
// stable identity key (tenant, connection, subject), so link and unlink move
// ownership without decrypting.
const tokensLabel = "federation-tokens/v1"

type tokenRecord struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitzero"`
}

// SealTokens encrypts the latest upstream tokens of one identity. The ID
// token is not kept.
func SealTokens(w keys.Wrapper, key store.FederatedIdentityKey, t TokenSet) ([]byte, error) {
	if t.AccessToken == "" {
		return nil, errors.New("federation: no access token to seal")
	}
	plain, err := json.Marshal(tokenRecord{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, TokenType: t.TokenType, Scope: t.Scope, ExpiresAt: t.ExpiresAt})
	if err != nil {
		return nil, errors.New("federation: encode tokens")
	}
	return keys.SealBound(w, tokensLabel, []string{key.TenantID, key.ConnectionID, key.Subject}, plain)
}

// OpenTokens reverses SealTokens under the same identity key.
func OpenTokens(w keys.Wrapper, key store.FederatedIdentityKey, sealed []byte) (TokenSet, error) {
	plain, err := keys.OpenBound(w, tokensLabel, []string{key.TenantID, key.ConnectionID, key.Subject}, sealed)
	if err != nil {
		return TokenSet{}, err
	}
	var r tokenRecord
	if err := json.Unmarshal(plain, &r); err != nil || r.AccessToken == "" {
		return TokenSet{}, errors.New("federation: malformed token record")
	}
	return TokenSet{AccessToken: r.AccessToken, RefreshToken: r.RefreshToken, TokenType: r.TokenType, Scope: r.Scope, ExpiresAt: r.ExpiresAt}, nil
}
