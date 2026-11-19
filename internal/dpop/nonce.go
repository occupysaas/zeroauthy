package dpop

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"time"
)

func nonceAAD(res tenant.Resolved, jkt string, domain NonceDomain) []byte {
	return []byte("zeroauthy:dpop-nonce:v1\x00" + string(domain) + "\x00" + res.Tenant.ID + "\x00" + res.Issuer() + "\x00" + jkt)
}
func (s *Service) newNonce(res tenant.Resolved, jkt string, domain NonceDomain, now time.Time) (string, error) {
	if s.Wrapper == nil || (domain != AuthorizationServer && domain != UserInfo) {
		return "", errors.New("nonce unavailable")
	}
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b, uint64(now.Unix()))
	if _, e := rand.Read(b[8:]); e != nil {
		return "", e
	}
	sealed, e := s.Wrapper.Wrap(b, nonceAAD(res, jkt, domain))
	if e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}
func (s *Service) validNonce(raw string, res tenant.Resolved, jkt string, domain NonceDomain, now time.Time) bool {
	if s.Wrapper == nil || len(raw) > 1024 || raw == "" {
		return false
	}
	b, e := base64.RawURLEncoding.DecodeString(raw)
	if e != nil {
		return false
	}
	plain, e := s.Wrapper.Unwrap(b, nonceAAD(res, jkt, domain))
	if e != nil || len(plain) != 32 {
		return false
	}
	iat := int64(binary.BigEndian.Uint64(plain))
	return iat <= now.Unix() && iat > now.Unix()-60
}
