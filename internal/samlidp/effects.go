package samlidp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sort"

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// applyEffects returns the add-on and binding with api.samlResponse.*
// settings applied for this response only. The stored add-on is not changed.
func applyEffects(addon *store.SAMLAddon, b Binding, e *actionresult.SAMLEffects) (*store.SAMLAddon, Binding) {
	cfg := addon.Clone()
	if e == nil {
		return cfg, b
	}
	setStr := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	setBool := func(dst **bool, v *bool) {
		if v != nil {
			c := *v
			*dst = &c
		}
	}
	setStr(&b.Audience, e.Audience)
	setStr(&cfg.Audience, e.Audience)
	setStr(&cfg.Recipient, e.Recipient)
	setStr(&cfg.Destination, e.Destination)
	setStr(&cfg.Issuer, e.Issuer)
	setStr(&cfg.SignatureAlgorithm, e.SignatureAlgorithm)
	setStr(&cfg.DigestAlgorithm, e.DigestAlgorithm)
	setStr(&cfg.NameIdentifierFormat, e.NameIdentifierFormat)
	setStr(&cfg.AuthnContextClassRef, e.AuthnContextClassRef)
	if e.RelayState != nil {
		b.RelayState = *e.RelayState
	}
	setBool(&cfg.CreateUpnClaim, e.CreateUpnClaim)
	setBool(&cfg.PassthroughClaimsWithNoMapping, e.PassthroughClaimsWithNoMapping)
	setBool(&cfg.MapUnknownClaimsAsIs, e.MapUnknownClaimsAsIs)
	setBool(&cfg.MapIdentities, e.MapIdentities)
	setBool(&cfg.SignResponse, e.SignResponse)
	setBool(&cfg.IncludeAttributeNameFormat, e.IncludeAttributeNameFormat)
	setBool(&cfg.TypedAttributes, e.TypedAttributes)
	if e.LifetimeInSeconds != nil {
		n := *e.LifetimeInSeconds
		cfg.LifetimeInSeconds = &n
	}
	if e.NameIdentifierProbes != nil {
		cfg.NameIdentifierProbes = append([]string(nil), e.NameIdentifierProbes...)
	}
	return cfg, b
}

// overrideAttributes applies setAttribute values (replacing by name) and
// removals.
func overrideAttributes(in []samlcore.Attribute, e *actionresult.SAMLEffects) []samlcore.Attribute {
	if e == nil {
		return in
	}
	out := make([]samlcore.Attribute, 0, len(in)+len(e.Attributes))
	for _, a := range in {
		if _, replaced := e.Attributes[a.Name]; replaced {
			continue
		}
		removed := false
		for _, r := range e.RemovedAttributes {
			removed = removed || r == a.Name
		}
		if !removed {
			out = append(out, a)
		}
	}
	names := make([]string, 0, len(e.Attributes))
	for n := range e.Attributes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, samlcore.Attribute{Name: n, Values: append([]string(nil), e.Attributes[n]...)})
	}
	return out
}

func parseRSAKey(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("samlidp: setKey needs a PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("samlidp: setKey needs an RSA private key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("samlidp: setKey needs an RSA private key")
	}
	return rk, nil
}

// effectSigner returns the Action's own signing key (setKey with setCert),
// or nil to use the tenant key. A key without its certificate, or a pair
// that does not match, is refused.
func effectSigner(e *actionresult.SAMLEffects) (*samlcore.Signer, error) {
	if e == nil || e.Key == "" && e.Cert == "" {
		return nil, nil
	}
	if e.Key == "" || e.Cert == "" {
		return nil, errors.New("samlidp: setKey and setCert must be used together")
	}
	key, err := parseRSAKey(e.Key)
	if err != nil {
		return nil, err
	}
	cert, err := clientrules.ParseCertificate(e.Cert)
	if err != nil {
		return nil, errors.New("samlidp: setCert needs a certificate")
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("samlidp: setKey and setCert do not match")
	}
	return &samlcore.Signer{Key: key, Cert: cert}, nil
}

// encryptionTarget returns a certificate carrying the key to encrypt the
// assertion for (setEncryptionCert or setEncryptionPublicKey), or nil.
func encryptionTarget(e *actionresult.SAMLEffects) (*x509.Certificate, error) {
	if e == nil {
		return nil, nil
	}
	if e.EncryptionCert != "" {
		return clientrules.ParseCertificate(e.EncryptionCert)
	}
	if e.EncryptionPublicKey == "" {
		return nil, nil
	}
	block, _ := pem.Decode([]byte(e.EncryptionPublicKey))
	if block == nil {
		return nil, errors.New("samlidp: setEncryptionPublicKey needs a PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if rk, err2 := x509.ParsePKCS1PublicKey(block.Bytes); err2 == nil {
			pub = rk
		} else {
			return nil, errors.New("samlidp: setEncryptionPublicKey needs an RSA public key")
		}
	}
	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("samlidp: setEncryptionPublicKey needs an RSA public key")
	}
	return &x509.Certificate{PublicKey: rk}, nil
}
