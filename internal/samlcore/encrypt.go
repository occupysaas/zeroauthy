package samlcore

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP MGF1-SHA1 is the XML-Enc default.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// XML Encryption algorithm URIs.
const (
	NSXMLEnc = "http://www.w3.org/2001/04/xmlenc#"

	EncAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	EncAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	EncAES128CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	EncAES256CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"

	KeyRSAOAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	// KeyRSAOAEP11SHA256 is XML-Enc 1.1 RSA-OAEP with SHA-256 digest and MGF1.
	KeyRSAOAEP11SHA256 = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	KeyRSA15           = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"

	digestSHA1URI   = "http://www.w3.org/2000/09/xmldsig#sha1"
	digestSHA256URI = "http://www.w3.org/2001/04/xmlenc#sha256"
	mgf1SHA1URI     = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
	mgf1SHA256URI   = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	typeElement     = "http://www.w3.org/2001/04/xmlenc#Element"
)

// ErrDecrypt is the only decryption failure reported: callers cannot tell a
// padding failure from a key or authentication failure.
var ErrDecrypt = errors.New("samlcore: encrypted assertion could not be decrypted")

var dataKeySizes = map[string]int{EncAES128GCM: 16, EncAES256GCM: 32, EncAES128CBC: 16, EncAES256CBC: 32}

// Decryption is the policy for opening encrypted assertions. RSA-1_5 key
// transport is refused unless AllowRSA15 (D-0130 ruling §9.3).
type Decryption struct {
	AllowRSA15 bool
}

// EncryptAssertion encrypts a standalone Assertion for the holder of cert's
// key and returns the saml:EncryptedAssertion element.
func EncryptAssertion(assertion *etree.Element, cert *x509.Certificate, dataAlg, keyAlg string) (*etree.Element, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	size, known := dataKeySizes[dataAlg]
	if assertion == nil || !ok || !known {
		return nil, errorf("unsupported encryption parameters")
	}
	doc := etree.NewDocument()
	doc.SetRoot(assertion.Copy())
	plain, err := doc.WriteToBytes()
	if err != nil {
		return nil, errorf("serialize assertion")
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	sealed, err := sealData(dataAlg, key, plain)
	if err != nil {
		return nil, err
	}
	var wrapped []byte
	switch keyAlg {
	case KeyRSAOAEP:
		wrapped, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, key, nil) //nolint:gosec // XML-Enc rsa-oaep-mgf1p.
	case KeyRSAOAEP11SHA256:
		wrapped, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
	case KeyRSA15:
		wrapped, err = rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	default:
		return nil, errorf("unsupported key transport")
	}
	if err != nil {
		return nil, errorf("wrap key")
	}
	ea := etree.NewElement("saml:EncryptedAssertion")
	ea.CreateAttr("xmlns:saml", NSAssertion)
	ed := ea.CreateElement("xenc:EncryptedData")
	ed.CreateAttr("xmlns:xenc", NSXMLEnc)
	ed.CreateAttr("Type", typeElement)
	ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", dataAlg)
	ki := ed.CreateElement("ds:KeyInfo")
	ki.CreateAttr("xmlns:ds", NSDSig)
	ek := ki.CreateElement("xenc:EncryptedKey")
	em := ek.CreateElement("xenc:EncryptionMethod")
	em.CreateAttr("Algorithm", keyAlg)
	switch keyAlg {
	case KeyRSAOAEP:
		dm := em.CreateElement("ds:DigestMethod")
		dm.CreateAttr("Algorithm", digestSHA1URI)
	case KeyRSAOAEP11SHA256:
		dm := em.CreateElement("ds:DigestMethod")
		dm.CreateAttr("Algorithm", digestSHA256URI)
		mgf := em.CreateElement("xenc11:MGF")
		mgf.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
		mgf.CreateAttr("Algorithm", mgf1SHA256URI)
	}
	ek.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))
	ed.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(sealed))
	return ea, nil
}

func sealData(alg string, key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch alg {
	case EncAES128GCM, EncAES256GCM:
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		iv := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
		return gcm.Seal(iv, iv, plain, nil), nil
	default:
		pad := aes.BlockSize - len(plain)%aes.BlockSize
		padded := append(append([]byte(nil), plain...), make([]byte, pad)...)
		padded[len(padded)-1] = byte(pad)
		out := make([]byte, aes.BlockSize+len(padded))
		if _, err := rand.Read(out[:aes.BlockSize]); err != nil {
			return nil, err
		}
		cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], padded)
		return out, nil
	}
}

func openData(alg string, key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	switch alg {
	case EncAES128GCM, EncAES256GCM:
		gcm, err := cipher.NewGCM(block)
		if err != nil || len(sealed) < gcm.NonceSize()+gcm.Overhead() {
			return nil, ErrDecrypt
		}
		plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
		if err != nil {
			return nil, ErrDecrypt
		}
		return plain, nil
	case EncAES128CBC, EncAES256CBC:
		if len(sealed) < 2*aes.BlockSize || len(sealed)%aes.BlockSize != 0 {
			return nil, ErrDecrypt
		}
		out := make([]byte, len(sealed)-aes.BlockSize)
		cipher.NewCBCDecrypter(block, sealed[:aes.BlockSize]).CryptBlocks(out, sealed[aes.BlockSize:])
		pad := int(out[len(out)-1])
		if pad < 1 || pad > aes.BlockSize {
			return nil, ErrDecrypt
		}
		return out[:len(out)-pad], nil
	}
	return nil, ErrDecrypt
}

func cipherValue(el *etree.Element) ([]byte, error) {
	cd := directChildren(el, NSXMLEnc, "CipherData")
	if len(cd) != 1 {
		return nil, ErrDecrypt
	}
	cv := directChildren(cd[0], NSXMLEnc, "CipherValue")
	if len(cv) != 1 {
		return nil, ErrDecrypt
	}
	out, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(cv[0].Text()), ""))
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

func oaepHash(uri string) (crypto.Hash, bool) {
	switch uri {
	case "", digestSHA1URI, mgf1SHA1URI:
		return crypto.SHA1, true
	case digestSHA256URI, mgf1SHA256URI:
		return crypto.SHA256, true
	}
	return 0, false
}

// unwrapKey opens one EncryptedKey. A failure of any kind returns ErrDecrypt;
// RSA-1_5 uses the constant-time session-key API.
func unwrapKey(ek *etree.Element, key *rsa.PrivateKey, size int, policy Decryption) ([]byte, error) {
	em := directChildren(ek, NSXMLEnc, "EncryptionMethod")
	if len(em) != 1 {
		return nil, ErrDecrypt
	}
	wrapped, err := cipherValue(ek)
	if err != nil {
		return nil, err
	}
	switch em[0].SelectAttrValue("Algorithm", "") {
	case KeyRSAOAEP, KeyRSAOAEP11SHA256:
		digest, mgf := "", ""
		for _, c := range em[0].ChildElements() {
			switch c.Tag {
			case "DigestMethod":
				digest = c.SelectAttrValue("Algorithm", "")
			case "MGF":
				mgf = c.SelectAttrValue("Algorithm", "")
			}
		}
		h, ok1 := oaepHash(digest)
		m, ok2 := oaepHash(mgf)
		if em[0].SelectAttrValue("Algorithm", "") == KeyRSAOAEP {
			m, ok2 = crypto.SHA1, true // mgf1p is MGF1 with SHA-1
		}
		if !ok1 || !ok2 {
			return nil, ErrDecrypt
		}
		plain, err := key.Decrypt(nil, wrapped, &rsa.OAEPOptions{Hash: h, MGFHash: m})
		if err != nil || len(plain) != size {
			return nil, ErrDecrypt
		}
		return plain, nil
	case KeyRSA15:
		if !policy.AllowRSA15 {
			return nil, ErrWeakAlg
		}
		session := make([]byte, size)
		if _, err := rand.Read(session); err != nil {
			return nil, ErrDecrypt
		}
		if err := rsa.DecryptPKCS1v15SessionKey(nil, key, wrapped, session); err != nil {
			return nil, ErrDecrypt
		}
		return session, nil
	}
	return nil, ErrDecrypt
}

// inScopeNamespaces returns the xmlns declarations visible at el.
func inScopeNamespaces(el *etree.Element) map[string]string {
	out := map[string]string{}
	for e := el; e != nil; e = e.Parent() {
		for _, a := range e.Attr {
			if a.Space == "xmlns" {
				if _, seen := out[a.Key]; !seen {
					out[a.Key] = a.Value
				}
			}
		}
	}
	return out
}

// DecryptAssertion opens a saml:EncryptedAssertion with the SP's private key.
// The EncryptedKey may sit in EncryptedData/KeyInfo or beside EncryptedData.
// The plaintext is parsed with Parse's limits, in the namespace context of
// the encrypted element.
func DecryptAssertion(encrypted *etree.Element, key *rsa.PrivateKey, policy Decryption) (*etree.Element, error) {
	if encrypted == nil || key == nil || !inNS(encrypted, NSAssertion, "EncryptedAssertion") {
		return nil, ErrDecrypt
	}
	eds := directChildren(encrypted, NSXMLEnc, "EncryptedData")
	if len(eds) != 1 {
		return nil, ErrDecrypt
	}
	ed := eds[0]
	em := directChildren(ed, NSXMLEnc, "EncryptionMethod")
	if len(em) != 1 {
		return nil, ErrDecrypt
	}
	dataAlg := em[0].SelectAttrValue("Algorithm", "")
	size, ok := dataKeySizes[dataAlg]
	if !ok {
		return nil, ErrDecrypt
	}
	var keys []*etree.Element
	for _, ki := range directChildren(ed, NSDSig, "KeyInfo") {
		keys = append(keys, directChildren(ki, NSXMLEnc, "EncryptedKey")...)
	}
	keys = append(keys, directChildren(encrypted, NSXMLEnc, "EncryptedKey")...)
	sealed, err := cipherValue(ed)
	if err != nil {
		return nil, err
	}
	for _, ek := range keys {
		dataKey, err := unwrapKey(ek, key, size, policy)
		if errors.Is(err, ErrWeakAlg) {
			return nil, err
		}
		if err != nil {
			continue
		}
		plain, err := openData(dataAlg, dataKey, sealed)
		if err != nil {
			return nil, ErrDecrypt
		}
		return parseInContext(encrypted, plain)
	}
	return nil, ErrDecrypt
}

func parseInContext(ctx *etree.Element, plain []byte) (*etree.Element, error) {
	plain = []byte(strings.TrimSpace(strings.TrimPrefix(string(plain), "\ufeff")))
	if i := strings.Index(string(plain), "?>"); strings.HasPrefix(string(plain), "<?xml") && i > 0 {
		plain = plain[i+2:]
	}
	var wrap strings.Builder
	wrap.WriteString("<zeroauthy-decrypted")
	for prefix, uri := range inScopeNamespaces(ctx) {
		wrap.WriteString(" xmlns:" + prefix + `="` + escapeAttr(uri) + `"`)
	}
	wrap.WriteString(">")
	wrap.Write(plain)
	wrap.WriteString("</zeroauthy-decrypted>")
	doc, err := Parse([]byte(wrap.String()))
	if err != nil {
		return nil, ErrDecrypt
	}
	kids := doc.Root().ChildElements()
	if len(kids) != 1 {
		return nil, ErrDecrypt
	}
	out, err := detach(kids[0])
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

func escapeAttr(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;").Replace(s)
}
