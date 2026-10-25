package keycert

import (
	"encoding/asn1"
	"errors"
)

var (
	contentInfoOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	idDataOID      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"tag:0,optional,explicit"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit"`
}

// certificatePKCS7 emits the certificate-only SignedData subset required by
// RFC 5652. It intentionally has no signers and no encapsulated content.
func certificatePKCS7(certDER []byte) ([]byte, error) {
	if len(certDER) == 0 {
		return nil, errors.New("keycert: empty certificate")
	}
	if _, err := asn1.Unmarshal(certDER, new(asn1.RawValue)); err != nil {
		return nil, err
	}
	certs := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certDER}
	sdDER, err := asn1.Marshal(signedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{},
		EncapContentInfo: encapsulatedContentInfo{EContentType: idDataOID},
		Certificates:     certs,
		SignerInfos:      []asn1.RawValue{},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(contentInfo{
		ContentType: contentInfoOID,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	})
}
