package grpcstore

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// These codecs transport private persistence records. Ciphertext remains an
// opaque sealed envelope; public certificate metadata carries no private key.
func customDomainToPB(v *store.CustomDomain) (*storev1.CustomDomain, error) {
	if v == nil {
		return nil, nil
	}
	return &storev1.CustomDomain{
		TenantId:                 v.TenantID,
		Id:                       v.ID,
		Domain:                   v.Domain,
		Type:                     v.Type,
		Source:                   v.Source,
		OriginHost:               v.OriginHost,
		Generation:               v.Generation,
		Revision:                 v.Revision,
		Status:                   v.Status,
		TlsPolicy:                v.TLSPolicy,
		CustomClientIpHeader:     v.CustomClientIPHeader,
		CustomClientIpHeaderNull: v.CustomClientIPHeaderNull,
		RelyingPartyIdentifier:   v.RelyingPartyIdentifier,
		DomainMetadata:           stringMapToPB(v.DomainMetadata),
		VerificationMethod:       v.VerificationMethod,
		ProofRecordName:          v.ProofRecordName,
		ProofRecordValue:         v.ProofRecordValue,
		ProofStatus:              v.ProofStatus,
		ProofToken:               cloneBytes(v.ProofToken),
		ProofCreatedAt:           tsToPB(v.ProofCreatedAt),
		ProofVerifiedAt:          optTSToPB(v.ProofVerifiedAt),
		LastProofCheckAt:         optTSToPB(v.LastProofCheckAt),
		ProofFailureSince:        optTSToPB(v.ProofFailureSince),
		Lifecycle:                v.Lifecycle,
		NextAttemptAt:            optTSToPB(v.NextAttemptAt),
		AttemptCount:             int64(v.AttemptCount),
		LastFailure:              v.LastFailure,
		ProxyKeyHash:             cloneBytes(v.ProxyKeyHash),
		ActiveCertificateKey:     v.ActiveCertificateKey,
		CreatedAt:                tsToPB(v.CreatedAt),
		UpdatedAt:                tsToPB(v.UpdatedAt),
	}, nil
}
func customDomainFromPB(v *storev1.CustomDomain) (*store.CustomDomain, error) {
	if v == nil {
		return nil, nil
	}
	if err := checkTS(v.ProofCreatedAt, v.ProofVerifiedAt, v.LastProofCheckAt, v.ProofFailureSince, v.NextAttemptAt, v.CreatedAt, v.UpdatedAt); err != nil {
		return nil, err
	}
	out := &store.CustomDomain{
		TenantID:                 v.TenantId,
		ID:                       v.Id,
		Domain:                   v.Domain,
		Type:                     v.Type,
		Source:                   v.Source,
		OriginHost:               v.OriginHost,
		Generation:               v.Generation,
		Revision:                 v.Revision,
		Status:                   v.Status,
		TLSPolicy:                v.TlsPolicy,
		CustomClientIPHeader:     v.CustomClientIpHeader,
		CustomClientIPHeaderNull: v.CustomClientIpHeaderNull,
		RelyingPartyIdentifier:   v.RelyingPartyIdentifier,
		DomainMetadata:           stringMapFromPB(v.DomainMetadata),
		VerificationMethod:       v.VerificationMethod,
		ProofRecordName:          v.ProofRecordName,
		ProofRecordValue:         v.ProofRecordValue,
		ProofStatus:              v.ProofStatus,
		ProofToken:               cloneBytes(v.ProofToken),
		ProofCreatedAt:           tsFromPB(v.ProofCreatedAt),
		ProofVerifiedAt:          optTSFromPB(v.ProofVerifiedAt),
		LastProofCheckAt:         optTSFromPB(v.LastProofCheckAt),
		ProofFailureSince:        optTSFromPB(v.ProofFailureSince),
		Lifecycle:                v.Lifecycle,
		NextAttemptAt:            optTSFromPB(v.NextAttemptAt),
		AttemptCount:             int(v.AttemptCount),
		LastFailure:              v.LastFailure,
		ProxyKeyHash:             cloneBytes(v.ProxyKeyHash),
		ActiveCertificateKey:     v.ActiveCertificateKey,
		CreatedAt:                tsFromPB(v.CreatedAt),
		UpdatedAt:                tsFromPB(v.UpdatedAt),
	}
	return out, nil
}

func hostBindingToPB(v *store.HostBinding) (*storev1.HostBinding, error) {
	if v == nil {
		return nil, nil
	}
	return &storev1.HostBinding{
		Host:       v.Host,
		TenantId:   v.TenantID,
		DomainId:   v.DomainID,
		Generation: v.Generation,
		Kind:       v.Kind,
		Active:     v.Active,
	}, nil
}
func hostBindingFromPB(v *storev1.HostBinding) (*store.HostBinding, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.HostBinding{
		Host:       v.Host,
		TenantID:   v.TenantId,
		DomainID:   v.DomainId,
		Generation: v.Generation,
		Kind:       v.Kind,
		Active:     v.Active,
	}
	return out, nil
}

func tlsPublicDataToPB(v *store.TLSPublicData) (*storev1.TLSPublicData, error) {
	if v == nil {
		return nil, nil
	}
	return &storev1.TLSPublicData{
		Version:             int64(v.Version),
		DirectoryUrl:        v.DirectoryURL,
		AccountUrl:          v.AccountURL,
		OrderUrl:            v.OrderURL,
		Status:              v.Status,
		ChallengeType:       v.ChallengeType,
		Identifier:          v.Identifier,
		Token:               v.Token,
		KeyAuthorization:    v.KeyAuthorization,
		RecordName:          v.RecordName,
		RecordValue:         v.RecordValue,
		DnsRecordId:         v.DNSRecordID,
		CertificateChainPem: cloneBytes(v.CertificateChainPEM),
		Sans:                stringsToPB(v.SANs),
		NotBefore:           tsToPB(v.NotBefore),
		NotAfter:            tsToPB(v.NotAfter),
	}, nil
}
func tlsPublicDataFromPB(v *storev1.TLSPublicData) (*store.TLSPublicData, error) {
	if v == nil {
		return nil, nil
	}
	if err := checkTS(v.NotBefore, v.NotAfter); err != nil {
		return nil, err
	}
	out := &store.TLSPublicData{
		Version:             int(v.Version),
		DirectoryURL:        v.DirectoryUrl,
		AccountURL:          v.AccountUrl,
		OrderURL:            v.OrderUrl,
		Status:              v.Status,
		ChallengeType:       v.ChallengeType,
		Identifier:          v.Identifier,
		Token:               v.Token,
		KeyAuthorization:    v.KeyAuthorization,
		RecordName:          v.RecordName,
		RecordValue:         v.RecordValue,
		DNSRecordID:         v.DnsRecordId,
		CertificateChainPEM: cloneBytes(v.CertificateChainPem),
		SANs:                stringsFromPB(v.Sans),
		NotBefore:           tsFromPB(v.NotBefore),
		NotAfter:            tsFromPB(v.NotAfter),
	}
	return out, nil
}

func tlsAssetToPB(v *store.TLSAsset) (*storev1.TLSAsset, error) {
	if v == nil {
		return nil, nil
	}
	publicData, err := tlsPublicDataToPB(&v.PublicData)
	if err != nil {
		return nil, err
	}
	return &storev1.TLSAsset{
		Key:        v.Key,
		Kind:       v.Kind,
		TenantId:   v.TenantID,
		DomainId:   v.DomainID,
		Generation: v.Generation,
		Revision:   v.Revision,
		Ciphertext: cloneBytes(v.Ciphertext),
		ExpiresAt:  tsToPB(v.ExpiresAt),
		PublicData: publicData,
	}, nil
}
func tlsAssetFromPB(v *storev1.TLSAsset) (*store.TLSAsset, error) {
	if v == nil {
		return nil, nil
	}
	if err := checkTS(v.ExpiresAt); err != nil {
		return nil, err
	}
	publicData, err := tlsPublicDataFromPB(v.PublicData)
	if err != nil {
		return nil, err
	}
	out := &store.TLSAsset{
		Key:        v.Key,
		Kind:       v.Kind,
		TenantID:   v.TenantId,
		DomainID:   v.DomainId,
		Generation: v.Generation,
		Revision:   v.Revision,
		Ciphertext: cloneBytes(v.Ciphertext),
		ExpiresAt:  tsFromPB(v.ExpiresAt),
	}
	if publicData != nil {
		out.PublicData = *publicData
	}
	return out, nil
}

func tlsLeaseToPB(v *store.TLSLease) (*storev1.TLSLease, error) {
	if v == nil {
		return nil, nil
	}
	return &storev1.TLSLease{
		Key:   v.Key,
		Owner: v.Owner,
		Fence: v.Fence,
		Until: tsToPB(v.Until),
	}, nil
}
func tlsLeaseFromPB(v *storev1.TLSLease) (*store.TLSLease, error) {
	if v == nil {
		return nil, nil
	}
	if err := checkTS(v.Until); err != nil {
		return nil, err
	}
	out := &store.TLSLease{
		Key:   v.Key,
		Owner: v.Owner,
		Fence: v.Fence,
		Until: tsFromPB(v.Until),
	}
	return out, nil
}
