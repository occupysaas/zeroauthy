package store

import (
	"context"
	"errors"
	"slices"
	"time"
)

var ErrTLSAssetRepositoryUnavailable = errors.New("store: TLS asset repository unavailable; upgrade the storage driver")

const (
	TLSAssetAccount     = "account"
	TLSAssetOrder       = "order"
	TLSAssetCertificate = "certificate"
	TLSAssetChallenge   = "challenge"
	TLSAssetDNSIntent   = "dns-intent"
)

// TLSPublicData is versioned non-secret TLS metadata. Private keys and provider
// credentials belong exclusively in TLSAsset.Ciphertext. Certificate chains,
// challenge values, and owned DNS record identifiers are public information.
type TLSPublicData struct {
	Version                                            int
	DirectoryURL, AccountURL, OrderURL, Status         string
	ChallengeType, Identifier, Token, KeyAuthorization string
	RecordName, RecordValue, DNSRecordID               string
	CertificateChainPEM                                []byte
	SANs                                               []string
	NotBefore, NotAfter                                time.Time
}

// TLSAsset stores sealed key material separately from public recovery metadata.
// TenantID/DomainID/Generation are empty/zero for deployment account assets.
type TLSAsset struct {
	Key, Kind, TenantID, DomainID string
	Generation, Revision          int64
	Ciphertext                    []byte
	PublicData                    TLSPublicData
	ExpiresAt                     time.Time
}

func (a *TLSAsset) Clone() *TLSAsset {
	if a == nil {
		return nil
	}
	c := *a
	c.Ciphertext = slices.Clone(a.Ciphertext)
	c.PublicData.CertificateChainPEM = slices.Clone(a.PublicData.CertificateChainPEM)
	c.PublicData.SANs = slices.Clone(a.PublicData.SANs)
	return &c
}

// TLSLease's Fence monotonically increases across releases and reacquisitions.
// Storage time decides validity: now >= Until is expired.
type TLSLease struct {
	Key, Owner string
	Fence      int64
	Until      time.Time
}

// TLSAssets returns copies and uses storage time for lease/expiry decisions.
// Implementations reject stale revisions/fences with ErrConflict, missing rows
// with ErrNotFound and invalid arguments with ErrInvalid.
type TLSAssets interface {
	Get(ctx context.Context, key string) (*TLSAsset, error)
	// Put creates at expectedRevision=0; successful writes increment revision.
	Put(ctx context.Context, row *TLSAsset, expectedRevision int64) error
	Delete(ctx context.Context, key string, expectedRevision int64) error
	// ListExpired is ordered by key, with expiry evaluated against storage time.
	ListExpired(ctx context.Context, limit int) ([]*TLSAsset, error)
	ClaimLease(ctx context.Context, key, owner string, duration time.Duration) (*TLSLease, error)
	RenewLease(ctx context.Context, lease TLSLease, duration time.Duration) (*TLSLease, error)
	// CheckLease participates in Store.WithTx: validation and a subsequent write
	// in that transaction cannot race takeover. Never hold a tx over network I/O.
	CheckLease(ctx context.Context, lease TLSLease) error
	ReleaseLease(ctx context.Context, lease TLSLease) error
}

type UnimplementedTLSAssets struct{}

func (UnimplementedTLSAssets) Get(context.Context, string) (*TLSAsset, error) {
	return nil, ErrTLSAssetRepositoryUnavailable
}
func (UnimplementedTLSAssets) Put(context.Context, *TLSAsset, int64) error {
	return ErrTLSAssetRepositoryUnavailable
}
func (UnimplementedTLSAssets) Delete(context.Context, string, int64) error {
	return ErrTLSAssetRepositoryUnavailable
}
func (UnimplementedTLSAssets) ListExpired(context.Context, int) ([]*TLSAsset, error) {
	return nil, ErrTLSAssetRepositoryUnavailable
}
func (UnimplementedTLSAssets) ClaimLease(context.Context, string, string, time.Duration) (*TLSLease, error) {
	return nil, ErrTLSAssetRepositoryUnavailable
}
func (UnimplementedTLSAssets) RenewLease(context.Context, TLSLease, time.Duration) (*TLSLease, error) {
	return nil, ErrTLSAssetRepositoryUnavailable
}
func (UnimplementedTLSAssets) CheckLease(context.Context, TLSLease) error {
	return ErrTLSAssetRepositoryUnavailable
}
func (UnimplementedTLSAssets) ReleaseLease(context.Context, TLSLease) error {
	return ErrTLSAssetRepositoryUnavailable
}
