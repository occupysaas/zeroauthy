package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// DirectoryProvisioning is a google-apps connection's directory
// provisioning configuration (Plan 37c Phase C, migration 0048). Doc holds
// the Management fields (mapping, synchronize_automatically,
// synchronize_groups). AdminGrant is the sealed Directory API refresh token
// from the administrator consent; it never leaves the server.
type DirectoryProvisioning struct {
	TenantID, ConnectionID string
	Doc                    json.RawMessage
	AdminGrant             []byte
	CreatedAt, UpdatedAt   time.Time
	// LastSync* describe the last finished synchronization.
	LastSyncAt                    *time.Time
	LastSyncStatus, LastSyncError string
	// SyncID names the requested or running synchronization; NextSyncAt is
	// when it is due (nil: none scheduled). LeaseUntil is a runner's claim.
	SyncID                 string
	NextSyncAt, LeaseUntil *time.Time
}

// Clone returns a deep copy.
func (p *DirectoryProvisioning) Clone() *DirectoryProvisioning {
	out := *p
	out.Doc, out.AdminGrant = slices.Clone(p.Doc), slices.Clone(p.AdminGrant)
	out.LastSyncAt, out.NextSyncAt, out.LeaseUntil = cloneTime(p.LastSyncAt), cloneTime(p.NextSyncAt), cloneTime(p.LeaseUntil)
	return &out
}

// SynchronizedGroup is a Google group selected for synchronization; Doc holds
// its Management payload (name, email, direct_members_count).
type SynchronizedGroup struct {
	GroupID string
	Doc     json.RawMessage
}

// ErrDirectorySyncUnavailable reports a storage plugin without scim.v1
// version 3.
var ErrDirectorySyncUnavailable = errors.New("store: directory provisioning is not supported by this storage plugin")

// DirectorySync stores directory provisioning. Configurations and their
// groups are removed with their connection or tenant.
type DirectorySync interface {
	// CreateProvisioning fails with ErrConflict when the connection has one.
	CreateProvisioning(ctx context.Context, p *DirectoryProvisioning) error
	GetProvisioning(ctx context.Context, tenantID, connectionID string) (*DirectoryProvisioning, error)
	// UpdateProvisioning replaces every field but CreatedAt.
	UpdateProvisioning(ctx context.Context, p *DirectoryProvisioning) error
	// DeleteProvisioning also deletes its synchronized groups.
	DeleteProvisioning(ctx context.Context, tenantID, connectionID string) error
	// ListProvisionings orders by connection ID.
	ListProvisionings(ctx context.Context, tenantID string, p Page) ([]*DirectoryProvisioning, int, error)
	// ClaimDue leases up to limit configurations of any tenant whose
	// NextSyncAt has passed and whose lease is free, until now+lease.
	ClaimDue(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]*DirectoryProvisioning, error)

	// ReplaceGroups sets the connection's group selection; ListGroups orders
	// by group ID.
	ReplaceGroups(ctx context.Context, tenantID, connectionID string, groups []SynchronizedGroup) error
	ListGroups(ctx context.Context, tenantID, connectionID string) ([]SynchronizedGroup, error)
}

// DirectorySyncSupporter reports scim.v1 version 3.
type DirectorySyncSupporter interface{ DirectorySyncSupported() bool }

// DirectorySyncAvailable reports whether st stores directory provisioning.
func DirectorySyncAvailable(st Store) bool {
	if s, ok := st.(DirectorySyncSupporter); ok {
		return s.DirectorySyncSupported()
	}
	return false
}

// UnimplementedDirectorySync fails every call with
// ErrDirectorySyncUnavailable.
type UnimplementedDirectorySync struct{}

func (UnimplementedDirectorySync) CreateProvisioning(context.Context, *DirectoryProvisioning) error {
	return ErrDirectorySyncUnavailable
}
func (UnimplementedDirectorySync) GetProvisioning(context.Context, string, string) (*DirectoryProvisioning, error) {
	return nil, ErrDirectorySyncUnavailable
}
func (UnimplementedDirectorySync) UpdateProvisioning(context.Context, *DirectoryProvisioning) error {
	return ErrDirectorySyncUnavailable
}
func (UnimplementedDirectorySync) DeleteProvisioning(context.Context, string, string) error {
	return ErrDirectorySyncUnavailable
}
func (UnimplementedDirectorySync) ListProvisionings(context.Context, string, Page) ([]*DirectoryProvisioning, int, error) {
	return nil, 0, ErrDirectorySyncUnavailable
}
func (UnimplementedDirectorySync) ClaimDue(context.Context, time.Time, time.Duration, int) ([]*DirectoryProvisioning, error) {
	return nil, ErrDirectorySyncUnavailable
}
func (UnimplementedDirectorySync) ReplaceGroups(context.Context, string, string, []SynchronizedGroup) error {
	return ErrDirectorySyncUnavailable
}
func (UnimplementedDirectorySync) ListGroups(context.Context, string, string) ([]SynchronizedGroup, error) {
	return nil, ErrDirectorySyncUnavailable
}
