package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// ErrMyOrgUnavailable reports a storage plugin without the my_org.v1
// capability (Plan 42b): it cannot store applications' My Organization
// configurations or the roles visible to the My Organization API.
var ErrMyOrgUnavailable = errors.New("store: my_org.v1 unavailable")

// MyOrgClientConfig is an application's my_organization_configuration,
// stored as the validated JSON object (internal/myorgrules).
type MyOrgClientConfig struct {
	TenantID, ClientID string
	Doc                json.RawMessage
}

// Clone returns a deep copy.
func (c *MyOrgClientConfig) Clone() *MyOrgClientConfig {
	if c == nil {
		return nil
	}
	out := *c
	out.Doc = bytes.Clone(c.Doc)
	return &out
}

// MyOrgStore stores the My Organization API's settings (my_org.v1).
// Deleting a client deletes its configuration, deleting a role its
// visibility, deleting a tenant both.
type MyOrgStore interface {
	// PutMyOrgClientConfig creates or replaces c.
	PutMyOrgClientConfig(ctx context.Context, c *MyOrgClientConfig) error
	// GetMyOrgClientConfig returns ErrNotFound when the client has none.
	GetMyOrgClientConfig(ctx context.Context, tenantID, clientID string) (*MyOrgClientConfig, error)
	// DeleteMyOrgClientConfig removes a configuration; absent is not an error.
	DeleteMyOrgClientConfig(ctx context.Context, tenantID, clientID string) error
	// SetMyOrgRoleVisible marks a role visible (or not) to the API.
	SetMyOrgRoleVisible(ctx context.Context, tenantID, roleID string, visible bool) error
	// ListMyOrgVisibleRoles returns the visible role IDs, sorted.
	ListMyOrgVisibleRoles(ctx context.Context, tenantID string) ([]string, error)
}

// MyOrgSupporter is implemented by stores that can tell whether they store
// My Organization settings.
type MyOrgSupporter interface{ CheckMyOrgSupport(context.Context) error }

// MyOrg returns s's MyOrgStore after checking the capability.
func MyOrg(ctx context.Context, s Store) (MyOrgStore, error) {
	if capability, ok := s.(MyOrgSupporter); ok {
		if err := capability.CheckMyOrgSupport(ctx); err != nil {
			return nil, err
		}
	}
	repo, ok := s.(MyOrgStore)
	if !ok {
		return nil, ErrMyOrgUnavailable
	}
	return repo, nil
}

// MyOrgAPIPath is the path of the My Organization API audience (Plan 42b).
const MyOrgAPIPath = "/my-org/"

// RBACRefused reports whether api refuses role and user permissions: system
// APIs do, except the My Organization API, whose permissions administrators
// hold through organization roles (LR42b-5). Only zeroauthy creates system
// APIs, so the identifier's path is decisive.
func RBACRefused(api *ResourceServer) bool {
	return api.IsSystem && !strings.HasSuffix(api.Identifier, MyOrgAPIPath)
}
