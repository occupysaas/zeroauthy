package mgmt

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/myorgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var errMyOrgUnavailable = &Error{Status: 501, Code: "not_implemented", Message: "This storage plugin cannot store My Organization settings (my_org.v1)"}

// writeMyOrgConfig stores or removes c's my_organization_configuration
// (Plan 42b) when the body named it. The landing application must exist.
func writeMyOrgConfig(ctx context.Context, tx store.Store, c *store.Client, in clientBody) error {
	if !in.myOrgSet {
		return nil
	}
	repo, err := store.MyOrg(ctx, tx)
	if errors.Is(err, store.ErrMyOrgUnavailable) {
		return errMyOrgUnavailable
	}
	if err != nil {
		return err
	}
	if in.myOrg == nil {
		return repo.DeleteMyOrgClientConfig(ctx, c.TenantID, c.ClientID)
	}
	cfg, err := myorgrules.Parse(in.myOrg)
	if err != nil {
		return badBody("%v", err)
	}
	if id := cfg.InvitationLandingClientID; id != "" {
		if _, err := tx.Clients().Get(ctx, c.TenantID, id); errors.Is(err, store.ErrNotFound) {
			return badBody("my_organization_configuration.invitation_landing_client_id: no such application")
		} else if err != nil {
			return err
		}
	}
	doc, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return repo.PutMyOrgClientConfig(ctx, &store.MyOrgClientConfig{TenantID: c.TenantID, ClientID: c.ClientID, Doc: doc})
}

// myOrgConfigView is c's stored configuration for the client view, or nil.
func myOrgConfigView(ctx context.Context, st store.Store, c *store.Client) *mgmtapi.ClientMyOrganizationConfiguration {
	repo, err := store.MyOrg(ctx, st)
	if err != nil {
		return nil
	}
	cfg, err := repo.GetMyOrgClientConfig(ctx, c.TenantID, c.ClientID)
	if err != nil {
		return nil
	}
	var v mgmtapi.ClientMyOrganizationConfiguration
	if json.Unmarshal(cfg.Doc, &v) != nil {
		return nil
	}
	return &v
}
