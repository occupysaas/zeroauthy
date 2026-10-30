package actions

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// InvitationDelivery is sealed into the existing leased ActionJob envelope.
// It contains frozen presentation context and resource IDs, never a bearer URL.
// The worker reloads active invitation state and opens the ticket just before send.
type InvitationDelivery struct {
	TenantID, OrganizationID, InvitationID, ClientID                                                 string
	OrganizationName, OrganizationDisplayName, ApplicationName, InviterName                          string
	NotificationHost, Language, TenantName, TenantFriendlyName, TenantSupportEmail, TenantSupportURL string
	OrganizationBranding                                                                             *store.OrgBranding
	OrganizationMetadata                                                                             map[string]string
	TemplateFields                                                                                   map[string]string
	Disabled                                                                                         bool
	Provider                                                                                         *store.EmailProvider
	CustomDomain                                                                                     map[string]any
}

// InvitationEmailDispatcher renders and delivers without creating another job.
// Snapshot runs within the creation transaction; Deliver opens only the active ticket.
type InvitationEmailDispatcher interface {
	SnapshotInvitation(context.Context, store.Store, *InvitationDelivery) error
	DeliverInvitation(context.Context, InvitationDelivery, *store.OrganizationInvitation) (*EmailInput, error)
}

var ErrInvitationProviderConfiguration = errors.New("actions: invalid invitation email provider configuration")

const InvitationDeliveryTrigger = TriggerCustomEmailProvider

func (e *Engine) EnqueueInvitation(ctx context.Context, tx store.Store, in InvitationDelivery) error {
	if in.TenantID == "" || in.OrganizationID == "" || in.InvitationID == "" || in.ClientID == "" {
		return store.ErrInvalid
	}
	// Reject a broken enabled provider before committing delivery work. Missing
	// provider means the configured global mailer will be selected by delivery.
	provider, err := tx.EmailProviders().Get(ctx, in.TenantID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err == nil && provider.Enabled && provider.Name == "custom" {
		bound, err := tx.Actions().Bindings(ctx, in.TenantID, TriggerCustomEmailProvider)
		if err != nil {
			return err
		}
		if len(bound) == 0 {
			return ErrEmailUnbound
		}
	}
	if err == nil && provider.Enabled && provider.Name != "custom" {
		plain, openErr := keys.OpenEmailProvider(e.Secrets, in.TenantID, provider.Name, provider.SealedCredentials)
		if openErr != nil {
			return ErrInvitationProviderConfiguration
		}
		credentials := map[string]any{}
		if json.Unmarshal(plain, &credentials) != nil {
			return ErrInvitationProviderConfiguration
		}
		factory := &providers.Factory{}
		if _, configErr := factory.New(ctx, in.TenantID, provider.Revision, providers.Config{Name: provider.Name, Credentials: credentials, Settings: provider.PublicConfig}); configErr != nil {
			return ErrInvitationProviderConfiguration
		}
	}
	if e.InvitationEmail != nil {
		if err := e.InvitationEmail.SnapshotInvitation(ctx, tx, &in); err != nil {
			return err
		}
	}
	p := jobPayload{Kind: "invitation", Invitation: &in}
	var ids []string
	if provider != nil && provider.Enabled && provider.Name == "custom" {
		bound, err := tx.Actions().Bindings(ctx, in.TenantID, TriggerCustomEmailProvider)
		if err != nil {
			return err
		}
		for _, u := range pinned(bound) {
			versions, err := resolveModuleVersions(ctx, tx.Actions(), in.TenantID, u)
			if err != nil {
				return err
			}
			p.Units = append(p.Units, continueUnit{Name: u.name, ActionID: u.actionID, VersionKey: u.versionKey, Code: u.code, BuildID: u.buildID, Secrets: u.secrets, Modules: u.moduleRefs, ModuleVersions: versions})
			for _, v := range versions {
				ids = append(ids, v.ID)
			}
		}
	}

	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	now := e.now()
	job := &store.ActionJob{TenantID: in.TenantID, ID: "ajob_" + secrets.RandomString(24), Trigger: InvitationDeliveryTrigger, Status: "pending", NextAt: now, CreatedAt: now, UpdatedAt: now, ModuleVersionIDs: ids}
	job.Sealed, err = keys.SealBound(e.Secrets, jobLabel, []string{job.TenantID, job.ID, job.Trigger}, plain)
	if err != nil {
		return err
	}
	return tx.Actions().EnqueueJob(ctx, job)
}
