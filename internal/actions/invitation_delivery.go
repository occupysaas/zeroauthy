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
	p := jobPayload{Kind: "invitation", Invitation: &in}
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	now := e.now()
	job := &store.ActionJob{TenantID: in.TenantID, ID: "ajob_" + secrets.RandomString(24), Trigger: InvitationDeliveryTrigger, Status: "pending", NextAt: now, CreatedAt: now, UpdatedAt: now}
	job.Sealed, err = keys.SealBound(e.Secrets, jobLabel, []string{job.TenantID, job.ID, job.Trigger}, plain)
	if err != nil {
		return err
	}
	return tx.Actions().EnqueueJob(ctx, job)
}
