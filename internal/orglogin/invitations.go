package orglogin

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// These keys are server-owned transaction bindings, never authorize inputs.
const (
	InvitationIDParam         = "za_invitation_id"
	InvitationClientParam     = "za_invitation_client"
	InvitationConnectionParam = "za_invitation_connection"
	InvitationSessionParam    = "za_invitation_session"
	InvitationSignupParam     = "za_invitation_signup"
)

var ErrInvitationIdentity = errors.New("organization invitation: sign in with the verified invited email")

type AcceptanceInput struct {
	TenantID, OrganizationID, ClientID, InvitationID, TransactionID, UserID, PrimaryConnectionID string
	Now                                                                                          time.Time
}

// AcceptInvitation runs after the existing authentication pipeline completes.
// Authentication evidence is a durable session bound by the server to this
// transaction; a browser assertion of verification/completion is never used.
func AcceptInvitation(ctx context.Context, st store.Store, in AcceptanceInput) (*store.InvitationReceipt, error) {
	var result *store.InvitationReceipt
	err := st.WithTx(ctx, func(tx store.Store) error {
		txn, err := tx.AuthTransactions().Get(ctx, in.TenantID, in.TransactionID)
		if err != nil {
			return err
		}
		if !in.Now.Before(txn.ExpiresAt) || txn.ClientID != in.ClientID || txn.Params[InvitationIDParam] != in.InvitationID || txn.Params[InvitationClientParam] != in.ClientID || txn.Params[store.TxnParamOrgID] != in.OrganizationID || txn.Params[store.TxnParamOrgMode] != "fixed" {
			return store.ErrPrecondition
		}
		sess, err := tx.Sessions().Get(ctx, in.TenantID, txn.Params[InvitationSessionParam])
		if err != nil {
			return err
		}
		if sess.UserID != in.UserID || !in.Now.Before(sess.ExpiresAt) || (!sess.IdleExpiresAt.IsZero() && !in.Now.Before(sess.IdleExpiresAt)) {
			return store.ErrPrecondition
		}
		conn, err := tx.Connections().GetByName(ctx, in.TenantID, sess.Connection)
		if err != nil {
			return err
		}
		if conn.ID != in.PrimaryConnectionID || (txn.Params[InvitationConnectionParam] != "" && txn.Params[InvitationConnectionParam] != conn.ID) {
			return store.ErrPrecondition
		}
		u, err := tx.Users().GetForUpdate(ctx, in.TenantID, in.UserID)
		if err != nil {
			return err
		}
		if !u.EmailVerified {
			return ErrInvitationIdentity
		}
		if u.Blocked {
			return ErrNotMember
		}
		client, err := tx.Clients().Get(ctx, in.TenantID, in.ClientID)
		if err != nil {
			return err
		}
		if !access.ConnectionUsable(client, conn) || (client.OrganizationUsage != store.OrgUsageAllow && client.OrganizationUsage != store.OrgUsageRequire) {
			return ErrNotMember
		}
		org, err := tx.Organizations().Get(ctx, in.TenantID, in.OrganizationID)
		if err != nil {
			return err
		}
		if !client.IsFirstParty && org.ThirdPartyClientAccess != orgrules.ThirdPartyAllow {
			return ErrNotMember
		}
		if err = CheckMemberClient(ctx, tx, in.TenantID, in.OrganizationID, in.ClientID); err != nil {
			return err
		}
		link, err := tx.Organizations().GetConnection(ctx, in.TenantID, in.OrganizationID, conn.ID)
		if err != nil {
			return err
		}
		if (txn.Params[InvitationSignupParam] == "1" || txn.Params["screen_hint"] == "signup") && (conn.DisableSignup || !link.IsSignupEnabled) {
			return ErrNotMember
		}
		if link.IsEnabledSet && !link.IsEnabled {
			return ErrNotMember
		}
		receipt, err := tx.OrganizationsII().GetInvitationReceipt(ctx, in.TenantID, in.TransactionID)
		if err == nil {
			if receipt.InvitationID != in.InvitationID || receipt.OrganizationID != in.OrganizationID || receipt.UserID != in.UserID {
				return store.ErrPrecondition
			}
			result = receipt
			return nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		invite, err := tx.OrganizationsII().GetInvitation(ctx, in.TenantID, in.OrganizationID, in.InvitationID)
		if err != nil {
			return err
		}
		if invite.ClientID != in.ClientID || !in.Now.Before(invite.ExpiresAt) || (invite.ConnectionID != "" && invite.ConnectionID != conn.ID) {
			return store.ErrPrecondition
		}
		if !u.EmailVerified || strings.ToLower(strings.TrimSpace(u.Email)) != strings.ToLower(strings.TrimSpace(invite.InviteeEmail)) {
			return ErrInvitationIdentity
		}
		// Consumption validates role ownership again, and all subsequent writes
		// share its transaction: no receipt or partial enrollment survives a failure.
		accepted, err := tx.OrganizationsII().ConsumeInvitation(ctx, in.TenantID, in.OrganizationID, in.InvitationID, in.TransactionID, in.UserID, in.Now)
		if err != nil {
			return err
		}
		if err = tx.Organizations().AddMembers(ctx, in.TenantID, in.OrganizationID, []string{in.UserID}); err != nil {
			return err
		}
		if len(invite.Roles) > 0 {
			if err = tx.Organizations().ChangeMemberRoles(ctx, in.TenantID, in.OrganizationID, in.UserID, true, invite.Roles); err != nil {
				return err
			}
		}
		u.UserMetadata = mergeInvitationMetadata(u.UserMetadata, invite.UserMetadata)
		u.AppMetadata = mergeInvitationMetadata(u.AppMetadata, invite.AppMetadata)
		if err = tx.Users().Update(ctx, u); err != nil {
			return err
		}
		result = &accepted
		return nil
	})
	return result, err
}
func mergeInvitationMetadata(existing, invited map[string]any) map[string]any {
	out := make(map[string]any, len(existing)+len(invited))
	for k, v := range invited {
		out[k] = v
	}
	for k, v := range existing {
		out[k] = v
	}
	return out
}
