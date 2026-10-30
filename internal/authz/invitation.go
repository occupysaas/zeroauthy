package authz

import (
	"context"
	"errors"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// bindInvitation runs only after ordinary client, callback and PKCE validation.
// Its internal keys survive PAR and hosted resumes, but ParseRequest ignores them.
func bindInvitation(ctx context.Context, st store.Store, t *store.Tenant, c *store.Client, req *Request) *Error {
	if req.Invitation == "" && req.invitationBinding[orglogin.InvitationIDParam] == "" {
		return nil
	}
	if slices.Contains(req.Prompts(), "none") {
		return errInteractionRequired()
	}
	if req.OrgMode != OrgFixed || req.OrgID == "" {
		return errInvalidRequest("an invitation requires its organization")
	}
	if req.invitationBinding[orglogin.InvitationIDParam] != "" {
		if req.invitationBinding[orglogin.InvitationClientParam] != c.ClientID {
			return errInvalidRequest("the invitation application changed")
		}
		return nil // Consumption/resume is checked against the durable receipt later.
	}
	inv, err := st.OrganizationsII().FindInvitation(ctx, t.ID, orglogin.InvitationTicketHash(req.Invitation))
	if err != nil || inv.OrganizationID != req.OrgID || inv.ClientID != c.ClientID {
		return errInvalidRequest("the invitation was not found")
	}
	bound := map[string]string{orglogin.InvitationIDParam: inv.ID, orglogin.InvitationClientParam: c.ClientID}
	if inv.ConnectionID != "" {
		conn, e := st.Connections().Get(ctx, t.ID, inv.ConnectionID)
		if e != nil || !access.ConnectionUsable(c, conn) || (req.Connection != "" && req.Connection != conn.Name) {
			return errInvalidRequest("the invitation connection is not available")
		}
		link, e := st.Organizations().GetConnection(ctx, t.ID, req.OrgID, conn.ID)
		if e != nil || (link.IsEnabledSet && !link.IsEnabled) {
			return errInvalidRequest("the invitation connection is not available")
		}
		req.Connection = conn.Name
		bound[orglogin.InvitationConnectionParam] = conn.ID
	}
	req.invitationBinding = bound
	req.Invitation = ""
	return nil
}

// bindInvitationSession records authentication evidence using only the session
// produced by the server authentication pipeline. No browser field is copied.
func (h *Handlers) bindInvitationSession(ctx context.Context, txn *store.AuthTransaction, sess *store.LoginSession) error {
	return h.Store.WithTx(ctx, func(tx store.Store) error {
		cur, e := tx.AuthTransactions().Get(ctx, txn.TenantID, txn.ID)
		if e != nil {
			return e
		}
		if old := cur.Params[orglogin.InvitationSessionParam]; old != "" && old != sess.ID {
			receipt, e := tx.OrganizationsII().GetInvitationReceipt(ctx, txn.TenantID, txn.ID)
			if e == nil && receipt.UserID != sess.UserID {
				return store.ErrPrecondition
			}
			if e != nil && !errors.Is(e, store.ErrNotFound) {
				return e
			}
		}
		current, e := tx.Sessions().Get(ctx, txn.TenantID, sess.ID)
		if e != nil {
			return e
		}
		if current.UserID != sess.UserID || current.Connection != sess.Connection {
			return store.ErrPrecondition
		}
		cur.Params[orglogin.InvitationSessionParam] = sess.ID
		if e = orglogin.SaveInvitationTransaction(ctx, tx, cur, h.now()); e != nil {
			return e
		}
		*txn = *cur
		return nil
	})
}

func (h *Handlers) acceptInvitation(ctx context.Context, txn *store.AuthTransaction, sess *store.LoginSession) error {
	if e := h.bindInvitationSession(ctx, txn, sess); e != nil {
		return e
	}
	conn, e := h.Store.Connections().GetByName(ctx, txn.TenantID, sess.Connection)
	if e != nil {
		return e
	}
	_, e = orglogin.AcceptInvitation(ctx, h.Store, orglogin.AcceptanceInput{TenantID: txn.TenantID, OrganizationID: txn.Params[store.TxnParamOrgID], ClientID: txn.ClientID, InvitationID: txn.Params[orglogin.InvitationIDParam], TransactionID: txn.ID, UserID: sess.UserID, PrimaryConnectionID: conn.ID, Now: h.now()})
	return e
}

// Claim final authorization once, independently of idempotent acceptance. A
// concurrent same-transaction request must not execute Actions or mint twice.
func (h *Handlers) claimInvitationCompletion(ctx context.Context, txn *store.AuthTransaction, sess *store.LoginSession) error {
	return h.Store.WithTx(ctx, func(tx store.Store) error {
		cur, err := tx.AuthTransactions().Get(ctx, txn.TenantID, txn.ID)
		if err != nil {
			return err
		}
		if cur.Params[orglogin.InvitationSessionParam] != sess.ID {
			return store.ErrPrecondition
		}
		if err = tx.AuthTransactions().CompareAndSwapHosted(ctx, cur.TenantID, cur.ID, cur.HostedState.Revision, cur.HostedState, h.now()); err != nil {
			return err
		}
		return tx.AuthTransactions().Delete(ctx, cur.TenantID, cur.ID)
	})
}
