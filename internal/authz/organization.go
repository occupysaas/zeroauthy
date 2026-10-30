package authz

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// orgNamesSetting is the tenant flag that lets the Authentication API accept
// an organization name in place of its ID (default off, D-0055).
const orgNamesSetting = "allow_organization_name_in_authentication_api"

// OrgMode is how an authorization request uses organizations. It is bound
// in the transaction under store.TxnParamOrgMode.
type OrgMode string

const (
	// OrgNone is an individual login; nothing is bound.
	OrgNone OrgMode = ""
	// OrgFixed is a login through the organization in OrgDecision.OrgID.
	OrgFixed OrgMode = "fixed"
	// OrgPromptBefore asks for the organization before login
	// (pre_login_prompt).
	OrgPromptBefore OrgMode = "prompt_before"
	// OrgPickAfter shows the organization picker after login
	// (require + post_login_prompt).
	OrgPickAfter OrgMode = "pick_after"
)

// OrgDecision is the result of resolving an organization request.
type OrgDecision struct {
	OrgID string // set only with OrgFixed
	Mode  OrgMode
}

// ResolveOrganization resolves the organization parameter raw for client c
// (spec §5.1, D-0055). An empty raw counts as absent. Every failure is
// redirectable: invalid_request, access_denied for a third-party client an
// organization blocks, or server_error.
func ResolveOrganization(ctx context.Context, st store.Store, t tenant.Resolved, c *store.Client, raw string) (OrgDecision, *Error) {
	usage := c.OrganizationUsage
	if usage == "" {
		usage = store.OrgUsageDeny
	}
	if !store.OrganizationsSupported(st) {
		// The storage plugin cannot hold organizations, so none can be
		// named, and a client that needs one cannot be served.
		if raw != "" || usage == store.OrgUsageRequire {
			return OrgDecision{}, errInvalidRequest("organizations are not available on this server")
		}
		return OrgDecision{Mode: OrgNone}, nil
	}

	if raw == "" {
		behavior := c.OrganizationRequireBehavior
		switch {
		case usage == store.OrgUsageDeny:
			return OrgDecision{Mode: OrgNone}, nil
		case behavior == store.OrgBehaviorPreLoginPrompt:
			return OrgDecision{Mode: OrgPromptBefore}, nil
		case usage == store.OrgUsageAllow:
			return OrgDecision{Mode: OrgNone}, nil
		case behavior == store.OrgBehaviorPostLoginPrompt:
			return OrgDecision{Mode: OrgPickAfter}, nil
		default: // require + no_prompt
			return OrgDecision{}, errInvalidRequest("this application requires an organization")
		}
	}

	if usage == store.OrgUsageDeny {
		return OrgDecision{}, errInvalidRequest("this application does not accept an organization")
	}
	org, e := lookupOrganization(ctx, st, t.Tenant, raw)
	if e != nil {
		return OrgDecision{}, e
	}
	if !c.IsFirstParty && org.ThirdPartyClientAccess != orgrules.ThirdPartyAllow {
		return OrgDecision{}, errAccessDenied("the organization does not admit third-party applications")
	}
	if err := orglogin.CheckMemberClient(ctx, st, t.Tenant.ID, org.ID, c.ClientID); err != nil {
		return OrgDecision{}, errAccessDenied("the organization does not admit this application")
	}
	return OrgDecision{OrgID: org.ID, Mode: OrgFixed}, nil
}

// lookupOrganization finds raw as an organization ID first and, only while
// the tenant accepts names, as an exact name second. An ID match always
// wins, so a name equal to another organization's ID never reaches it
// (Review Focus 2).
func lookupOrganization(ctx context.Context, st store.Store, t *store.Tenant, raw string) (*store.Organization, *Error) {
	names, _ := t.SettingsExtra[orgNamesSetting].(bool)
	if orgrules.ValidID(raw) {
		org, err := st.Organizations().Get(ctx, t.ID, raw)
		switch {
		case err == nil:
			return org, nil
		case !errors.Is(err, store.ErrNotFound):
			return nil, errServer()
		case !names:
			return nil, errInvalidRequest("the organization does not exist")
		}
	} else if !names {
		return nil, errInvalidRequest("organization must be an organization ID")
	}
	org, err := st.Organizations().GetByName(ctx, t.ID, raw)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errInvalidRequest("the organization does not exist")
	case err != nil:
		return nil, errServer()
	}
	return org, nil
}

// bindOrganization resolves req's organization and binds the result to req.
// A request already bound (by PAR or an earlier step) keeps its binding and
// is never resolved again from the organization parameter. A fixed
// organization is checked again by ID, so a deleted organization or a client
// that no longer accepts it fails closed.
func bindOrganization(ctx context.Context, st store.Store, t *store.Tenant, c *store.Client, req *Request) *Error {
	res := tenant.Resolved{Tenant: t}
	switch req.OrgMode {
	case OrgNone:
		d, e := ResolveOrganization(ctx, st, res, c, req.Organization)
		if e != nil {
			return e
		}
		req.OrgID, req.OrgMode = d.OrgID, d.Mode
		return nil
	case OrgFixed:
		if req.OrgID == "" {
			return errInvalidRequest("the organization binding is not valid")
		}
		d, e := ResolveOrganization(ctx, st, res, c, req.OrgID)
		if e != nil {
			return e
		}
		if d.OrgID != req.OrgID {
			return errInvalidRequest("the organization does not exist")
		}
		return nil
	case OrgPromptBefore, OrgPickAfter:
		if !store.OrganizationsSupported(st) {
			return errInvalidRequest("organizations are not available on this server")
		}
		if c.OrganizationUsage != store.OrgUsageAllow && c.OrganizationUsage != store.OrgUsageRequire {
			return errInvalidRequest("this application does not accept an organization")
		}
		if req.OrgMode == OrgPromptBefore && c.OrganizationRequireBehavior != store.OrgBehaviorPreLoginPrompt {
			return errInvalidRequest("the organization behavior changed")
		}
		if req.OrgMode == OrgPickAfter && (c.OrganizationUsage != store.OrgUsageRequire || c.OrganizationRequireBehavior != store.OrgBehaviorPostLoginPrompt) {
			return errInvalidRequest("the organization behavior changed")
		}
		return nil
	default:
		return errInvalidRequest("the organization binding is not valid")
	}
}

// organizationSession rechecks policy for an authenticated browser. A true
// result means the picker/name prompt needs a hosted screen. It never trusts
// an organization or connection from the current HTTP request.
func (h *Handlers) organizationSession(w http.ResponseWriter, r *http.Request, res tenant.Resolved, c *store.Client, fr *flowReq, sess *store.LoginSession) (bool, *Error) {
	if fr.OrgMode == OrgNone {
		return false, nil
	}
	silent := slices.Contains(fr.Prompts(), "none")
	if fr.OrgMode == OrgPromptBefore {
		if silent {
			return false, errInteractionRequired()
		}
		return true, nil
	}
	conn, err := h.Store.Connections().GetByName(r.Context(), res.Tenant.ID, sess.Connection)
	if err != nil {
		return false, errLoginRequired()
	}
	emptyPicker := false
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		fresh, e := tx.Clients().Get(r.Context(), res.Tenant.ID, c.ClientID)
		if e != nil {
			return e
		}
		current, e := tx.Connections().Get(r.Context(), res.Tenant.ID, conn.ID)
		if e != nil {
			return e
		}
		if !access.ConnectionUsable(fresh, current) {
			return orglogin.ErrNotMember
		}
		if e := CheckOrganizationBinding(r.Context(), tx, res.Tenant, fresh, fr.params()); e != nil {
			return orglogin.ErrNotMember
		}

		if fr.OrgMode == OrgPickAfter {
			choices, auto, e := orglogin.PickerChoicesForClient(r.Context(), tx, res.Tenant.ID, sess.UserID, conn.ID, fresh)
			if e != nil {
				return e
			}
			if auto == nil {
				emptyPicker = len(choices) == 0
				return orglogin.ErrNotMember
			}
			fr.OrgID, fr.OrgMode = auto.ID, OrgFixed
		}
		oc, e := orglogin.Load(r.Context(), tx, res.Tenant.ID, fr.params())
		if e != nil {
			return e
		}
		return orglogin.EnsureMembership(r.Context(), tx, oc, sess.UserID, conn.ID)
	})
	if errors.Is(err, orglogin.ErrNotMember) || errors.Is(err, store.ErrNotFound) {
		if fr.OrgMode == OrgPickAfter {
			if emptyPicker && !silent {
				return false, errAccessDenied("the user has no eligible organization")
			}
			if silent {
				return false, errInteractionRequired()
			}
			return true, nil
		}
		if silent {
			return false, errLoginRequired()
		}
		return false, errAccessDenied("the user cannot log in through this organization")
	}
	if err != nil {
		return false, errServer()
	}
	return false, nil
}

// CheckOrganizationBinding revalidates a hosted transaction's binding without
// allowing query or form values to replace it.
func CheckOrganizationBinding(ctx context.Context, st store.Store, t *store.Tenant, c *store.Client, params map[string]string) *Error {
	req := RequestFromParams(params)
	return bindOrganization(ctx, st, t, c, &req)
}

// RejectOrganizationConnection reports a hosted connection selection refusal
// through the transaction's validated OAuth response mode and callback.
func (h *Handlers) RejectOrganizationConnection(w http.ResponseWriter, r *http.Request, res tenant.Resolved, txn *store.AuthTransaction) {
	h.EndTxn(w, r, res, txn)
	fr := flowFromParams(txn.Params)
	client, e, redirectable := h.validateFlow(r.Context(), res, &fr)
	if e != nil {
		if !redirectable {
			h.flowError(w, r, res, fr, e)
		} else {
			h.refuse(w, r, res, client, fr, e)
		}
		return
	}
	h.refuse(w, r, res, client, fr, errInvalidRequest("the connection is not enabled for this organization"))
}
