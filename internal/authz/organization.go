package authz

import (
	"context"
	"errors"

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
		return nil
	default:
		return errInvalidRequest("the organization binding is not valid")
	}
}
