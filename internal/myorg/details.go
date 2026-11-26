package myorg

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) getConfig(w http.ResponseWriter, r *http.Request, c *Caller) {
	strategies := c.Config.AllowedStrategies
	if strategies == nil {
		strategies = []string{}
	}
	out := map[string]any{"allowed_strategies": strategies, "connection_deletion_behavior": c.Config.ConnectionDeletionBehavior, "organization_deletion_behavior": "allow_if_empty"}
	if c.Config.ThirdPartyClientAccess != nil {
		out["third_party_client_access"] = c.Config.ThirdParty()
	}
	writeJSON(w, r, http.StatusOK, out)
}

func detailsView(o *store.Organization) map[string]any {
	out := map[string]any{"id": o.ID, "name": o.Name, "display_name": o.DisplayName, "third_party_client_access": o.ThirdPartyClientAccess}
	if b := o.Branding; b != nil {
		branding := map[string]any{}
		if b.LogoURL != nil {
			branding["logo_url"] = *b.LogoURL
		}
		if b.Colors != nil {
			branding["colors"] = map[string]any{"primary": b.Colors.Primary, "page_background": b.Colors.PageBackground}
		}
		out["branding"] = branding
	}
	return out
}

func (h *Handlers) getDetails(w http.ResponseWriter, r *http.Request, c *Caller) {
	writeJSON(w, r, http.StatusOK, detailsView(c.Org))
}

type detailsPatch struct {
	Name                   *string         `json:"name"`
	DisplayName            *string         `json:"display_name"`
	Branding               json.RawMessage `json:"branding"`
	ThirdPartyClientAccess *string         `json:"third_party_client_access"`
}

type brandingBody struct {
	LogoURL *string `json:"logo_url"`
	Colors  *struct {
		Primary        string `json:"primary"`
		PageBackground string `json:"page_background"`
	} `json:"colors"`
}

func (h *Handlers) patchDetails(w http.ResponseWriter, r *http.Request, c *Caller) {
	var b detailsPatch
	if p := decode(r, &b); p != nil {
		writeProblem(w, r, p)
		return
	}
	if b.Name == nil && b.DisplayName == nil && b.Branding == nil && b.ThirdPartyClientAccess == nil {
		writeProblem(w, r, badRequest("invalid_body", "Send at least one of name, display_name, branding or third_party_client_access."))
		return
	}
	ctx := r.Context()
	var out *store.Organization
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		o, err := tx.Organizations().Get(ctx, c.TenantID, c.Org.ID)
		if err != nil {
			return err
		}
		if b.Name != nil {
			o.Name = *b.Name
		}
		if b.DisplayName != nil {
			o.DisplayName = *b.DisplayName
		}
		if v := b.ThirdPartyClientAccess; v != nil {
			if !slices.Contains(c.Config.ThirdParty().AllowedValues, *v) {
				return badRequest("invalid_body", "third_party_client_access is not allowed by the application's configuration.", ValidationError{Detail: "not allowed", Field: "third_party_client_access", Source: "body"})
			}
			o.ThirdPartyClientAccess = *v
		}
		if b.Branding != nil {
			var bb brandingBody
			if err := strictJSON(b.Branding, &bb); err != nil {
				return badRequest("invalid_body", "branding is invalid.")
			}
			nb := &store.OrgBranding{LogoURL: bb.LogoURL}
			if bb.Colors != nil {
				nb.Colors = &store.OrgColors{Primary: bb.Colors.Primary, PageBackground: bb.Colors.PageBackground}
			}
			o.Branding = nb
		}
		if _, err := orgrules.NormalizeOrganization(*o); err != nil {
			return badRequest("invalid_body", err.Error())
		}
		if err := tx.Organizations().Update(ctx, o); err != nil {
			if err == store.ErrConflict {
				return problem(http.StatusConflict, "conflict", "Conflict", "Another organization has this name.")
			}
			if err == store.ErrInvalid {
				return badRequest("invalid_body", "The organization details are invalid.")
			}
			return err
		}
		out, err = tx.Organizations().Get(ctx, c.TenantID, c.Org.ID)
		return err
	})
	if err != nil {
		h.fail(w, r, "update organization details", err)
		return
	}
	h.event(r, c, "my_organization_api_org_details_succeeded")
	writeJSON(w, r, http.StatusOK, detailsView(out))
}

func strictJSON(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
