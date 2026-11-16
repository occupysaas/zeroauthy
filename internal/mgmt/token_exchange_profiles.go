package mgmt

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/exchangerules"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const (
	maxTokenExchangeProfiles = exchangerules.MaxProfiles
	profileTypeCustomAuth    = exchangerules.TypeCustomAuthentication
)

var (
	errProfileNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_token_exchange_profile", Message: "The token exchange profile does not exist"}
	errProfileConflict = &Error{Status: http.StatusConflict, Code: "token_exchange_profile_conflict", Message: "A token exchange profile with this subject_token_type already exists"}
	errProfileLimit    = &Error{Status: http.StatusForbidden, Code: "entity_limit_reached", Message: "The tenant has reached the limit of token exchange profiles"}
)

// newProfileID is "tep_" and 22 random base62 characters.
func newProfileID() string { return "tep_" + secrets.RandomString(22) }

func validProfileName(name string) error {
	if err := exchangerules.ValidateName(name); err != nil {
		return badBody("%s", err)
	}
	return nil
}

func validSubjectTokenType(t string) error {
	if err := exchangerules.ValidateSubjectTokenType(t); err != nil {
		return badBody("%s", err)
	}
	return nil
}

func profileView(p *store.TokenExchangeProfile) mgmtapi.TokenExchangeProfile {
	return mgmtapi.TokenExchangeProfile{
		Id: p.ID, Name: p.Name, SubjectTokenType: p.SubjectTokenType, ActionId: p.ActionID,
		Type: mgmtapi.TokenExchangeProfileType(p.Type), CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC(),
	}
}

// profileWriteError maps a store error of a profile write.
func profileWriteError(err error) error {
	switch {
	case errors.Is(err, store.ErrConflict):
		return errProfileConflict
	case errors.Is(err, store.ErrPrecondition):
		return errProfileLimit
	case errors.Is(err, store.ErrNotFound):
		return errProfileNotFound
	}
	return err
}

// checkProfileAction refuses an action_id that is not a deployed Action with
// the custom-token-exchange trigger. The three messages are Auth0's
// documented short identifiers (spec 5.1).
func (h *Handlers) checkProfileAction(r *http.Request, tid, actionID string) error {
	a, err := h.Store.Actions().GetAction(r.Context(), tid, actionID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return badBodyRaw("Action not found")
	case err != nil:
		return err
	case a.Trigger != actions.TriggerCustomTokenExchange:
		return badBodyRaw("Action must have supported_triggers: custom-token-exchange")
	case a.DeployedVersionID == "":
		return badBodyRaw("Action is not deployed")
	}
	return nil
}

// GetTokenExchangeProfiles lists token exchange profiles by checkpoint.
func (h *Handlers) GetTokenExchangeProfiles(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetTokenExchangeProfilesParams) {
	if !h.supportsClientCredentials(r.Context()) {
		Fail(w, errClientCredentialsUnavailable)
		return
	}
	take, err := takeParam(r)
	if err != nil {
		Fail(w, err)
		return
	}
	list, next, err := h.Store.ClientCredentials().ListProfiles(r.Context(), resolved(r).ID, r.URL.Query().Get("from"), take)
	if err != nil {
		Fail(w, internalError(h, r, "list token exchange profiles", err))
		return
	}
	page := mgmtapi.TokenExchangeProfilePage{TokenExchangeProfiles: make([]mgmtapi.TokenExchangeProfile, len(list))}
	for i, p := range list {
		page.TokenExchangeProfiles[i] = profileView(p)
	}
	if next != "" {
		page.Next = &next
	}
	writeJSON(w, http.StatusOK, page)
}

// PostTokenExchangeProfile creates a token exchange profile.
func (h *Handlers) PostTokenExchangeProfile(w http.ResponseWriter, r *http.Request) {
	if !h.supportsClientCredentials(r.Context()) {
		Fail(w, errClientCredentialsUnavailable)
		return
	}
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	var b mgmtapi.TokenExchangeProfileCreate
	if err := decodeStrict(mustMarshal(body), &b); err != nil {
		Fail(w, badBody("%v", err))
		return
	}
	for _, k := range []string{"name", "subject_token_type", "action_id", "type"} {
		if _, ok := body[k]; !ok {
			Fail(w, badBody("%s is required", k))
			return
		}
	}
	if string(b.Type) != profileTypeCustomAuth {
		Fail(w, badBody("type must be %s", profileTypeCustomAuth))
		return
	}
	if err := validProfileName(b.Name); err != nil {
		Fail(w, err)
		return
	}
	if err := validSubjectTokenType(b.SubjectTokenType); err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	if err := h.checkProfileAction(r, tn.ID, b.ActionId); err != nil {
		Fail(w, asAPIError(h, r, "get Action", err))
		return
	}
	now := h.now()
	p := &store.TokenExchangeProfile{
		TenantID: tn.ID, ID: newProfileID(), Name: b.Name, SubjectTokenType: b.SubjectTokenType,
		ActionID: b.ActionId, Type: profileTypeCustomAuth, CreatedAt: now, UpdatedAt: now,
	}
	if err := h.Store.ClientCredentials().CreateProfile(r.Context(), p, maxTokenExchangeProfiles); err != nil {
		Fail(w, asAPIError(h, r, "create token exchange profile", profileWriteError(err)))
		return
	}
	logDetails(r, "create token exchange profile", "profile_id", p.ID, "action_id", p.ActionID)
	writeJSON(w, http.StatusCreated, profileView(p))
}

// GetTokenExchangeProfile returns one token exchange profile.
func (h *Handlers) GetTokenExchangeProfile(w http.ResponseWriter, r *http.Request, id string) {
	if !h.supportsClientCredentials(r.Context()) {
		Fail(w, errClientCredentialsUnavailable)
		return
	}
	p, err := h.Store.ClientCredentials().GetProfile(r.Context(), resolved(r).ID, id)
	if err != nil {
		Fail(w, asAPIError(h, r, "get token exchange profile", profileWriteError(err)))
		return
	}
	writeJSON(w, http.StatusOK, profileView(p))
}

// PatchTokenExchangeProfile changes a profile's name or subject_token_type.
// action_id and type cannot change, and are refused as unknown properties.
func (h *Handlers) PatchTokenExchangeProfile(w http.ResponseWriter, r *http.Request, id string) {
	if !h.supportsClientCredentials(r.Context()) {
		Fail(w, errClientCredentialsUnavailable)
		return
	}
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, ok := body["action_id"]; ok {
		Fail(w, badBody("action_id cannot be changed"))
		return
	}
	var b mgmtapi.TokenExchangeProfileUpdate
	if err := decodeStrict(mustMarshal(body), &b); err != nil {
		Fail(w, badBody("%v", err))
		return
	}
	for k, raw := range body {
		if isNull(raw) {
			Fail(w, badBody("%s must not be null", k))
			return
		}
	}
	tn := resolved(r)
	p, err := h.Store.ClientCredentials().GetProfile(r.Context(), tn.ID, id)
	if err != nil {
		Fail(w, asAPIError(h, r, "get token exchange profile", profileWriteError(err)))
		return
	}
	if b.Name != nil {
		if err := validProfileName(*b.Name); err != nil {
			Fail(w, err)
			return
		}
		p.Name = *b.Name
	}
	if b.SubjectTokenType != nil {
		if err := validSubjectTokenType(*b.SubjectTokenType); err != nil {
			Fail(w, err)
			return
		}
		p.SubjectTokenType = *b.SubjectTokenType
	}
	p.UpdatedAt = h.now()
	if err := h.Store.ClientCredentials().UpdateProfile(r.Context(), p); err != nil {
		Fail(w, asAPIError(h, r, "update token exchange profile", profileWriteError(err)))
		return
	}
	logDetails(r, "update token exchange profile", "profile_id", id)
	writeJSON(w, http.StatusOK, profileView(p))
}

// DeleteTokenExchangeProfile removes a token exchange profile.
func (h *Handlers) DeleteTokenExchangeProfile(w http.ResponseWriter, r *http.Request, id string) {
	if !h.supportsClientCredentials(r.Context()) {
		Fail(w, errClientCredentialsUnavailable)
		return
	}
	if err := h.Store.ClientCredentials().DeleteProfile(r.Context(), resolved(r).ID, id); err != nil {
		Fail(w, asAPIError(h, r, "delete token exchange profile", profileWriteError(err)))
		return
	}
	logDetails(r, "delete token exchange profile", "profile_id", id)
	w.WriteHeader(http.StatusNoContent)
}
