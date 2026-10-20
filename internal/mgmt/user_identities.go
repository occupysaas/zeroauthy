package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Account linking (U7, D-0043). Linking moves the secondary user's identity,
// with its password hash, into the primary's identities, records the
// secondary's email, email_verified and username in that identity's
// ProfileData, and deletes the secondary user with everything that names
// it. Unlinking recreates the secondary from ProfileData alone.

var (
	errIdentityConflict = &Error{Status: http.StatusConflict, Code: "identity_conflict", Message: "Specified identity already exists."}
	errLinkSelf         = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "Main identity and the new one are the same."}
	// errNoSecondary has no errorCode, as observed (U7).
	errNoSecondary    = &Error{Status: http.StatusBadRequest, Message: "the provided secondary account does not exist"}
	errLinkInexistent = badBodyRaw("linking to an inexistent identity is not allowed")
	errLinkWithToken  = badBodyRaw("Invalid token (link_with).")
	errLinkWithAud    = badBodyRaw("JWT (link_with) contains an invalid aud claim.")
	// errLinkWithAndID is not observed; Auth0's schema offers link_with or
	// provider and user_id, not both.
	errLinkWithAndID = badBodyRaw("Payload validation error: 'link_with cannot be combined with provider, user_id or connection_id'.")
	// errSecondaryHasLinks is not observed: zeroauthy refuses to link a user
	// that holds linked identities itself rather than drop them.
	errSecondaryHasLinks = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "The secondary account has linked identities; unlink them first."}
	errMainIdentity      = &Error{Status: http.StatusBadRequest, Code: "delete_main_user_identity", Message: "Main identity cannot be removed."}
)

// linkWithLeeway is the clock skew allowed on a link_with token's exp.
const linkWithLeeway = time.Minute

// identityJSON renders one identity of a user. A linked identity carries its
// profileData; the user's own does not (GET /users/{id}, U7).
func identityJSON(id *store.Identity) map[string]any {
	m := map[string]any{"connection": id.Connection, "user_id": id.UserID, "provider": id.Provider, "isSocial": false}
	if id.Linked() {
		m["profileData"] = id.ProfileData
	}
	return m
}

// linkIdentitiesJSON renders u's identities as the link and unlink
// responses do: every identity with profileData, the user's own built from
// its root email, email_verified and username. Auth0 adds
// last_password_reset there when known; zeroauthy does not track it, so it
// is left out.
func linkIdentitiesJSON(u *store.User) []map[string]any {
	out := make([]map[string]any, len(u.Identities))
	for i := range u.Identities {
		id := &u.Identities[i]
		out[i] = identityJSON(id)
		if !id.Linked() {
			pd := map[string]any{}
			if u.Email != "" {
				pd["email"], pd["email_verified"] = u.Email, u.EmailVerified
			}
			if u.Username != "" {
				pd["username"] = u.Username
			}
			out[i]["profileData"] = pd
		}
	}
	return out
}

// linkBody is a POST /users/{id}/identities body.
type linkBody struct {
	provider, userID, connectionID, linkWith string
	hasProvider, hasUserID, hasConnection    bool
	hasLinkWith                              bool
}

func readLinkBody(body map[string]json.RawMessage) (*linkBody, error) {
	b := userBody{body}
	in := &linkBody{}
	var err error
	for _, k := range slices.Sorted(maps.Keys(body)) {
		switch k {
		case "provider":
			in.provider, err = b.str(k)
			in.hasProvider = true
		case "connection_id":
			in.connectionID, err = b.str(k)
			in.hasConnection = true
		case "link_with":
			in.linkWith, err = b.str(k)
			in.hasLinkWith = true
		case "user_id":
			in.userID, err = linkUserID(body[k])
			in.hasUserID = true
		default:
			err = badBodyRaw(fmt.Sprintf("Payload validation error: 'Additional properties not allowed: %s'.", k))
		}
		if err != nil {
			return nil, err
		}
	}
	return in, nil
}

// linkUserID reads user_id, which Auth0 accepts as a string or an integer.
func linkUserID(raw json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, nil
	}
	var n json.Number
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if d.Decode(&n) == nil {
		if _, err := n.Int64(); err == nil {
			return n.String(), nil
		}
	}
	return "", wrongType("user_id", "string", raw)
}

// linkWithSubject verifies a link_with ID token: signed with the tenant's
// keys, issued under one of its hosts, not expired, and issued to the
// calling client. It returns the token's sub, the secondary user.
func (h *Handlers) linkWithSubject(r *http.Request, raw string) (string, error) {
	ctx := r.Context()
	res := resolved(r)
	if h.Keys == nil {
		return "", internalError(h, r, "verify link_with", errors.New("mgmt: no key manager"))
	}
	var std jwt.Claims
	if err := h.Keys.Verify(ctx, res.ID, raw, &std); errors.Is(err, keys.ErrInvalidToken) {
		return "", errLinkWithToken
	} else if err != nil {
		return "", internalError(h, r, "verify link_with", err)
	}
	rv, _ := tenant.FromContext(ctx)
	issuers := append(tenant.Issuers(res, h.BaseDomain), rv.Issuer())
	if !slices.Contains(issuers, std.Issuer) || std.Expiry == nil || h.now().After(std.Expiry.Time().Add(linkWithLeeway)) || !validUserID(std.Subject) {
		return "", errLinkWithToken
	}
	caller, _ := CallerFrom(ctx)
	if len(std.Audience) != 1 || std.Audience[0] != caller.ClientID {
		return "", errLinkWithAud
	}
	return std.Subject, nil
}

// identityHeld reports whether a user of the tenant holds the identity
// provider|userID, as its own or linked.
func identityHeld(ctx context.Context, st store.Store, tenantID, provider, userID string) (bool, error) {
	q := &store.UserQuery{Op: store.QueryAnd, Kids: []*store.UserQuery{
		{Op: store.QueryTerm, Field: "identities.user_id", Kind: store.KindString, Value: userID},
		{Op: store.QueryTerm, Field: "identities.provider", Kind: store.KindString, Value: provider},
	}}
	for page := 0; ; page++ {
		users, total, err := st.Users().List(ctx, tenantID, q, store.UserSort{Field: "user_id"}, store.Page{Offset: page * 100, Limit: 100})
		if err != nil {
			return false, err
		}
		for _, u := range users {
			if holdsIdentity(u, provider, userID) {
				return true, nil
			}
		}
		if (page+1)*100 >= total || len(users) == 0 {
			return false, nil
		}
	}
}

func holdsIdentity(u *store.User, provider, userID string) bool {
	return slices.ContainsFunc(u.Identities, func(id store.Identity) bool { return id.Provider == provider && id.UserID == userID })
}

// LinkUserIdentity links a secondary account to the user (U7).
func (h *Handlers) LinkUserIdentity(w http.ResponseWriter, r *http.Request, id string) {
	if !validUserID(id) {
		Fail(w, badUserID(id))
		return
	}
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if err := checkBodyText(body); err != nil {
		Fail(w, err)
		return
	}
	in, err := readLinkBody(body)
	if err != nil {
		Fail(w, err)
		return
	}
	var secondary string
	switch {
	case in.hasLinkWith && (in.hasProvider || in.hasUserID || in.hasConnection):
		Fail(w, errLinkWithAndID)
		return
	case in.hasLinkWith:
		if secondary, err = h.linkWithSubject(r, in.linkWith); err != nil {
			Fail(w, err)
			return
		}
		in.provider, in.userID, _ = strings.Cut(secondary, "|")
	case in.userID == "":
		Fail(w, badBodyRaw("Payload validation error: 'Missing required property: user_id'."))
		return
	case in.provider == "":
		Fail(w, badBodyRaw("Payload validation error: 'Missing required property: provider'."))
		return
	default:
		secondary = in.provider + "|" + in.userID
	}
	ctx := r.Context()
	tn := resolved(r)
	now := h.now()
	var out *store.User
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		p, err := tx.Users().Get(ctx, tn.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return errUserNotFound
		}
		if err != nil {
			return err
		}
		if secondary == p.UserID {
			return errLinkSelf
		}
		if holdsIdentity(p, in.provider, in.userID) {
			return errIdentityConflict
		}
		sec, err := tx.Users().Get(ctx, tn.ID, secondary)
		if errors.Is(err, store.ErrNotFound) {
			held, err := identityHeld(ctx, tx, tn.ID, in.provider, in.userID)
			switch {
			case err != nil:
				return err
			case held:
				return errIdentityConflict
			case in.provider == store.StrategyDatabase:
				return errNoSecondary
			}
			return errLinkInexistent
		}
		if err != nil {
			return err
		}
		own := sec.OwnIdentity()
		if own == nil {
			return errNoSecondary
		}
		if len(sec.Identities) > 1 {
			return errSecondaryHasLinks
		}
		if in.connectionID != "" {
			c, err := tx.Connections().GetByName(ctx, tn.ID, own.Connection)
			if errors.Is(err, store.ErrNotFound) || (err == nil && c.ID != in.connectionID) {
				return errNoSecondary
			}
			if err != nil {
				return err
			}
		}
		moved := store.Identity{Connection: own.Connection, Provider: own.Provider, UserID: own.UserID, PasswordHash: own.PasswordHash,
			ProfileData: map[string]any{"email": sec.Email, "email_verified": sec.EmailVerified}}
		if sec.Username != "" {
			moved.ProfileData["username"] = sec.Username
		}
		// The secondary goes first, so its logins are free for the primary.
		if err := tx.Users().Delete(ctx, tn.ID, secondary); err != nil {
			return err
		}
		p.Identities = append(p.Identities, moved)
		p.UpdatedAt = now
		if err := tx.Users().Update(ctx, p); errors.Is(err, store.ErrConflict) {
			return errIdentityConflict
		} else if err != nil {
			return err
		}
		if _, err := tx.Users().BumpVersion(ctx, tn.ID, id); err != nil {
			return err
		}
		out, err = tx.Users().Get(ctx, tn.ID, id)
		return err
	})
	if err != nil {
		h.failTx(w, r, "link user identity", err)
		return
	}
	h.audit(r, "link user identity", "user_id", id, "secondary", secondary)
	writeJSON(w, http.StatusCreated, linkIdentitiesJSON(out))
}

// UnlinkUserIdentity removes a linked identity from the user and recreates
// it as a user of its own (U7).
func (h *Handlers) UnlinkUserIdentity(w http.ResponseWriter, r *http.Request, id, provider, userID string) {
	if !validUserID(id) {
		Fail(w, badUserID(id))
		return
	}
	ctx := r.Context()
	tn := resolved(r)
	now := h.now()
	secondary := provider + "|" + userID
	var out *store.User
	changed := false
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		p, err := tx.Users().Get(ctx, tn.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return errUserNotFound
		}
		if err != nil {
			return err
		}
		if secondary == p.UserID {
			return errMainIdentity
		}
		i := slices.IndexFunc(p.Identities, func(x store.Identity) bool {
			return x.Linked() && x.Provider == provider && x.UserID == userID
		})
		if i < 0 {
			out, changed = p, false // not linked: 200 with the identities (U7)
			return nil
		}
		moved := p.Identities[i]
		p.Identities = slices.Delete(p.Identities, i, i+1)
		p.UpdatedAt = now
		if err := tx.Users().Update(ctx, p); err != nil {
			return err
		}
		if _, err := tx.Users().BumpVersion(ctx, tn.ID, id); err != nil {
			return err
		}
		// The secondary comes back from profileData only: no names, picture
		// or metadata, a new created_at and no logins (U7).
		email, username := moved.ProfileString("email"), moved.ProfileString("username")
		verified, _ := moved.ProfileData["email_verified"].(bool)
		name, nickname := identity.DefaultNames("", "", email, username)
		nu := &store.User{
			TenantID: tn.ID, UserID: secondary, Email: email, EmailVerified: verified, Username: username, Name: name, Nickname: nickname,
			Identities: []store.Identity{{Connection: moved.Connection, Provider: moved.Provider, UserID: moved.UserID, PasswordHash: moved.PasswordHash}},
			CreatedAt:  now, UpdatedAt: now,
		}
		if err := tx.Users().Create(ctx, nu); errors.Is(err, store.ErrConflict) {
			return errUserExists
		} else if err != nil {
			return err
		}
		// A fresh Version: nothing issued to the user before the link
		// matches it.
		if _, err := tx.Users().BumpVersion(ctx, tn.ID, secondary); err != nil {
			return err
		}
		if moved.PasswordHash != "" {
			c, err := tx.Connections().GetByName(ctx, tn.ID, moved.Connection)
			if err == nil {
				err = identity.RecordPassword(ctx, tx, c, secondary, moved.PasswordHash)
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		changed = true
		out, err = tx.Users().Get(ctx, tn.ID, id)
		return err
	})
	if err != nil {
		h.failTx(w, r, "unlink user identity", err)
		return
	}
	if changed {
		h.audit(r, "unlink user identity", "user_id", id, "secondary", secondary)
	}
	writeJSON(w, http.StatusOK, linkIdentitiesJSON(out))
}
