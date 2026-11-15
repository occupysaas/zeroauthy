package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/clientcred"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// errClientCredentialsUnavailable answers the client credential and token
// exchange profile routes. It is the permanent answer for a storage plugin
// without the client_credentials.v1 capability (D-0063).
var errClientCredentialsUnavailable = &Error{Status: http.StatusNotImplemented, Code: "client_credentials_unavailable", Message: "Client credentials are not available with this storage plugin"}

var errCredentialNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_credential", Message: "The credential does not exist"}

const (
	// maxClientCredentials is the number of credentials one client may hold.
	maxClientCredentials = 2
	maxCredentialName    = 128
	algRS256             = "RS256"
	credTypeSubjectDN    = "cert_subject_dn"
)

var kidPattern = clientcred.KIDPattern

// supportsClientCredentials reports whether the store keeps client
// credentials. It is the single capability check of Plan 35 (R3).
func (h *Handlers) supportsClientCredentials(ctx context.Context) bool {
	return store.ClientCredentialsAvailable(ctx, h.Store)
}

// newCredentialID is "cred_" and 22 random base62 characters.
func newCredentialID() string { return "cred_" + secrets.RandomString(22) }

// credentialInput is the body of a credential create, or an inline
// credential of a client setting.
type credentialInput struct {
	Type, Name, Pem, Alg, Kid string
	ParseExpiry               bool
	ExpiresAt                 *time.Time
}

func (in credentialInput) fromCreate(b mgmtapi.ClientCredentialCreate) credentialInput {
	in.Type = string(b.CredentialType)
	in.Name, in.Pem, in.Kid = deref(b.Name), deref(b.Pem), deref(b.Kid)
	if b.Alg != nil {
		in.Alg = string(*b.Alg)
	}
	in.ParseExpiry, in.ExpiresAt = deref(b.ParseExpiryFromCert), b.ExpiresAt
	return in
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// build validates the input and returns the credential to store. The PEM is
// parsed and dropped; it is never kept, returned or logged.
func (in credentialInput) build(tid, clientID string, now time.Time) (*store.ClientCredential, error) {
	switch {
	case in.Type == credTypeSubjectDN:
		return nil, badBody("credential_type %s is not supported", credTypeSubjectDN)
	case in.Pem == "":
		return nil, badBody("pem is required")
	case len(in.Name) > maxCredentialName:
		return nil, badBody("name must be at most %d characters", maxCredentialName)
	case in.Kid != "" && !kidPattern.MatchString(in.Kid):
		return nil, badBody("kid must match %s", kidPattern)
	case in.ParseExpiry && in.ExpiresAt != nil:
		return nil, badBody("parse_expiry_from_cert and expires_at cannot be combined")
	}
	alg := in.Alg
	if alg == "" {
		alg = algRS256 // ParsePEM treats "" as RS256, but the stored credential needs the name
	}
	parsed, err := clientcred.ParsePEM(in.Type, in.Pem, alg)
	if err != nil {
		var ce *clientcred.Error
		if errors.As(err, &ce) {
			return nil, badBody("%s", ce.Error())
		}
		return nil, err
	}
	exp := in.ExpiresAt
	if in.ParseExpiry {
		if parsed.CertNotAfter == nil {
			return nil, badBody("parse_expiry_from_cert needs credential_type x509_cert")
		}
		exp = parsed.CertNotAfter
	}
	if exp != nil {
		t := exp.UTC()
		exp = &t
	}
	kid := in.Kid
	if kid == "" {
		kid = parsed.KID
	}
	return &store.ClientCredential{
		TenantID: tid, ClientID: clientID, ID: newCredentialID(), Type: in.Type, Name: in.Name,
		KID: kid, Alg: alg, PublicKeyDER: parsed.DER, Thumbprint: parsed.Thumbprint,
		ExpiresAt: exp, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// credentialError maps a store error of a credential write.
func credentialWriteError(err error) error {
	switch {
	case errors.Is(err, store.ErrPrecondition):
		return badBody("an application can have at most %d credentials", maxClientCredentials)
	case errors.Is(err, store.ErrNotFound):
		return errClientNotFound
	case errors.Is(err, store.ErrConflict):
		return &Error{Status: http.StatusConflict, Code: "credential_conflict", Message: "The credential already exists"}
	}
	return err
}

// credentialView is c in the API's shape, without the key material.
func credentialView(c *store.ClientCredential) mgmtapi.ClientCredential {
	v := mgmtapi.ClientCredential{
		Id: c.ID, Name: c.Name, Kid: c.KID, Alg: mgmtapi.ClientCredentialAlg(c.Alg),
		CredentialType: mgmtapi.ClientCredentialType(c.Type), ThumbprintSha256: c.Thumbprint,
		CreatedAt: c.CreatedAt.UTC(), UpdatedAt: c.UpdatedAt.UTC(),
	}
	if c.ExpiresAt != nil {
		t := c.ExpiresAt.UTC()
		v.ExpiresAt = &t
	}
	return v
}

// credentialTarget answers 501 without the capability and 404 for an unknown
// client; it returns false after writing the answer.
func (h *Handlers) credentialTarget(w http.ResponseWriter, r *http.Request, clientID string, write bool) (*store.Tenant, bool) {
	if !h.supportsClientCredentials(r.Context()) {
		Fail(w, errClientCredentialsUnavailable)
		return nil, false
	}
	tn := resolved(r)
	if write {
		if err := protectedClient(tn, clientID); err != nil {
			Fail(w, err)
			return nil, false
		}
	}
	if _, err := h.Store.Clients().Get(r.Context(), tn.ID, clientID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			Fail(w, errClientNotFound)
		} else {
			Fail(w, internalError(h, r, "get client", err))
		}
		return nil, false
	}
	return tn, true
}

// GetClientCredentials lists an application's credentials.
func (h *Handlers) GetClientCredentials(w http.ResponseWriter, r *http.Request, id string) {
	tn, ok := h.credentialTarget(w, r, id, false)
	if !ok {
		return
	}
	list, err := h.Store.ClientCredentials().List(r.Context(), tn.ID, id)
	if err != nil {
		Fail(w, internalError(h, r, "list client credentials", err))
		return
	}
	out := make([]mgmtapi.ClientCredential, len(list))
	for i, c := range list {
		out[i] = credentialView(c)
	}
	writeJSON(w, http.StatusOK, out)
}

// PostClientCredentials adds a credential to an application.
func (h *Handlers) PostClientCredentials(w http.ResponseWriter, r *http.Request, id string) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	tn, ok := h.credentialTarget(w, r, id, true)
	if !ok {
		return
	}
	var b mgmtapi.ClientCredentialCreate
	if err := decodeStrict(mustMarshal(body), &b); err != nil {
		Fail(w, badBody("%v", err))
		return
	}
	cred, err := credentialInput{}.fromCreate(b).build(tn.ID, id, h.now())
	if err != nil {
		Fail(w, asAPIError(h, r, "build client credential", err))
		return
	}
	if err := h.Store.ClientCredentials().Create(r.Context(), cred, maxClientCredentials); err != nil {
		Fail(w, asAPIError(h, r, "create client credential", credentialWriteError(err)))
		return
	}
	logDetails(r, "create client credential", "client_id", id, "credential_id", cred.ID)
	writeJSON(w, http.StatusCreated, credentialView(cred))
}

// GetClientCredential returns one credential.
func (h *Handlers) GetClientCredential(w http.ResponseWriter, r *http.Request, id, credentialID string) {
	tn, ok := h.credentialTarget(w, r, id, false)
	if !ok {
		return
	}
	c, err := h.Store.ClientCredentials().Get(r.Context(), tn.ID, id, credentialID)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errCredentialNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get client credential", err))
		return
	}
	writeJSON(w, http.StatusOK, credentialView(c))
}

// PatchClientCredential changes a credential's expiry.
func (h *Handlers) PatchClientCredential(w http.ResponseWriter, r *http.Request, id, credentialID string) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	tn, ok := h.credentialTarget(w, r, id, true)
	if !ok {
		return
	}
	if _, ok := body["expires_at"]; !ok {
		Fail(w, badBody("expires_at is required"))
		return
	}
	var b mgmtapi.ClientCredentialUpdate
	if err := decodeStrict(mustMarshal(body), &b); err != nil {
		Fail(w, badBody("%v", err))
		return
	}
	if err := h.Store.ClientCredentials().UpdateExpiry(r.Context(), tn.ID, id, credentialID, b.ExpiresAt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			err = errCredentialNotFound
		}
		Fail(w, asAPIError(h, r, "update client credential", err))
		return
	}
	c, err := h.Store.ClientCredentials().Get(r.Context(), tn.ID, id, credentialID)
	if err != nil {
		Fail(w, internalError(h, r, "get client credential", err))
		return
	}
	logDetails(r, "update client credential", "client_id", id, "credential_id", credentialID)
	writeJSON(w, http.StatusOK, credentialView(c))
}

// DeleteClientCredential removes a credential and detaches it from the
// application's settings (C3: Auth0 may refuse instead).
func (h *Handlers) DeleteClientCredential(w http.ResponseWriter, r *http.Request, id, credentialID string) {
	tn, ok := h.credentialTarget(w, r, id, true)
	if !ok {
		return
	}
	err := h.Store.ClientCredentials().Delete(r.Context(), tn.ID, id, credentialID)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errCredentialNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "delete client credential", err))
		return
	}
	logDetails(r, "delete client credential", "client_id", id, "credential_id", credentialID)
	w.WriteHeader(http.StatusNoContent)
}

// asAPIError returns err as an *Error, logging anything else as internal.
func asAPIError(h *Handlers, r *http.Request, what string, err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return internalError(h, r, what, err)
}

func mustMarshal(body map[string]json.RawMessage) json.RawMessage {
	data, _ := json.Marshal(body)
	return data
}

// credentialSettings are the three client settings of Plan 35 as a client
// body carries them. A nil pointer with its Set flag is JSON null.
type credentialSettings struct {
	methodsSet  bool
	methods     *mgmtapi.ClientAuthenticationMethods // nil: null
	signedSet   bool
	signed      *mgmtapi.SignedRequestObject // nil: null
	exchangeSet bool
	exchange    *mgmtapi.ClientTokenExchange // nil: null
	// authMethodSet and authMethodNull describe token_endpoint_auth_method.
	authMethodSet, authMethodNull bool
}

// privateKeyJWT reports the private_key_jwt reference list the body sets;
// ok is false for an absent or null setting.
func (cs *credentialSettings) privateKeyJWT() (refs []mgmtapi.ClientCredentialRef, ok bool) {
	if !cs.methodsSet || cs.methods == nil || cs.methods.PrivateKeyJwt == nil {
		return nil, false
	}
	if cs.methods.PrivateKeyJwt.Credentials != nil {
		refs = *cs.methods.PrivateKeyJwt.Credentials
	}
	return refs, true
}

// needsSupport is true when the body writes a value that only a store with
// client_credentials.v1 can keep.
func (cs *credentialSettings) needsSupport() bool {
	_, pkj := cs.privateKeyJWT()
	return pkj || cs.signed != nil || cs.exchange != nil
}

// any is true when the body touches any of the three settings.
func (cs *credentialSettings) any() bool { return cs.methodsSet || cs.signedSet || cs.exchangeSet }

func (cs *credentialSettings) readMethods(raw json.RawMessage) error {
	cs.methodsSet, cs.methods = true, nil
	if isNull(raw) {
		return nil
	}
	var v mgmtapi.ClientAuthenticationMethods
	if err := decodeStrict(raw, &v); err != nil {
		return err
	}
	if v.PrivateKeyJwt != nil {
		cs.methods = &v
	}
	return nil
}

func (cs *credentialSettings) readSigned(raw json.RawMessage) error {
	cs.signedSet, cs.signed = true, nil
	if isNull(raw) {
		return nil
	}
	var v mgmtapi.SignedRequestObject
	if err := decodeStrict(raw, &v); err != nil {
		return err
	}
	cs.signed = &v
	return nil
}

func (cs *credentialSettings) readExchange(raw json.RawMessage) error {
	cs.exchangeSet, cs.exchange = true, nil
	if isNull(raw) {
		return nil
	}
	var v mgmtapi.ClientTokenExchange
	if err := decodeStrict(raw, &v); err != nil {
		return err
	}
	for _, t := range deref(v.AllowAnyProfileOfType) {
		if t != mgmtapi.ClientTokenExchangeAllowAnyProfileOfTypeCustomAuthentication {
			return errors.New("allow_any_profile_of_type may only contain custom_authentication")
		}
	}
	cs.exchange = &v
	return nil
}

// authenticationState applies the mutual exclusion of private_key_jwt and
// token_endpoint_auth_method (C4) to spec, whose method is the stored one
// unless the body changed it. It reports whether the client authenticates
// with private_key_jwt afterwards. Normalize would turn the empty method of
// such a client into a default, so spec carries a confidential placeholder
// that the caller clears again after Apply.
func (cs *credentialSettings) authenticationState(spec *clientrules.Spec, before bool) (bool, error) {
	after := before
	if cs.methodsSet {
		_, after = cs.privateKeyJWT()
	}
	switch {
	case after && !before:
		if !cs.authMethodSet || !cs.authMethodNull {
			return false, badBody("client_authentication_methods private_key_jwt requires token_endpoint_auth_method null")
		}
	case after:
		if cs.authMethodSet && !cs.authMethodNull {
			return false, badBody("token_endpoint_auth_method must be null while private_key_jwt is configured")
		}
	case before:
		if spec.TokenEndpointAuthMethod == "" {
			return false, badBody("token_endpoint_auth_method is required when client_authentication_methods is null")
		}
	}
	if after {
		spec.TokenEndpointAuthMethod = store.AuthMethodClientSecretPost
	}
	return after, nil
}

// checkParty refuses token_exchange for a third-party client (LR35-6).
func (cs *credentialSettings) checkParty(spec *clientrules.Spec) error {
	if cs.exchange != nil && len(deref(cs.exchange.AllowAnyProfileOfType)) > 0 && !deref(spec.IsFirstParty) {
		return badBody("token_exchange is only for first-party applications")
	}
	return nil
}

// resolve returns the credential ids refs name, creating inline credentials.
// Existing ids must belong to the client.
func (h *Handlers) resolveCredentialRefs(ctx context.Context, tx store.Store, c *store.Client, refs []mgmtapi.ClientCredentialRef) ([]string, error) {
	ids := []string{}
	for _, ref := range refs {
		if ref.Id != nil {
			if ref.CredentialType != nil || ref.Pem != nil || ref.Name != nil || ref.Kid != nil || ref.Alg != nil || ref.ExpiresAt != nil || ref.ParseExpiryFromCert != nil {
				return nil, badBody("a credential reference carries an id or the fields of a new credential, not both")
			}
			if _, err := tx.ClientCredentials().Get(ctx, c.TenantID, c.ClientID, *ref.Id); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return nil, badBody("credential %q does not exist for this application", *ref.Id)
				}
				return nil, err
			}
			ids = append(ids, *ref.Id)
			continue
		}
		in := credentialInput{Type: string(deref(ref.CredentialType)), Name: deref(ref.Name), Pem: deref(ref.Pem), Kid: deref(ref.Kid),
			ParseExpiry: deref(ref.ParseExpiryFromCert), ExpiresAt: ref.ExpiresAt}
		if ref.Alg != nil {
			in.Alg = string(*ref.Alg)
		}
		cred, err := in.build(c.TenantID, c.ClientID, h.now())
		if err != nil {
			return nil, err
		}
		if err := tx.ClientCredentials().Create(ctx, cred, maxClientCredentials); err != nil {
			return nil, credentialWriteError(err)
		}
		ids = append(ids, cred.ID)
	}
	return ids, nil
}

// writeCredentialSettings stores inline credentials and sets the three
// settings on c; the caller saves c in the same transaction.
func (h *Handlers) writeCredentialSettings(ctx context.Context, tx store.Store, c *store.Client, cs *credentialSettings) error {
	if cs.needsSupport() && !h.supportsClientCredentials(ctx) {
		return errClientCredentialsUnavailable
	}
	if cs.methodsSet {
		c.PrivateKeyJWTCredentials = nil
		if refs, ok := cs.privateKeyJWT(); ok {
			ids, err := h.resolveCredentialRefs(ctx, tx, c, refs)
			if err != nil {
				return err
			}
			c.PrivateKeyJWTCredentials = ids
		}
	}
	if cs.signedSet {
		var prev []string
		if c.SignedRequestObject != nil {
			prev = c.SignedRequestObject.Credentials
		}
		c.SignedRequestObject = nil
		if cs.signed != nil {
			next := &store.SignedRequestObject{Required: deref(cs.signed.Required), Credentials: prev}
			if cs.signed.Credentials != nil {
				ids, err := h.resolveCredentialRefs(ctx, tx, c, *cs.signed.Credentials)
				if err != nil {
					return err
				}
				next.Credentials = ids
			}
			c.SignedRequestObject = next
		}
	}
	if cs.exchangeSet {
		c.TokenExchangeTypes = nil
		if cs.exchange != nil {
			c.TokenExchangeTypes = []string{}
			for _, t := range deref(cs.exchange.AllowAnyProfileOfType) {
				c.TokenExchangeTypes = append(c.TokenExchangeTypes, string(t))
			}
		}
	}
	return nil
}

// credentialSettingsView renders the three settings of c.
func credentialSettingsView(v *mgmtapi.Client, c *store.Client) {
	refs := func(ids []string) *[]mgmtapi.ClientCredentialRef {
		out := make([]mgmtapi.ClientCredentialRef, len(ids))
		for i := range ids {
			out[i].Id = &ids[i]
		}
		return &out
	}
	if c.PrivateKeyJWTCredentials != nil {
		v.ClientAuthenticationMethods = &mgmtapi.ClientAuthenticationMethods{PrivateKeyJwt: &struct {
			Credentials *[]mgmtapi.ClientCredentialRef `json:"credentials,omitempty"`
		}{Credentials: refs(c.PrivateKeyJWTCredentials)}}
		v.TokenEndpointAuthMethod = nil
	}
	if so := c.SignedRequestObject; so != nil {
		required := so.Required
		v.SignedRequestObject = &mgmtapi.SignedRequestObject{Required: &required, Credentials: refs(so.Credentials)}
	}
	if c.TokenExchangeTypes != nil {
		types := make([]mgmtapi.ClientTokenExchangeAllowAnyProfileOfType, len(c.TokenExchangeTypes))
		for i, t := range c.TokenExchangeTypes {
			types[i] = mgmtapi.ClientTokenExchangeAllowAnyProfileOfType(t)
		}
		v.TokenExchange = &mgmtapi.ClientTokenExchange{AllowAnyProfileOfType: &types}
	}
}
