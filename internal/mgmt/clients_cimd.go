package mgmt

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/cimd"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// cimdMappedFields is Auth0's mapped_fields (CimdMappedFields).
type cimdMappedFields struct {
	ExternalClientID            string               `json:"external_client_id"`
	Name                        string               `json:"name,omitempty"`
	AppType                     string               `json:"app_type,omitempty"`
	Callbacks                   []string             `json:"callbacks,omitempty"`
	LogoURI                     string               `json:"logo_uri,omitempty"`
	Description                 string               `json:"description,omitempty"`
	GrantTypes                  []string             `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod     string               `json:"token_endpoint_auth_method,omitempty"`
	JWKSURI                     string               `json:"jwks_uri,omitempty"`
	ClientAuthenticationMethods *cimdAuthMethodsView `json:"client_authentication_methods,omitempty"`
}

type cimdAuthMethodsView struct {
	PrivateKeyJWT struct {
		Credentials []cimdCredentialView `json:"credentials"`
	} `json:"private_key_jwt"`
}

type cimdCredentialView struct {
	CredentialType string `json:"credential_type"`
	KID            string `json:"kid"`
	Alg            string `json:"alg"`
}

type cimdPreview struct {
	ClientID                  string            `json:"client_id,omitempty"`
	ExternalMetadataCreatedBy string            `json:"external_metadata_created_by,omitempty"`
	Errors                    []string          `json:"errors,omitempty"`
	Validation                *cimd.Validation  `json:"validation,omitempty"`
	MappedFields              *cimdMappedFields `json:"mapped_fields,omitempty"`
}

type cimdRegistration struct {
	ClientID     string           `json:"client_id"`
	MappedFields cimdMappedFields `json:"mapped_fields"`
	Validation   cimd.Validation  `json:"validation"`
}

func mappedFieldsView(m cimd.Mapped) cimdMappedFields {
	v := cimdMappedFields{ExternalClientID: m.ExternalClientID, Name: m.Name, AppType: m.AppType, Callbacks: m.Callbacks,
		LogoURI: m.LogoURI, Description: m.Description, GrantTypes: m.GrantTypes, TokenEndpointAuthMethod: m.TokenEndpointAuthMethod, JWKSURI: m.JWKSURI}
	if len(m.Credentials) > 0 {
		v.ClientAuthenticationMethods = &cimdAuthMethodsView{}
		for _, c := range m.Credentials {
			v.ClientAuthenticationMethods.PrivateKeyJWT.Credentials = append(v.ClientAuthenticationMethods.PrivateKeyJWT.Credentials,
				cimdCredentialView{CredentialType: "public_key", KID: c.KID, Alg: c.Alg})
		}
	}
	return v
}

// readCimdRequest reads {external_client_id} from a JSON or form body.
func readCimdRequest(r *http.Request) (string, error) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var id string
	if mt == "application/x-www-form-urlencoded" {
		data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
		if err != nil {
			return "", badBody("the body is too large or unreadable")
		}
		form, err := url.ParseQuery(string(data))
		if err != nil {
			return "", badBody("the body is not a valid form")
		}
		for k, v := range form {
			if k != "external_client_id" || len(v) != 1 {
				return "", badBody("unknown or repeated property %q", k)
			}
		}
		id = form.Get("external_client_id")
	} else {
		body, err := decodeObject(r)
		if err != nil {
			return "", err
		}
		for k := range body {
			if k != "external_client_id" {
				return "", badBody("unknown property %q", k)
			}
		}
		raw, ok := body["external_client_id"]
		if !ok {
			return "", badBody("Missing required property: external_client_id")
		}
		if err := decodeString(raw, &id); err != nil {
			return "", badBody("external_client_id must be a string")
		}
	}
	if id == "" {
		return "", badBody("Missing required property: external_client_id")
	}
	if err := cimd.CheckURL(id); err != nil {
		return "", badBody("external_client_id: %v", err)
	}
	return id, nil
}

// PreviewCimdMetadata fetches, validates and maps a Client ID Metadata
// Document without creating anything.
func (h *Handlers) PreviewCimdMetadata(w http.ResponseWriter, r *http.Request) {
	url, err := readCimdRequest(r)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	var out cimdPreview
	existing, err := cimd.Lookup(r.Context(), h.Store, tn.ID, url)
	if err != nil {
		Fail(w, internalError(h, r, "find CIMD client", err))
		return
	}
	if existing != nil {
		out.ClientID, out.ExternalMetadataCreatedBy = existing.ClientID, existing.External.CreatedBy
	}
	doc, err := h.CIMD.Fetcher.Fetch(r.Context(), url)
	if err != nil {
		out.Errors = []string{retrievalMessage(err)}
		writeJSON(w, http.StatusOK, out)
		return
	}
	m, v := h.CIMD.Fetcher.Evaluate(r.Context(), doc)
	mf := mappedFieldsView(m)
	out.Validation, out.MappedFields = &v, &mf
	writeJSON(w, http.StatusOK, out)
}

// RegisterCimdClient creates (201, create:clients) or updates (200,
// update:clients) the client of a Client ID Metadata Document.
func (h *Handlers) RegisterCimdClient(w http.ResponseWriter, r *http.Request) {
	url, err := readCimdRequest(r)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	permit := func(create bool) error {
		scope := "update:clients"
		if create {
			scope = "create:clients"
		}
		if !callerHas(r, scope) {
			return &Error{Status: http.StatusForbidden, Code: "insufficient_scope", Message: "Insufficient scope; expected any of: " + scope}
		}
		return nil
	}
	out, err := h.CIMD.Register(r.Context(), tn, url, store.ExternalCreatedByAdmin, permit)
	var me *Error
	switch {
	case errors.As(err, &me):
		Fail(w, me)
		return
	case errors.Is(err, cimd.ErrDynamicConflict):
		Fail(w, &Error{Status: http.StatusConflict, Message: "A dynamically registered client already exists with external_client_id " + url})
		return
	case errors.Is(err, cimd.ErrRetrieval):
		Fail(w, badBody("%s", retrievalMessage(err)))
		return
	case errors.Is(err, cimd.ErrInvalid):
		msg := "the Client ID Metadata Document is invalid"
		if len(out.Validation.Violations) > 0 {
			msg += ": " + strings.Join(out.Validation.Violations, "; ")
		}
		Fail(w, badBody("%s", msg))
		return
	case errors.Is(err, store.ErrCIMDUnavailable):
		Fail(w, &Error{Status: http.StatusServiceUnavailable, Code: "cimd_unavailable", Message: "the storage backend cannot hold Client ID Metadata Document clients"})
		return
	case errors.Is(err, store.ErrClientCredentialsUnavailable):
		Fail(w, errClientCredentialsUnavailable)
		return
	case err != nil:
		Fail(w, internalError(h, r, "register CIMD client", err))
		return
	}
	status := http.StatusOK
	if out.Created {
		status = http.StatusCreated
	}
	logDetails(r, "register CIMD client", "client_id", out.Client.ClientID)
	writeJSON(w, status, cimdRegistration{ClientID: out.Client.ClientID, MappedFields: mappedFieldsView(out.Mapped), Validation: out.Validation})
}

// retrievalMessage is a fetch error for an administrator: the cause class,
// never response bodies.
func retrievalMessage(err error) string {
	return strings.TrimPrefix(err.Error(), cimd.ErrRetrieval.Error()+": ")
}
