package mgmt

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keycert"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"slices"
)

func (h *Handlers) keyConnection(r *http.Request, id string) (*store.Connection, error) {
	if !connectionID.MatchString(id) {
		return nil, errBadConnectionID
	}
	c, e := h.Store.Connections().Get(r.Context(), resolved(r).ID, id)
	if errors.Is(e, store.ErrNotFound) {
		return nil, errConnectionNotFound
	}
	if e != nil {
		return nil, e
	}
	if c.Strategy != "oidc" && c.Strategy != "okta" && c.Strategy != rules.SAMLP {
		return nil, badBody("keys are not available for this connection")
	}
	if supporter, ok := h.Store.(store.ConnectionKeysSupporter); ok && !supporter.ConnectionKeysSupported() {
		return nil, &Error{Status: 501, Code: "connection_keys_unavailable", Message: "The storage plugin does not support connection keys"}
	}
	return c, nil
}
func keyFailure(w http.ResponseWriter, e error) {
	if errors.Is(e, store.ErrConnectionKeysUnavailable) {
		WriteError(w, 501, "connection_keys_unavailable", "The storage plugin does not support connection keys")
		return
	}
	if errors.Is(e, store.ErrConflict) {
		WriteError(w, 409, "conflict", "Keys of this use already exist")
		return
	}
	Fail(w, e)
}
func publicConnectionKey(k *store.ConnectionKey) (map[string]any, error) {
	cert, pkcs, fp, tp, e := keycert.DescribeConnection(k.CertDER)
	if e != nil {
		return nil, e
	}
	parsed, e := x509.ParseCertificate(k.CertDER)
	if e != nil {
		return nil, e
	}
	v := map[string]any{"kid": k.KID, "cert": cert, "pkcs": pkcs, "fingerprint": fp, "thumbprint": tp, "algorithm": k.Alg, "key_use": k.Use, "subject_dn": parsed.Subject.String(), "current": k.State == "current", "next": k.State == "next", "previous": k.State == "previous"}
	if k.CurrentSince != nil {
		v["current_since"] = k.CurrentSince.UTC()
	}
	return v, nil
}
func (h *Handlers) writeConnectionKeys(w http.ResponseWriter, r *http.Request, c *store.Connection, status int) {
	list, e := h.Store.ConnectionKeys().List(r.Context(), c.TenantID, c.ID)
	if e != nil {
		keyFailure(w, e)
		return
	}
	out := []map[string]any{}
	for _, k := range list {
		v, e := publicConnectionKey(k)
		if e != nil {
			Fail(w, e)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, status, out)
}
func (h *Handlers) GetConnectionKeys(w http.ResponseWriter, r *http.Request, id string) {
	c, e := h.keyConnection(r, id)
	if e != nil {
		keyFailure(w, e)
		return
	}
	h.writeConnectionKeys(w, r, c, 200)
}
func (h *Handlers) connectionKeyBody(r *http.Request, c *store.Connection) (use, alg string, err error) {
	body := map[string]json.RawMessage{}
	if r.ContentLength != 0 {
		body, err = decodeObject(r)
		if err != nil {
			return
		}
	}
	values := map[string]string{}
	for k, v := range body {
		if !slices.Contains([]string{"key_use", "signing_alg", "encryption_alg"}, k) {
			err = badBody("unknown property %q", k)
			return
		}
		var s string
		if json.Unmarshal(v, &s) != nil || s == "" {
			err = badBody("%s must be a nonempty string", k)
			return
		}
		values[k] = s
	}
	use = values["key_use"]
	if use == "" {
		use = "signing"
	}
	switch use {
	case "signing":
		alg = values["signing_alg"]
		if alg == "" {
			alg = "RS256"
		}
		if !slices.Contains(rules.AssertionAlgorithms, alg) {
			err = badBody("unsupported signing algorithm")
		}
	case "encryption":
		alg = values["encryption_alg"]
		if alg == "" {
			alg, _ = c.Extra["id_token_encrypted_response_alg"].(string)
		}
		if alg == "" {
			alg = "RSA-OAEP-256"
		}
		if !slices.Contains(rules.EncryptionAlgorithms, alg) {
			err = badBody("unsupported encryption algorithm")
		}
	default:
		err = badBody("key_use must be signing or encryption")
	}
	return
}
func (h *Handlers) PostConnectionKeys(w http.ResponseWriter, r *http.Request, id string) {
	c, e := h.keyConnection(r, id)
	if e != nil {
		keyFailure(w, e)
		return
	}
	use, alg, e := h.connectionKeyBody(r, c)
	if e != nil {
		Fail(w, e)
		return
	}
	now := h.now()
	subject := resolved(r).CanonicalHost
	if subject == "" {
		subject = resolved(r).Name
	}
	current, e := federation.GenerateConnectionKey(h.Wrapper, c, use, alg, subject, now)
	if e != nil {
		Fail(w, e)
		return
	}
	next, e := federation.GenerateConnectionKey(h.Wrapper, c, use, alg, subject, now)
	if e != nil {
		Fail(w, e)
		return
	}
	current.CurrentSince = &now
	current.State = "current"
	next.State = "next"
	if e = h.Store.ConnectionKeys().Create(r.Context(), c.TenantID, c.ID, use, current, next); e != nil {
		keyFailure(w, e)
		return
	}
	h.writeConnectionKeys(w, r, c, 201)
}
func (h *Handlers) PostConnectionKeysRotate(w http.ResponseWriter, r *http.Request, id string) {
	c, e := h.keyConnection(r, id)
	if e != nil {
		keyFailure(w, e)
		return
	}
	use, alg, e := h.connectionKeyBody(r, c)
	if e != nil {
		Fail(w, e)
		return
	}
	if use == "signing" && c.Extra["token_endpoint_auth_method"] != "private_key_jwt" {
		Fail(w, badBody("signing key rotation requires private_key_jwt"))
		return
	}
	if use == "encryption" {
		if configured, _ := c.Extra["id_token_encrypted_response_alg"].(string); configured == "" {
			Fail(w, badBody("encryption key rotation requires encrypted ID tokens"))
			return
		}
	}
	now := h.now()
	subject := resolved(r).CanonicalHost
	next, e := federation.GenerateConnectionKey(h.Wrapper, c, use, alg, subject, now)
	if e != nil {
		Fail(w, e)
		return
	}
	current, e := h.Store.ConnectionKeys().Rotate(r.Context(), c.TenantID, c.ID, use, next, now)
	if errors.Is(e, store.ErrNotFound) {
		list, ensureErr := federation.EnsureKeys(r.Context(), h.Store, h.Wrapper, c, use, alg, subject, now)
		e = ensureErr
		for _, k := range list {
			if k.Use == use && k.State == "current" {
				current = k
			}
		}
	}
	if e != nil {
		keyFailure(w, e)
		return
	}
	if current == nil {
		Fail(w, fmt.Errorf("missing current connection key"))
		return
	}
	v, e := publicConnectionKey(current)
	if e != nil {
		Fail(w, e)
		return
	}
	writeJSON(w, 201, v)
}
