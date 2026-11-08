package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var errMFAMissing = &Error{Status: 404, Code: "inexistent_authentication_method", Message: "The authentication method does not exist"}
var errMFAUnavailable = &Error{Status: 501, Code: "mfa_unavailable", Message: "MFA is unavailable"}

// MFAOperation is the common Management MFA boundary. The generated adapter
// supplies a frozen operation ID and separately checked live scopes.
func (h *Handlers) MFAOperation(w http.ResponseWriter, r *http.Request, op, uid, id string) {
	route := mfarules.Route(op)
	if route.Operation == "" {
		Fail(w, errMFAMissing)
		return
	}
	var body any
	var err error
	if len(route.Body) > 0 {
		body, err = mfaBody(r, route.Body)
		if err != nil {
			Fail(w, err)
			return
		}
	}
	if _, err = h.Store.MFA().GetGuardian(r.Context(), resolved(r).ID); err != nil {
		if errors.Is(err, store.ErrMFAUnavailable) && op == "GetGuardianPolicies" {
			writeJSON(w, 200, []string{})
			return
		}
		h.mfaFail(w, r, err)
		return
	}
	if strings.HasPrefix(route.Path, "/users/") {
		h.userMFA(w, r, route, uid, id, body)
		return
	}
	switch op {
	case "GetGuardianFactors":
		g, e := h.Store.MFA().GetGuardian(r.Context(), resolved(r).ID)
		if e != nil {
			h.mfaFail(w, r, e)
			return
		}
		out := []any{}
		for _, f := range mfarules.Factors() {
			out = append(out, map[string]any{"name": f.Name, "enabled": g.Factors[f.Name], "trial_expired": false})
		}
		writeJSON(w, 200, out)
	case "SetGuardianFactor":
		found := false
		for _, f := range mfarules.Factors() {
			found = found || f.Name == id
		}
		if !found {
			Fail(w, badBody("invalid factor"))
			return
		}
		enabled := body.(map[string]any)["enabled"].(bool)
		err = h.guardianWrite(r, func(g *store.GuardianSettings) error { g.Factors[id] = enabled; return nil })
		if err != nil {
			h.mfaFail(w, r, err)
			return
		}
		h.domainEvent(r, "gd_tenant_update", nil, nil, nil)
		logDetails(r, "update Guardian factor", "factor", id)
		writeJSON(w, 200, map[string]any{"enabled": enabled})
	case "GetGuardianPolicies":
		g, e := h.Store.MFA().GetGuardian(r.Context(), resolved(r).ID)
		if e != nil {
			h.mfaFail(w, r, e)
			return
		}
		out := g.Policies
		if out == nil {
			out = []string{}
		}
		writeJSON(w, 200, out)
	case "SetGuardianPolicies":
		out := []string{}
		for _, v := range body.([]any) {
			out = append(out, v.(string))
		}
		err = h.guardianWrite(r, func(g *store.GuardianSettings) error { g.Policies = out; return nil })
		if err != nil {
			h.mfaFail(w, r, err)
			return
		}
		h.domainEvent(r, "gd_tenant_update", nil, nil, nil)
		logDetails(r, "update Guardian policies")
		writeJSON(w, 200, out)
	case "GetGuardianEnrollment", "DeleteGuardianEnrollment":
		h.guardianEnrollment(w, r, uid, op == "DeleteGuardianEnrollment")
	case "CreateGuardianEnrollmentTicket":
		h.guardianTicket(w, r, body.(map[string]any))
	default:
		h.guardianStored(w, r, route, body)
	}
}
func mfaBody(r *http.Request, contract map[string]any) (any, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, badBody("invalid MFA configuration")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var v any
	if dec.Decode(&v) != nil {
		return nil, badBody("invalid MFA configuration")
	}
	*r = *r.WithContext(registerManagementCredentials(r.Context(), v, false))
	if object, ok := v.(map[string]any); ok {
		properties, _ := contract["properties"].(map[string]any)
		for k, value := range object {
			p, _ := properties[k].(map[string]any)
			if p["writeOnly"] == true {
				if secret, ok := value.(string); ok {
					*r = *r.WithContext(logscrub.WithCredentials(r.Context(), secret))
				}
			}
		}
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, badBody("invalid MFA configuration")
	}
	b, _ := json.Marshal(contract)
	var schema openapi3.Schema
	if json.Unmarshal(b, &schema) != nil || schema.VisitJSON(v, openapi3.VisitAsRequest(), openapi3.EnableFormatValidation(), openapi3.WithStringFormatValidator("non-empty-string", openapi3.NewCallbackValidator(func(value string) error {
		if value == "" {
			return store.ErrInvalid
		}
		return nil
	}))) != nil {
		return nil, badBody("invalid MFA configuration")
	}
	// Reject non-storable strings without reflecting supplied values into errors.
	if !mfaText(v) {
		return nil, badBody("invalid MFA configuration")
	}
	return v, nil
}
func mfaText(v any) bool {
	switch x := v.(type) {
	case string:
		return storableText(x)
	case map[string]any:
		for k, v := range x {
			if !storableText(k) || !mfaText(v) {
				return false
			}
		}
	case []any:
		for _, v := range x {
			if !mfaText(v) {
				return false
			}
		}
	}
	return true
}
func (h *Handlers) mfaFail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrWebAuthnUnavailable):
		Fail(w, &Error{Status: 501, Code: "webauthn_unavailable", Message: "WebAuthn is unavailable"})
	case errors.Is(err, store.ErrMFAUnavailable):
		Fail(w, errMFAUnavailable)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errMFAMissing)
	case errors.Is(err, store.ErrInvalid):
		Fail(w, badBody("invalid MFA configuration"))
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrPrecondition):
		Fail(w, &Error{Status: 409, Code: "conflict", Message: "The MFA resource changed concurrently"})
	default:
		Fail(w, err)
	}
}
func (h *Handlers) guardianWrite(r *http.Request, fn func(*store.GuardianSettings) error) error {
	return h.Store.WithTx(r.Context(), func(tx store.Store) error {
		t, err := tx.Tenants().Get(r.Context(), resolved(r).ID)
		if err != nil {
			return err
		}
		if t.Reserved {
			return errSystemTenant
		}
		g, err := tx.MFA().GetGuardian(r.Context(), t.ID)
		if err != nil {
			return err
		}
		if g.Factors == nil {
			g.Factors = map[string]bool{}
		}
		if g.Stored == nil {
			g.Stored = map[string]json.RawMessage{}
		}
		if g.SealedSecrets == nil {
			g.SealedSecrets = map[string][]byte{}
		}
		if err = fn(g); err != nil {
			return err
		}
		return tx.MFA().PutGuardian(r.Context(), g, g.Version)
	})
}
func mfaEmail(s string) bool { return identity.CheckEmail(s) == nil }
