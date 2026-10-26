package mgmt

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	errCustomDomainNotFound    = &Error{Status: http.StatusNotFound, Code: "inexistent_custom_domain", Message: "The custom domain does not exist"}
	errCustomDomainsOff        = &Error{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable", Message: "Custom domains are not available on this deployment."}
	errCustomDomainNotReady    = &Error{Status: http.StatusConflict, Code: "custom_domain_not_ready", Message: "The custom domain is not ready."}
	errCustomDomainExists      = &Error{Status: http.StatusConflict, Code: "custom_domain_conflict", Message: "The domain is already claimed or the custom domain limit is reached."}
	errCustomDomainTooLarge    = &Error{Status: http.StatusRequestEntityTooLarge, Code: "payload_too_large", Message: "The request body is larger than 64 KiB."}
	errCustomDomainManagedOff  = &Error{Status: http.StatusServiceUnavailable, Code: "custom_domain_unavailable", Message: "Managed certificates are not enabled on this deployment."}
	errCustomDomainOriginOff   = &Error{Status: http.StatusServiceUnavailable, Code: "custom_domain_unavailable", Message: "Self-managed custom domains need origin TLS on this deployment."}
	errCustomDomainUnavailable = &Error{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable", Message: "The custom domain service is temporarily unavailable."}
)

// domainError maps service errors to Management API errors without echoing
// internal detail.
func (h *Handlers) domainError(w http.ResponseWriter, r *http.Request, what string, err error) {
	var rl *customdomain.RateLimitError
	switch {
	case errors.As(err, &rl):
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int((rl.RetryAfter+time.Second-1)/time.Second))))
		Fail(w, &Error{Status: http.StatusTooManyRequests, Code: "too_many_requests", Message: "Too many verification attempts; retry later."})
	case errors.Is(err, customdomain.ErrBodyTooLarge):
		Fail(w, errCustomDomainTooLarge)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errCustomDomainNotFound)
	case errors.Is(err, store.ErrInvalid):
		Fail(w, badBody("Payload validation error: %s", strings.TrimPrefix(strings.TrimSuffix(err.Error(), ": "+store.ErrInvalid.Error()), "customdomain: ")))
	case errors.Is(err, store.ErrConflict):
		Fail(w, errCustomDomainExists)
	case errors.Is(err, customdomain.ErrNotReady):
		Fail(w, errCustomDomainNotReady)
	case errors.Is(err, customdomain.ErrManagedUnavailable):
		Fail(w, errCustomDomainManagedOff)
	case errors.Is(err, customdomain.ErrOriginTLSUnavailable):
		Fail(w, errCustomDomainOriginOff)
	case errors.Is(err, customdomain.ErrDiagnosticUnavailable), errors.Is(err, store.ErrCustomDomainRepositoryUnavailable):
		Fail(w, errCustomDomainUnavailable)
	default:
		Fail(w, internalError(h, r, what, err))
	}
}

// readDomainBody reads at most 64 KiB plus one byte so oversize is a 413.
func readDomainBody(r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil {
		return nil, badBody("Payload validation error: the body could not be read")
	}
	return raw, nil
}

func (h *Handlers) domainsOn(w http.ResponseWriter) bool {
	if h.Domains == nil {
		Fail(w, errCustomDomainsOff)
		return false
	}
	return true
}

// customDomainJSON is the public DTO, mapped field by field: proofs tokens,
// key hashes, generations and worker state never leave storage.
func (h *Handlers) customDomainJSON(r *http.Request, d *store.CustomDomain, defaultID string) map[string]any {
	header := any(d.CustomClientIPHeader)
	if d.CustomClientIPHeaderNull {
		header = nil
	}
	md := map[string]any{}
	for k, v := range d.DomainMetadata {
		md[k] = v
	}
	verification := map[string]any{
		"methods": []any{map[string]any{"name": "txt", "record": d.ProofRecordValue, "domain": d.ProofRecordName}},
		"status":  d.ProofStatus,
	}
	if d.ProofVerifiedAt != nil {
		verification["last_verified_at"] = d.ProofVerifiedAt.UTC().Format(time.RFC3339)
	}
	if d.LastFailure != "" && d.ProofStatus != customdomain.ProofVerified {
		verification["error_msg"] = d.LastFailure
	}
	out := map[string]any{
		"custom_domain_id": d.ID, "domain": d.Domain, "primary": false, "status": d.Status, "type": d.Type,
		"verification": verification, "is_default": d.ID == defaultID, "custom_client_ip_header": header,
		"tls_policy": d.TLSPolicy, "domain_metadata": md, "relying_party_identifier": d.RelyingPartyIdentifier,
	}
	if d.OriginHost != "" {
		out["origin_domain_name"] = d.OriginHost
	}
	if c := certificateJSON(r, h, d); c != nil {
		out["certificate"] = c
	}
	return out
}

// certificateJSON projects the sourced certificate status of a managed domain.
func certificateJSON(r *http.Request, h *Handlers, d *store.CustomDomain) map[string]any {
	if d.Type != customdomain.TypeManaged {
		return nil
	}
	var status string
	switch d.Lifecycle {
	case customdomain.LifecycleIssuing:
		status = "provisioning"
		if d.Status == customdomain.StatusFailed {
			status = "provisioning_failed"
		}
	case customdomain.LifecycleActive:
		status = "provisioned"
	case customdomain.LifecycleRenewalError:
		status = "renewing_failed"
	default:
		return nil
	}
	c := map[string]any{"status": status}
	if d.LastFailure != "" && status != "provisioned" {
		c["error_msg"] = d.LastFailure
	}
	if d.ActiveCertificateKey != "" {
		if a, err := h.Store.TLSAssets().Get(r.Context(), d.ActiveCertificateKey); err == nil && !a.PublicData.NotAfter.IsZero() {
			c["renews_before"] = a.PublicData.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	return c
}

func (h *Handlers) defaultID(r *http.Request) (string, error) {
	return h.Store.CustomDomains().GetDefault(r.Context(), resolved(r).ID)
}

// GetCustomDomains serves GET /custom-domains.
func (h *Handlers) GetCustomDomains(w http.ResponseWriter, r *http.Request) {
	if !h.domainsOn(w) {
		return
	}
	q, err := customdomain.ValidateListQuery(r.URL.Query())
	if err != nil {
		Fail(w, badQuery("Query validation error: %s", strings.TrimPrefix(strings.TrimSuffix(err.Error(), ": "+store.ErrInvalid.Error()), "customdomain: ")))
		return
	}
	rows, err := h.Store.CustomDomains().List(r.Context(), resolved(r).ID)
	if err != nil {
		h.domainError(w, r, "list custom domains", err)
		return
	}
	def, err := h.defaultID(r)
	if err != nil {
		h.domainError(w, r, "list custom domains", err)
		return
	}
	slices.SortFunc(rows, func(a, b *store.CustomDomain) int { return strings.Compare(a.Domain, b.Domain) })
	out := []any{}
	for _, d := range rows {
		if !q.Query.Matches(d) {
			continue
		}
		out = append(out, project(h.customDomainJSON(r, d, def), q.Fields, q.IncludeFields))
	}
	writeJSON(w, http.StatusOK, out)
}

// project keeps (or drops) the listed fields; no list means everything.
func project(m map[string]any, fields []string, include bool) map[string]any {
	if len(fields) == 0 {
		return m
	}
	out := map[string]any{}
	for k, v := range m {
		if slices.Contains(fields, k) == include {
			out[k] = v
		}
	}
	return out
}

// CreateCustomDomain serves POST /custom-domains.
func (h *Handlers) CreateCustomDomain(w http.ResponseWriter, r *http.Request) {
	if !h.domainsOn(w) {
		return
	}
	raw, err := readDomainBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	in, err := customdomain.ValidateCreate(raw, h.Domains.Reserved())
	if err != nil {
		h.domainError(w, r, "create custom domain", err)
		return
	}
	d, err := h.Domains.Create(r.Context(), resolved(r).ID, in)
	if err != nil {
		h.domainError(w, r, "create custom domain", err)
		return
	}
	h.audit(r, "create custom domain", "id", d.ID, "domain", d.Domain, "type", d.Type)
	writeJSON(w, http.StatusCreated, h.customDomainJSON(r, d, ""))
}

// GetCustomDomain serves GET /custom-domains/{id}.
func (h *Handlers) GetCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	if !h.domainsOn(w) {
		return
	}
	d, err := h.Domains.Get(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.domainError(w, r, "get custom domain", err)
		return
	}
	def, err := h.defaultID(r)
	if err != nil {
		h.domainError(w, r, "get custom domain", err)
		return
	}
	writeJSON(w, http.StatusOK, h.customDomainJSON(r, d, def))
}

// UpdateCustomDomain serves PATCH /custom-domains/{id}.
func (h *Handlers) UpdateCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	if !h.domainsOn(w) {
		return
	}
	raw, err := readDomainBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	cur, err := h.Domains.Get(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.domainError(w, r, "update custom domain", err)
		return
	}
	in, err := customdomain.ValidatePatch(raw, cur)
	if err != nil {
		h.domainError(w, r, "update custom domain", err)
		return
	}
	d, err := h.Domains.Update(r.Context(), resolved(r).ID, id, in)
	if err != nil {
		h.domainError(w, r, "update custom domain", err)
		return
	}
	def, _ := h.defaultID(r)
	h.audit(r, "update custom domain", "id", d.ID)
	writeJSON(w, http.StatusOK, h.customDomainJSON(r, d, def))
}

// DeleteCustomDomain serves DELETE /custom-domains/{id}.
func (h *Handlers) DeleteCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	if !h.domainsOn(w) {
		return
	}
	if err := h.Domains.Delete(r.Context(), resolved(r).ID, id); err != nil {
		h.domainError(w, r, "delete custom domain", err)
		return
	}
	h.audit(r, "delete custom domain", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// VerifyCustomDomain serves POST /custom-domains/{id}/verify. The proxy key
// is in this response only when this call created it.
func (h *Handlers) VerifyCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	if !h.domainsOn(w) {
		return
	}
	res, err := h.Domains.Verify(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.domainError(w, r, "verify custom domain", err)
		return
	}
	def, _ := h.defaultID(r)
	out := h.customDomainJSON(r, res.Domain, def)
	if res.CNAMEAPIKey != "" {
		out["cname_api_key"] = res.CNAMEAPIKey
	}
	h.audit(r, "verify custom domain", "id", id, "status", res.Domain.Status)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// TestCustomDomain serves POST /custom-domains/{id}/test.
func (h *Handlers) TestCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	if !h.domainsOn(w) {
		return
	}
	diag, err := h.Domains.Test(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.domainError(w, r, "test custom domain", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": diag.Success, "message": diag.Message})
}

// GetDefaultCustomDomain serves GET /custom-domains/default: the configured
// domain even while unavailable, or {"domain": canonical}.
func (h *Handlers) GetDefaultCustomDomain(w http.ResponseWriter, r *http.Request) {
	if !h.domainsOn(w) {
		return
	}
	d, err := h.Domains.Default(r.Context(), resolved(r).ID)
	if err != nil {
		h.domainError(w, r, "get default custom domain", err)
		return
	}
	if d == nil {
		writeJSON(w, http.StatusOK, map[string]any{"domain": resolved(r).CanonicalHost})
		return
	}
	writeJSON(w, http.StatusOK, h.customDomainJSON(r, d, d.ID))
}

// SetDefaultCustomDomain serves PATCH /custom-domains/default.
func (h *Handlers) SetDefaultCustomDomain(w http.ResponseWriter, r *http.Request) {
	if !h.domainsOn(w) {
		return
	}
	raw, err := readDomainBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if len(raw) > 65536 {
		Fail(w, errCustomDomainTooLarge)
		return
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil || body == nil {
		Fail(w, badBody("the body must be a JSON object"))
		return
	}
	domain, ok := body["domain"].(string)
	if !ok || domain == "" || len(body) != 1 {
		Fail(w, badBody("Payload validation error: domain is required and is the only property"))
		return
	}
	d, err := h.Domains.SetDefault(r.Context(), resolved(r).ID, domain)
	if err != nil {
		h.domainError(w, r, "set default custom domain", err)
		return
	}
	h.audit(r, "set default custom domain", "domain", domain)
	if d == nil {
		writeJSON(w, http.StatusOK, map[string]any{"domain": resolved(r).CanonicalHost})
		return
	}
	writeJSON(w, http.StatusOK, h.customDomainJSON(r, d, d.ID))
}
