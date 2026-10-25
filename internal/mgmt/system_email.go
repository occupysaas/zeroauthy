package mgmt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/emailrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const systemEmailBodyLimit = 32 << 10

var (
	errSystemEmailTemplate = &Error{Status: http.StatusNotFound, Code: "inexistent_email_template", Message: "The enabled email template does not exist"}
	errSystemEmailTenant   = &Error{Status: http.StatusForbidden, Code: "operation_not_supported", Message: "Email preview and test require a non-reserved tenant"}
	errSystemEmailLimit    = &Error{Status: http.StatusTooManyRequests, Code: "rate_limit_exceeded", Message: "Email preview or test limit reached"}
)

func (h *Handlers) systemEmailTarget(w http.ResponseWriter, r *http.Request, name string) (*store.Tenant, Caller, bool) {
	base, ok := tenant.FromContext(r.Context())
	if !ok || h.SystemHost == "" || tenant.NormalizeHost(base.Host) != tenant.NormalizeHost(h.SystemHost) {
		WriteError(w, http.StatusNotFound, "", "Not Found")
		return nil, Caller{}, false
	}
	c, ok := CallerFrom(r.Context())
	if !ok || c.Kind != Operator || c.UserID == "" {
		WriteError(w, http.StatusForbidden, "insufficient_scope", "Only console operators may preview or test email")
		return nil, Caller{}, false
	}
	t, err := h.Store.Tenants().GetByName(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, &Error{Status: http.StatusNotFound, Code: "inexistent_tenant", Message: "The tenant does not exist"})
		return nil, Caller{}, false
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal error")
		return nil, Caller{}, false
	}
	if t.Reserved {
		Fail(w, errSystemEmailTenant)
		return nil, Caller{}, false
	}
	return t, c, true
}

func (h *Handlers) claimSystemEmail(w http.ResponseWriter, r *http.Request, t *store.Tenant, c Caller, purpose string, period time.Duration, limit int) bool {
	now := h.now().UTC()
	start := now.Truncate(period)
	event := fmt.Sprint(start.Unix())
	claimed, err := h.Store.EmailNotifications().Claim(r.Context(), t.ID, c.UserID, purpose, event, now, start.Add(period), limit)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal error")
		return false
	}
	if !claimed {
		w.Header().Set("Retry-After", fmt.Sprint(max(1, int(start.Add(period).Sub(now).Seconds()))))
		Fail(w, errSystemEmailLimit)
		return false
	}
	return true
}

func (h *Handlers) PreviewEmail(w http.ResponseWriter, r *http.Request, tenantName string) {
	t, c, ok := h.systemEmailTarget(w, r, tenantName)
	if !ok {
		return
	}
	if h.EmailService == nil {
		WriteError(w, http.StatusServiceUnavailable, "email_unavailable", "Email service is unavailable")
		return
	}
	body, err := readSystemEmailBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	for key := range body {
		if key != "template" && key != "overrides" {
			Fail(w, badBody("unknown property"))
			return
		}
	}
	name, err := rawString(body["template"])
	if err != nil || !emailrules.KnownTemplate(name) {
		Fail(w, badBody("template must name a supported email template"))
		return
	}
	overrides := map[string]any{}
	if raw, exists := body["overrides"]; exists {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil || len(raw) > 16<<10 {
			Fail(w, badBody("overrides must be a bounded object"))
			return
		}
		for key, value := range fields {
			switch key {
			case "body", "subject", "from":
				var v string
				if json.Unmarshal(value, &v) != nil {
					Fail(w, badBody("invalid override"))
					return
				}
				overrides[key] = v
			case "variables":
				var v map[string]any
				dec := json.NewDecoder(strings.NewReader(string(value)))
				dec.UseNumber()
				if dec.Decode(&v) != nil || v == nil {
					Fail(w, badBody("variables must be an object"))
					return
				}
				overrides[key] = v
			default:
				Fail(w, badBody("unsupported override"))
				return
			}
		}
	}
	policy, err := h.EmailService.Resolve(r.Context(), t.ID, name)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal error")
		return
	}
	if policy.Template == nil || !policy.Enabled {
		Fail(w, errSystemEmailTemplate)
		return
	}
	if !h.claimSystemEmail(w, r, t, c, "preview", time.Minute, 30) {
		return
	}
	rendered, err := h.EmailService.Preview(r.Context(), t.ID, name, overrides)
	if err != nil {
		Fail(w, badBody("template could not be rendered"))
		return
	}
	h.auditSystemEmail(r, t, "preview email", name, "rendered")
	WriteJSON(w, http.StatusOK, rendered)
}

func readSystemEmailBody(r *http.Request) (map[string]json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, systemEmailBodyLimit+1))
	if err != nil || len(data) > systemEmailBodyLimit {
		return nil, badBody("the body is too large or unreadable")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(data, &body) != nil || body == nil {
		return nil, badBody("the body must be a JSON object")
	}
	return body, nil
}

func rawString(raw json.RawMessage) (string, error) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return "", store.ErrInvalid
	}
	return value, nil
}

func (h *Handlers) auditSystemEmail(r *http.Request, t *store.Tenant, action, template, outcome string) {
	c, _ := CallerFrom(r.Context())
	h.log().InfoContext(r.Context(), "management API: "+action, "tenant", t.Name, "actor", c.UserID, "template", template, "outcome", outcome)
}
