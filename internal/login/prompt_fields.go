package login

import (
	"maps"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

func formVariables(f *flow, prompt, screen string) map[string]any {
	return map[string]any{
		"tenant":      map[string]any{"name": f.view.Name, "support_url": f.view.SupportURL, "support_email": f.view.SupportEmail},
		"application": map[string]any{"name": f.clientName}, "locale": map[string]any{"language": f.view.L.Lang()},
		"prompt":   map[string]any{"name": prompt, "screen": map[string]any{"name": screen, "text": f.view.L.ScreenText(prompt, screen)}},
		"branding": map[string]any{"logo_url": f.view.LogoURL, "primary_color": f.view.PrimaryColor},
	}
}

func (h *Handlers) renderedFields(r *http.Request, f *flow, prompt, screen string) map[string]string {
	if f.config == nil {
		return map[string]string{}
	}
	out, err := hostedlogin.RenderPartials(r.Context(), f.config.Partials[prompt][screen], formVariables(f, prompt, screen), f.txn.HostedState.PromptFields, "")
	bytes := 0
	for _, slot := range out.Slots {
		bytes += len(slot)
	}
	// Reserve space for the original widget within the shared 512 KiB page
	// output budget. An omitted partial must also have no capturable controls.
	if bytes > 384<<10 {
		err = hostedlogin.ErrPartialFields
	}
	if err != nil {
		h.log().WarnContext(r.Context(), "hosted partial fallback", "tenant", f.res.Tenant.ID, "screen", screen)
		ui.ApplyPartials(&f.view, hostedlogin.PartialOutput{})
		return map[string]string{}
	}
	ui.ApplyPartials(&f.view, out)
	return out.Fields
}

func (h *Handlers) prepareHostedForm(w http.ResponseWriter, r *http.Request, f *flow, prompt, screen string) bool {
	if f.config == nil {
		return true
	}
	state := f.txn.HostedState
	fields := h.renderedFields(r, f, prompt, screen)
	if state.FormConfigRevision != f.config.Revision || state.FormScreen != screen || state.FormLanguage != f.view.L.Lang() || !maps.Equal(state.FormFields, fields) {
		next := state.Clone()
		next.FormConfigRevision = f.config.Revision
		next.FormScreen = screen
		next.FormLanguage = f.view.L.Lang()
		next.FormFields = maps.Clone(fields)
		if state.FormScreen == screen {
			for name := range state.FormFields {
				if _, present := fields[name]; !present {
					delete(next.PromptFields, name)
				}
			}
		}
		if err := h.transitionHosted(r, f, next); err != nil {
			h.fail(w, r, errTxn, f)
			return false
		}
	}
	return true
}

func (h *Handlers) guardHostedForm(w http.ResponseWriter, r *http.Request, f *flow, prompt, screen string, redisplay func(int, string)) bool {
	if f.config == nil {
		return true
	}
	state := f.txn.HostedState
	if !postedHostedRevision(r, f) || state.FormConfigRevision != f.config.Revision || state.FormScreen != screen {
		redisplay(http.StatusConflict, f.view.L.T(i18n.KeyHostedFormChanged))
		return false
	}
	fields := h.renderedFields(r, f, prompt, screen)
	if !maps.Equal(state.FormFields, fields) {
		redisplay(http.StatusConflict, f.view.L.T(i18n.KeyHostedFormChanged))
		return false
	}
	values, err := hostedlogin.CaptureFields(r.PostForm, fields, state.PromptFields)
	if err != nil {
		redisplay(http.StatusBadRequest, f.view.L.T(i18n.KeyHostedFieldsInvalid))
		return false
	}
	next := state.Clone()
	next.PromptFields = values
	if err := h.transitionHosted(r, f, next); err != nil {
		h.fail(w, r, errTxn, f)
		return false
	}
	return true
}

func hostedRevision(f *flow) *int64 {
	if f.config == nil {
		return nil
	}
	revision := f.txn.HostedState.Revision
	return &revision
}
func (h *Handlers) renderIdentifier(w http.ResponseWriter, r *http.Request, status int, f *flow, data ui.LoginStageData) {
	if !h.prepareHostedForm(w, r, f, "login-id", "login-id") {
		return
	}
	data.Revision = f.txn.HostedState.Revision
	ui.RenderLoginIdentifier(w, status, f.view, data)
}
func (h *Handlers) renderSignup(w http.ResponseWriter, r *http.Request, status int, f *flow, data ui.SignupData) {
	if !h.prepareHostedForm(w, r, f, "signup", "signup") {
		return
	}
	data.HostedRevision = hostedRevision(f)
	ui.RenderSignup(w, status, f.view, data)
}
