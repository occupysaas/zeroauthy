package phone

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/liquid"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrTemplateDisabled reports a branding template the operator disabled:
// no message of that type is sent.
var ErrTemplateDisabled = errors.New("phone: the phone template is disabled")

// errRender never carries the template source or variables.
var errRender = errors.New("phone: the phone template could not be rendered")

// Template types (phonerules). "passwordless" is a message type that uses
// otp_verify under the consolidated experience (D-0060 P7).
func templateType(messageType string) string {
	if messageType == "passwordless" {
		return "otp_verify"
	}
	return messageType
}

// rules caches the frozen phonerules data the dispatcher reads per send.
var rules = sync.OnceValue(func() struct {
	templates        map[string]phonerules.TemplateType
	guardianDefaults map[string]string
	routing          []phonerules.RoutingRule
	required         map[string][]string
	providers        []phonerules.Provider
} {
	inv := phonerules.Inventory()
	out := struct {
		templates        map[string]phonerules.TemplateType
		guardianDefaults map[string]string
		routing          []phonerules.RoutingRule
		required         map[string][]string
		providers        []phonerules.Provider
	}{templates: map[string]phonerules.TemplateType{}, guardianDefaults: map[string]string{}, routing: inv.Routing, required: map[string][]string{}, providers: inv.Providers}
	for _, t := range inv.Templates {
		out.templates[t.Type] = t
	}
	if d, ok := inv.GuardianTemplates["defaults"].(map[string]any); ok {
		for k, v := range d {
			out.guardianDefaults[k], _ = v.(string)
		}
	}
	for _, p := range inv.ProviderSchemas {
		for _, f := range p.Required {
			if f != "delivery_methods" {
				out.required[p.Name] = append(out.required[p.Name], f)
			}
		}
	}
	return out
})

// Content is a branding template's content.
type Content struct {
	From string `json:"from"`
	Body struct {
		Text  string `json:"text"`
		Voice string `json:"voice"`
	} `json:"body"`
}

// brandingContent returns the stored content of type typ over its default.
func brandingContent(ctx context.Context, st store.Store, tid, typ string) (Content, error) {
	var c Content
	d, ok := rules().templates[typ]
	if !ok {
		return c, errors.New("phone: unknown template type")
	}
	c.From, c.Body.Text, c.Body.Voice = d.Default.From, d.Default.Body.Text, d.Default.Body.Voice
	list, err := st.Phone().ListPhoneTemplates(ctx, tid)
	if err != nil {
		return c, err
	}
	for _, t := range list {
		if t.Type != typ {
			continue
		}
		if t.Disabled {
			return c, ErrTemplateDisabled
		}
		_ = json.Unmarshal(t.Content, &c)
		break
	}
	return c, nil
}

// SpokenCode separates the code's characters with dots so a voice reads it
// digit by digit (D-0060 guardian voice_code rule). It is as secret as the
// code.
func SpokenCode(code string) string {
	return strings.Join(strings.Split(code, ""), ".")
}

// codeFor is the code as a template sees it for one delivery method.
func codeFor(code, method string) string {
	if method == "voice" {
		return SpokenCode(code)
	}
	return code
}

// renderInfo is what templates may reference about one send.
type renderInfo struct {
	tenant     *store.Tenant
	user       *store.User
	client     *store.Client
	connection string
	code       string
	locale     string
	request    Request
	phone      string
}

func (ri renderInfo) friendlyName() string {
	if ri.tenant == nil {
		return ""
	}
	if ri.tenant.FriendlyName != "" {
		return ri.tenant.FriendlyName
	}
	return ri.tenant.Name
}

// brandingVars are the documented branding template variables (phonerules
// templates[].variables) that zeroauthy knows; unknown ones render empty.
func brandingVars(ri renderInfo, method string) map[string]any {
	v := map[string]any{"code": codeFor(ri.code, method), "friendly_name": ri.friendlyName(), "locale": ri.locale, "connection": ri.connection}
	if t := ri.tenant; t != nil {
		v["tenant"], v["support_email"], v["support_url"], v["logo_url"] = t.Name, t.SupportEmail, t.SupportURL, t.Branding.LogoURL
	}
	if u := ri.user; u != nil {
		v["user"] = map[string]any{"name": u.Name, "nickname": u.Nickname, "given_name": u.GivenName, "family_name": u.FamilyName,
			"picture": u.Picture, "login_count": u.LoginsCount, "user_metadata": u.UserMetadata, "app_metadata": u.AppMetadata,
			"email_verified": u.EmailVerified, "email": u.Email, "phone_number": u.PhoneNumber, "phone_verified": u.PhoneVerified}
	}
	if c := ri.client; c != nil {
		v["client"] = map[string]any{"name": c.Name, "clientID": c.ClientID, "metadata": map[string]any{}}
		v["application"] = map[string]any{"name": c.Name, "client_metadata": map[string]any{}}
	}
	return v
}

// guardianVars are the Guardian SMS template variables.
func guardianVars(ri renderInfo, method string) map[string]any {
	mt := "sms"
	if method == "voice" {
		mt = "voice"
	}
	pause := ""
	if method == "voice" {
		pause = ". "
	}
	return map[string]any{"code": codeFor(ri.code, method), "locale": ri.locale, "message_type": mt, "pause": pause,
		"requestInfo": map[string]any{"lang": ri.request.Language},
		// friendly_name is accepted too: Plan 33's stored defaults use it.
		"tenant": map[string]any{"friendlyName": ri.friendlyName(), "friendly_name": ri.friendlyName()}}
}

// connectionVars are an sms connection template's variables.
func connectionVars(ri renderInfo) map[string]any {
	app := ""
	if ri.client != nil {
		app = ri.client.Name
	}
	lang := ri.request.Language
	if lang == "" {
		lang = ri.locale
	}
	return map[string]any{"password": ri.code, "code": ri.code, "phone_number": ri.phone, "application": map[string]any{"name": app}, "request_language": lang}
}

func renderLiquid(ctx context.Context, src string, vars map[string]any) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// The renderer drops code-like keys from ordinary variables; the
	// documented code variables are passed as trusted codes instead.
	codes := map[string]string{}
	for _, k := range []string{"code", "password"} {
		if v, ok := vars[k].(string); ok {
			codes[k] = v
			delete(vars, k)
		}
	}
	out, err := liquid.Render(ctx, src, vars, nil, liquid.Limits{MaxSourceBytes: phonerules.Limits.TemplateBodyMax, MaxOutputBytes: 64 << 10, Codes: codes})
	if err != nil || strings.TrimSpace(out) == "" {
		return "", errRender
	}
	return out, nil
}

// renderMacros expands md_with_macros "@@name@@" macros (and the Liquid-like
// "{{name}}" form Auth0's examples also use) from flat dotted names.
func renderMacros(src string, vars map[string]any) (string, error) {
	flat := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				walk(prefix+k+".", e)
			}
		case string:
			flat[strings.TrimSuffix(prefix, ".")] = x
		}
	}
	walk("", vars)
	pairs := []string{}
	for k, v := range flat {
		pairs = append(pairs, "@@"+k+"@@", v, "{{"+k+"}}", v, "{{ "+k+" }}", v)
	}
	out := strings.NewReplacer(pairs...).Replace(src)
	if strings.TrimSpace(out) == "" {
		return "", errRender
	}
	return out, nil
}

// CodeForms are the code and its digit-separated spellings (dots, spaces,
// dashes, commas): every form a log scrubber must mask.
func CodeForms(code string) []string {
	if code == "" {
		return nil
	}
	out := []string{code}
	if len(code) < 2 {
		return out
	}
	chars := strings.Split(code, "")
	for _, sep := range []string{".", " ", "-", ",", ", ", ". "} {
		out = append(out, strings.Join(chars, sep))
	}
	return out
}
