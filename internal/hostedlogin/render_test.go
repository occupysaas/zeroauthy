package hostedlogin

import (
	"context"
	"strings"
	"testing"
)

func TestTemplateTagBranches(t *testing.T) {
	r := Renderer{}
	in := RenderInput{Source: `<html><head>{%- auth0:head -%}</head><body>{% if prompt.screen %}{%- auth0:widget -%}{% endif %}</body></html>`, Variables: map[string]any{"prompt": map[string]any{"screen": "login"}}, Head: `<meta name="x" content="y">`, Widget: `<form id="login"></form>`}
	out, err := r.Render(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.HTML, `<form id="login">`) != 1 {
		t.Fatalf("widget count: %s", out.HTML)
	}
	in.Variables["prompt"] = map[string]any{"screen": ""}
	if _, err := r.Render(context.Background(), in); err == nil {
		t.Fatal("branch emitted no widget")
	}
	in.Source = `<html><head>{% auth0:head %}</head><body>{% auth0:widget %}{% auth0:widget %}</body></html>`
	if _, err := r.Render(context.Background(), in); err == nil {
		t.Fatal("two widgets accepted")
	}
}
func TestRenderBudgets(t *testing.T) {
	r := Renderer{}
	src := `<html><head>{% auth0:head %}</head><body>{% auth0:widget %}` + strings.Repeat("a", 100<<10) + `</body></html>`
	if _, err := r.Render(context.Background(), RenderInput{Source: src, Widget: "<form></form>"}); err == nil {
		t.Fatal("oversized source accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Render(ctx, RenderInput{Source: `<html><head>{% auth0:head %}</head><body>{% auth0:widget %}</body></html>`, Widget: "<form></form>"}); err == nil {
		t.Fatal("cancelled render succeeded")
	}
}

func TestTemplateExactSourceLimit(t *testing.T) {
	prefix := `<html><head>{% auth0:head %}</head><body>{% auth0:widget %}`
	suffix := `</body></html>`
	source := prefix + strings.Repeat("a", 100<<10-len(prefix)-len(suffix)) + suffix
	if _, err := (Renderer{}).Render(context.Background(), RenderInput{Source: source, Widget: "<form></form>"}); err != nil {
		t.Fatalf("100 KiB source rejected: %v", err)
	}
	if err := ValidateSource(source+"a", false); err == nil {
		t.Fatal("source over 100 KiB accepted")
	}
}
func TestTemplateCapabilities(t *testing.T) {
	bad := []string{`<html><head>{% auth0:head %}</head><body><script>alert(1)</script>{% auth0:widget %}</body></html>`, `<html><head>{% auth0:head %}</head><body><div onclick="go()"></div>{% auth0:widget %}</body></html>`, `<html><head>{% auth0:head %}</head><body><form>{% auth0:widget %}</form></body></html>`}
	for _, src := range bad {
		if err := ValidateSource(src, false); err == nil {
			t.Fatalf("accepted unsafe template: %s", src)
		}
	}
}
func TestProjectedContext(t *testing.T) {
	vars := ProjectContext(map[string]any{"tenant": map[string]any{"name": "acme", "secret": "bad"}, "password": "bad", "csrf": "bad", "application": map[string]any{"name": "test"}})
	if _, ok := vars["password"]; ok {
		t.Fatal("password projected")
	}
	if _, ok := vars["csrf"]; ok {
		t.Fatal("CSRF projected")
	}
	if vars["tenant"].(map[string]any)["name"] != "acme" {
		t.Fatal("tenant name missing")
	}
	if _, ok := vars["tenant"].(map[string]any)["secret"]; ok {
		t.Fatal("tenant secret projected")
	}
}
func TestCSSPolicy(t *testing.T) {
	if err := ValidateCSS(`.za-decoration { color: #abcdef; padding: 12px; }`); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`.za-decoration { opacity: 0 }`, `.za-decoration > form { display:none }`, `.za-decoration { margin: -1px }`, `@import url(https://a.test/a.css);`, `.za-decoration { position: absolute }`} {
		if err := ValidateCSS(s); err == nil {
			t.Errorf("accepted CSS %q", s)
		}
	}
}

func TestTemplateTagSpoof(t *testing.T) {
	for _, source := range []string{
		`<html><head>ZA_INTERNAL_HEAD_MARKER</head><body>ZA_INTERNAL_WIDGET_MARKER</body></html>`,
		`<html><head>{% auth0:head %}</head><body>ZA_INTERNAL_WIDGET_MARKER</body></html>`,
		`<html><head>{% auth0:widget %}</head><body>{% auth0:head %}</body></html>`,
		`<html><head><!-- {% auth0:head %} --></head><body>{% auth0:widget %}</body></html>`,
		`<html><head>{% auth0:head %}</head><body><div title="{% auth0:widget %}">Hidden</div></body></html>`,
	} {
		if err := ValidateSource(source, false); err == nil {
			t.Errorf("accepted missing or misplaced trusted tags: %s", source)
		}
	}
}
func TestHTMLContexts(t *testing.T) {
	r := Renderer{}
	source := `<html><head>{% auth0:head %}</head><body><a href="{{ tenant.support_url }}">Help</a>{% auth0:widget %}</body></html>`
	_, err := r.Render(context.Background(), RenderInput{Source: source, Variables: map[string]any{"tenant": map[string]any{"support_url": "javascript:alert(1)"}}, Widget: "<form></form>"})
	if err == nil {
		t.Fatal("dynamic javascript URL accepted")
	}
}

func TestTemplateMarkerCannotComeFromTenantValue(t *testing.T) {
	r := Renderer{}
	source := `<html><head>{% auth0:head %}</head><body>{{ tenant.name }}{% if prompt.screen %}{% auth0:widget %}{% endif %}</body></html>`
	_, err := r.Render(context.Background(), RenderInput{Source: source, Variables: map[string]any{"tenant": map[string]any{"name": "ZA_INTERNAL_WIDGET_MARKER"}, "prompt": map[string]any{"screen": ""}}, Widget: "<form></form>"})
	if err == nil {
		t.Fatal("tenant data satisfied missing widget branch")
	}
}

func TestTemplateVoidImageTag(t *testing.T) {
	src := `<html><head>{% auth0:head %}</head><body><img src="https://example.test/logo.png" alt="Logo">{% auth0:widget %}</body></html>`
	if err := ValidateSource(src, false); err != nil {
		t.Fatalf("safe image rejected: %v", err)
	}
}
func TestTemplateUnknownLiquidTag(t *testing.T) {
	src := `<html><head>{% auth0:head %}</head><body>{% include 'remote' %}{% auth0:widget %}</body></html>`
	if err := ValidateSource(src, false); err == nil {
		t.Fatal("unsupported tag accepted at save")
	}
}
func TestWidgetCannotBeDecoration(t *testing.T) {
	src := `<html><head>{% auth0:head %}</head><body><div class="za-decoration">{% auth0:widget %}</div></body></html>`
	if err := ValidateSource(src, false); err == nil {
		t.Fatal("widget inside tenant styled decoration accepted")
	}
}
func TestPartialControlSafety(t *testing.T) {
	for _, source := range []string{
		`<input name="password" type="text">`,
		`<input aria-label="Additional information" name="ulp-note" type="password">`,
		`<input aria-label="Additional information" name="ulp-document" type="file">`,
		`<textarea name="csrf"></textarea>`,
		`<button type="submit">Continue</button>`,
	} {
		if ValidateSource(source, true) == nil {
			t.Errorf("accepted unsafe partial control: %q", source)
		}
	}
	if err := ValidateSource(`<label for="note">Note</label><input aria-label="Additional information" id="note" name="ulp-note" type="text">`, true); err != nil {
		t.Fatal(err)
	}
}

func TestTemplateCannotConcealWidget(t *testing.T) {
	for _, wrapper := range []string{`<div hidden>`, `<div inert>`, `<div aria-hidden="true">`, `<details>`, `<dialog>`, `<template>`, `<marquee>`} {
		tag := strings.Fields(strings.TrimPrefix(wrapper, "<"))[0]
		tag = strings.TrimSuffix(tag, ">")
		source := `<html><head>{% auth0:head %}</head><body>` + wrapper + `{% auth0:widget %}</` + tag + `></body></html>`
		if ValidateSource(source, false) == nil {
			t.Errorf("accepted concealing wrapper %q", wrapper)
		}
	}
}

func TestTemplateInterpolationContexts(t *testing.T) {
	for _, fragment := range []string{`<{{ tenant.name }}>Hello</{{ tenant.name }}>`, `<div class={{tenant.name}}>Hello</div>`, `<img src={{tenant.support_url}}>`, `<style>.za-decoration { color:{{branding.primary_color}} }</style>`} {
		source := `<html><head>{% auth0:head %}</head><body>` + fragment + `{% auth0:widget %}</body></html>`
		if ValidateSource(source, false) == nil {
			t.Errorf("accepted unsafe interpolation context: %s", fragment)
		}
	}
}

func TestTemplateTagWhitespace(t *testing.T) {
	for _, pair := range [][2]string{{`{%auth0:head%}`, `{%auth0:widget%}`}, {`{%- auth0:head %}`, `{% auth0:widget -%}`}, {"{%\t auth0:head \n%}", "{%\n auth0:widget\t%}"}} {
		source := `<html><head>` + pair[0] + `</head><body>` + pair[1] + `</body></html>`
		if _, err := (Renderer{}).Render(context.Background(), RenderInput{Source: source, Widget: "<form></form>"}); err != nil {
			t.Errorf("whitespace rejected: %v", err)
		}
	}
}

func TestTemplateSkippedFilterRejectedAtSave(t *testing.T) {
	source := `<html><head>{% auth0:head %}</head><body>{% if false %}{{tenant.name | unsupported}}{% endif %}{% auth0:widget %}</body></html>`
	if ValidateSource(source, false) == nil {
		t.Fatal("unknown filter in skipped branch accepted")
	}
}

func TestTemplateExpressionsUseUnescapedValues(t *testing.T) {
	out, err := (Renderer{}).Render(context.Background(), RenderInput{Source: `<html><head>{% auth0:head %}</head><body>{% if tenant.name == 'A&B' %}<p>RIGHT</p>{% else %}<p>WRONG</p>{% endif %}<p>LEN[{{tenant.name | size}}]</p><p>{{tenant.name | replace: '&', ' and '}}</p><p>{{application.name}}</p>{% auth0:widget %}</body></html>`, Head: "", Widget: "<form></form>", Variables: map[string]any{"tenant": map[string]any{"name": "A&B"}, "application": map[string]any{"name": "<script>unsafe()</script>"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RIGHT", "LEN[3]", "A and B", "&lt;script&gt;unsafe()&lt;/script&gt;"} {
		if !strings.Contains(out.HTML, want) {
			t.Errorf("missing %s: %s", want, out.HTML)
		}
	}
	if strings.Contains(out.HTML, "<script>") {
		t.Fatal("substitution emitted markup")
	}
}
