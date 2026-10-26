package hostedlogin

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestPartialFieldRedisplay(t *testing.T) {
	slots := map[string]string{"form-content-start": `<label for="note">{{tenant.name}}</label><input aria-label="Additional information" id="note" name="ulp-note" value="default"><textarea aria-label="Additional information" name="ulp-bio">Default</textarea>`, "form-footer-end": `<p>Footer</p>`, "secondary-actions-start": `<p>Future</p>`}
	out, err := RenderPartials(context.Background(), slots, map[string]any{"tenant": map[string]any{"name": "<Acme>"}}, map[string]string{"ulp-note": `"><script>alert(1)</script>`, "ulp-bio": "<b>Hello</b>"}, "nonce")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Fields) != 2 || out.Fields["ulp-note"] != "text" {
		t.Fatalf("fields=%v", out.Fields)
	}
	if strings.Contains(out.Slots["form-content-start"], "<script>") || !strings.Contains(out.Slots["form-content-start"], "&lt;Acme&gt;") || !strings.Contains(out.Slots["form-content-start"], "&lt;b&gt;Hello&lt;/b&gt;") {
		t.Fatalf("unsafe redisplay: %s", out.Slots["form-content-start"])
	}
	if out.Slots["secondary-actions-start"] != "" {
		t.Fatal("future slot rendered")
	}
}

func TestPartialCaptureOwnershipAndLimits(t *testing.T) {
	fields := map[string]string{"ulp-note": "text", "ulp-accept": "checkbox"}
	current := map[string]string{"ulp-identifier-note": "kept", "ulp-accept": "on"}
	got, err := CaptureFields(url.Values{"ulp-note": {"<new>"}, "password": {"private"}}, fields, current)
	if err != nil {
		t.Fatal(err)
	}
	if got["ulp-identifier-note"] != "kept" || got["ulp-note"] != "<new>" {
		t.Fatalf("capture=%v", got)
	}
	if _, ok := got["ulp-accept"]; ok {
		t.Fatal("unchecked field was not cleared")
	}
	if _, ok := got["password"]; ok {
		t.Fatal("core password was captured")
	}
	for _, form := range []url.Values{{"ulp-unknown": {"x"}}, {"ulp-note": {"a", "b"}}, {"ulp-note": {strings.Repeat("a", 1025)}}} {
		if _, err := CaptureFields(form, fields, current); err == nil {
			t.Errorf("accepted invalid fields: %v", form)
		}
	}
	if current["ulp-accept"] != "on" {
		t.Fatal("input was mutated")
	}
}

func TestPartialAggregateFieldBoundary(t *testing.T) {
	fields := map[string]string{}
	form := url.Values{}
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("ulp-%d", i)
		fields[name] = "text"
		form.Set(name, strings.Repeat("x", 1024))
	}
	// Count names and values toward the aggregate byte budget.
	form.Set("ulp-7", strings.Repeat("x", 984))
	if _, err := CaptureFields(form, fields, nil); err != nil {
		t.Fatalf("8 KiB rejected: %v", err)
	}
	form.Set("ulp-7", strings.Repeat("x", 985))
	if _, err := CaptureFields(form, fields, nil); err == nil {
		t.Fatal("8 KiB plus one accepted")
	}
}

func TestPartialHTMLFragmentBoundaries(t *testing.T) {
	for _, source := range []string{
		`<textarea name="ulp-note" aria-label="Note"/>`,
		`<fieldset disabled></div>`,
		`<div></form>`,
		`<select name="ulp-note" aria-label="Note"/>`,
	} {
		slots := map[string]string{"form-content-start": source}
		if err := ValidatePartials(map[string]map[string]string{"login": slots}); err == nil {
			t.Errorf("save accepted parser-repaired fragment %s", source)
		}
		if _, err := RenderPartials(context.Background(), slots, nil, nil, ""); err == nil {
			t.Errorf("render accepted parser-repaired fragment %s", source)
		}
	}
	for _, source := range []string{`<input name="ulp-note" aria-label="Note"/>`, `<textarea name="ulp-note" aria-label="Note"></textarea>`} {
		if _, err := RenderPartials(context.Background(), map[string]string{"form-content-start": source}, nil, nil, ""); err != nil {
			t.Errorf("safe balanced fragment rejected: %s: %v", source, err)
		}
	}
}

func TestPartialExpressionsUseUnescapedValues(t *testing.T) {
	out, err := RenderPartials(context.Background(), map[string]string{"form-footer-start": `{% if tenant.name == 'A&B' %}<p>RIGHT</p>{% else %}<p>WRONG</p>{% endif %}<p>LEN[{{tenant.name | size}}]</p><p>{{tenant.name | replace: '&', ' and '}}</p>`}, map[string]any{"tenant": map[string]any{"name": "A&B"}}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	html := out.Slots["form-footer-start"]
	for _, want := range []string{"RIGHT", "LEN[3]", "A and B"} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s: %s", want, html)
		}
	}
}
