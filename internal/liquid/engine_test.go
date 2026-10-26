package liquid

import (
	"context"
	"strings"
	"testing"
)

func TestLiquidEmailCompatibility(t *testing.T) {
	out, err := Render(context.Background(), `Hello {{ user.name | upcase }}`, map[string]any{"user": map[string]any{"name": "Ada"}}, nil, Limits{})
	if err != nil || out != "Hello ADA" {
		t.Fatalf("render=%q err=%v", out, err)
	}
}
func TestRenderLimit(t *testing.T) {
	_, err := Render(context.Background(), strings.Repeat("a", 100<<10), nil, nil, Limits{MaxSourceBytes: 1024})
	if err == nil {
		t.Fatal("source limit ignored")
	}
}

func TestRenderHostedOutputBudget(t *testing.T) {
	source := "{% for x in (1..4) %}" + strings.Repeat("a", 75_000) + "{% endfor %}"
	out, err := Render(context.Background(), source, nil, nil, Limits{})
	if err != nil || len(out) != 300_000 {
		t.Fatalf("300 KiB output: len=%d err=%v", len(out), err)
	}
	tooLarge := "{% for x in (1..7) %}" + strings.Repeat("a", 75_000) + "{% endfor %}"
	if _, err := Render(context.Background(), tooLarge, nil, nil, Limits{}); err == nil {
		t.Fatal("output above 512 KiB accepted")
	}
}

func TestRenderHostedFilterBudget(t *testing.T) {
	out, err := Render(context.Background(), `{{ value | replace: 'x', 'xxxxxxxx' }}`, map[string]any{"value": strings.Repeat("x", 40000)}, nil, Limits{})
	if err != nil || len(out) != 320000 {
		t.Fatalf("hosted filter budget: bytes=%d err=%v", len(out), err)
	}
}

func TestQuotedFilterArgumentsKeepOperatorText(t *testing.T) {
	out, err := Render(context.Background(), `{{value | replace: '&', ' and '}}`, map[string]any{"value": "A&B"}, nil, Limits{})
	if err != nil || out != "A and B" {
		t.Fatalf("quoted operator text=%q err=%v", out, err)
	}
}

func TestHostedOutputEscapingPreservesEmailMode(t *testing.T) {
	vars := map[string]any{"value": "<b>&lt;</b>"}
	for _, source := range []string{`{{value}}`, `{{value | escape}}`, `{% assign escaped = value | escape %}{{escaped}}`, `{{value | escape_once}}`} {
		out, err := Render(context.Background(), source, vars, nil, Limits{EscapeVariables: true})
		want := "&lt;b&gt;&amp;lt;&lt;/b&gt;"
		if strings.Contains(source, "escape_once") {
			want = "&lt;b&gt;&lt;&lt;/b&gt;"
		}
		if err != nil || out != want {
			t.Errorf("hosted %s=%q want=%q err=%v", source, out, want, err)
		}
	}
	out, err := Render(context.Background(), `{{value}}`, vars, nil, Limits{})
	if err != nil || out != "<b>&lt;</b>" {
		t.Fatalf("email mode changed: %q %v", out, err)
	}
}
