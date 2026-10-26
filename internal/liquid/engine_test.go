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
