package email

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func renderer(t *testing.T) Renderer {
	t.Helper()
	r, err := NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRenderBudgets(t *testing.T) {
	r := renderer(t)
	t.Run("nested loops", func(t *testing.T) {
		_, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": "{% for a in (1..101) %}{% for b in (1..101) %}x{% endfor %}{% endfor %}"}})
		if !errors.Is(err, ErrRenderLimit) {
			t.Fatalf("Render() error = %v, want ErrRenderLimit", err)
		}
	})
	t.Run("intermediate amplification", func(t *testing.T) {
		_, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": "{{ amplify | replace: 'x', 'xxxxxxxx' }}"}, Variables: map[string]any{"amplify": strings.Repeat("x", 32_769)}})
		if !errors.Is(err, ErrRenderLimit) {
			t.Fatalf("Render() error = %v, want ErrRenderLimit", err)
		}
	})
	t.Run("concurrent capacity", func(t *testing.T) {
		block := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-block
				_, _ = r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": strings.Repeat("{{ 'x' }}", 12_000)}})
			}()
		}
		close(block)
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if renderSlotsInUse() == 8 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		_, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": "ninth"}})
		if !errors.Is(err, ErrRenderCapacity) {
			t.Fatalf("ninth Render() error = %v, want ErrRenderCapacity", err)
		}
		wg.Wait()
	})
	t.Run("byte boundaries", func(t *testing.T) {
		good := strings.Repeat("é", 64*1024)
		if _, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": good}}); err != nil {
			t.Fatalf("valid UTF-8 body at byte limit: %v", err)
		}
		if _, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": good + "é"}}); !errors.Is(err, ErrRenderLimit) {
			t.Fatalf("over-limit UTF-8 body error = %v", err)
		}
	})
	t.Run("nesting depth", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 33; i++ {
			b.WriteString("{% if true %}")
		}
		b.WriteString("x")
		for i := 0; i < 33; i++ {
			b.WriteString("{% endif %}")
		}
		if _, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": b.String()}}); !errors.Is(err, ErrRenderLimit) {
			t.Fatalf("depth 33 error = %v", err)
		}
	})
	t.Run("total output", func(t *testing.T) {
		chunk := strings.Repeat("a", 65_535)
		_, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": "{{ x | append: x }}", "html": "{{ x | append: x }}", "from": "abcd"}, Variables: map[string]any{"x": chunk}})
		if err != nil {
			t.Fatalf("render at exact output limit: %v", err)
		}
		_, err = r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": "{{ x | append: x }}", "html": "{{ x | append: x }}", "subject": "x", "from": "abcd"}, Variables: map[string]any{"x": chunk}})
		if !errors.Is(err, ErrRenderLimit) {
			t.Fatalf("total output error = %v, want ErrRenderLimit", err)
		}
	})
}

func TestRenderCapabilities(t *testing.T) {
	r := renderer(t)
	for _, tc := range []struct{ name, source string }{
		{"file include", `{% include '/etc/passwd' %}`},
		{"debug tag", `{% debug %}`},
		{"object method", `{{ user.String }}`},
		{"unknown tag", `{% execute 'id' %}`},
		{"unknown filter", `{{ 'x' | shell }}`},
		{"unclosed comment", `{% comment %}ignored`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars := map[string]any{}
			if tc.name == "object method" {
				vars["user"] = struct{ Value string }{Value: "unsafe"}
			}
			if _, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": tc.source}, Variables: vars}); !errors.Is(err, ErrRenderSyntax) {
				t.Fatalf("Render() error = %v, want ErrRenderSyntax", err)
			}
		})
	}
	if _, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"unknown": "x"}}); !errors.Is(err, ErrRenderSyntax) {
		t.Fatalf("unknown rendered field error = %v, want ErrRenderSyntax", err)
	}
	t.Run("cancel parse", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := r.Render(ctx, RenderInput{Fields: map[string]string{"body": strings.Repeat("x", 1000)}})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Render() error = %v, want context.Canceled", err)
		}
	})
	t.Run("cancel during render", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(time.Millisecond, cancel)
		_, err := r.Render(ctx, RenderInput{Fields: map[string]string{"body": "{% for x in (1..10000) %}{{ x }}{% endfor %}"}})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Render() error = %v, want context.Canceled", err)
		}
	})
	t.Run("supported syntax", func(t *testing.T) {
		out, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": "{% assign who = user.name | upcase %}{% if who == 'ADA' %}Hello {{ who | escape }}{% endif %}"}, Variables: map[string]any{"user": map[string]any{"name": "Ada"}}})
		if err != nil || out.Text != "Hello ADA" {
			t.Fatalf("Render() = (%q, %v), want Hello ADA", out.Text, err)
		}
	})
}

func TestRenderContextSecrets(t *testing.T) {
	r := renderer(t)
	out, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": "{{ user.email }} {{ user.password }} {{ provider.secret }}"}, Variables: map[string]any{"user": map[string]any{"email": "ok@example.test", "password": "SENTINEL_PASSWORD"}, "provider": map[string]any{"secret": "SENTINEL_PROVIDER"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.Text+out.HTML, "SENTINEL_") {
		t.Fatalf("sensitive value rendered: %q", out.Text)
	}
}

func TestRenderMissingOptional(t *testing.T) {
	out, err := renderer(t).Render(context.Background(), RenderInput{Fields: map[string]string{"body": "before{{ optional.value }}after"}, Variables: map[string]any{"optional": map[string]any{}}})
	if err != nil || out.Text != "beforeafter" {
		t.Fatalf("Render() = (%q, %v), want beforeafter", out.Text, err)
	}
}

func TestRenderFields(t *testing.T) {
	input := RenderInput{Fields: map[string]string{"from": "{{ user.email }}", "subject": "Hi {{ user.name }}", "body": "plain {{ url }}", "html": "<a href=\"{{ url }}\">go</a>", "resultUrl": "{{ support_url }}"}, Variables: map[string]any{"user": map[string]any{"name": "Ada", "email": "a@example.test"}, "url": "https://example.test/one", "support_url": "https://example.test/help"}}
	out, err := renderer(t).Render(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if out.From != "a@example.test" || out.Subject != "Hi Ada" || out.Text != "plain https://example.test/one" || out.HTML != "<a href=\"https://example.test/one\">go</a>" || out.ResultURL != "https://example.test/help" {
		t.Fatalf("unexpected rendered fields: %+v", out)
	}
}

func TestRenderParallelTenantIsolation(t *testing.T) {
	r := renderer(t)
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for _, name := range []string{"tenant-a", "tenant-b"} {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": "{{ tenant.name }}"}, Variables: map[string]any{"tenant": map[string]any{"name": name}}})
			if err != nil || out.Text != name {
				errCh <- fmt.Errorf("tenant %s got %q, err=%v", name, out.Text, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
