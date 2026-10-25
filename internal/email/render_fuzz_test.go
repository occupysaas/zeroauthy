package email

import (
	"context"
	"testing"
)

func FuzzRender(f *testing.F) {
	f.Add("{% for x in (1..3) %}{{ x | escape }}{% endfor %}")
	f.Add("{{ 'a' | replace: 'a', 'aaaaaaaa' }}")
	f.Add("{% if true %}safe{% endif %}")
	r, err := NewRenderer()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, source string) {
		_, _ = r.Render(context.Background(), RenderInput{Fields: map[string]string{"body": source}})
	})
}
