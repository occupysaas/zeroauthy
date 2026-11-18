package federation

import (
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"reflect"
	"testing"
)

func FuzzAttrMapCompile(f *testing.F) {
	for _, s := range []string{"Jane", "${context.tokenset.sub}", "${${x}}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, e := CompileAttrMap(&rules.AttrMap{Mode: "use_map", Attributes: map[string]string{"name": s}}, "oidc", "back_channel")
		if e != nil {
			return
		}
		ctx := MapContext{TokenSet: map[string]any{"sub": "123"}}
		a, b := c.Apply(ctx)
		x, y := c.Apply(ctx)
		if !reflect.DeepEqual(a, x) || !reflect.DeepEqual(b, y) {
			t.Fatal("non-deterministic mapping")
		}
	})
}
