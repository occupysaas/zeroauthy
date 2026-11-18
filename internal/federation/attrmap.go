package federation

import (
	"encoding/json"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"maps"
	"strings"
)

var RestrictedTargets = rules.RestrictedTargets

// MapContext carries validated provider claims, never unverified token data.
type MapContext struct {
	TokenSet, UserInfo     map[string]any
	ConnectionID, Strategy string
}
type CompiledMap struct {
	mode      string
	templates map[string][]rules.MapPart
	userinfo  bool
}

func CompileAttrMap(m *rules.AttrMap, strategy, channel string) (*CompiledMap, error) {
	if m == nil {
		return nil, nil
	}
	if err := rules.ValidateAttrMap(m, strategy, channel); err != nil {
		return nil, err
	}
	c := &CompiledMap{mode: m.Mode, templates: map[string][]rules.MapPart{}, userinfo: m.Mode == "bind_all" && m.UserinfoScope != ""}
	for k, v := range m.Attributes {
		p, e := rules.ParseTemplate(v)
		if e != nil {
			return nil, e
		}
		c.templates[k] = p
		for _, x := range p {
			c.userinfo = c.userinfo || x.Source == "userinfo"
		}
	}
	return c, nil
}
func (c *CompiledMap) NeedsUserInfo() bool { return c != nil && c.userinfo }
func (c *CompiledMap) Apply(ctx MapContext) (root, profileData map[string]any) {
	root = map[string]any{}
	profileData = map[string]any{}
	if c == nil {
		return
	}
	assign := func(k string, v any) {
		if rules.RestrictedTarget(k) || v == nil {
			return
		}
		if k == "email_verified" {
			if _, ok := v.(bool); !ok {
				return
			}
		}
		switch k {
		case "email", "email_verified", "name", "nickname", "given_name", "family_name", "picture", "username", "phone_number", "phone_verified":
			root[k] = cloneMapValue(v)
		default:
			profileData[k] = cloneMapValue(v)
		}
	}
	if c.mode == "bind_all" {
		claims := maps.Clone(ctx.TokenSet)
		if claims == nil {
			claims = map[string]any{}
		}
		if c.userinfo {
			maps.Copy(claims, ctx.UserInfo)
		}
		for k, v := range claims {
			assign(k, v)
		}
		return
	}
	get := func(p rules.MapPart) (any, bool) {
		switch p.Source {
		case "tokenset":
			v, ok := ctx.TokenSet[p.Claim]
			return v, ok
		case "userinfo":
			v, ok := ctx.UserInfo[p.Claim]
			return v, ok
		case "connection":
			if p.Claim == "id" {
				return ctx.ConnectionID, true
			}
			return ctx.Strategy, true
		}
		return p.Literal, true
	}
	for k, parts := range c.templates {
		if len(parts) == 1 {
			v, ok := get(parts[0])
			if ok {
				assign(k, v)
			}
			continue
		}
		var b strings.Builder
		for _, p := range parts {
			v, ok := get(p)
			if ok && v != nil {
				if s, ok := v.(string); ok {
					b.WriteString(s)
				} else {
					b.WriteString(fmt.Sprint(v))
				}
			}
		}
		assign(k, b.String())
	}
	return
}
func cloneMapValue(v any) any {
	b, e := json.Marshal(v)
	if e != nil || len(b) > 65536 {
		return nil
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}
