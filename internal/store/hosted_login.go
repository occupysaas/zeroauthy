package store

import (
	"context"
	"errors"
	"maps"
)

var ErrHostedLoginRepositoryUnavailable = errors.New("store: hosted login repository unavailable; upgrade the storage plugin")

type HostedLoginConfig struct {
	TenantID       string
	Revision       int64
	Branding       map[string]any
	Template       *string
	Themes         map[string]map[string]any
	DefaultThemeID string
	Prompts        map[string]any
	CustomText     CustomText
	Partials       map[string]map[string]map[string]string
}

func (c *HostedLoginConfig) Clone() *HostedLoginConfig {
	if c == nil {
		return nil
	}
	out := *c
	out.Branding = CloneSettings(c.Branding)
	if c.Template != nil {
		v := *c.Template
		out.Template = &v
	}
	if c.Themes != nil {
		out.Themes = make(map[string]map[string]any, len(c.Themes))
		for id, theme := range c.Themes {
			out.Themes[id] = CloneSettings(theme)
		}
	}
	out.Prompts = CloneSettings(c.Prompts)
	out.CustomText = c.CustomText.Clone()
	if c.Partials != nil {
		out.Partials = make(map[string]map[string]map[string]string, len(c.Partials))
		for prompt, screens := range c.Partials {
			out.Partials[prompt] = make(map[string]map[string]string, len(screens))
			for screen, slots := range screens {
				out.Partials[prompt][screen] = maps.Clone(slots)
			}
		}
	}
	return &out
}

type HostedLogins interface {
	Get(ctx context.Context, tenantID string) (*HostedLoginConfig, error)
	Put(ctx context.Context, config *HostedLoginConfig, expectedRevision int64) error
}

type UnimplementedHostedLogins struct{}

func (UnimplementedHostedLogins) Get(context.Context, string) (*HostedLoginConfig, error) {
	return nil, ErrHostedLoginRepositoryUnavailable
}
func (UnimplementedHostedLogins) Put(context.Context, *HostedLoginConfig, int64) error {
	return ErrHostedLoginRepositoryUnavailable
}

type HostedLoginState struct {
	Step, Identifier, ConnectionID string
	PromptFields                   map[string]string
	FormFields                     map[string]string
	Revision, FormConfigRevision   int64
	FormScreen, FormLanguage       string
}

func (s HostedLoginState) Clone() HostedLoginState {
	s.PromptFields = maps.Clone(s.PromptFields)
	s.FormFields = maps.Clone(s.FormFields)
	return s
}
