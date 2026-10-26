package hostedlogin

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type configKey struct{}

// WithConfiguration attaches one immutable snapshot to the rendered request.
func WithConfiguration(ctx context.Context, c *store.HostedLoginConfig) context.Context {
	return context.WithValue(ctx, configKey{}, c.Clone())
}
func Configuration(ctx context.Context) *store.HostedLoginConfig {
	c, _ := ctx.Value(configKey{}).(*store.HostedLoginConfig)
	return c.Clone()
}
