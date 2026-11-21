package dpop

import "context"

type proofKey struct{}

func WithProof(ctx context.Context, p *Proof) context.Context {
	return context.WithValue(ctx, proofKey{}, p)
}
func FromContext(ctx context.Context) *Proof { p, _ := ctx.Value(proofKey{}).(*Proof); return p }
