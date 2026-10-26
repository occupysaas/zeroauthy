package email

import "github.com/zeroauthy/zeroauthy/internal/liquid"

// Email retains its existing renderer API, errors and field/output limits.
// The bounded parser and capacity guard are shared with hosted pages.
type RenderInput = liquid.RenderInput
type Rendered = liquid.Rendered
type Renderer = liquid.Renderer

var (
	ErrRenderLimit    = liquid.ErrRenderLimit
	ErrRenderSyntax   = liquid.ErrRenderSyntax
	ErrRenderCapacity = liquid.ErrRenderCapacity
)

func NewRenderer() (Renderer, error) { return liquid.NewRenderer() }
func renderSlotsInUse() int32        { return liquid.SlotsInUse() }

const maxContextBytes = liquid.ContextByteLimit
const maxOutputBytes = liquid.EmailOutputByteLimit

func projectVariables(value any, depth int) (any, int, error) {
	return liquid.ProjectVariables(value, depth)
}
