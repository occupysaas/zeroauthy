package liquid

import (
	"context"
	"time"
)

// Validate parses all branches and checks every expression without expanding
// loops. A filter in an unselected branch must still be supported at save time.
func Validate(parent context.Context, source string, limits Limits) error {
	maxSource := limits.MaxSourceBytes
	if maxSource == 0 {
		maxSource = 100 << 10
	}
	maxOutput := limits.MaxOutputBytes
	if maxOutput == 0 {
		maxOutput = 512 << 10
	}
	if !utf8String(source) || len(source) > maxSource {
		return ErrLimit
	}
	if activeRenders.Add(1) > maxConcurrent {
		activeRenders.Add(-1)
		return ErrRenderCapacity
	}
	defer activeRenders.Add(-1)
	ctx, cancel := context.WithTimeout(parent, maxRenderTime)
	defer cancel()
	state := renderState{ctx: ctx, deadline: time.Now().Add(maxRenderTime), vars: map[string]any{}, maxSource: maxSource, maxOutput: maxOutput}
	nodes, _, err := state.parse(source, 0)
	if err != nil {
		return err
	}
	return state.validateNodes(nodes)
}

func (s *renderState) validateNodes(nodes []templateNode) error {
	for _, node := range nodes {
		if err := s.step(); err != nil {
			return err
		}
		switch n := node.(type) {
		case valueNode:
			if _, err := s.eval(string(n)); err != nil {
				return err
			}
		case assignNode:
			if _, err := s.eval(n.expr); err != nil {
				return err
			}
		case forNode:
			if _, err := s.eval(n.expr); err != nil {
				return err
			}
			if err := s.validateNodes(n.body); err != nil {
				return err
			}
		case ifNode:
			for _, branch := range n.branches {
				if _, err := s.eval(branch.expr); err != nil {
					return err
				}
				if err := s.validateNodes(branch.body); err != nil {
					return err
				}
			}
			if err := s.validateNodes(n.otherwise); err != nil {
				return err
			}
		}
	}
	return s.checkContext()
}
