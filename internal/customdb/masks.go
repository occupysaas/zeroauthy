package customdb

import (
	"context"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type maskTimer interface{ Stop() bool }

// Limits bound retained distinct plaintext payload (not exact allocator
// overhead). All configuration and request values share the same allowance.
// Forgetting any value permanently mutes this process, including captured logs:
// scripts can cache values and print them under an unrelated later request.
type maskPolicy struct {
	maxValues, maxBytes int
	retention           time.Duration
	now                 func() time.Time
	afterFunc           func(time.Duration, func()) maskTimer
}

func (p maskPolicy) defaults() maskPolicy {
	if p.maxValues == 0 {
		p.maxValues = 256
	}
	if p.maxBytes == 0 {
		p.maxBytes = 64 << 10
	}
	if p.retention == 0 {
		p.retention = 60 * time.Second
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.afterFunc == nil {
		p.afterFunc = func(d time.Duration, f func()) maskTimer { return time.AfterFunc(d, f) }
	}
	return p
}

func (p *proc) muteLocked() {
	p.muted = true
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	p.values, p.configValues, p.masks, p.red = nil, nil, nil, nil
	p.payloadBytes = 0
	p.deadline = time.Time{}
}

func (p *proc) diagnosticsLocked() bool {
	if !p.muted && !p.deadline.IsZero() && !p.policy.now().Before(p.deadline) {
		p.muteLocked()
	}
	return !p.muted
}

func (p *proc) registerMasks(ctx context.Context, req Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.diagnosticsLocked() {
		return
	}
	changed := false
	add := func(value string, configuration bool) bool {
		if value == "" {
			return true
		}
		detached, exists := p.values[value]
		if !exists {
			if len(p.values) >= p.policy.maxValues || len(value) > p.policy.maxBytes-p.payloadBytes {
				p.muteLocked()
				return false
			}
			if p.values == nil {
				p.values = map[string]string{}
			}
			detached = strings.Clone(value)
			p.values[detached] = detached
			p.payloadBytes += len(detached)
			if p.deadline.IsZero() {
				p.deadline = p.policy.now().Add(p.policy.retention)
				p.timer = p.policy.afterFunc(p.policy.retention, func() { p.mu.Lock(); defer p.mu.Unlock(); p.muteLocked() })
			}
			changed = true
		}
		if configuration {
			if p.configValues == nil {
				p.configValues = map[string]struct{}{}
			}
			if _, exists := p.configValues[detached]; !exists {
				p.configValues[detached] = struct{}{}
				changed = true
			}
		}
		return true
	}
	for value := range logscrub.MaskValues(ctx) {
		if !add(value, false) {
			return
		}
	}
	// Direct callers need the script credential too, without copying all masks
	// from a possibly oversized request context via credentialContext/CopyMasks.
	var credential string
	if (req.Script == store.ScriptLogin || req.Script == store.ScriptChangePassword) && len(req.Args) > 1 {
		credential, _ = req.Args[1].(string)
	}
	if req.Script == store.ScriptCreate && len(req.Args) > 0 {
		if object, ok := req.Args[0].(map[string]any); ok {
			credential, _ = object["password"].(string)
		}
	}
	if !add(credential, false) {
		return
	}
	for _, value := range req.Config {
		if !add(value, true) {
			return
		}
	}
	if !changed {
		return
	}
	values := make([]string, 0, len(p.values))
	for value := range p.values {
		values = append(values, value)
	}
	p.masks = logscrub.WithCredentials(context.Background(), values...)
	configured := make([]string, 0, len(p.configValues))
	for value := range p.configValues {
		configured = append(configured, value)
	}
	p.red = newRedactor(configured)
}

func (p *proc) scrubLocked(line string) string {
	ctx := p.masks
	if ctx == nil {
		ctx = context.Background()
	}
	return logscrub.ScrubTruncatedText(ctx, p.red.RedactLine(line), cutMin)
}

func (p *proc) capture(lines []string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.diagnosticsLocked() {
		return nil
	}
	for i, line := range lines {
		lines[i] = p.scrubLocked(line)
	}
	return lines
}
