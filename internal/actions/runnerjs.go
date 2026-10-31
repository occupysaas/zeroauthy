// Package actions runs Auth0-compatible Actions.
package actions

import (
	"context"
	_ "embed"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
)

// RunnerJS is the Actions runner script for a noderunner.Pool. Actions own
// their Pool, separate from custom databases' (spec §6).
//
//go:embed runner.mjs
var RunnerJS []byte

// maxStderrLog bounds one logged runner diagnostic.
const maxStderrLog = 2048

// procState retains a bounded credential union for delayed diagnostics. Once
// its lifetime or capacity is exhausted, all future output is dropped until the
// process retires; no eviction can make an older timer's secret visible.
type procState struct {
	mu     sync.Mutex
	values map[string]struct{}
	bytes  int
	until  time.Time
	muted  bool
}

func (p *procState) add(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.muted {
		return
	}
	if p.until.IsZero() {
		p.until = time.Now().Add(time.Minute)
		p.values = map[string]struct{}{}
	}
	if !time.Now().Before(p.until) {
		p.mute()
		return
	}
	for value := range logscrub.MaskValues(ctx) {
		if _, ok := p.values[value]; ok {
			continue
		}
		if len(p.values) >= 256 || p.bytes+len(value) > 64*1024 {
			p.mute()
			return
		}
		p.values[value] = struct{}{}
		p.bytes += len(value)
	}
}
func (p *procState) mute() { p.muted = true; p.values = nil; p.bytes = 0 }
func (p *procState) scrub(line string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.muted || (!p.until.IsZero() && !time.Now().Before(p.until)) {
		p.mute()
		return "", false
	}
	values := make([]string, 0, len(p.values))
	for value := range p.values {
		values = append(values, value)
	}
	return logscrub.ScrubTruncatedTextWithMask(context.Background(), line, 1024, values, customdb.Mask), true
}

// NewRunner returns the Actions runner Pool: one process per tenant that may
// read only the tenant's extracted-build root (Action and Module trees),
// with the flow budget as the call limit, and stderr lines masked with all
// Action and Module secrets carried by calls in that process (D-0023 masking).
func NewRunner(cfg config.Actions, builds *build.Manager, log *slog.Logger) (*noderunner.Pool, error) {
	if log == nil {
		log = slog.Default()
	}
	return noderunner.New(noderunner.Config{
		Node: cfg.Node, MaxMemoryMB: cfg.MaxMemoryMB, IdleTimeout: cfg.IdleTimeout,
		ReadDirs: func(tenantID string) []string {
			if builds == nil {
				return nil
			}
			root, err := builds.TenantRoot(tenantID)
			if err != nil {
				return nil
			}
			return []string{root}
		},
		Script: RunnerJS, Name: "actions", Budget: flowBudget,
		OnStart: func(string) any { return &procState{} },
		OnStderr: func(tenantID string, state any, line []byte) {
			msg := string(line)
			var l struct{ Msg string }
			if json.Unmarshal(line, &l) == nil && l.Msg != "" {
				msg = l.Msg
			}
			// Secrets reach the process only in calls, and Prepare registers
			// each call's values before the call is written.
			ps, ok := state.(*procState)
			if !ok {
				return
			}
			msg, ok = ps.scrub(msg)
			if !ok {
				return
			}
			log.Warn("actions runner output", "tenant", tenantID, "output", noderunner.Truncate(msg, maxStderrLog))
		},
	}, log)
}
