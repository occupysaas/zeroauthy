// Package actions runs Auth0-compatible Actions.
package actions

import (
	_ "embed"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
)

// RunnerJS is the Actions runner script for a noderunner.Pool. Actions own
// their Pool, separate from custom databases' (spec §6).
//
//go:embed runner.mjs
var RunnerJS []byte

// maxStderrLog bounds one logged runner diagnostic.
const maxStderrLog = 2048

// procState is the masking state of one tenant's runner process: the union
// of the secret values every call in it has carried. Entries stay after a
// call ends, because stderr (an uncaught exception from a timer) is read
// apart from answers and may arrive later.
type procState struct {
	mu  sync.Mutex
	red *customdb.Redactor
}

func (p *procState) add(r *customdb.Redactor) {
	p.mu.Lock()
	p.red = p.red.Union(r)
	p.mu.Unlock()
}

func (p *procState) redactor() *customdb.Redactor {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.red
}

// NewRunner returns the Actions runner Pool: one process per tenant that may
// read only the tenant's extracted-build root, with the flow budget as the
// call limit, and stderr lines masked with the secrets of the calls made in
// that process (D-0023 masking) before they are logged.
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
			var red *customdb.Redactor
			if ps, ok := state.(*procState); ok {
				red = ps.redactor()
			}
			msg := string(line)
			var l struct{ Msg string }
			if json.Unmarshal(line, &l) == nil && l.Msg != "" {
				msg = l.Msg
			}
			// Secrets reach the process only in calls, and Prepare registers
			// each call's values before the call is written.
			log.Warn("actions runner output", "tenant", tenantID, "output", noderunner.Truncate(red.RedactLine(msg), maxStderrLog))
		},
	}, log)
}
