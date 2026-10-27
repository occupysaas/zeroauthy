// Package actions runs Auth0-compatible Actions.
package actions

import _ "embed"

// RunnerJS is the Actions runner script for a noderunner.Pool. Actions own
// their Pool, separate from custom databases' (spec §6).
//
//go:embed runner.mjs
var RunnerJS []byte
