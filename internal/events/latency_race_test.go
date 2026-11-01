//go:build race

package events_test

import "time"

// Instrumentation and concurrent package builds are not runtime request latency.
const captureLatencyGuard = 30 * time.Second
