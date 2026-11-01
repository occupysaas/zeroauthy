//go:build !race

package events_test

import "time"

const captureLatencyGuard = 5 * time.Second
