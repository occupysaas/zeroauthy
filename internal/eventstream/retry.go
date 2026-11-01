package eventstream

import (
	"context"
	"time"
)

var retryDelays = [...]time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second}

func sleep(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
