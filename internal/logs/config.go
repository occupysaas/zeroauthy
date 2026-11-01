package logs

import "time"

const DefaultRetention = 30 * 24 * time.Hour
const DefaultQueueSize = 10000

// Config controls the process-local queue, deployment-wide retention and stream policy.
// Now is an optional clock for deterministic scheduling and overflow warnings.
type Config struct {
	Streams StreamsConfig

	Retention time.Duration
	QueueSize int
	Now       func() time.Time
}

func (c Config) defaults() Config {
	if c.Retention < 24*time.Hour {
		c.Retention = DefaultRetention
	}
	if c.QueueSize <= 0 {
		c.QueueSize = DefaultQueueSize
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// StreamsConfig controls deployment opt-ins for outbound log delivery.
// Secure transport and public addresses are the defaults.
type StreamsConfig struct {
	AllowInsecureHTTP    bool
	AllowPrivateNetworks bool
}
