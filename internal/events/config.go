package events

import "time"

// Config controls retention, streams and live subscriptions.
type Config struct {
	Retention            time.Duration `koanf:"retention"`
	MaxStreams           int           `koanf:"max_streams"`
	MaxConnections       int           `koanf:"max_connections"`
	AllowPrivateNetworks bool          `koanf:"allow_private_networks"`
	AllowInsecureHTTP    bool          `koanf:"allow_insecure_http"`
}

func DefaultConfig() Config {
	return Config{Retention: 7 * 24 * time.Hour, MaxStreams: 10, MaxConnections: 4}
}
