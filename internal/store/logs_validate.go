package store

import (
	"bytes"
	"encoding/json"
)

// ValidateLogEvents validates a batch before any event or statistic is written.
// Body contains an Auth0 object JSON document. Empty bodies remain accepted for
// repository callers that supply indexed fields only, including older plugins.
func ValidateLogEvents(events []LogEvent) error {
	for _, e := range events {
		if err := ValidateLogTimes(e.Date); err != nil {
			return err
		}
		if len(e.Body) == 0 {
			continue
		}
		body := bytes.TrimSpace(e.Body)
		if len(body) == 0 || body[0] != '{' || !json.Valid(body) {
			return ErrInvalid
		}
	}
	return nil
}
