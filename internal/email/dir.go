package email

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
)

// dirMailer writes each message as an .eml file; used by tests and demos.
type dirMailer struct {
	from string
	dir  string
}

func (d *dirMailer) Send(_ context.Context, m Message) error {
	raw, err := build(d.from, m, time.Now())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("%d-%s", time.Now().UnixNano(), secrets.RandomString(8))
	tmp := filepath.Join(d.dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(d.dir, name+".eml")); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
