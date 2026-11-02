package email

import (
	"bytes"
	"context"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"log/slog"
	"strings"
	"testing"
)

func TestMFALogDriverNeverLogsCode(t *testing.T) {
	for _, links := range []bool{false, true} {
		var output bytes.Buffer
		m, err := New(config.Email{Driver: "log", From: "auth@example.test", LogLinks: links}, slog.New(slog.NewJSONHandler(&output, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if err = m.Send(context.Background(), Message{Type: "mfa_oob_code", To: "user@example.test", Subject: "Code 834927", Text: "Code 834927", HTML: "<p>834927</p>"}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "834927") {
			t.Fatal("MFA code logged")
		}
	}
}
