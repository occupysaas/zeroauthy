package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/awssig"
)

type sesTransport struct {
	f                                        *Factory
	access, secret, region, configurationSet string
}

func (t *sesTransport) Send(ctx context.Context, m Message) error {
	if err := validMessage(m); err != nil {
		return err
	}
	payload := map[string]any{"FromEmailAddress": m.From, "Destination": map[string]any{"ToAddresses": []string{m.To}}, "Content": map[string]any{"Simple": map[string]any{"Subject": map[string]string{"Data": m.Subject, "Charset": "UTF-8"}, "Body": map[string]any{"Text": map[string]string{"Data": m.Text, "Charset": "UTF-8"}, "Html": map[string]string{"Data": m.HTML, "Charset": "UTF-8"}}}}}
	if t.configurationSet != "" {
		payload["ConfigurationSetName"] = t.configurationSet
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("email provider: request encoding failed")
	}
	endpoint := "https://email." + t.region + ".amazonaws.com" + "/v2/email/outbound-emails"
	reqCtx, cancel := boundedContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return errors.New("email provider: request construction failed")
	}
	req.Header.Set("Content-Type", "application/json")
	awssig.Sign(req, body, t.region, "ses", t.access, t.secret, now(t.f))
	resp, err := clientFor(t.f).Do(req)
	if err != nil {
		return errors.New("email provider: SES transport request failed")
	}
	defer resp.Body.Close()
	if _, err = readBoundedResponse(resp); err != nil {
		return errors.New("email provider: SES response exceeded limit")
	}
	if resp.StatusCode == 200 {
		return nil
	}
	return errors.New("email provider: SES rejected the request")
}
func now(f *Factory) time.Time {
	if f != nil && f.Now != nil {
		return f.Now()
	}
	return time.Now()
}
