package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type azureTransport struct {
	f        *Factory
	endpoint string
	key      []byte
}

func (t *azureTransport) Send(ctx context.Context, m Message) error {
	if err := validMessage(m); err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"senderAddress": m.From, "recipients": map[string]any{"to": []any{map[string]string{"address": m.To}}}, "content": map[string]string{"subject": m.Subject, "plainText": m.Text, "html": m.HTML}})
	if err != nil {
		return errors.New("email provider: request encoding failed")
	}
	const path = "/emails:send?api-version=2023-03-31"
	endpoint := t.endpoint + path
	u, _ := url.Parse(endpoint)
	timestamp := now(t.f).UTC().Format(http.TimeFormat)
	sum := sha256.Sum256(body)
	contentHash := base64.StdEncoding.EncodeToString(sum[:])
	stringToSign := "POST\n" + path + "\n" + timestamp + ";" + u.Host + ";" + contentHash
	h := hmac.New(sha256.New, t.key)
	_, _ = h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	reqCtx, cancel := boundedContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return errors.New("email provider: request construction failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-ms-date", timestamp)
	req.Header.Set("x-ms-content-sha256", contentHash)
	req.Header.Set("Authorization", "HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+signature)
	resp, err := clientFor(t.f).Do(req)
	if err != nil {
		return errors.New("email provider: Azure transport request failed")
	}
	defer resp.Body.Close()
	if _, err = readBoundedResponse(resp); err != nil {
		return errors.New("email provider: Azure response exceeded limit")
	}
	if resp.StatusCode == 202 {
		return nil
	}
	return errors.New("email provider: Azure rejected the request")
}
