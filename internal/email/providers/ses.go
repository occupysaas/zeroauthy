package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
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
	host := "email." + t.region + ".amazonaws.com"
	endpoint := "https://" + host + "/v2/email/outbound-emails"
	reqCtx, cancel := boundedContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return errors.New("email provider: request construction failed")
	}
	req.Header.Set("Content-Type", "application/json")
	date := now(t.f).UTC()
	amz := date.Format("20060102T150405Z")
	day := date.Format("20060102")
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Date", amz)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	canonical := "POST\n/v2/email/outbound-emails\n\ncontent-type:application/json\nhost:" + host + "\nx-amz-content-sha256:" + payloadHash + "\nx-amz-date:" + amz + "\n\ncontent-type;host;x-amz-content-sha256;x-amz-date\n" + payloadHash
	ch := sha256.Sum256([]byte(canonical))
	scope := day + "/" + t.region + "/ses/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope + "\n" + hex.EncodeToString(ch[:])
	kDate := signHMAC([]byte("AWS4"+t.secret), day)
	kRegion := signHMAC(kDate, t.region)
	kService := signHMAC(kRegion, "ses")
	kSigning := signHMAC(kService, "aws4_request")
	sig := hex.EncodeToString(signHMAC(kSigning, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+t.access+"/"+scope+", SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature="+sig)
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
func signHMAC(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(s))
	return h.Sum(nil)
}
func now(f *Factory) time.Time {
	if f != nil && f.Now != nil {
		return f.Now()
	}
	return time.Now()
}
