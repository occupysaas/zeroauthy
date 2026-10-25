package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

type ms365Transport struct {
	f                      *Factory
	tenant, client, secret string
	cacheKey               tokenKey
}

func (t *ms365Transport) Send(ctx context.Context, m Message) error {
	if err := validMessage(m); err != nil {
		return err
	}
	token, err := t.accessToken(ctx)
	if err != nil {
		return err
	}
	contentType, content := "HTML", m.HTML
	if content == "" {
		contentType, content = "Text", m.Text
	}
	body, err := json.Marshal(map[string]any{"message": map[string]any{"subject": m.Subject, "body": map[string]string{"contentType": contentType, "content": content}, "toRecipients": []any{map[string]any{"emailAddress": map[string]string{"address": m.To}}}}, "saveToSentItems": false})
	if err != nil {
		return errors.New("email provider: request encoding failed")
	}
	from, _ := mail.ParseAddress(m.From)
	endpoint := "https://graph.microsoft.com/v1.0/users/" + url.PathEscape(from.Address) + "/sendMail"
	reqCtx, cancel := boundedContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return errors.New("email provider: request construction failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := clientFor(t.f).Do(req)
	if err != nil {
		return errors.New("email provider: Microsoft Graph transport request failed")
	}
	defer resp.Body.Close()
	if _, err = readBoundedResponse(resp); err != nil {
		return errors.New("email provider: Microsoft Graph response exceeded limit")
	}
	if resp.StatusCode == 202 {
		return nil
	}
	return errors.New("email provider: Microsoft Graph rejected the request")
}
func (t *ms365Transport) accessToken(ctx context.Context) (string, error) {
	f := t.f
	if f == nil {
		f = &Factory{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens == nil {
		f.tokens = map[tokenKey]cachedToken{}
	}
	now := now(f)
	if cached, ok := f.tokens[t.cacheKey]; ok && cached.expires.After(now.Add(time.Minute)) {
		return cached.value, nil
	}
	form := url.Values{"client_id": {t.client}, "client_secret": {t.secret}, "scope": {"https://graph.microsoft.com/.default"}, "grant_type": {"client_credentials"}}
	endpoint := "https://login.microsoftonline.com/" + url.PathEscape(t.tenant) + "/oauth2/v2.0/token"
	reqCtx, cancel := boundedContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("email provider: Microsoft token request construction failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := clientFor(f).Do(req)
	if err != nil {
		return "", errors.New("email provider: Microsoft token request failed")
	}
	defer resp.Body.Close()
	raw, err := readBoundedResponse(resp)
	if err != nil {
		return "", errors.New("email provider: Microsoft token response invalid")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("email provider: Microsoft authentication rejected")
	}
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if json.Unmarshal(raw, &result) != nil || result.AccessToken == "" || result.ExpiresIn <= 0 {
		return "", errors.New("email provider: Microsoft token response invalid")
	}
	if result.ExpiresIn > 24*60*60 {
		return "", errors.New("email provider: Microsoft token lifetime invalid")
	}
	for key, value := range f.tokens {
		if !value.expires.After(now) {
			delete(f.tokens, key)
		}
	}
	if len(f.tokens) >= 512 {
		var oldest tokenKey
		var expires time.Time
		first := true
		for key, value := range f.tokens {
			if first || value.expires.Before(expires) {
				oldest, expires, first = key, value.expires, false
			}
		}
		delete(f.tokens, oldest)
	}
	f.tokens[t.cacheKey] = cachedToken{value: result.AccessToken, expires: now.Add(time.Duration(result.ExpiresIn) * time.Second)}
	return result.AccessToken, nil
}
func (f *Factory) ForgetMS365(tenantID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key := range f.tokens {
		if key.tenant == tenantID {
			delete(f.tokens, key)
		}
	}
}
