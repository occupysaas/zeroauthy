package providers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sendTimeout = 15 * time.Second
const responseLimit = 64 << 10

type Config struct {
	Name                  string
	Credentials, Settings map[string]any
}
type Transport interface {
	Send(context.Context, Message) error
}
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// Factory dependencies are replaceable in tests. A nil dependency selects the
// production transport with certificate verification and outbound filtering.
type Factory struct {
	HTTPClient         *http.Client
	DialContext        DialContextFunc
	Now                func() time.Time
	LocalSMTPAllowlist []string
	mu                 sync.Mutex
	tokens             map[tokenKey]cachedToken
}
type tokenKey struct {
	tenant         string
	authority      string
	revision       int64
	client         string
	credentialHash [32]byte
}
type cachedToken struct {
	value   string
	expires time.Time
}

func (f *Factory) New(ctx context.Context, tenantID string, revision int64, cfg Config) (Transport, error) {
	if tenantID == "" || revision < 1 {
		return nil, errors.New("email provider: invalid configuration identity")
	}
	switch cfg.Name {
	case "smtp":
		host := providerValue(cfg, "smtp_host")
		port := 587
		raw, ok := cfg.Credentials["smtp_port"]
		if !ok {
			raw, ok = cfg.Settings["smtp_port"]
		}
		if ok {
			var valid bool
			port, valid = integerExact(raw)
			if !valid {
				return nil, errors.New("email provider: invalid SMTP port")
			}
		}
		if host == "" || port < 1 || port > 65535 {
			return nil, errors.New("email provider: invalid SMTP settings")
		}
		headers, err := normalizeSMTPHeaders(cfg.Settings["headers"])
		if err != nil {
			return nil, err
		}
		return &smtpTransport{f: f, host: host, port: port, user: providerValue(cfg, "smtp_user"), pass: str(cfg.Credentials, "smtp_pass"), headers: headers}, nil
	case "sendgrid":
		return httpTransport(f, cfg.Name, str(cfg.Credentials, "api_key"), "https://api.sendgrid.com/v3/mail/send", nil)
	case "mailgun":
		domain := providerValue(cfg, "domain")
		if !validDomain(domain) {
			return nil, errors.New("email provider: invalid Mailgun domain")
		}
		base := "https://api.mailgun.net"
		region := providerValue(cfg, "region")
		if region != "" && !strings.EqualFold(region, "eu") {
			return nil, errors.New("email provider: invalid Mailgun region")
		}
		if strings.EqualFold(region, "eu") {
			base = "https://api.eu.mailgun.net"
		}
		return httpTransport(f, cfg.Name, str(cfg.Credentials, "api_key"), base+"/v3/"+url.PathEscape(domain)+"/messages", nil)
	case "mandrill":
		return httpTransport(f, cfg.Name, str(cfg.Credentials, "api_key"), "https://mandrillapp.com/api/1.0/messages/send.json", nil)
	case "sparkpost":
		base := "https://api.sparkpost.com"
		region := providerValue(cfg, "region")
		if region != "" && !strings.EqualFold(region, "eu") {
			return nil, errors.New("email provider: invalid SparkPost region")
		}
		if strings.EqualFold(region, "eu") {
			base = "https://api.eu.sparkpost.com"
		}
		return httpTransport(f, cfg.Name, str(cfg.Credentials, "api_key"), base+"/api/v1/transmissions", nil)
	case "resend":
		return httpTransport(f, cfg.Name, str(cfg.Credentials, "api_key"), "https://api.resend.com/emails", nil)
	case "ses":
		if str(cfg.Credentials, "accessKeyId") == "" || str(cfg.Credentials, "secretAccessKey") == "" || !validRegion(providerValue(cfg, "region")) {
			return nil, errors.New("email provider: invalid SES credentials or region")
		}
		return &sesTransport{f: f, access: str(cfg.Credentials, "accessKeyId"), secret: str(cfg.Credentials, "secretAccessKey"), region: providerValue(cfg, "region"), configurationSet: str(cfg.Settings, "configuration_set_name")}, nil
	case "azure_cs":
		endpoint, key, err := parseAzureConnectionString(str(cfg.Credentials, "connectionString"))
		if err != nil {
			return nil, errors.New("email provider: invalid Azure Communication Services credentials")
		}
		return &azureTransport{f: f, endpoint: endpoint, key: key}, nil
	case "ms365":
		if !validUUID(str(cfg.Credentials, "tenantId")) || !validUUID(str(cfg.Credentials, "clientId")) || str(cfg.Credentials, "clientSecret") == "" {
			return nil, errors.New("email provider: invalid Microsoft 365 credentials")
		}
		client := str(cfg.Credentials, "clientId")
		authority := str(cfg.Credentials, "tenantId")
		secret := str(cfg.Credentials, "clientSecret")
		return &ms365Transport{f: f, tenant: authority, client: client, secret: secret, cacheKey: tokenKey{tenant: tenantID, authority: authority, revision: revision, client: client, credentialHash: sha256.Sum256([]byte(client + "\x00" + secret))}}, nil
	default:
		return nil, errors.New("email provider: unsupported provider")
	}
}
func providerValue(c Config, key string) string {
	if v := str(c.Credentials, key); v != "" {
		return v
	}
	return str(c.Settings, key)
}

func httpTransport(f *Factory, name, key, endpoint string, extra map[string]string) (Transport, error) {
	if key == "" {
		return nil, fmt.Errorf("email provider: missing %s credentials", name)
	}
	return &apiTransport{f: f, name: name, key: key, endpoint: endpoint, extra: extra}, nil
}

type apiTransport struct {
	f                   *Factory
	name, key, endpoint string
	extra               map[string]string
}

func (t *apiTransport) Send(ctx context.Context, m Message) error {
	if err := validMessage(m); err != nil {
		return err
	}
	var body any
	var data []byte
	var err error
	var contentType string
	switch t.name {
	case "sendgrid":
		body = map[string]any{"personalizations": []any{map[string]any{"to": []any{map[string]string{"email": m.To}}, "subject": m.Subject}}, "from": map[string]string{"email": m.From}, "content": []any{map[string]string{"type": "text/plain", "value": m.Text}, map[string]string{"type": "text/html", "value": m.HTML}}}
	case "mailgun":
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for _, field := range [][2]string{{"from", m.From}, {"to", m.To}, {"subject", m.Subject}, {"text", m.Text}, {"html", m.HTML}} {
			if err := mw.WriteField(field[0], field[1]); err != nil {
				return errors.New("email provider: request encoding failed")
			}
		}
		if err := mw.Close(); err != nil {
			return errors.New("email provider: request encoding failed")
		}
		data = buf.Bytes()
		contentType = mw.FormDataContentType()
	case "mandrill":
		body = map[string]any{"key": t.key, "message": map[string]any{"from_email": m.From, "to": []any{map[string]string{"email": m.To, "type": "to"}}, "subject": m.Subject, "text": m.Text, "html": m.HTML}}
	case "sparkpost":
		body = map[string]any{"recipients": []any{map[string]any{"address": map[string]string{"email": m.To}}}, "content": map[string]any{"from": map[string]string{"email": m.From}, "subject": m.Subject, "text": m.Text, "html": m.HTML}}
	case "resend":
		body = map[string]any{"from": m.From, "to": []string{m.To}, "subject": m.Subject, "text": m.Text, "html": m.HTML}
	default:
		return errors.New("email provider: invalid transport")
	}
	if contentType == "" {
		data, err = json.Marshal(body)
		contentType = "application/json"
		if err != nil {
			return errors.New("email provider: request encoding failed")
		}
	}
	ctx, cancel := boundedContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, strings.NewReader(string(data)))
	if err != nil {
		return errors.New("email provider: request construction failed")
	}
	req.Header.Set("Content-Type", contentType)
	switch t.name {
	case "sendgrid":
		req.Header.Set("Authorization", "Bearer "+t.key)
	case "mailgun":
		req.SetBasicAuth("api", t.key)
	case "mandrill":
	case "sparkpost":
		req.Header.Set("Authorization", t.key)
	case "resend":
		req.Header.Set("Authorization", "Bearer "+t.key)
	}
	resp, err := clientFor(t.f).Do(req)
	if err != nil {
		return errors.New("email provider: transport request failed")
	}
	defer resp.Body.Close()
	bodyRead, readErr := readBoundedResponse(resp)
	if readErr != nil {
		return errors.New("email provider: provider response exceeded limit")
	}
	if acceptedResponse(t.name, resp.StatusCode, bodyRead) {
		return nil
	}
	return fmt.Errorf("email provider: %s rejected the request (HTTP %d)", t.name, resp.StatusCode)
}

func accepted(name string, code int) bool {
	switch name {
	case "sendgrid":
		return code == 202
	case "mailgun", "mandrill", "sparkpost", "resend":
		return code >= 200 && code < 300
	default:
		return false
	}
}
func acceptedResponse(name string, code int, body []byte) bool {
	if !accepted(name, code) {
		return false
	}
	switch name {
	case "mandrill":
		var results []struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(body, &results) != nil || len(results) != 1 {
			return false
		}
		return results[0].Status == "sent" || results[0].Status == "queued" || results[0].Status == "scheduled"
	case "sparkpost":
		var result struct {
			Results struct {
				Accepted int `json:"total_accepted_recipients"`
			} `json:"results"`
		}
		return json.Unmarshal(body, &result) == nil && result.Results.Accepted > 0
	}
	return true
}
func clientFor(f *Factory) *http.Client {
	if f != nil && f.HTTPClient != nil {
		c := *f.HTTPClient
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		if c.Timeout == 0 {
			c.Timeout = sendTimeout
		}
		return &c
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = newPolicyDialer(nil).DialContext
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: sendTimeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func boundedContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, sendTimeout)
}
func validMessage(m Message) error {
	if _, err := mail.ParseAddress(m.From); err != nil {
		return errors.New("email provider: invalid sender")
	}
	if _, err := mail.ParseAddress(m.To); err != nil {
		return errors.New("email provider: invalid recipient")
	}
	if strings.ContainsAny(m.Subject, "\r\n") {
		return errors.New("email provider: invalid subject")
	}
	if m.Text == "" && m.HTML == "" {
		return errors.New("email provider: message body is empty")
	}
	return nil
}
func readBoundedResponse(resp *http.Response) ([]byte, error) {
	if resp.ContentLength > responseLimit {
		return nil, errors.New("email provider: provider response exceeded limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit))
	if err != nil {
		return nil, err
	}
	if len(body) >= responseLimit {
		return nil, errors.New("email provider: provider response exceeded limit")
	}
	return body, nil
}
func str(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func integerExact(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		if int64(int(n)) == n {
			return int(n), true
		}
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	case string:
		x, e := strconv.Atoi(n)
		return x, e == nil
	}
	return 0, false
}
func validDomain(s string) bool {
	if len(s) < 1 || len(s) > 253 || strings.ContainsAny(s, "/\\:@?#") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func validRegion(s string) bool {
	if s == "" || len(s) < 9 || len(s) > 32 {
		return false
	}
	parts := strings.Split(s, "-")
	if len(parts) < 3 || len(parts[0]) != 2 || len(parts[len(parts)-1]) != 1 {
		return false
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" {
			return false
		}
		for _, c := range part {
			if c < 'a' || c > 'z' {
				return false
			}
		}
	}
	last := parts[len(parts)-1][0]
	return last >= '0' && last <= '9'
}
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

func parseAzureConnectionString(s string) (string, []byte, error) {
	vals := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok {
			vals[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	endpoint := strings.TrimRight(vals["endpoint"], "/")
	key := vals["accesskey"]
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || !strings.HasSuffix(strings.ToLower(u.Hostname()), ".communication.azure.com") || u.User != nil || u.Port() != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || key == "" {
		return "", nil, errors.New("bad connection string")
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) == 0 {
		return "", nil, errors.New("bad access key")
	}
	return endpoint, decoded, nil
}
