package phone

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
)

// GatewayConfig is an sms connection's sms_gateway settings.
type GatewayConfig struct {
	URL, From      string
	ForwardReqInfo bool
	// Auth is nil when gateway_authentication is not set.
	Auth *GatewayAuth
}

// GatewayAuth signs the gateway request as an HS256 JWT (D-0060 LR6).
type GatewayAuth struct {
	Audience, Subject, Secret string
	SecretBase64Encoded       bool
}

type gateway struct {
	cfg GatewayConfig
	hc  *http.Client
	now func() time.Time
}

// NewGatewayClient returns the gateway transport: the address is checked at
// dial time (private, loopback, CGNAT and other non-public ranges refused),
// no redirects, the documented 30 s timeout. allowPrivate is only for test
// endpoints (ZA_TEST_MODE).
func NewGatewayClient(allowPrivate bool) *http.Client {
	return &http.Client{
		Timeout:       time.Duration(phonerules.Limits.GatewayTimeoutSeconds) * time.Second,
		Transport:     &http.Transport{DialContext: httpx.GuardedDialer(allowPrivate)},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// NewGateway posts each text to an operator's SMS gateway. A nil hc uses
// NewGatewayClient (private addresses only while test endpoints are active).
func NewGateway(cfg GatewayConfig, hc *http.Client, now func() time.Time) Sender {
	if hc == nil {
		hc = NewGatewayClient(testEndpoints)
	}
	if now == nil {
		now = time.Now
	}
	return &gateway{cfg: cfg, hc: hc, now: now}
}

func (g *gateway) Send(ctx context.Context, m Message) (Result, error) {
	if m.DeliveryMethod != "" && m.DeliveryMethod != "text" {
		return Result{}, &SendError{Class: ClassUnsupportedDelivery, Err: errors.New("the SMS gateway sends text only")}
	}
	body := map[string]any{"recipient": m.To, "body": m.Body, "sender": g.cfg.From}
	if g.cfg.ForwardReqInfo {
		r := RequestFrom(ctx)
		body["req"] = map[string]any{"ip": r.IP, "user-agent": r.UserAgent}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return Result{}, &SendError{Class: ClassTransient, Err: errors.New("encode gateway body")}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.URL, bytes.NewReader(raw))
	if err != nil {
		return Result{}, &SendError{Class: ClassProviderAuth, Err: errors.New("invalid gateway_url")}
	}
	req.Header.Set("Content-Type", "application/json")
	if a := g.cfg.Auth; a != nil {
		token, err := gatewayJWT(*a, g.now())
		if err != nil {
			return Result{}, &SendError{Class: ClassProviderAuth, Err: err}
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := g.hc.Do(req)
	if err != nil {
		// Only the class reaches the caller; the transport error may name
		// the gateway host but never the number, body or secret.
		reason := "request failed"
		if errors.Is(err, httpx.ErrBlockedAddress) {
			reason = "address not allowed"
		} else if ctx.Err() != nil || isTimeout(err) {
			reason = "timeout"
		}
		return Result{}, failed(m, ClassTransient, fmt.Errorf("Timeout while calling the SMS gateway: %s", reason))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode == http.StatusOK:
		return Result{}, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return Result{}, failed(m, ClassProviderAuth, errors.New("Authentication failed while calling the SMS gateway: 401"))
	}
	class := ClassUnreachable
	if resp.StatusCode >= 500 {
		class = ClassTransient
	}
	return Result{}, failed(m, class, fmt.Errorf("Unexpected response while calling the SMS gateway: %d", resp.StatusCode))
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// gatewayJWT signs {sub, aud, iat, exp} with HS256; exp is iat plus the
// gateway JWT lifetime (D-0060 LR6).
func gatewayJWT(a GatewayAuth, now time.Time) (string, error) {
	key := []byte(a.Secret)
	if a.SecretBase64Encoded {
		dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(a.Secret, "="))
		if err != nil {
			if dec, err = base64.StdEncoding.DecodeString(a.Secret); err != nil {
				return "", errors.New("gateway secret is not base64")
			}
		}
		key = dec
	}
	if len(key) == 0 {
		return "", errors.New("gateway secret missing")
	}
	iat := now.Unix()
	claims := map[string]any{"iat": iat, "exp": iat + int64(phonerules.Limits.GatewayJWTSeconds)}
	if a.Subject != "" {
		claims["sub"] = a.Subject
	}
	if a.Audience != "" {
		claims["aud"] = a.Audience
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	data := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return data + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
