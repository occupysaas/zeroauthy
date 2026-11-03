package phone

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

type TwilioConfig struct{ SID, AuthToken, DefaultFrom, MessagingServiceSID string }

type twilio struct {
	cfg TwilioConfig
	hc  *http.Client
}

// NewTwilio sends text through the Messages API and voice through the Calls
// API. A nil hc uses NewHTTPClient.
func NewTwilio(cfg TwilioConfig, hc *http.Client) Sender {
	if hc == nil {
		hc = NewHTTPClient()
	}
	return &twilio{cfg: cfg, hc: hc}
}

func (t *twilio) Send(ctx context.Context, m Message) (Result, error) {
	form := url.Values{"To": {m.To}}
	from := m.From
	if from == "" {
		from = t.cfg.DefaultFrom
	}
	var path string
	switch m.DeliveryMethod {
	case "voice":
		if from == "" {
			return Result{}, &SendError{Class: ClassUnsupportedDelivery, Err: errors.New("voice needs a from number")}
		}
		var b bytes.Buffer
		b.WriteString("<Response><Say>")
		if err := xml.EscapeText(&b, []byte(m.Body)); err != nil {
			return Result{}, &SendError{Class: ClassTransient, Err: err}
		}
		b.WriteString("</Say></Response>")
		form.Set("From", from)
		form.Set("Twiml", b.String())
		path = "Calls.json"
	case "text", "":
		form.Set("Body", m.Body)
		switch {
		case m.From != "":
			form.Set("From", m.From)
		case t.cfg.MessagingServiceSID != "":
			form.Set("MessagingServiceSid", t.cfg.MessagingServiceSID)
		case from != "":
			form.Set("From", from)
		default:
			return Result{}, &SendError{Class: ClassUnsupportedDelivery, Err: errors.New("no from number or messaging service")}
		}
		path = "Messages.json"
	default:
		return Result{}, &SendError{Class: ClassUnsupportedDelivery, Err: errors.New("unknown delivery method")}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Endpoints.Twilio+"/2010-04-01/Accounts/"+url.PathEscape(t.cfg.SID)+"/"+path, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, &SendError{Class: ClassTransient, Err: errors.New("build request")}
	}
	req.SetBasicAuth(t.cfg.SID, t.cfg.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := t.hc.Do(req)
	if err != nil {
		return Result{}, failed(m, ClassTransient, errors.New("request failed"))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		SID  string `json:"sid"`
		Code int    `json:"code"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode/100 == 2 {
		return Result{ProviderMessageID: out.SID}, nil
	}
	return Result{}, failed(m, twilioClass(resp.StatusCode, out.Code), errors.New("twilio status "+http.StatusText(resp.StatusCode)))
}

func twilioClass(status, code int) ErrorClass {
	switch code {
	case 21211, 21614, 21217, 21216:
		return ClassInvalidNumber
	case 20003:
		return ClassProviderAuth
	case 21610, 21612, 21408:
		return ClassUnreachable
	case 20429:
		return ClassRateLimited
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ClassProviderAuth
	case status == http.StatusTooManyRequests:
		return ClassRateLimited
	case status >= 500:
		return ClassTransient
	}
	return ClassUnreachable
}

// failed logs the class with a masked number (never body, code or secrets).
func failed(m Message, c ErrorClass, err error) error {
	slog.Warn("phone send failed", "class", string(c), "to", Mask(m.To), "method", m.DeliveryMethod)
	return &SendError{Class: c, Err: err}
}
