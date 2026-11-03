package phone

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/awssig"
)

type SNSConfig struct{ Region, AccessKeyID, Secret, SenderID, SMSType string }

type sns struct {
	cfg SNSConfig
	hc  *http.Client
	now func() time.Time
}

// NewSNS publishes SMS through Amazon SNS. Voice is unsupported. A nil hc uses
// NewHTTPClient.
func NewSNS(cfg SNSConfig, hc *http.Client) Sender {
	if hc == nil {
		hc = NewHTTPClient()
	}
	return &sns{cfg: cfg, hc: hc, now: time.Now}
}

func (s *sns) Send(ctx context.Context, m Message) (Result, error) {
	if m.DeliveryMethod == "voice" {
		return Result{}, &SendError{Class: ClassUnsupportedDelivery, Err: errors.New("sns sends text only")}
	}
	form := url.Values{"Action": {"Publish"}, "Version": {"2010-03-31"}, "PhoneNumber": {m.To}, "Message": {m.Body}}
	n := 0
	attr := func(name, value string) {
		if value == "" {
			return
		}
		n++
		p := "MessageAttributes.entry." + string(rune('0'+n))
		form.Set(p+".Name", name)
		form.Set(p+".Value.DataType", "String")
		form.Set(p+".Value.StringValue", value)
	}
	sender := s.cfg.SenderID
	if m.From != "" {
		sender = m.From
	}
	attr("AWS.SNS.SMS.SenderID", sender)
	attr("AWS.SNS.SMS.SMSType", s.cfg.SMSType)
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, snsURL(s.cfg.Region), strings.NewReader(body))
	if err != nil {
		return Result{}, &SendError{Class: ClassTransient, Err: errors.New("build request")}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	awssig.Sign(req, []byte(body), s.cfg.Region, "sns", s.cfg.AccessKeyID, s.cfg.Secret, s.now())
	resp, err := s.hc.Do(req)
	if err != nil {
		return Result{}, failed(m, ClassTransient, errors.New("request failed"))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 == 2 {
		var ok struct {
			MessageID string `xml:"PublishResult>MessageId"`
		}
		_ = xml.Unmarshal(raw, &ok)
		return Result{ProviderMessageID: ok.MessageID}, nil
	}
	var e struct {
		Code string `xml:"Error>Code"`
	}
	_ = xml.Unmarshal(raw, &e)
	return Result{}, failed(m, snsClass(resp.StatusCode, e.Code), errors.New("sns status "+http.StatusText(resp.StatusCode)))
}

func snsClass(status int, code string) ErrorClass {
	switch code {
	case "InvalidParameter", "InvalidParameterValue":
		return ClassInvalidNumber
	case "OptedOut":
		return ClassUnreachable
	case "AuthorizationError", "InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException", "AccessDenied", "InvalidSecurity":
		return ClassProviderAuth
	case "Throttling", "ThrottlingException", "ThrottledException":
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
