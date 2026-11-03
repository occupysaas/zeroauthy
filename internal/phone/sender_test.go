package phone

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type captured struct {
	method, path, auth string
	form               url.Values
	header             http.Header
}

func fake(t *testing.T, status int, ctype, body string) (*httptest.Server, *captured, *int32) {
	t.Helper()
	c := &captured{}
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		raw, _ := io.ReadAll(r.Body)
		c.method, c.path, c.auth, c.header = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Clone()
		c.form, _ = url.ParseQuery(string(raw))
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, c, &n
}

func useEndpoints(t *testing.T, twilio, sns string) {
	t.Helper()
	old, oldTest := Endpoints, testEndpoints
	SetTestEndpoints(twilio, sns)
	t.Cleanup(func() { Endpoints, testEndpoints = old, oldTest })
}

func TestTwilioTextRequest(t *testing.T) {
	srv, c, _ := fake(t, 201, "application/json", `{"sid":"SM123"}`)
	useEndpoints(t, srv.URL, "")
	s := NewTwilio(TwilioConfig{SID: "AC1", AuthToken: "tok", DefaultFrom: "+15550001111"}, NewHTTPClient())
	res, err := s.Send(context.Background(), Message{To: "+14155550100", DeliveryMethod: "text", Body: "code 123456"})
	if err != nil || res.ProviderMessageID != "SM123" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if c.method != "POST" || c.path != "/2010-04-01/Accounts/AC1/Messages.json" {
		t.Fatalf("%s %s", c.method, c.path)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", c.auth)
	if u, p, ok := req.BasicAuth(); !ok || u != "AC1" || p != "tok" {
		t.Fatalf("auth=%q", c.auth)
	}
	if c.form.Get("To") != "+14155550100" || c.form.Get("Body") != "code 123456" || c.form.Get("From") != "+15550001111" || c.form.Get("MessagingServiceSid") != "" {
		t.Fatalf("form=%v", c.form)
	}
	s = NewTwilio(TwilioConfig{SID: "AC1", AuthToken: "tok", MessagingServiceSID: "MG9"}, NewHTTPClient())
	if _, err := s.Send(context.Background(), Message{To: "+14155550100", DeliveryMethod: "text", Body: "x"}); err != nil {
		t.Fatal(err)
	}
	if c.form.Get("MessagingServiceSid") != "MG9" || c.form.Get("From") != "" {
		t.Fatalf("form=%v", c.form)
	}
}

func TestTwilioVoiceRequest(t *testing.T) {
	srv, c, _ := fake(t, 201, "application/json", `{"sid":"CA1"}`)
	useEndpoints(t, srv.URL, "")
	s := NewTwilio(TwilioConfig{SID: "AC1", AuthToken: "tok", DefaultFrom: "+15550001111"}, NewHTTPClient())
	res, err := s.Send(context.Background(), Message{To: "+14155550100", DeliveryMethod: "voice", Body: `a<b & "c"`})
	if err != nil || res.ProviderMessageID != "CA1" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if c.path != "/2010-04-01/Accounts/AC1/Calls.json" || c.form.Get("From") != "+15550001111" {
		t.Fatalf("%s %v", c.path, c.form)
	}
	if got := c.form.Get("Twiml"); got != `<Response><Say>a&lt;b &amp; &#34;c&#34;</Say></Response>` {
		t.Fatalf("twiml=%s", got)
	}
	s = NewTwilio(TwilioConfig{SID: "AC1", AuthToken: "tok", MessagingServiceSID: "MG9"}, NewHTTPClient())
	if _, err := s.Send(context.Background(), Message{To: "+14155550100", DeliveryMethod: "voice", Body: "x"}); ClassOf(err) != ClassUnsupportedDelivery {
		t.Fatalf("err=%v", err)
	}
}

func TestTwilioErrorClasses(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   ErrorClass
	}{
		{400, `{"code":21211,"message":"invalid To"}`, ClassInvalidNumber},
		{401, `{"code":20003,"message":"auth"}`, ClassProviderAuth},
		{429, `{"code":20429}`, ClassRateLimited},
		{429, ``, ClassRateLimited},
		{503, `oops`, ClassTransient},
		{400, `{"code":21610}`, ClassUnreachable},
	}
	for _, tc := range cases {
		srv, _, _ := fake(t, tc.status, "application/json", tc.body)
		useEndpoints(t, srv.URL, "")
		s := NewTwilio(TwilioConfig{SID: "AC1", AuthToken: "tok", DefaultFrom: "+1555"}, NewHTTPClient())
		_, err := s.Send(context.Background(), Message{To: "+14155550100", DeliveryMethod: "text", Body: "x"})
		if ClassOf(err) != tc.want {
			t.Errorf("%d %s: class=%q err=%v", tc.status, tc.body, ClassOf(err), err)
		}
	}
	// Unreachable server is transient.
	srv, _, _ := fake(t, 200, "", "")
	useEndpoints(t, srv.URL, "")
	srv.Close()
	_, err := NewTwilio(TwilioConfig{SID: "AC1", DefaultFrom: "+1"}, NewHTTPClient()).Send(context.Background(), Message{To: "+14155550100", Body: "x"})
	if ClassOf(err) != ClassTransient {
		t.Fatalf("err=%v", err)
	}
}

func TestTwilioNoRedirects(t *testing.T) {
	target, _, n := fake(t, 200, "", "")
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	useEndpoints(t, redir.URL, "")
	_, err := NewTwilio(TwilioConfig{SID: "AC1", DefaultFrom: "+1"}, NewHTTPClient()).Send(context.Background(), Message{To: "+14155550100", Body: "x"})
	if err == nil || atomic.LoadInt32(n) != 0 {
		t.Fatalf("err=%v followed=%d", err, atomic.LoadInt32(n))
	}
}

func TestProductionClientBlocksPrivate(t *testing.T) {
	useEndpoints(t, "", "")
	srv, _, n := fake(t, 200, "", "")
	Endpoints.Twilio = srv.URL // loopback while the guard is on
	_, err := NewTwilio(TwilioConfig{SID: "AC1", DefaultFrom: "+1"}, NewHTTPClient()).Send(context.Background(), Message{To: "+14155550100", Body: "x"})
	if ClassOf(err) != ClassTransient || atomic.LoadInt32(n) != 0 {
		t.Fatalf("err=%v hits=%d", err, atomic.LoadInt32(n))
	}
}

func TestSNSPublishSigned(t *testing.T) {
	srv, c, _ := fake(t, 200, "text/xml", `<PublishResponse><PublishResult><MessageId>mid-1</MessageId></PublishResult></PublishResponse>`)
	useEndpoints(t, "", srv.URL)
	s := NewSNS(SNSConfig{Region: "eu-west-1", AccessKeyID: "AKID", Secret: "sek", SenderID: "ACME", SMSType: "Transactional"}, NewHTTPClient())
	res, err := s.Send(context.Background(), Message{To: "+14155550100", DeliveryMethod: "text", Body: "code 1"})
	if err != nil || res.ProviderMessageID != "mid-1" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	f := c.form
	if c.method != "POST" || f.Get("Action") != "Publish" || f.Get("PhoneNumber") != "+14155550100" || f.Get("Message") != "code 1" {
		t.Fatalf("form=%v", f)
	}
	if f.Get("MessageAttributes.entry.1.Name") != "AWS.SNS.SMS.SenderID" || f.Get("MessageAttributes.entry.1.Value.StringValue") != "ACME" ||
		f.Get("MessageAttributes.entry.2.Name") != "AWS.SNS.SMS.SMSType" || f.Get("MessageAttributes.entry.2.Value.StringValue") != "Transactional" ||
		f.Get("MessageAttributes.entry.2.Value.DataType") != "String" {
		t.Fatalf("attrs=%v", f)
	}
	if !strings.HasPrefix(c.auth, "AWS4-HMAC-SHA256 Credential=AKID/") || !strings.Contains(c.auth, "/eu-west-1/sns/aws4_request") ||
		!strings.Contains(c.auth, "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date") || c.header.Get("X-Amz-Date") == "" {
		t.Fatalf("auth=%s", c.auth)
	}
}

func TestSNSErrorClasses(t *testing.T) {
	cases := map[string]struct {
		status int
		want   ErrorClass
	}{
		"InvalidParameter":   {400, ClassInvalidNumber},
		"AuthorizationError": {403, ClassProviderAuth},
		"Throttling":         {400, ClassRateLimited},
		"InternalFailure":    {500, ClassTransient},
		"OptedOut":           {400, ClassUnreachable},
	}
	for code, tc := range cases {
		srv, _, _ := fake(t, tc.status, "text/xml", `<ErrorResponse><Error><Code>`+code+`</Code></Error></ErrorResponse>`)
		useEndpoints(t, "", srv.URL)
		_, err := NewSNS(SNSConfig{Region: "us-east-1"}, NewHTTPClient()).Send(context.Background(), Message{To: "+14155550100", Body: "x"})
		if ClassOf(err) != tc.want {
			t.Errorf("%s: class=%q", code, ClassOf(err))
		}
	}
}

func TestSNSVoiceUnsupported(t *testing.T) {
	srv, _, n := fake(t, 200, "", "")
	useEndpoints(t, "", srv.URL)
	_, err := NewSNS(SNSConfig{Region: "us-east-1"}, NewHTTPClient()).Send(context.Background(), Message{To: "+14155550100", DeliveryMethod: "voice", Body: "x"})
	if ClassOf(err) != ClassUnsupportedDelivery || atomic.LoadInt32(n) != 0 {
		t.Fatalf("err=%v hits=%d", err, atomic.LoadInt32(n))
	}
}

func TestSenderNeverLogsSecrets(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	srv, _, _ := fake(t, 400, "application/json", `{"code":21211,"message":"bad +14155550100 code 424242"}`)
	useEndpoints(t, srv.URL, srv.URL)
	m := Message{To: "+14155550100", DeliveryMethod: "text", Body: "your code is 424242", Code: "424242"}
	_, _ = NewTwilio(TwilioConfig{SID: "AC1", AuthToken: "twilio-secret-token", DefaultFrom: "+1555"}, NewHTTPClient()).Send(context.Background(), m)
	_, _ = NewSNS(SNSConfig{Region: "us-east-1", AccessKeyID: "AKIDSECRETID", Secret: "sns-secret-key"}, NewHTTPClient()).Send(context.Background(), m)
	out := buf.String()
	if out == "" {
		t.Fatal("expected a masked failure log")
	}
	for _, bad := range []string{"twilio-secret-token", "sns-secret-key", "AKIDSECRETID", "424242", "+14155550100", "14155550100"} {
		if strings.Contains(out, bad) {
			t.Fatalf("log leaks %q: %s", bad, out)
		}
	}
}
