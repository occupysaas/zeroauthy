package protection

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var ErrCaptchaInvalid = errors.New("complete the verification and try again")
var ErrCaptchaUnavailable = errors.New("verification is unavailable; retry or contact support")

// CaptchaChallenge is assembled from validated server-held transaction/ticket
// state. Providers without action binding guarantee site ownership and replay
// prevention, not cryptographic first-use transaction binding.
type CaptchaChallenge struct{ TenantID, Flow, TransactionID, Hostname, SiteKey, Action, ProviderID string }
type CaptchaVerifier interface {
	Verify(context.Context, CaptchaChallenge, string) error
}

// Challenge exposes public widget configuration only; no credential is opened
// until a required, locally validated form is submitted.
func (s *Service) Challenge(ctx context.Context, tenantID, flow, transactionID, hostname string) (CaptchaChallenge, error) {
	t, err := s.Store.Tenants().Get(ctx, tenantID)
	if err != nil {
		return CaptchaChallenge{}, err
	}
	p := t.ProtectionSettings.CAPTCHA
	c := CaptchaChallenge{TenantID: tenantID, Flow: flow, TransactionID: transactionID, Hostname: hostname, ProviderID: p.ActiveProviderID, Action: flow}
	switch p.ActiveProviderID {
	case "recaptcha_v2":
		c.SiteKey = p.RecaptchaV2.SiteKey
	case "hcaptcha":
		c.SiteKey = p.HCaptcha.SiteKey
	case "friendly_captcha":
		c.SiteKey = p.FriendlyCaptcha.SiteKey
	case "recaptcha_enterprise":
		c.SiteKey = p.RecaptchaEnterprise.SiteKey
		c.Action = enterpriseAction(tenantID, flow, transactionID)
	default:
		return c, ErrCaptchaUnavailable
	}
	if c.SiteKey == "" || c.Hostname == "" || c.TransactionID == "" {
		return c, ErrCaptchaUnavailable
	}
	return c, nil
}
func (s *Service) VerifyChallenge(ctx context.Context, c CaptchaChallenge, response string) error {
	if c.TenantID == "" || c.Flow == "" || c.TransactionID == "" || c.Hostname == "" || c.SiteKey == "" {
		return ErrCaptchaUnavailable
	}
	if response == "" || len(response) > 16*1024 {
		return ErrCaptchaInvalid
	}
	// Re-read public configuration to fail closed if a policy changed mid-form.
	current, err := s.Challenge(ctx, c.TenantID, c.Flow, c.TransactionID, c.Hostname)
	if err != nil {
		return err
	}
	if current.ProviderID != c.ProviderID || current.SiteKey != c.SiteKey || current.Action != c.Action {
		return ErrCaptchaInvalid
	}
	verifier := s.CaptchaVerifier
	if verifier == nil {
		verifier = NewCaptchaVerifier(s.Store, s.Wrapper, nil)
	}
	if err := verifier.Verify(ctx, c, response); err != nil {
		if errors.Is(err, ErrCaptchaInvalid) {
			return ErrCaptchaInvalid
		}
		return ErrCaptchaUnavailable
	}
	now := s.now()
	used, err := s.Store.Protection().UseProof(ctx, Proof(c.ProviderID, response), now, now.Add(5*time.Minute))
	if err != nil {
		return ErrCaptchaUnavailable
	}
	if !used {
		return ErrCaptchaInvalid
	}
	return nil
}

// Proof is global across tenants/flows sharing vendor credentials. Length
// prefixes prevent ambiguous concatenation; raw responses never enter storage.
func Proof(provider, response string) string {
	h := sha256.New()
	for _, v := range []string{provider, response} {
		_ = binary.Write(h, binary.BigEndian, uint64(len(v)))
		_, _ = io.WriteString(h, v)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type providerVerifier struct {
	store   store.Store
	wrapper keys.Wrapper
	client  *http.Client
}

func NewCaptchaVerifier(st store.Store, w keys.Wrapper, transport http.RoundTripper) CaptchaVerifier {
	return &providerVerifier{st, w, &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (v *providerVerifier) Verify(ctx context.Context, c CaptchaChallenge, response string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	t, err := v.store.Tenants().Get(ctx, c.TenantID)
	if err != nil {
		return ErrCaptchaUnavailable
	}
	// Only open the selected credential: an unrelated inactive credential must
	// not make an otherwise configured provider unavailable.
	stored := t.ProtectionSettings.CAPTCHA
	selected := store.CAPTCHAPolicy{}
	if stored.ActiveProviderID != c.ProviderID {
		return ErrCaptchaInvalid
	}
	switch c.ProviderID {
	case "recaptcha_v2":
		selected.RecaptchaV2 = stored.RecaptchaV2
	case "hcaptcha":
		selected.HCaptcha = stored.HCaptcha
	case "friendly_captcha":
		selected.FriendlyCaptcha = stored.FriendlyCaptcha
	case "recaptcha_enterprise":
		selected.RecaptchaEnterprise = stored.RecaptchaEnterprise
	default:
		return ErrCaptchaUnavailable
	}
	p, err := keys.OpenCAPTCHA(v.wrapper, c.TenantID, selected)
	if err != nil {
		return ErrCaptchaUnavailable
	}
	switch c.ProviderID {
	case "recaptcha_v2":
		return v.recaptchaV2(ctx, c, response, p.RecaptchaV2)
	case "hcaptcha":
		return v.hcaptcha(ctx, c, response, p.HCaptcha)
	case "friendly_captcha":
		return v.friendlyCaptcha(ctx, c, response, p.FriendlyCaptcha)
	case "recaptcha_enterprise":
		return v.enterprise(ctx, c, response, p.RecaptchaEnterprise)
	}
	return ErrCaptchaUnavailable
}
func (v *providerVerifier) request(req *http.Request, out any) error {
	resp, err := v.client.Do(req)
	if err != nil {
		return ErrCaptchaUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ErrCaptchaUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
	if err != nil || len(raw) > 256*1024 {
		return ErrCaptchaUnavailable
	}
	if json.Unmarshal(raw, out) != nil {
		return ErrCaptchaUnavailable
	}
	return nil
}

func enterpriseAction(tenantID, flow, transactionID string) string {
	return strings.ReplaceAll(flow, "-", "_") + "_" + Proof(tenantID, Proof(flow, transactionID))[:32]
}
