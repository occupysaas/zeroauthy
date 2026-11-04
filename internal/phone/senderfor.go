package phone

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrActionProvider is returned by SenderFor for providers that are not
// native adapters (custom). Task 9 replaces it with the Action adapter.
var ErrActionProvider = errors.New("phone: provider is backed by an Action")

// SenderFor builds the native sender of a stored provider. unseal opens the
// provider's sealed credentials. A nil hc uses NewHTTPClient.
func SenderFor(p store.PhoneProvider, unseal func([]byte) ([]byte, error), hc *http.Client) (Sender, error) {
	switch p.Name {
	case "twilio":
		var cfg struct {
			SID         string `json:"sid"`
			DefaultFrom string `json:"default_from"`
			MSSID       string `json:"mssid"`
		}
		var creds struct {
			AuthToken string `json:"auth_token"`
		}
		if err := open(p, unseal, &cfg, &creds); err != nil {
			return nil, err
		}
		return NewTwilio(TwilioConfig{SID: cfg.SID, AuthToken: creds.AuthToken, DefaultFrom: cfg.DefaultFrom, MessagingServiceSID: cfg.MSSID}, hc), nil
	case "sns":
		var cfg struct {
			Region   string `json:"region"`
			SenderID string `json:"sender_id"`
			SMSType  string `json:"sms_type"`
		}
		var creds struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
		}
		if err := open(p, unseal, &cfg, &creds); err != nil {
			return nil, err
		}
		return NewSNS(SNSConfig{Region: cfg.Region, AccessKeyID: creds.AccessKeyID, Secret: creds.SecretAccessKey, SenderID: cfg.SenderID, SMSType: cfg.SMSType}, hc), nil
	}
	return nil, ErrActionProvider
}

// open decodes the public configuration and the unsealed credentials. Errors
// never carry the credential plaintext.
func open(p store.PhoneProvider, unseal func([]byte) ([]byte, error), cfg, creds any) error {
	if err := json.Unmarshal(p.Configuration, cfg); err != nil {
		return errors.New("phone: provider configuration unreadable")
	}
	plain, err := unseal(p.SealedCredentials)
	if err != nil {
		return errors.New("phone: provider credentials unavailable")
	}
	if err := json.Unmarshal(plain, creds); err != nil {
		return errors.New("phone: provider credentials unreadable")
	}
	return nil
}
