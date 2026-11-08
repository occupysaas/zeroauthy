// Package webauthnrules freezes the Plan 33b passkey and WebAuthn contract:
// documented rules with their sources, prompt screens, text keys, log detail
// fields and limits. It holds no ceremony or storage code; see D-0062.
package webauthnrules

import (
	_ "embed"
	"encoding/json"
	"slices"
	"time"
)

// Rule is one documented behaviour and the page it comes from.
type Rule struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	Statement string `json:"statement"`
}

type inventory struct {
	Rules      []Rule              `json:"rules"`
	Screens    map[string][]string `json:"screens"`
	TextKeys   map[string][]string `json:"text_keys"`
	LogDetails map[string][]string `json:"log_details"`
}

//go:embed inventory.json
var raw []byte

var frozen = func() inventory {
	var inv inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		panic("webauthnrules: " + err.Error())
	}
	return inv
}()

// LimitSet holds the Plan 33b numeric limits; later tasks read Limits instead
// of literals.
type LimitSet struct {
	MaxPasskeys        int
	HostedChallengeTTL time.Duration
	NativeTimeout      time.Duration
	NativeGrace        time.Duration
	ProgressiveSnooze  time.Duration
	LocalSnooze        time.Duration
	PlatformRemind     time.Duration
	PlatformRefuse     time.Duration
	NicknameMin        int
	NicknameMax        int
	ChallengeBytes     int
	UserHandleBytes    int
	AttestationMax     int
	ClientDataMax      int
	CredentialIDMax    int
	COSEMax            int
	CBORDepth          int
	CBORItems          int
	RPIDMax            int
}

// Limits are the documented limits and the D-0062 local rulings.
var Limits = LimitSet{
	MaxPasskeys:        20,
	HostedChallengeTTL: 5 * time.Minute,
	NativeTimeout:      60 * time.Second,
	NativeGrace:        10 * time.Second,
	ProgressiveSnooze:  30 * 24 * time.Hour,
	LocalSnooze:        30 * 24 * time.Hour,
	PlatformRemind:     14 * 24 * time.Hour,
	PlatformRefuse:     365 * 24 * time.Hour,
	NicknameMin:        1,
	NicknameMax:        20,
	ChallengeBytes:     32,
	UserHandleBytes:    32,
	AttestationMax:     64 << 10,
	ClientDataMax:      16 << 10,
	CredentialIDMax:    1023,
	COSEMax:            16 << 10,
	CBORDepth:          16,
	CBORItems:          1024,
	RPIDMax:            255,
}

// Rules returns the frozen documented rules.
func Rules() []Rule { return slices.Clone(frozen.Rules) }

// Screens maps a prompt to its passkey and WebAuthn screens.
func Screens() map[string][]string {
	out := map[string][]string{}
	for k, v := range frozen.Screens {
		out[k] = slices.Clone(v)
	}
	return out
}

// TextKeys lists the custom-text keys a screen uses for passkeys.
func TextKeys(screen string) []string { return slices.Clone(frozen.TextKeys[screen]) }

// LogDetails lists the details fields a log code may carry for passkeys.
func LogDetails(code string) []string { return slices.Clone(frozen.LogDetails[code]) }
