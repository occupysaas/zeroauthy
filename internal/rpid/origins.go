package rpid

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// NativeOrigins lists the origins a native or embedded passkey ceremony may
// report (LR33b-26): the request origin; the client's web origins that sit
// under the RP ID; and android:apk-key-hash origins from the client's
// Android certificate fingerprints (32-byte SHA-256, hex with colons).
func NativeOrigins(r Result, c *store.Client) []string {
	out := []string{r.Origin}
	if c == nil {
		return out
	}
	for _, o := range c.WebOrigins {
		u, err := url.Parse(o)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(o, "#") || o == r.Origin {
			continue
		}
		host, err := hostname.NormalizeDNSName(u.Hostname())
		if err != nil || host != u.Hostname() || strings.HasSuffix(u.Host, ":") {
			continue
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				continue
			}
		}
		if covers(r.RPID, host) {
			out = append(out, o)
		}
	}
	if c.Mobile != nil && c.Mobile.Android != nil {
		for _, fp := range c.Mobile.Android.SHA256CertFingerprints {
			parts := strings.Split(fp, ":")
			if len(parts) != 32 {
				continue
			}
			valid := true
			for _, part := range parts {
				if len(part) != 2 {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			b, err := hex.DecodeString(strings.ReplaceAll(fp, ":", ""))
			if err != nil || len(b) != 32 {
				continue
			}
			out = append(out, "android:apk-key-hash:"+base64.RawURLEncoding.EncodeToString(b))
		}
	}
	return out
}
