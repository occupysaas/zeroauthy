package ui

import (
	"net/http"
	"strings"
)

// Captcha contains public widget configuration derived from current tenant policy.
type Captcha struct{ Provider, SiteKey, Action string }

func captchaHeaders(w http.ResponseWriter, c *Captcha) {
	if c == nil {
		return
	}
	var script, frame, connect string
	switch c.Provider {
	case "recaptcha_v2", "recaptcha_enterprise":
		script = "https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/"
		frame = "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/"
		connect = "https://www.google.com/recaptcha/"
	case "hcaptcha":
		script = "https://js.hcaptcha.com"
		frame = "https://newassets.hcaptcha.com"
		connect = "https://hcaptcha.com https://api.hcaptcha.com https://newassets.hcaptcha.com"
	case "friendly_captcha":
		script = "https://cdn.jsdelivr.net/npm/friendly-challenge@0.9.18/ 'wasm-unsafe-eval'"
		frame = "'none'"
		connect = "https://api.friendlycaptcha.com"
	default:
		return
	}
	csp := w.Header().Get("Content-Security-Policy")
	csp = strings.Replace(csp, "; style-src", " "+script+"; style-src", 1)
	csp += "; frame-src " + frame + "; connect-src " + connect
	if c.Provider == "friendly_captcha" {
		csp += "; worker-src blob:"
	}
	w.Header().Set("Content-Security-Policy", csp)
}
