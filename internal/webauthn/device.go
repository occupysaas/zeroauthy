package webauthn

import "strings"

// Device classifies a browser for platform-authenticator recognition
// (LR33b-19): OS is windows, ios, macos, android or other; the browser
// counts only on macOS; Class is phone, tablet or desktop.
type Device struct {
	OS, Browser, Class string
}

// Key identifies "the same device" for platform enrollments.
func (d Device) Key() string {
	k := d.OS
	if d.OS == "macos" {
		k += "/" + d.Browser
	}
	return k + "/" + d.Class
}

// DeviceOf classifies a User-Agent string. Android is recognised only in
// Chrome (documented); other Android browsers map to OS "other".
func DeviceOf(ua string) Device {
	browser := "other"
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "edge"
	case strings.Contains(ua, "SamsungBrowser/"), strings.Contains(ua, "OPR/"):
		browser = "other"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "CriOS/"):
		browser = "chrome"
	case strings.Contains(ua, "Firefox/"), strings.Contains(ua, "FxiOS/"):
		browser = "firefox"
	case strings.Contains(ua, "Safari/"):
		browser = "safari"
	}
	d := Device{OS: "other", Browser: browser, Class: "desktop"}
	switch {
	case strings.Contains(ua, "iPhone"):
		d.OS, d.Class = "ios", "phone"
	case strings.Contains(ua, "iPad"):
		d.OS, d.Class = "ios", "tablet"
	case strings.Contains(ua, "Android"):
		d.Class = "tablet"
		if strings.Contains(ua, "Mobile") {
			d.Class = "phone"
		}
		if browser == "chrome" {
			d.OS = "android"
		}
	case strings.Contains(ua, "Windows"):
		d.OS = "windows"
	case strings.Contains(ua, "Macintosh"), strings.Contains(ua, "Mac OS X"):
		d.OS = "macos"
	}
	return d
}
