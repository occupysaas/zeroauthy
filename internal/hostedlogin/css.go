package hostedlogin

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var cssBlock = regexp.MustCompile(`(?s)^\s*\.za-decoration\s*\{([^{}]*)\}\s*$`)
var hexColor = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
var cssError = errors.New("unsafe CSS")

func ValidateCSS(src string) error {
	m := cssBlock.FindStringSubmatch(src)
	if m == nil {
		return cssError
	}
	for _, declaration := range strings.Split(m[1], ";") {
		declaration = strings.TrimSpace(declaration)
		if declaration == "" {
			continue
		}
		parts := strings.SplitN(declaration, ":", 2)
		if len(parts) != 2 {
			return cssError
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "color", "background-color":
			if !hexColor.MatchString(value) && !validRGB(value) {
				return cssError
			}
		case "font-size", "margin", "padding":
			if !strings.HasSuffix(value, "px") {
				return cssError
			}
			n, err := strconv.Atoi(strings.TrimSuffix(value, "px"))
			if err != nil || n < 0 || n > 64 || (key == "font-size" && (n < 12 || n > 48)) {
				return cssError
			}
		case "font-weight":
			if value != "400" && value != "600" && value != "700" {
				return cssError
			}
		case "text-align":
			if value != "left" && value != "center" && value != "right" {
				return cssError
			}
		default:
			return cssError
		}
	}
	return nil
}

func validRGB(value string) bool {
	alpha := false
	var args string
	switch {
	case strings.HasPrefix(value, "rgb(") && strings.HasSuffix(value, ")"):
		args = strings.TrimSuffix(strings.TrimPrefix(value, "rgb("), ")")
	case strings.HasPrefix(value, "rgba(") && strings.HasSuffix(value, ")"):
		args = strings.TrimSuffix(strings.TrimPrefix(value, "rgba("), ")")
		alpha = true
	default:
		return false
	}
	parts := strings.Split(args, ",")
	count := 3
	if alpha {
		count = 4
	}
	if len(parts) != count {
		return false
	}
	for _, part := range parts[:3] {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
		n, err := strconv.Atoi(part)
		if err != nil || n > 255 {
			return false
		}
	}
	if alpha {
		part := strings.TrimSpace(parts[3])
		if part == "" {
			return false
		}
		for _, r := range part {
			if (r < '0' || r > '9') && r != '.' {
				return false
			}
		}
		n, err := strconv.ParseFloat(part, 64)
		if err != nil || n < 0 || n > 1 {
			return false
		}
	}
	return true
}
