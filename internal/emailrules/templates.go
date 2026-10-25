package emailrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var ErrInvalidTemplate = errors.New("invalid email template")

var templateFields = map[string]bool{"template": true, "body": true, "from": true, "subject": true, "syntax": true, "enabled": true, "resultUrl": true, "urlLifetimeInSeconds": true, "includeEmailInRedirect": true}
var templateNames = map[string]bool{"verify_email": true, "verify_email_by_code": true, "auth_email_by_code": true, "reset_email": true, "reset_email_by_code": true, "welcome_email": true, "blocked_account": true, "stolen_credentials": true, "enrollment_email": true, "mfa_oob_code": true, "user_invitation": true, "async_approval": true, "change_password": true, "password_reset": true}
var liquidFilters = map[string]bool{"escape": true, "escape_once": true, "upcase": true, "downcase": true, "capitalize": true, "strip": true, "lstrip": true, "rstrip": true, "append": true, "prepend": true, "replace": true, "replace_first": true, "remove": true, "remove_first": true, "truncate": true, "truncatewords": true, "default": true, "size": true, "first": true, "last": true, "join": true, "date": true}

func ValidateTemplate(raw map[string]json.RawMessage, partial bool) error {
	if len(raw) == 0 || len(raw) > len(templateFields) {
		return ErrInvalidTemplate
	}
	for key, value := range raw {
		if !templateFields[key] {
			return ErrInvalidTemplate
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			continue
		}
		switch key {
		case "body", "from", "subject", "syntax", "resultUrl", "template":
			var s string
			if json.Unmarshal(value, &s) != nil {
				return ErrInvalidTemplate
			}
			limit := 128 << 10
			switch key {
			case "from", "subject":
				limit = 1 << 10
			case "resultUrl":
				limit = 4 << 10
			case "template":
				limit = 64
			}
			if len(s) > limit || !validUTF8(s) {
				return ErrInvalidTemplate
			}
			if key == "template" && !templateNames[s] {
				return ErrInvalidTemplate
			}
			if key == "syntax" && s != "liquid" {
				return ErrInvalidTemplate
			}
			if key != "template" && key != "syntax" {
				if err := validateLiquid(s); err != nil {
					return err
				}
			}
		case "enabled", "includeEmailInRedirect":
			var b bool
			if json.Unmarshal(value, &b) != nil {
				return ErrInvalidTemplate
			}
		case "urlLifetimeInSeconds":
			var n int64
			if json.Unmarshal(value, &n) != nil || n < 0 || n > 604800 {
				return ErrInvalidTemplate
			}
		}
	}
	if !partial {
		for _, key := range []string{"template", "body", "subject", "enabled"} {
			if _, ok := raw[key]; !ok {
				return ErrInvalidTemplate
			}
		}
	}
	return nil
}

func validateLiquid(source string) error {
	stack := []string{}
	for _, open := range []struct {
		start, end string
		output     bool
	}{{"{{", "}}", true}, {"{%", "%}", false}} {
		remaining := source
		for {
			i := strings.Index(remaining, open.start)
			if i < 0 {
				break
			}
			j := strings.Index(remaining[i+2:], open.end)
			if j < 0 {
				return ErrInvalidTemplate
			}
			content := strings.TrimSpace(remaining[i+2 : i+2+j])
			remaining = remaining[i+2+j+2:]
			if open.output {
				parts := strings.Split(content, "|")
				for _, filter := range parts[1:] {
					name := strings.TrimSpace(strings.SplitN(filter, ":", 2)[0])
					if !liquidFilters[name] {
						return ErrInvalidTemplate
					}
				}
				if content == "" {
					return ErrInvalidTemplate
				}
				continue
			}
			fields := strings.Fields(content)
			if len(fields) == 0 {
				return ErrInvalidTemplate
			}
			switch fields[0] {
			case "if", "unless":
				stack = append(stack, "endif")
			case "for":
				stack = append(stack, "endfor")
			case "comment":
				stack = append(stack, "endcomment")
			case "elsif", "else":
				if len(stack) == 0 || stack[len(stack)-1] != "endif" {
					return ErrInvalidTemplate
				}
			case "endif", "endfor", "endcomment":
				if len(stack) == 0 || stack[len(stack)-1] != fields[0] {
					return ErrInvalidTemplate
				}
				stack = stack[:len(stack)-1]
			case "assign":
			default:
				return ErrInvalidTemplate
			}
		}
		if strings.Count(source, open.start) != strings.Count(source, open.end) {
			return ErrInvalidTemplate
		}
	}
	if len(stack) != 0 {
		return ErrInvalidTemplate
	}
	if len(source) > 128<<10 || !validUTF8(source) {
		return ErrInvalidTemplate
	}
	return nil
}

func validUTF8(s string) bool { return strings.ToValidUTF8(s, "\uFFFD") == s }

func DecodeTemplate(data []byte) (map[string]json.RawMessage, error) {
	if len(data) > 256<<10 {
		return nil, ErrInvalidTemplate
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, ErrInvalidTemplate
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, ErrInvalidTemplate
	}
	if err := ValidateTemplate(raw, false); err != nil {
		return nil, err
	}
	return raw, nil
}
