package eventstream

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"golang.org/x/net/http/httpguts"
)

func decode(raw json.RawMessage, out any) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, out) != nil {
		return store.ErrInvalid
	}
	return nil
}
func object(raw json.RawMessage, keys ...string) (map[string]json.RawMessage, error) {
	var out map[string]json.RawMessage
	if decode(raw, &out) != nil || out == nil {
		return nil, store.ErrInvalid
	}
	for k, v := range out {
		if !slices.Contains(keys, k) || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, store.ErrInvalid
		}
	}
	return out, nil
}

var accountRE = regexp.MustCompile(`^[0-9]{12}$`)
var eventTypes = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range eventrules.Types() {
		m[t.Name] = true
	}
	return m
}()

// Configure applies a validated patch to a detached stream. A destination,
// when supplied, replaces its public configuration; omitted credentials are
// retained only when the authorization method stays the same.
func Configure(s *store.EventStream, raw map[string]json.RawMessage, create, allowHTTP bool, private map[string]any) error {
	for k, v := range raw {
		if !slices.Contains([]string{"name", "subscriptions", "destination", "status"}, k) || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return store.ErrInvalid
		}
	}
	if v, ok := raw["name"]; ok {
		if decode(v, &s.Name) != nil {
			return store.ErrInvalid
		}
	} else if create {
		return store.ErrInvalid
	}
	if !utf8.ValidString(s.Name) || utf8.RuneCountInString(s.Name) < 1 || utf8.RuneCountInString(s.Name) > 128 {
		return store.ErrInvalid
	}
	if v, ok := raw["status"]; ok {
		if decode(v, &s.Status) != nil {
			return store.ErrInvalid
		}
	}
	if s.Status != "enabled" && s.Status != "disabled" {
		return store.ErrInvalid
	}
	if v, ok := raw["subscriptions"]; ok {
		var rows []json.RawMessage
		if decode(v, &rows) != nil || len(rows) == 0 {
			return store.ErrInvalid
		}
		s.Subscriptions = nil
		for _, row := range rows {
			obj, err := object(row, "event_type")
			var typ string
			if err != nil || decode(obj["event_type"], &typ) != nil || !eventTypes[typ] {
				return store.ErrInvalid
			}
			s.Subscriptions = append(s.Subscriptions, typ)
		}
	} else if create {
		return store.ErrInvalid
	}
	dest, hasDest := raw["destination"]
	if !hasDest {
		if create {
			return store.ErrInvalid
		}
		if s.DestType == "eventbridge" && s.Status != "disabled" {
			return store.ErrInvalid
		}
		return nil
	}
	obj, err := object(dest, "type", "configuration")
	var typ string
	if err != nil || decode(obj["type"], &typ) != nil || eventrules.Destination(typ).Type == "" || !create && typ != s.DestType {
		return store.ErrInvalid
	}
	s.DestType = typ
	if typ == "eventbridge" && !create {
		return store.ErrInvalid
	}
	schema := eventrules.Destination(typ)
	configKeys := []string{}
	for _, path := range schema.PublicFields {
		root, _, _ := strings.Cut(path, ".")
		if !slices.Contains(configKeys, root) && root != "aws_partner_event_source" {
			configKeys = append(configKeys, root)
		}
	}
	cfg, err := object(obj["configuration"], configKeys...)
	if err != nil {
		return err
	}
	switch typ {
	case "action":
		var id string
		if decode(cfg["action_id"], &id) != nil || id == "" {
			return store.ErrInvalid
		}
		s.Config = map[string]any{"action_id": id}
	case "eventbridge":
		var account, region string
		if decode(cfg["aws_account_id"], &account) != nil || !accountRE.MatchString(account) || decode(cfg["aws_region"], &region) != nil {
			return store.ErrInvalid
		}
		// Frozen public enum (api/management.yaml).
		if !slices.Contains(awsRegions, region) {
			return store.ErrInvalid
		}
		s.Config = map[string]any{"aws_account_id": account, "aws_region": region, "aws_partner_event_source": "aws.partner/zeroauthy/" + s.ID}
		s.Status = "disabled"
	case "webhook":
		var endpoint string
		if decode(cfg["webhook_endpoint"], &endpoint) != nil || !validEndpoint(endpoint, allowHTTP) {
			return store.ErrInvalid
		}
		auth, err := object(cfg["webhook_authorization"], "method", "username", "password", "token", "header_key", "header_value")
		if err != nil {
			return err
		}
		var method string
		if decode(auth["method"], &method) != nil {
			return store.ErrInvalid
		}
		oldAuth, _ := s.Config["webhook_authorization"].(map[string]any)
		oldMethod, _ := oldAuth["method"].(string)
		public := map[string]any{"method": method}
		allowed := []string{"method"}
		secretKey := ""
		switch method {
		case "basic":
			var username string
			if decode(auth["username"], &username) != nil || username == "" || utf8.RuneCountInString(username) > 128 || strings.Contains(username, ":") || !httpguts.ValidHeaderFieldValue(username) {
				return store.ErrInvalid
			}
			public["username"] = username
			secretKey = "password"
			allowed = append(allowed, "username", secretKey)
		case "bearer":
			secretKey = "token"
			allowed = append(allowed, secretKey)
		case "custom_header":
			var key string
			if decode(auth["header_key"], &key) != nil || !httpguts.ValidHeaderFieldName(key) || reservedHeader(key) {
				return store.ErrInvalid
			}
			public["header_key"] = key
			secretKey = "header_value"
			allowed = append(allowed, "header_key", secretKey)
		default:
			return store.ErrInvalid
		}
		for key := range auth {
			if !slices.Contains(allowed, key) {
				return store.ErrInvalid
			}
		}
		secret, hasSecret := auth[secretKey]
		if create || method != oldMethod {
			clear(private)
			if !hasSecret {
				return store.ErrInvalid
			}
		}
		if hasSecret {
			var value string
			if decode(secret, &value) != nil || value == "" || (method != "basic" && !httpguts.ValidHeaderFieldValue(value)) {
				return store.ErrInvalid
			}
			private[secretKey] = value
		}
		if value, _ := private[secretKey].(string); value == "" {
			return store.ErrInvalid
		}
		s.Config = map[string]any{"webhook_endpoint": endpoint, "webhook_authorization": public}
	}
	return nil
}
func validEndpoint(text string, allowHTTP bool) bool {
	u, err := url.Parse(text)
	if err != nil || u.Opaque != "" || u.User != nil || u.Hostname() == "" || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || strings.ContainsAny(text, "\r\n\t ") {
		return false
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return false
	}
	return true
}
func reservedHeader(key string) bool {
	return slices.Contains([]string{"host", "content-length", "content-type", "connection", "transfer-encoding", "trailer", "te", "upgrade", "proxy-authorization", "proxy-connection"}, strings.ToLower(key))
}

var awsRegions = strings.Fields("af-south-1 ap-east-1 ap-east-2 ap-northeast-1 ap-northeast-2 ap-northeast-3 ap-south-1 ap-south-2 ap-southeast-1 ap-southeast-2 ap-southeast-3 ap-southeast-4 ap-southeast-5 ap-southeast-6 ap-southeast-7 ca-central-1 ca-west-1 eu-central-1 eu-central-2 eu-north-1 eu-south-1 eu-south-2 eu-west-1 eu-west-2 eu-west-3 il-central-1 me-central-1 me-south-1 mx-central-1 sa-east-1 us-gov-east-1 us-gov-west-1 us-east-1 us-east-2 us-west-1 us-west-2")
