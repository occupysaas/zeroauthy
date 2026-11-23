package adhub

import (
	"encoding/json"
	"strings"
)

// The wire protocol of auth0/ad-ldap-connector v8.0.5 (ws_validator.js; D-0160
// records every message with its source lines). Frames are JSON text
// messages {n, p}.

// Events.
const (
	evAuthenticate          = "authenticate"           // connector → hub, p {jwt}
	evAuthenticated         = "authenticated"          // hub → connector
	evAuthenticationFailure = "authentication_failure" // hub → connector; the connector exits
)

// Op is a request zeroauthy sends to a connector. Each carries {jwt}: an
// HS256 token signed with the connection's signing key whose claims hold the
// request id (pid) and the arguments.
type Op string

const (
	OpAuthenticateUser Op = "authenticate_user" // claims username, password, escaped
	OpSearchUsers      Op = "search_users"      // claims search, limit, escaped
	OpListGroups       Op = "list_groups"       // claims limit
	OpChangePassword   Op = "change_password"   // claims username, password, escaped
)

// replySuffix is the reply event of op: "{pid}" + suffix.
func (op Op) replySuffix() string {
	switch op {
	case OpAuthenticateUser:
		return "_result"
	case OpSearchUsers:
		return "_search_users_result"
	case OpListGroups:
		return "_list_groups_result"
	case OpChangePassword:
		return "_change_password_result"
	}
	return ""
}

func (op Op) valid() bool { return op.replySuffix() != "" }

type frame struct {
	N string          `json:"n"`
	P json.RawMessage `json:"p,omitempty"`
}

type tokenPayload struct {
	JWT string `json:"jwt"`
}

// ConnectorError is the serialized error of a reply (the connector's error
// classes in lib/errors: name and message).
type ConnectorError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

func (e *ConnectorError) Error() string {
	if e.Name != "" {
		return "connector: " + e.Name
	}
	return "connector: unexpected error"
}

// Reply is a connector's answer to a request.
type Reply struct {
	Err     *ConnectorError `json:"err,omitempty"`
	Profile json.RawMessage `json:"profile,omitempty"`
	Users   json.RawMessage `json:"users,omitempty"`
	Groups  json.RawMessage `json:"groups,omitempty"`
}

// splitReply splits a reply event into its pid and suffix. pids are hex, so
// the first underscore starts the suffix.
func splitReply(name string) (pid, suffix string, ok bool) {
	i := strings.IndexByte(name, '_')
	if i <= 0 {
		return "", "", false
	}
	return name[:i], name[i:], true
}
