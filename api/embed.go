// Package api embeds zeroauthy's hand-written OpenAPI contracts.
package api

import _ "embed"

//go:embed authentication.yaml
var AuthenticationYAML []byte

//go:embed management.yaml
var ManagementYAML []byte
