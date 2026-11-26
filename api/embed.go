// Package api embeds zeroauthy's hand-written OpenAPI contracts.
package api

import _ "embed"

//go:embed authentication.yaml
var AuthenticationYAML []byte

//go:embed management.yaml
var ManagementYAML []byte

//go:embed scim.yaml
var SCIMYAML []byte

//go:embed myaccount.yaml
var MyAccountYAML []byte

//go:embed myorg.yaml
var MyOrgYAML []byte
