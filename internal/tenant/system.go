package tenant

// SystemName is the reserved name of the tenant zeroauthy runs for itself:
// its users are the console operators. No other tenant may use the name.
const SystemName = "system"

// OperatorAudience is the API identifier of operator tokens, defined only
// in the system tenant. No other tenant may define an API with it.
const OperatorAudience = "urn:zeroauthy:management"

// SystemHost is the normalized host of the system tenant: systemHost
// (server.system_host) when set, otherwise system.<baseDomain>. It is ""
// when neither is set.
func SystemHost(baseDomain, systemHost string) string {
	switch {
	case systemHost != "":
		return NormalizeHost(systemHost)
	case baseDomain != "":
		return NormalizeHost(SystemName + "." + baseDomain)
	}
	return ""
}

// OperatorClaim is the access-token claim listing the tenants an operator
// manages (store.Operator.Tenants; "*" means all). Only the system tenant
// mints it, and only for OperatorAudience.
const OperatorClaim = "https://zeroauthy.dev/operator"
