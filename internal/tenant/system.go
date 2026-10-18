package tenant

// SystemName is the reserved name of the tenant zeroauthy runs for itself:
// its users are the console operators. No other tenant may use the name.
const SystemName = "system"

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
