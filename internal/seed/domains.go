package seed

import (
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"go.yaml.in/yaml/v3"
)

// decodeDomainAliases keeps the existing []string Go API while accepting the
// YAML object form. The normal strict decoder still checks all other fields.
func decodeDomainAliases(data []byte) ([]byte, []map[string]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	if len(doc.Content) == 0 {
		return data, nil, nil
	}
	root := doc.Content[0]
	var overrides []map[string]string
	if root.Kind != yaml.MappingNode {
		return data, nil, nil
	}
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "tenants" {
			continue
		}
		tenants := root.Content[i+1]
		if tenants.Kind != yaml.SequenceNode {
			return data, nil, nil
		}
		overrides = make([]map[string]string, len(tenants.Content))
		for ti, tn := range tenants.Content {
			if tn.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j < len(tn.Content); j += 2 {
				if tn.Content[j].Value != "domains" {
					continue
				}
				domains := tn.Content[j+1]
				if domains.Kind != yaml.SequenceNode {
					continue
				}
				for _, d := range domains.Content {
					if d.Kind != yaml.MappingNode {
						continue
					}
					host, rp := "", ""
					seen := map[string]bool{}
					for k := 0; k < len(d.Content); k += 2 {
						key, val := d.Content[k].Value, d.Content[k+1]
						if seen[key] {
							return nil, nil, fmt.Errorf("duplicate domain property %q", key)
						}
						seen[key] = true
						switch key {
						case "host":
							if val.Tag != "!!str" {
								return nil, nil, fmt.Errorf("domain host must be a string")
							}
							host = val.Value
						case "relying_party_identifier":
							if val.Tag == "!!null" {
								continue
							}
							if val.Tag != "!!str" || val.Value == "" {
								return nil, nil, fmt.Errorf("domain relying_party_identifier must be a hostname or null")
							}
							var err error
							rp, err = hostname.NormalizeDNSName(val.Value)
							if err != nil {
								return nil, nil, err
							}
						default:
							return nil, nil, fmt.Errorf("unknown domain property %q", key)
						}
					}
					name, err := hostname.NormalizeOperatorHost(host)
					if err != nil {
						return nil, nil, err
					}
					if rp != "" {
						if overrides[ti] == nil {
							overrides[ti] = map[string]string{}
						}
						overrides[ti][name] = rp
					}
					*d = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}
				}
			}
		}
	}
	if overrides == nil {
		return data, nil, nil
	}
	normalized, err := yaml.Marshal(&doc)
	return normalized, overrides, err
}
