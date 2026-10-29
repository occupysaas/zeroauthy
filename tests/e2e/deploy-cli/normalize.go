package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
)

type Domains struct{ Source, Target string }
type Difference struct {
	Resource string `json:"resource"`
	Path     string `json:"path"`
	Reason   string `json:"reason"`
}
type ResourceCount struct {
	Resource string `json:"resource"`
	Source   int    `json:"source"`
	Target   int    `json:"target"`
}
type Report struct {
	Equivalent  bool            `json:"equivalent"`
	Counts      []ResourceCount `json:"counts"`
	Differences []Difference    `json:"differences"`
}

// Compare validates a strict field-preserving equivalence for all included
// families. Identifiers are mapped only through resource-specific identities.
func Compare(source, target deploymigration.Export, manifest Manifest, domains Domains) Report {
	r := Report{Equivalent: true}
	entries := map[string]ManifestResource{}
	for _, e := range manifest.Resources {
		entries[e.Name] = e
	}
	for name := range source.Resources {
		if _, ok := entries[name]; !ok {
			addDiff(&r, name, "$", "resource family is not classified by the manifest")
		}
	}
	for name := range target.Resources {
		if _, ok := entries[name]; !ok {
			addDiff(&r, name, "$", "resource family is not classified by the manifest")
		}
	}
	validateReferences(source, entries, &r)
	validateReferences(target, entries, &r)
	clientMap := clientIdentityMap(source.Resources["clients"], target.Resources["clients"], &r)
	apiMap := identityMap(source.Resources["resourceServers"], target.Resources["resourceServers"], "identifier", "id", &r, "resourceServers")
	connMap := identityMap(source.Resources["connections"], target.Resources["connections"], "name", "id", &r, "connections")
	compareFiles(source.Files, target.Files, &r)
	for name, entry := range entries {
		if entry.Status != "included" {
			continue
		}
		src, sn, se := decodeRows(source.Resources[name])
		dst, dn, de := decodeRows(target.Resources[name])
		r.Counts = append(r.Counts, ResourceCount{name, sn, dn})
		if se != nil || de != nil {
			addDiff(&r, name, "$", "resource is missing or invalid")
			continue
		}
		if len(src) == 0 || len(dst) == 0 {
			addDiff(&r, name, "$", "included resource family is empty")
			continue
		}
		if len(src) != len(dst) {
			addDiff(&r, name, "$", "resource counts differ")
			continue
		}
		if name == "clientGrants" {
			compareGrants(src, dst, clientMap, apiMap, &r)
			continue
		}
		if name == "connections" {
			mapObjectIDs(dst, connMap)
			mapEnabledClientRefs(dst, clientMap)
		}
		if name == "clients" {
			mapObjectIDs(dst, clientMap)
		}
		if name == "resourceServers" {
			mapObjectIDs(dst, apiMap)
		}
		compareRecords(name, src, dst, manifest, domains, &r)
	}
	sort.Slice(r.Counts, func(i, j int) bool { return r.Counts[i].Resource < r.Counts[j].Resource })
	r.Equivalent = len(r.Differences) == 0
	return r
}

type object = map[string]any

func decodeRows(raw json.RawMessage) ([]object, int, error) {
	if len(raw) == 0 {
		return nil, 0, fmt.Errorf("missing")
	}
	var rows []object
	if err := json.Unmarshal(raw, &rows); err == nil {
		return rows, len(rows), nil
	}
	var single object
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, 0, err
	}
	return []object{single}, 1, nil
}
func identityMap(srcRaw, dstRaw json.RawMessage, identity, id string, r *Report, resource string) map[string]string {
	s, _, e1 := decodeRows(srcRaw)
	d, _, e2 := decodeRows(dstRaw)
	out := map[string]string{}
	if e1 != nil || e2 != nil {
		return out
	}
	type itemIdentity struct{ natural, stable string }
	byNatural, byStable := map[string]itemIdentity{}, map[string]itemIdentity{}
	for _, v := range s {
		k, _ := v[identity].(string)
		old, _ := v[id].(string)
		if k == "" || byNatural[k].natural != "" {
			addDiff(r, resource, identity, "missing or duplicate natural identity")
			continue
		}
		entry := itemIdentity{natural: k, stable: old}
		byNatural[k] = entry
		if old != "" {
			if _, duplicate := byStable[old]; duplicate {
				addDiff(r, resource, id, "duplicate stable identity")
				continue
			}
			byStable[old] = entry
		}
	}
	seen := map[string]bool{}
	newIDs := map[string]bool{}
	for _, v := range d {
		k, _ := v[identity].(string)
		now, _ := v[id].(string)
		entry, ok := byStable[now]
		if !ok {
			entry, ok = byNatural[k]
		}
		if !ok || seen[entry.natural] || (now != "" && newIDs[now]) {
			addDiff(r, resource, identity, "target identity has no unique source match")
			continue
		}
		seen[entry.natural] = true
		if now != "" {
			newIDs[now] = true
			if entry.stable != "" {
				out[now] = entry.stable
			}
		}
	}
	return out
}

// clientIdentityMap follows deploy-cli's client matching order: stable
// client_id first, then name for imports where IDs were generated anew.
func clientIdentityMap(srcRaw, dstRaw json.RawMessage, r *Report) map[string]string {
	src, _, se := decodeRows(srcRaw)
	dst, _, de := decodeRows(dstRaw)
	out := map[string]string{}
	if se != nil || de != nil {
		return out
	}
	type identity struct{ key, sourceID string }
	byID, byName := map[string]identity{}, map[string]identity{}
	for _, o := range src {
		id, _ := o["client_id"].(string)
		name, _ := o["name"].(string)
		if id == "" && name == "" {
			addDiff(r, "clients", "client_id", "client has no supported identity")
			continue
		}
		sourceIdentity := identity{sourceID: id}
		if id != "" {
			sourceIdentity.key = "id:" + id
			if _, duplicate := byID[id]; duplicate {
				addDiff(r, "clients", "client_id", "duplicate stable identity")
				continue
			}
			byID[id] = sourceIdentity
		} else {
			sourceIdentity.key = "name:" + name
		}
		if name != "" {
			if _, duplicate := byName[name]; duplicate {
				addDiff(r, "clients", "name", "duplicate fallback identity")
			} else {
				byName[name] = sourceIdentity
			}
		}
	}
	seen := map[string]bool{}
	for _, o := range dst {
		id, _ := o["client_id"].(string)
		name, _ := o["name"].(string)
		matched, ok := byID[id]
		if !ok && name != "" {
			matched, ok = byName[name]
		}
		if !ok || seen[matched.key] {
			addDiff(r, "clients", "client_id", "target identity has no unique source match")
			continue
		}
		seen[matched.key] = true
		if id != "" && matched.sourceID != "" {
			out[id] = matched.sourceID
		}
	}
	return out
}
func mapObjectIDs(rows []object, m map[string]string) {
	for _, o := range rows {
		if id, ok := o["client_id"].(string); ok && m[id] != "" {
			o["client_id"] = m[id]
		}
		if id, ok := o["id"].(string); ok && m[id] != "" {
			o["id"] = m[id]
		}
	}
}
func mapEnabledClientRefs(rows []object, clients map[string]string) {
	for _, o := range rows {
		items, _ := o["enabled_clients"].([]any)
		for i, item := range items {
			if id, ok := item.(string); ok {
				if mapped := clients[id]; mapped != "" {
					items[i] = mapped
				}
				continue
			}
			entry, _ := item.(map[string]any)
			id, _ := entry["client_id"].(string)
			if mapped := clients[id]; mapped != "" {
				entry["client_id"] = mapped
			}
		}
	}
}

// Validate references independently on each side: two equally broken exports
// must never pass merely because their dangling IDs happen to be identical.
func validateReferences(export deploymigration.Export, entries map[string]ManifestResource, r *Report) {
	if entries["actionModules"].Status == "included" {
		modules := map[string]float64{}
		rows, _, _ := decodeRows(export.Resources["actionModules"])
		for _, row := range rows {
			name, _ := row["name"].(string)
			version, _ := row["latest_version_number"].(float64)
			if name == "" || modules[name] != 0 {
				addDiff(r, "actionModules", "name", "missing or duplicate module name")
			}
			modules[name] = version
			if secrets, ok := row["secrets"].([]any); ok {
				for _, secret := range secrets {
					if s, ok := secret.(map[string]any); ok && s["value"] != nil {
						addDiff(r, "actionModules", "secrets", "public export contains a secret value")
					}
				}
			}
		}
		actions, _, _ := decodeRows(export.Resources["actions"])
		for _, action := range actions {
			refs, _ := action["modules"].([]any)
			for _, ref := range refs {
				m, ok := ref.(map[string]any)
				if !ok {
					addDiff(r, "actions", "modules", "invalid module reference")
					continue
				}
				name, _ := m["module_name"].(string)
				version, _ := m["module_version_number"].(float64)
				if name == "" || version < 1 || version != math.Trunc(version) || modules[name] < version {
					addDiff(r, "actions", "modules", "module name/version is not present in export")
				}
				if m["module_id"] != nil || m["module_version_id"] != nil {
					addDiff(r, "actions", "modules", "export must use canonical module names and version numbers")
				}
			}
		}
	}
	if entries["actions"].Status == "included" {
		actions := map[string]bool{}
		rows, _, _ := decodeRows(export.Resources["actions"])
		for _, row := range rows {
			name, _ := row["name"].(string)
			if name == "" || actions[name] {
				addDiff(r, "actions", "name", "missing or duplicate Action name")
			}
			actions[name] = true
			if secrets, ok := row["secrets"].([]any); ok {
				for _, secret := range secrets {
					if s, ok := secret.(map[string]any); ok && s["value"] != nil {
						addDiff(r, "actions", "secrets", "public export contains a secret value")
					}
				}
			}
		}
		var triggers map[string][]object
		if json.Unmarshal(export.Resources["triggers"], &triggers) == nil {
			for _, bindings := range triggers {
				for _, binding := range bindings {
					name, _ := binding["action_name"].(string)
					if !actions[name] {
						addDiff(r, "triggers", "action_name", "binding Action is not present in export")
					}
				}
			}
		}
	}
	clients := map[string]bool{}
	rows, _, _ := decodeRows(export.Resources["clients"])
	for _, row := range rows {
		for _, field := range []string{"client_id", "name"} {
			if id, ok := row[field].(string); ok && id != "" {
				clients[id] = true
			}
		}
		if raw, exists := row["client_secret"]; exists {
			secret, ok := raw.(string)
			upper := strings.ToUpper(secret)
			if !ok || strings.Trim(secret, "*") == "" || strings.Contains(upper, "REDACTED") || strings.HasPrefix(upper, "YOUR_") || row["token_endpoint_auth_method"] == "none" {
				addDiff(r, "clients", "client_secret", "invalid secret placeholder or public-client credential")
			}
		}
	}
	apis := map[string]bool{}
	rows, _, _ = decodeRows(export.Resources["resourceServers"])
	for _, row := range rows {
		for _, field := range []string{"id", "identifier"} {
			if id, ok := row[field].(string); ok && id != "" {
				apis[id] = true
			}
		}
	}
	if entries["clientGrants"].Status == "included" {
		rows, _, _ = decodeRows(export.Resources["clientGrants"])
		for _, row := range rows {
			client, _ := row["client_id"].(string)
			audience, _ := row["audience"].(string)
			if !clients[client] {
				addDiff(r, "clientGrants", "client_id", "client reference is not present in export")
			}
			if !apis[audience] {
				addDiff(r, "clientGrants", "audience", "API reference is not present in export")
			}
		}
	}
	for _, resource := range []string{"connections", "databases"} {
		if entries[resource].Status != "included" {
			continue
		}
		rows, _, _ = decodeRows(export.Resources[resource])
		for _, row := range rows {
			refs, _ := row["enabled_clients"].([]any)
			for _, ref := range refs {
				id, _ := ref.(string)
				if obj, ok := ref.(map[string]any); ok {
					id, _ = obj["client_id"].(string)
				}
				if !clients[id] {
					addDiff(r, resource, "enabled_clients", "client reference is not present in export")
				}
			}
		}
	}
}

func compareFiles(source, target map[string][]byte, r *Report) {
	all := map[string]bool{}
	for k := range source {
		all[k] = true
	}
	for k := range target {
		all[k] = true
	}
	for k := range all {
		a, aok := source[k]
		b, bok := target[k]
		if !aok || !bok {
			addDiff(r, "files", k, "file is missing on one side")
			continue
		}
		if sha256.Sum256(a) != sha256.Sum256(b) {
			addDiff(r, "files", k, "file content hashes differ")
		}
	}
}
func compareGrants(src, dst []object, clients, apis map[string]string, r *Report) {
	key := func(o object) (string, bool) {
		client, _ := o["client_id"].(string)
		aud, _ := o["audience"].(string)
		if v := clients[client]; v != "" {
			client = v
		}
		if v := apis[aud]; v != "" {
			aud = v
		}
		return client + "\x00" + aud + "\x00" + fmt.Sprint(o["subject_type"]), client != "" && aud != ""
	}
	bys := map[string]object{}
	for _, o := range src {
		k, ok := key(o)
		if !ok || bys[k] != nil {
			addDiff(r, "clientGrants", "$", "grant identity is missing or duplicated")
		}
		bys[k] = o
	}
	for _, o := range dst {
		k, ok := key(o)
		s := bys[k]
		if !ok || s == nil {
			addDiff(r, "clientGrants", "$", "grant has no source identity")
			continue
		}
		normalized := cloneObject(o)
		if id, ok := normalized["client_id"].(string); ok && clients[id] != "" {
			normalized["client_id"] = clients[id]
		}
		if id, ok := normalized["audience"].(string); ok && apis[id] != "" {
			normalized["audience"] = apis[id]
		}
		delete(normalized, "id")
		delete(s, "id")
		sortNamedSets("clientGrants", s)
		sortNamedSets("clientGrants", normalized)
		if !reflect.DeepEqual(s, normalized) {
			addDiff(r, "clientGrants", "scopes", "grant fields or scopes differ")
		}
		delete(bys, k)
	}
	if len(bys) > 0 {
		addDiff(r, "clientGrants", "$", "source grants were dropped")
	}
}
func compareRecords(name string, src, dst []object, m Manifest, domains Domains, r *Report) {
	keyField := map[string]string{"clients": "name", "resourceServers": "identifier", "connections": "name", "databases": "name", "tenant": "name", "attackProtection": "name", "emailProvider": "name", "emailTemplates": "template", "branding": "$singleton", "prompts": "$singleton", "themes": "displayName", "customDomains": "domain", "roles": "name", "organizations": "name", "actions": "name", "actionModules": "name", "triggers": "$singleton"}[name]
	by := map[string]object{}
	for _, o := range src {
		k := naturalKey(o, keyField)
		if k == "" || by[k] != nil {
			addDiff(r, name, keyField, "missing or duplicate natural identity")
		}
		by[k] = o
	}
	for _, o := range dst {
		k := naturalKey(o, keyField)
		s := by[k]
		if s == nil {
			addDiff(r, name, keyField, "target resource has no source match")
			continue
		}
		delete(by, k)
		a, b := cloneObject(s), cloneObject(o)
		for _, n := range m.Normalizations {
			if n.Resource == name {
				switch n.Rule {
				case "read-only", "system-exclusion":
					removePath(a, n.Path)
					removePath(b, n.Path)
				case "tenant-url":
					normalizeDomainPath(b, n.Path, domains)
				}
			}
		}
		if name == "themes" {
			delete(a, "themeId")
			delete(b, "themeId")
		}
		if name == "clients" {
			delete(a, "client_id")
			delete(b, "client_id")
			if _, sourceHasSecret := a["client_secret"]; !sourceHasSecret {
				if _, targetHasSecret := b["client_secret"]; targetHasSecret {
					addDiff(r, name, "client_secret", "target export contains a secret placeholder or unexpected secret")
				}
			}
		}
		if name == "resourceServers" || name == "roles" || name == "organizations" || name == "actions" || name == "actionModules" {
			delete(a, "id")
			delete(b, "id")
		}
		if name == "connections" {
			delete(a, "id")
			delete(b, "id")
		}
		sortNamedSets(name, a)
		sortNamedSets(name, b)
		if !reflect.DeepEqual(a, b) {
			addDiff(r, name, "$", "resource fields differ")
		}
	}
	if len(by) > 0 {
		addDiff(r, name, "$", "source resources were dropped")
	}
}

// These resource-specific arrays represent sets. Every other array keeps
// its order, and sorting never removes duplicates or fields.
func sortNamedSets(resource string, row object) {
	fields := map[string][]string{
		"clientGrants": {"scope", "scopes"}, "clients": {"grant_types"},
		"organizations": {"connections", "client_grants"}, "roles": {"permissions"}, "resourceServers": {"scopes"}, "connections": {"enabled_clients"}, "databases": {"enabled_clients"},
	}
	for _, field := range fields[resource] {
		values, ok := row[field].([]any)
		if !ok {
			continue
		}
		sort.SliceStable(values, func(i, j int) bool {
			a, _ := json.Marshal(values[i])
			b, _ := json.Marshal(values[j])
			return string(a) < string(b)
		})
	}
}

func naturalKey(o object, f string) string {
	if f == "$singleton" {
		return "$singleton"
	}
	v, _ := o[f].(string)
	if v == "" && f == "name" {
		v, _ = o["client_id"].(string)
	}
	if v == "" && (f == "name" && (o["friendly_name"] != nil || o["breached_password_detection"] != nil)) {
		return "$singleton"
	}
	return v
}
func cloneObject(o object) object {
	b, _ := json.Marshal(o)
	var x object
	_ = json.Unmarshal(b, &x)
	return x
}
func removePath(o object, path string) {
	p := strings.Split(path, ".")
	cur := o
	for i, k := range p {
		if strings.HasSuffix(k, "[]") {
			k = strings.TrimSuffix(k, "[]")
		}
		if i == len(p)-1 {
			delete(cur, k)
			return
		}
		next, ok := cur[k].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
}
func normalizeDomainPath(o object, path string, d Domains) {
	if d.Source == "" || d.Target == "" {
		return
	}
	array := strings.HasSuffix(path, "[]")
	key := strings.TrimSuffix(path, "[]")
	if array {
		values, _ := o[key].([]any)
		for i, v := range values {
			if s, ok := v.(string); ok {
				values[i] = strings.ReplaceAll(s, d.Target, d.Source)
			}
		}
		return
	}
	if s, ok := o[key].(string); ok {
		o[key] = strings.ReplaceAll(s, d.Target, d.Source)
	}
}
func addDiff(r *Report, res, path, reason string) {
	r.Differences = append(r.Differences, Difference{res, path, reason})
}
