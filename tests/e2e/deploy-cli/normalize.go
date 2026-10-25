package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
	by := map[string]string{}
	oldIDs := map[string]bool{}
	for _, v := range s {
		k, _ := v[identity].(string)
		old, _ := v[id].(string)
		if k == "" || old == "" || by[k] != "" || oldIDs[old] {
			addDiff(r, resource, identity, "missing or duplicate natural identity")
			continue
		}
		by[k] = old
		oldIDs[old] = true
	}
	seen := map[string]bool{}
	newIDs := map[string]bool{}
	for _, v := range d {
		k, _ := v[identity].(string)
		now, _ := v[id].(string)
		old := by[k]
		if old == "" || now == "" || seen[k] || newIDs[now] {
			addDiff(r, resource, identity, "target identity has no unique source match")
			continue
		}
		seen[k] = true
		newIDs[now] = true
		out[now] = old
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
	byID, byName := map[string]string{}, map[string]string{}
	for _, o := range src {
		id, _ := o["client_id"].(string)
		name, _ := o["name"].(string)
		if id == "" || byID[id] != "" {
			addDiff(r, "clients", "client_id", "missing or duplicate identity")
			continue
		}
		byID[id] = id
		if name != "" {
			if byName[name] != "" {
				addDiff(r, "clients", "name", "duplicate fallback identity")
			} else {
				byName[name] = id
			}
		}
	}
	seen := map[string]bool{}
	for _, o := range dst {
		id, _ := o["client_id"].(string)
		name, _ := o["name"].(string)
		old := byID[id]
		if old == "" && name != "" {
			old = byName[name]
		}
		if id == "" || old == "" || seen[old] {
			addDiff(r, "clients", "client_id", "target identity has no unique source match")
			continue
		}
		seen[old] = true
		out[id] = old
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
		for _, item := range items {
			entry, _ := item.(map[string]any)
			id, _ := entry["client_id"].(string)
			if mapped := clients[id]; mapped != "" {
				entry["client_id"] = mapped
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
	keyField := map[string]string{"clients": "name", "resourceServers": "identifier", "connections": "name", "databases": "name", "tenant": "name", "attackProtection": "name"}[name]
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
		if name == "clients" {
			delete(a, "client_id")
			delete(b, "client_id")
			if _, sourceHasSecret := a["client_secret"]; !sourceHasSecret {
				if _, targetHasSecret := b["client_secret"]; targetHasSecret {
					addDiff(r, name, "client_secret", "target export contains a secret placeholder or unexpected secret")
				}
			}
		}
		if name == "resourceServers" {
			delete(a, "id")
			delete(b, "id")
		}
		if name == "connections" {
			delete(a, "id")
			delete(b, "id")
		}
		if !reflect.DeepEqual(a, b) {
			addDiff(r, name, "$", "resource fields differ")
		}
	}
	if len(by) > 0 {
		addDiff(r, name, "$", "source resources were dropped")
	}
}
func naturalKey(o object, f string) string {
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
