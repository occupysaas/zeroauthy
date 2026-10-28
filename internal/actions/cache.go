package actions

import (
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
)

// cacheEntry is one api.cache record.
type cacheEntry struct {
	value   string
	expires time.Time
	seq     uint64 // insertion order, the eviction tie-break
}

// cacheRecord is a record as the runner sees it (expires_at in ms).
type cacheRecord struct {
	Value     string `json:"value"`
	ExpiresAt int64  `json:"expires_at"`
}

// actionCache is the in-memory api.cache of one tenant and trigger (spec
// §6): at most 20 entries and 8192 bytes of keys and values; records expire
// and the soonest-expiring (then oldest) are evicted first. It is local to
// this server node and promises no consistency, as on Auth0.
type actionCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	seq     uint64
}

func newActionCache() *actionCache { return &actionCache{entries: map[string]*cacheEntry{}} }

func cacheLimit(name string) int { return actionsrules.Inventory().Limits[name] }

// snapshot drops expired records and returns the rest.
func (c *actionCache) snapshot(now time.Time) map[string]cacheRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]cacheRecord, len(c.entries))
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, k)
			continue
		}
		out[k] = cacheRecord{Value: e.value, ExpiresAt: e.expires.UnixMilli()}
	}
	return out
}

// cacheExpiry is the earlier of ttl and expiresAt (both in ms, 0 = unset),
// defaulting to 15 minutes and capped at 24 hours.
func cacheExpiry(now time.Time, ttl, expiresAt int64) time.Time {
	def := time.Duration(cacheLimit("cache_default_ttl_seconds")) * time.Second
	maxTTL := time.Duration(cacheLimit("cache_max_ttl_seconds")) * time.Second
	life := def
	if ttl > 0 {
		life = time.Duration(min(ttl, int64(maxTTL/time.Millisecond))) * time.Millisecond
	}
	exp := now.Add(min(life, maxTTL))
	if expiresAt > 0 {
		if at := time.UnixMilli(expiresAt); at.Before(exp) {
			exp = at
		}
	}
	return exp
}

// apply runs one Action's validated cache operations.
func (c *actionCache) apply(now time.Time, ops []cacheOp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, op := range ops {
		if op.delete {
			delete(c.entries, op.key)
			continue
		}
		exp := cacheExpiry(now, op.ttl, op.expiresAt)
		if !now.Before(exp) {
			delete(c.entries, op.key)
			continue
		}
		c.seq++
		c.entries[op.key] = &cacheEntry{value: op.value, expires: exp, seq: c.seq}
		c.evict(now)
	}
}

// evict drops expired records, then the soonest-expiring until the entry
// and size limits hold.
func (c *actionCache) evict(now time.Time) {
	maxEntries, maxBytes := cacheLimit("cache_entries_max"), cacheLimit("cache_total_bytes_max")
	size := 0
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, k)
			continue
		}
		size += len(k) + len(e.value)
	}
	for len(c.entries) > maxEntries || size > maxBytes {
		var victim string
		var v *cacheEntry
		for k, e := range c.entries {
			if v == nil || e.expires.Before(v.expires) || e.expires.Equal(v.expires) && e.seq < v.seq {
				victim, v = k, e
			}
		}
		size -= len(victim) + len(v.value)
		delete(c.entries, victim)
	}
}

// caches holds every tenant's and trigger's cache on this node.
type caches struct {
	mu sync.Mutex
	m  map[string]*actionCache
}

func (cs *caches) get(tenantID, trigger string) *actionCache {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.m == nil {
		cs.m = map[string]*actionCache{}
	}
	k := tenantID + "\x00" + trigger
	c := cs.m[k]
	if c == nil {
		c = newActionCache()
		cs.m[k] = c
	}
	return c
}
