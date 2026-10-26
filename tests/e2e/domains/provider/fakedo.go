// Package provider is a local fake of the DigitalOcean domain-records API
// for Plan 23 tests. It never contacts DigitalOcean.
package provider

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Record is a TXT record as the API reports it; Name is zone-relative.
type Record struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

// Server implements GET/POST/DELETE on /v2/domains/{zone}/records for one
// bearer token. Hooks let tests simulate lost replies and rate limits.
type Server struct {
	Token string
	Zone  string

	mu      sync.Mutex
	next    int64
	records map[int64]Record
	Calls   []string // "METHOD path" in order

	// BeforeCreate may fail a create with a status (0 continues); AfterCreate
	// runs after a create is stored, and may drop the reply.
	BeforeCreate func() int
	AfterCreate  func(Record) (dropReply bool)
}

func New(token, zone string) *Server {
	return &Server{Token: token, Zone: zone, next: 1000, records: map[int64]Record{}}
}

// Add inserts a record directly (a pre-existing or external record).
func (s *Server) Add(name, data string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	s.records[s.next] = Record{ID: s.next, Type: "TXT", Name: name, Data: data, TTL: 30}
	return s.next
}

// TXT returns the values at a fully qualified name.
func (s *Server) TXT(fqdn string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.records {
		if r.Type == "TXT" && s.fqdn(r.Name) == strings.TrimSuffix(strings.ToLower(fqdn), ".") {
			out = append(out, r.Data)
		}
	}
	return out
}

// Records lists all records.
func (s *Server) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Record{}
	for _, r := range s.records {
		out = append(out, r)
	}
	return out
}

func (s *Server) fqdn(name string) string {
	if name == "@" {
		return s.Zone
	}
	return name + "." + s.Zone
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.Calls = append(s.Calls, r.Method+" "+r.URL.Path)
	s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		http.Error(w, `{"id":"unauthorized","message":"Unable to authenticate you."}`, http.StatusUnauthorized)
		return
	}
	prefix := "/v2/domains/" + s.Zone + "/records"
	rest, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok {
		http.Error(w, `{"id":"not_found","message":"The resource you were accessing could not be found."}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && rest == "":
		name, typ := r.URL.Query().Get("name"), r.URL.Query().Get("type")
		out := []Record{}
		for _, rec := range s.Records() {
			if (typ == "" || rec.Type == typ) && (name == "" || s.fqdn(rec.Name) == strings.ToLower(name)) {
				out = append(out, rec)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"domain_records": out, "links": map[string]any{}, "meta": map[string]int{"total": len(out)}})
	case r.Method == http.MethodPost && rest == "":
		if s.BeforeCreate != nil {
			if code := s.BeforeCreate(); code != 0 {
				if code == http.StatusTooManyRequests {
					w.Header().Set("Retry-After", "30")
				}
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`{"id":"too_many_requests","message":"API Rate limit exceeded."}`))
				return
			}
		}
		var in Record
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Type != "TXT" || in.Name == "" || in.Data == "" {
			http.Error(w, `{"id":"unprocessable_entity","message":"invalid record"}`, http.StatusUnprocessableEntity)
			return
		}
		s.mu.Lock()
		s.next++
		in.ID = s.next
		s.records[in.ID] = in
		s.mu.Unlock()
		if s.AfterCreate != nil && s.AfterCreate(in) {
			hj, ok := w.(http.Hijacker)
			if ok {
				if c, _, err := hj.Hijack(); err == nil {
					c.Close()
					return
				}
			}
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]Record{"domain_record": in})
	case r.Method == http.MethodDelete && strings.HasPrefix(rest, "/"):
		id, err := strconv.ParseInt(rest[1:], 10, 64)
		s.mu.Lock()
		_, found := s.records[id]
		delete(s.records, id)
		s.mu.Unlock()
		if err != nil || !found {
			http.Error(w, `{"id":"not_found","message":"The resource you were accessing could not be found."}`, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, `{"id":"not_found"}`, http.StatusNotFound)
	}
}
