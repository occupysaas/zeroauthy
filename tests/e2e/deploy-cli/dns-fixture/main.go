// Local authoritative proof fixture. The HTTP control plane only changes DNS
// answers; product readiness still requires the public verification API.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/zeroauthy/zeroauthy/tests/e2e/domains/dns"
)

func main() {
	var mu sync.RWMutex
	records := map[string]string{}
	s := &dns.Server{TXT: func(name string) []string {
		mu.RLock()
		defer mu.RUnlock()
		if v := records[name]; v != "" {
			return []string{v}
		}
		return nil
	}}
	if err := s.Listen("127.0.0.1:8063"); err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/proof", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			w.WriteHeader(405)
			return
		}
		var proof struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&proof) != nil || proof.Name == "" || proof.Value == "" {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		records[proof.Name] = proof.Value
		mu.Unlock()
		w.WriteHeader(204)
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	log.Fatal(http.ListenAndServe("127.0.0.1:8064", nil))
}
