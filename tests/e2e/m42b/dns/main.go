// Command dns is the Plan 42b Phase B lane's authoritative DNS fixture: it
// answers TXT queries from a JSON file (name to values), re-read on every
// query so the lane can publish verification records while it runs.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	dnsfixture "github.com/zeroauthy/zeroauthy/tests/e2e/domains/dns"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8076", "UDP address")
	records := flag.String("records", "", "JSON file: {\"name\": [\"value\"]}")
	flag.Parse()
	s := &dnsfixture.Server{A: [4]byte{127, 0, 0, 1}, TXT: func(name string) []string {
		var m map[string][]string
		raw, err := os.ReadFile(*records)
		if err != nil || json.Unmarshal(raw, &m) != nil {
			return nil
		}
		return m[strings.ToLower(strings.TrimSuffix(name, "."))]
	}}
	if err := s.Listen(*addr); err != nil {
		log.Fatal(err)
	}
	log.Printf("Plan42b DNS fixture on %s", s.Addr())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	s.Close()
}
