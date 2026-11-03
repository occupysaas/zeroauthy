// Command phone-fakes is a local fake of Twilio Messages and Calls, SNS Publish
// and an SMS gateway for E2E runs. Every request is appended to a JSON-lines
// log (-log) and served from GET /_requests; DELETE /_requests clears it. A
// recipient ending in 9999 gets a provider "invalid number" error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type record struct {
	Time    string            `json:"time"`
	Kind    string            `json:"kind"` // twilio_message|twilio_call|sns_publish|gateway
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Auth    string            `json:"authorization,omitempty"`
	Form    map[string]string `json:"form,omitempty"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type server struct {
	mu   sync.Mutex
	log  *os.File
	recs []record
	seq  int
}

func (s *server) add(r record) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, r)
	s.seq++
	if s.log != nil {
		b, _ := json.Marshal(r)
		_, _ = s.log.Write(append(b, '\n'))
	}
	return s.seq
}

func flat(v url.Values) map[string]string {
	m := map[string]string{}
	for k := range v {
		m[k] = v.Get(k)
	}
	return m
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/_requests", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.Method == http.MethodDelete {
			s.recs = nil
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		out := s.recs
		if out == nil {
			out = []record{}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/2010-04-01/Accounts/", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		form, _ := url.ParseQuery(string(raw))
		kind := "twilio_message"
		if strings.HasSuffix(r.URL.Path, "/Calls.json") {
			kind = "twilio_call"
		}
		n := s.add(record{Time: now(), Kind: kind, Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Form: flat(form)})
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(form.Get("To"), "9999") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"code":21211,"message":"invalid To number","status":400}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"sid":"SMfake%06d","status":"queued"}`, n)
	})
	mux.HandleFunc("/gateway", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.add(record{Time: now(), Kind: "gateway", Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: string(raw),
			Headers: map[string]string{"Content-Type": r.Header.Get("Content-Type")}})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// SNS Publish: POST / with a form body.
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		form, _ := url.ParseQuery(string(raw))
		if r.Method != http.MethodPost || form.Get("Action") != "Publish" {
			http.NotFound(w, r)
			return
		}
		n := s.add(record{Time: now(), Kind: "sns_publish", Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Form: flat(form)})
		w.Header().Set("Content-Type", "text/xml")
		if strings.HasSuffix(form.Get("PhoneNumber"), "9999") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidParameter</Code><Message>Invalid parameter: PhoneNumber</Message></Error></ErrorResponse>`)
			return
		}
		fmt.Fprintf(w, `<PublishResponse><PublishResult><MessageId>snsfake-%06d</MessageId></PublishResult></PublishResponse>`, n)
	})
	return mux
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func main() {
	addr := flag.String("listen", "127.0.0.1:0", "listen address")
	logPath := flag.String("log", "", "JSON-lines request log path")
	flag.Parse()
	s := &server{}
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		s.log = f
	}
	srv := &http.Server{Addr: *addr, Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("phone-fakes listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
