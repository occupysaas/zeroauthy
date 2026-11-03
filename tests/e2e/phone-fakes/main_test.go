package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFakesRecordAndFail(t *testing.T) {
	s := &server{}
	ts := httptest.NewServer(s.handler())
	defer ts.Close()
	post := func(path, body string) int {
		r, err := http.Post(ts.URL+path, "application/x-www-form-urlencoded", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if c := post("/2010-04-01/Accounts/AC1/Messages.json", "To=%2B14155550100&Body=x"); c != 201 {
		t.Fatal(c)
	}
	if c := post("/2010-04-01/Accounts/AC1/Calls.json", "To=%2B14155559999"); c != 400 {
		t.Fatal(c)
	}
	if c := post("/", "Action=Publish&PhoneNumber=%2B14155550100"); c != 200 {
		t.Fatal(c)
	}
	if len(s.recs) != 3 || s.recs[0].Kind != "twilio_message" || s.recs[1].Kind != "twilio_call" || s.recs[2].Kind != "sns_publish" {
		t.Fatalf("recs=%+v", s.recs)
	}
}
