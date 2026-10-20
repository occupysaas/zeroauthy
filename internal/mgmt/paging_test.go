package mgmt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestPage(t *testing.T) {
	for _, tc := range []struct {
		query         string
		page, perPage int
		totals        bool
	}{
		{"", 0, DefaultPerPage, false},
		{"page=2&per_page=10", 2, 10, false},
		{"per_page=100&include_totals=true", 0, 100, true},
		{"per_page=1&include_totals=false", 0, 1, false},
		{"page=&per_page=", 0, DefaultPerPage, false},
	} {
		r := httptest.NewRequest("GET", "/api/v2/clients?"+tc.query, nil)
		page, perPage, totals, err := Page(r)
		if err != nil || page != tc.page || perPage != tc.perPage || totals != tc.totals {
			t.Errorf("%q: %d %d %v %v", tc.query, page, perPage, totals, err)
		}
	}
	// M6: per_page at most 100; anything else malformed is the same error.
	for _, q := range []string{"per_page=101", "per_page=0", "per_page=-1", "per_page=x", "page=-1", "page=1.5", "include_totals=yes",
		"page=2147483648", "page=9223372036854775807", "page=99999999999999999999"} {
		r := httptest.NewRequest("GET", "/api/v2/clients?"+q, nil)
		_, _, _, err := Page(r)
		e, ok := err.(*Error)
		if !ok || e.Status != http.StatusBadRequest || e.Code != "invalid_query_string" {
			t.Errorf("%q: err = %#v", q, err)
		}
	}
}

func TestFields(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?fields=name,client_id&include_fields=false", nil)
	f, inc, err := Fields(r)
	if err != nil || !slices.Equal(f, []string{"name", "client_id"}) || inc {
		t.Errorf("fields = %v %v %v", f, inc, err)
	}
	r = httptest.NewRequest("GET", "/x", nil)
	if f, inc, err := Fields(r); err != nil || f != nil || !inc {
		t.Errorf("none = %v %v %v", f, inc, err)
	}
	r = httptest.NewRequest("GET", "/x?fields=name&include_fields=maybe", nil)
	if _, _, err := Fields(r); err == nil {
		t.Error("bad include_fields: err nil")
	}
}

type sample struct {
	ClientID string `json:"client_id"`
	Name     string `json:"name"`
	Tenant   string `json:"tenant"`
	AppType  string `json:"app_type,omitempty"`
}

// M7: fields=name returns name and tenant; include_fields=false leaves the
// listed fields out. tenant is always there.
func TestProject(t *testing.T) {
	v := sample{ClientID: "c1", Name: "App", Tenant: "acme", AppType: "spa"}
	got := Project(v, []string{"name"}, true)
	if len(got) != 2 || got["name"] != "App" || got["tenant"] != "acme" {
		t.Errorf("include = %v", got)
	}
	got = Project(v, []string{"name", "tenant"}, false)
	if len(got) != 3 || got["client_id"] != "c1" || got["app_type"] != "spa" || got["tenant"] != "acme" {
		t.Errorf("exclude = %v", got)
	}
	got = Project(v, nil, true)
	if len(got) != 4 {
		t.Errorf("all = %v", got)
	}
	got = Project(&v, []string{"nope"}, true)
	if len(got) != 1 || got["tenant"] != "acme" {
		t.Errorf("unknown field = %v", got)
	}
}

// D-0041: APIs keep no member when fields names none of them.
func TestProjectKeeping(t *testing.T) {
	v := sample{ClientID: "c1", Name: "App", Tenant: "acme"}
	if got := ProjectKeeping(v, []string{"name"}, true, nil); len(got) != 1 || got["name"] != "App" {
		t.Errorf("include = %v", got)
	}
	if got := ProjectKeeping(v, []string{"nope"}, true, nil); len(got) != 0 {
		t.Errorf("unknown field = %v", got)
	}
	if got := ProjectKeeping(v, []string{"name", "tenant"}, false, nil); len(got) != 1 || got["client_id"] != "c1" {
		t.Errorf("exclude = %v", got)
	}
	if got := ProjectKeeping(v, []string{"name"}, true, []string{"client_id"}); len(got) != 2 || got["client_id"] != "c1" {
		t.Errorf("always = %v", got)
	}
}

// M6: a bare array without include_totals; {<plural>, start, limit, total}
// with it.
func TestWriteList(t *testing.T) {
	items := []any{"a", "b", "c", "d", "e"}
	rec := httptest.NewRecorder()
	WriteList(rec, "clients", items, 1, 2, false)
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `["c","d"]` {
		t.Errorf("bare: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	WriteList(rec, "clients", items, 2, 2, true)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if l, _ := body["clients"].([]any); len(l) != 1 || l[0] != "e" || body["start"] != float64(4) || body["limit"] != float64(2) || body["total"] != float64(5) {
		t.Errorf("totals: %s", rec.Body)
	}
	rec = httptest.NewRecorder()
	WriteList(rec, "clients", items, 9, 2, false)
	if strings.TrimSpace(rec.Body.String()) != `[]` {
		t.Errorf("past the end: %s", rec.Body)
	}
}

// A huge page never overflows the reported start or the slice bounds.
func TestWriteListHugePage(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteList(rec, "clients", []any{"a"}, MaxPage, MaxPerPage, true)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if l, _ := body["clients"].([]any); len(l) != 0 || body["start"] != float64(MaxPage)*MaxPerPage || body["total"] != float64(1) {
		t.Errorf("huge page: %s", rec.Body)
	}
}

// WritePage writes a page the store cut, with the total it counted.
func TestWritePage(t *testing.T) {
	rec := httptest.NewRecorder()
	WritePage[string](rec, "clients", nil, 3, 2, 7, false)
	if strings.TrimSpace(rec.Body.String()) != `[]` {
		t.Errorf("bare: %s", rec.Body)
	}
	rec = httptest.NewRecorder()
	WritePage(rec, "clients", []string{"g"}, 3, 2, 7, true)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if l, _ := body["clients"].([]any); len(l) != 1 || body["start"] != float64(6) || body["limit"] != float64(2) || body["total"] != float64(7) {
		t.Errorf("totals: %s", rec.Body)
	}
}
