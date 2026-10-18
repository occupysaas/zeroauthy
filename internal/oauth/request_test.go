// internal/oauth/request_test.go
package oauth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A repeated parameter is named on the error, so callers need not match
// its text.
func TestParseTokenRequestNamesRepeatedParam(t *testing.T) {
	for name, tc := range map[string]struct{ ct, body string }{
		"form": {"application/x-www-form-urlencoded", "client_id=a&client_id=b"},
		"json": {"application/json", `{"client_id":"a","client_id":"b"}`},
	} {
		r := httptest.NewRequest("POST", "/oauth/device/code", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.ct)
		_, oerr := parseTokenRequest(httptest.NewRecorder(), r)
		if oerr == nil || oerr.repeated != "client_id" {
			t.Errorf("%s: error = %+v, want repeated client_id", name, oerr)
		}
	}
}

func TestParseTokenRequest(t *testing.T) {
	cases := []struct {
		name, contentType, body string
		want                    map[string]string
		wantErr                 string
	}{
		{name: "form", contentType: "application/x-www-form-urlencoded", body: "grant_type=client_credentials&audience=https%3A%2F%2Fapi",
			want: map[string]string{"grant_type": "client_credentials", "audience": "https://api"}},
		// Review focus 4: media type parameters.
		{name: "form with charset", contentType: "application/x-www-form-urlencoded; charset=UTF-8", body: "grant_type=x",
			want: map[string]string{"grant_type": "x"}},
		{name: "json with charset", contentType: "application/json; charset=utf-8", body: `{"grant_type":"x","client_id":"c"}`,
			want: map[string]string{"grant_type": "x", "client_id": "c"}},
		{name: "json number and null", contentType: "application/json", body: `{"grant_type":"x","n":5,"skip":null}`,
			want: map[string]string{"grant_type": "x", "n": "5"}},
		{name: "json object value", contentType: "application/json", body: `{"grant_type":{"a":1}}`, wantErr: "invalid_request"},
		{name: "json malformed", contentType: "application/json", body: `{`, wantErr: "invalid_request"},
		{name: "json trailing data", contentType: "application/json", body: `{"grant_type":"x"} {"grant_type":"y"}`, wantErr: "invalid_request"},
		{name: "json trailing garbage", contentType: "application/json", body: `{"grant_type":"x"}x`, wantErr: "invalid_request"},
		{name: "json duplicate key", contentType: "application/json", body: `{"grant_type":"x","grant_type":"y"}`, wantErr: "invalid_request"},
		{name: "json duplicate null key", contentType: "application/json", body: `{"a":null,"a":"y","grant_type":"x"}`, wantErr: "invalid_request"},
		{name: "json not an object", contentType: "application/json", body: `["a"]`, wantErr: "invalid_request"},
		{name: "json trailing whitespace ok", contentType: "application/json", body: "{\"grant_type\":\"x\"}\n",
			want: map[string]string{"grant_type": "x"}},
		{name: "repeated param", contentType: "application/x-www-form-urlencoded", body: "grant_type=a&grant_type=b", wantErr: "invalid_request"},
		{name: "unsupported type", contentType: "text/plain", body: "grant_type=x", wantErr: "invalid_request"},
		{name: "missing type", contentType: "", body: "grant_type=x", wantErr: "invalid_request"},
		{name: "too large", contentType: "application/x-www-form-urlencoded", body: "grant_type=" + strings.Repeat("a", maxTokenRequestBytes), wantErr: "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			form, oerr := parseTokenRequest(httptest.NewRecorder(), req)
			if tc.wantErr != "" {
				if oerr == nil || oerr.Code != tc.wantErr || oerr.Status != 400 {
					t.Fatalf("err = %+v, want %s", oerr, tc.wantErr)
				}
				return
			}
			if oerr != nil {
				t.Fatalf("unexpected error %+v", oerr)
			}
			if len(form) != len(tc.want) {
				t.Fatalf("form = %v, want %v", form, tc.want)
			}
			for k, v := range tc.want {
				if form.Get(k) != v {
					t.Errorf("%s = %q, want %q", k, form.Get(k), v)
				}
			}
		})
	}
}

func TestQueryParametersAreIgnored(t *testing.T) {
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token?client_secret=leak", strings.NewReader("grant_type=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form, oerr := parseTokenRequest(httptest.NewRecorder(), req)
	if oerr != nil || form.Has("client_secret") {
		t.Fatalf("query parameters must not be read as body parameters: %v %+v", form, oerr)
	}
}
