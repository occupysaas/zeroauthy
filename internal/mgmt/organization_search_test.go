package mgmt_test

import (
	"bytes"
	"net/url"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
)

func TestOrganizationSearchCursorBinding(t *testing.T) {
	e := newOrgEnv(t)
	for _, name := range []string{"search-a", "search-b", "search-c"} {
		e.create(map[string]any{"name": name}, 201)
	}
	fn := e.h.SearchOrganizations
	first := e.obj("GET", "/search?take=1&sort=name", nil, fn, 200)
	next := first["next"].(string)
	// Reconstruct the server key wrapper, simulating a process restart.
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e.h.Wrapper = w
	rest := e.obj("GET", "/search?take=100&sort=name&from="+url.QueryEscape(next), nil, fn, 200)
	if len(rest["organizations"].([]any)) != 2 || rest["next"] != nil {
		t.Fatal(rest)
	}
	for _, query := range []string{"take=0", "take=101", "take=null", "sort=name:1", "parser=null", "parser=", "q=x&q=y", "unknown=x", "q=%zz", "q=a;b=c", "from=null", "sort=name&parser=scim&from=" + next, "sort=display_name&from=" + next, "sort=name&q=name:search-a&from=" + next, "sort=name&from=" + next[:len(next)-3] + "AAA"} {
		e.obj("GET", "/search?"+query, nil, fn, 400)
	}
	other := *e.tn
	other.ID = "other"
	e.do(&other, "GET", "/search?sort=name&from="+next, nil, fn, 400)
}
