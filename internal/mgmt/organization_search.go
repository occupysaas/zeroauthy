package mgmt

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/zeroauthy/zeroauthy/internal/orgsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) SearchOrganizations(w http.ResponseWriter, r *http.Request) {
	if !h.orgIIAvailable(w, r) {
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		Fail(w, badQuery("invalid search query"))
		return
	}
	for k, vs := range values {
		if !slices.Contains([]string{"q", "parser", "sort", "take", "from"}, k) || len(vs) != 1 || vs[0] == "null" {
			Fail(w, badQuery("unsupported or repeated search parameter"))
			return
		}
	}
	parser := values.Get("parser")
	if values.Has("parser") && parser == "" {
		Fail(w, badQuery("invalid search parser"))
		return
	}
	q, err := orgsearch.Parse(values.Get("q"), parser)
	if err != nil {
		Fail(w, badQuery("invalid organization filter"))
		return
	}
	p := store.OrganizationSearchPage{Sort: values.Get("sort")}
	if values.Has("sort") && p.Sort == "" {
		Fail(w, badQuery("invalid search sort"))
		return
	}
	if values.Has("take") {
		p.Take, err = strconv.Atoi(values.Get("take"))
		if err != nil || p.Take < 1 || p.Take > 100 {
			Fail(w, badQuery("take must be an integer from 1 to 100"))
			return
		}
	}
	p, err = orgsearch.Page(p)
	if err != nil {
		Fail(w, badQuery("invalid search page"))
		return
	}
	if values.Has("from") {
		p, err = decodeOrganizationSearchCursor(h.Wrapper, values.Get("from"), resolved(r).ID, parser, q, p)
		if err != nil {
			Fail(w, badQuery("invalid search cursor"))
			return
		}
	}
	res, err := h.Store.OrganizationsII().Search(r.Context(), resolved(r).ID, q, p)
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	items := make([]map[string]any, 0, len(res.Items))
	for _, o := range res.Items {
		items = append(items, orgView(o))
	}
	out := map[string]any{"organizations": items}
	if res.Next != "" && len(res.Items) > 0 {
		last := res.Items[len(res.Items)-1]
		p.LastValue, p.LastID = orgsearch.SortValue(last, p.Sort), last.ID
		next, err := encodeOrganizationSearchCursor(h.Wrapper, resolved(r).ID, parser, q, p)
		if err != nil {
			h.orgIIError(w, r, err)
			return
		}
		out["next"] = next
	}
	writeJSON(w, http.StatusOK, out)
}
