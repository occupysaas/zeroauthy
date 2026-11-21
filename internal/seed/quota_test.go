package seed

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
	"time"
)

func TestQuotaSeed(t *testing.T) {
	f, err := Parse([]byte(`tenants:
 - name: quota
   domains: [quota.example]
   settings:
     default_token_quota:
       clients: {client_credentials: {per_hour: 20}}
   clients:
     - client_id: machine
       app_type: spa
       token_quota: {client_credentials: {per_day: 30, enforce: false}}
   organizations:
     - name: business
       token_quota: {client_credentials: {per_hour: 10}}
`))
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	if err = Apply(context.Background(), st, f, time.Now, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(t.Context(), "quota")
	c, _ := st.Clients().Get(t.Context(), tn.ID, "machine")
	org, _ := st.Organizations().GetByName(t.Context(), tn.ID, "business")
	if tn.DefaultTokenQuota == nil || tn.DefaultTokenQuota.Clients.PerHour != 20 || c.TokenQuota == nil || c.TokenQuota.Enforce || c.TokenQuota.PerDay != 30 || org.TokenQuota == nil || !org.TokenQuota.Enforce {
		t.Fatal("seed quota lost")
	}
}
