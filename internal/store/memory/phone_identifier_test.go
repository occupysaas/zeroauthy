package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestPhoneUniqueOnWriteAfterEnable(t *testing.T) {
	st := memory.New()
	ctx := context.Background()
	c := &store.Connection{TenantID: "t", ID: "c", Name: "db", Strategy: "auth0", Extra: map[string]any{"attributes": map[string]any{"phone_number": map[string]any{"identifier": map[string]any{"active": true}}}}}
	if err := st.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []string{"a", "b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- st.Users().Create(ctx, &store.User{TenantID: "t", UserID: id, PhoneNumber: "+1 (415) 555-0100", Identities: []store.Identity{{Provider: "auth0", Connection: "db", UserID: id}}})
		}()
	}
	wg.Wait()
	close(results)
	won, lost := 0, 0
	for err := range results {
		if err == nil {
			won++
		} else if errors.Is(err, store.ErrConflict) {
			lost++
		} else {
			t.Fatal(err)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("wins=%d conflicts=%d", won, lost)
	}
}
