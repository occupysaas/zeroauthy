package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestExecutionConsole(t *testing.T) { storetest.ExecutionConsole(t, memory.New()) }

func TestExecutionConsoleTransaction(t *testing.T) {
	st := memory.New()
	ctx := context.Background()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "tx", Name: "tx"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Actions().CreateExecution(ctx, &store.Execution{TenantID: "tx", ID: "ex"}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(ctx, func(tx store.Store) error {
		page, err := tx.Actions().ListExecutions(ctx, "tx", store.ExecutionFilter{})
		if err == nil && len(page) != 1 {
			t.Fatalf("page=%+v", page)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionListTransactionIsolation(t *testing.T) {
	st := memory.New()
	ctx := context.Background()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "tx", Name: "tx"}); err != nil {
		t.Fatal(err)
	}
	written, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_ = st.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Actions().CreateExecution(ctx, &store.Execution{TenantID: "tx", ID: "uncommitted"}); err != nil {
				return err
			}
			close(written)
			<-release
			return errors.New("rollback")
		})
	}()
	<-written
	read := make(chan []store.Execution, 1)
	go func() { page, _ := st.Actions().ListExecutions(ctx, "tx", store.ExecutionFilter{}); read <- page }()
	select {
	case page := <-read:
		close(release)
		<-done
		t.Fatalf("read uncommitted executions: %+v", page)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	<-done
	if page := <-read; len(page) != 0 {
		t.Fatalf("rollback visible: %+v", page)
	}
}
