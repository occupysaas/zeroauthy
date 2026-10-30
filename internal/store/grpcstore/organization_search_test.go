package grpcstore

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

func TestOrganizationSearchParity(t *testing.T) {
	storetest.OrganizationSearchParity(t, func(t *testing.T) store.Store { return serve(t, memory.New()) })
}
func TestOrganizationSearchRawRPCValidation(t *testing.T) {
	s := NewServer(memory.New())
	tests := []*storev1.OrganizationsIIRequest{
		{SearchQuery: &storev1.OrganizationQueryMsg{Op: "eq", Field: "name); DROP TABLE organizations;--", Value: "x"}},
		{SearchQuery: &storev1.OrganizationQueryMsg{}, SearchPage: &storev1.OrganizationSearchPageMsg{Sort: "name;DELETE", Take: 1}},
	}
	deep := &storev1.OrganizationQueryMsg{Op: "eq", Field: "name", Value: "x"}
	for i := 0; i < 30; i++ {
		deep = &storev1.OrganizationQueryMsg{Op: "and", Left: deep, Right: &storev1.OrganizationQueryMsg{Op: "eq", Field: "name", Value: "x"}}
	}
	tests = append(tests, &storev1.OrganizationsIIRequest{SearchQuery: deep, SearchPage: &storev1.OrganizationSearchPageMsg{Take: 1}})
	for _, q := range tests {
		out, e := s.OrganizationsIISearch(context.Background(), q)
		if e != nil || !errors.Is(errFromPB(out.Error), store.ErrInvalid) {
			t.Fatalf("raw invalid AST: %v %v", out, e)
		}
	}
}
