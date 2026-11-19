package grpcstore

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	"github.com/zeroauthy/zeroauthy/internal/store"
	pb "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// refreshRead selects a wire method whose presence on the responding peer
// proves it can carry all II fields. Use the legacy method only when the
// original negotiation established a genuinely legacy peer.
func refreshRead[Q any, R result](c *Client, old, current func(context.Context, Q, ...grpc.CallOption) (R, error)) func(context.Context, Q, ...grpc.CallOption) (R, error) {
	return func(ctx context.Context, q Q, opts ...grpc.CallOption) (R, error) {
		var zero R
		if err := c.CheckRefreshTokensIISupport(ctx); err != nil {
			if errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
				return old(ctx, q, opts...)
			}
			return zero, c.refreshOperationError(err)
		}
		v, err := current(ctx, q, opts...)
		if err != nil {
			return zero, c.refreshOperationError(capabilityError(err, store.ErrRefreshTokensIIUnavailable))
		}
		// Keep value+domain error together (notably on a code replay).
		if e := errFromPB(v.GetError()); errors.Is(e, store.ErrRefreshTokensIIUnavailable) || errors.Is(e, store.ErrRefreshTokensIISupportLost) {
			return zero, c.refreshOperationError(e)
		}
		return v, nil
	}
}

// withRefreshII resolves a transaction exactly once. Check the current base
// capability and, under the tree lock, the transaction's own capability before
// the handler can read or mutate anything. The scoped service reuses the
// existing typed handler against that same resolved view.
func withRefreshII[Q interface{ GetTxId() string }, R any](s *Server, ctx context.Context, q Q, call func(*Server, context.Context, Q) (*R, error)) (*R, error) {
	txID := q.GetTxId()
	if txID != "" {
		if err := store.CheckRefreshTokensIISupport(ctx, s.st); err != nil {
			return nil, refreshBackendError(err)
		}
	}
	var result *R
	err := s.with(txID, func(st store.Store) error {
		if err := store.CheckRefreshTokensIISupport(ctx, st); err != nil {
			return refreshBackendError(err)
		}
		view := &Server{st: st, boundTxID: txID}
		var err error
		result, err = call(view, ctx, q)
		return err
	})
	return result, err
}

func (s *Server) RefreshIITenantsGet(ctx context.Context, q *pb.TenantsGetRequest) (*pb.TenantResult, error) {
	return withRefreshII(s, ctx, q, (*Server).TenantsGet)
}

func (s *Server) RefreshIITenantsGetByName(ctx context.Context, q *pb.TenantsGetRequest) (*pb.TenantResult, error) {
	return withRefreshII(s, ctx, q, (*Server).TenantsGetByName)
}

func (s *Server) RefreshIITenantsGetByDomain(ctx context.Context, q *pb.TenantsGetRequest) (*pb.TenantResult, error) {
	return withRefreshII(s, ctx, q, (*Server).TenantsGetByDomain)
}

func (s *Server) RefreshIITenantsList(ctx context.Context, q *pb.TenantsListRequest) (*pb.TenantList, error) {
	return withRefreshII(s, ctx, q, (*Server).TenantsList)
}

func (s *Server) RefreshIIClientsGet(ctx context.Context, q *pb.ScopedKey) (*pb.ClientResult, error) {
	return withRefreshII(s, ctx, q, (*Server).ClientsGet)
}

func (s *Server) RefreshIIClientsList(ctx context.Context, q *pb.TenantScope) (*pb.ClientList, error) {
	return withRefreshII(s, ctx, q, (*Server).ClientsList)
}

func (s *Server) RefreshIIClientsListPage(ctx context.Context, q *pb.ClientsListPageRequest) (*pb.ClientPage, error) {
	return withRefreshII(s, ctx, q, (*Server).ClientsListPage)
}

func (s *Server) RefreshIIResourceServersGet(ctx context.Context, q *pb.ScopedKey) (*pb.ResourceServerResult, error) {
	return withRefreshII(s, ctx, q, (*Server).ResourceServersGet)
}

func (s *Server) RefreshIIResourceServersGetByIdentifier(ctx context.Context, q *pb.ScopedKey) (*pb.ResourceServerResult, error) {
	return withRefreshII(s, ctx, q, (*Server).ResourceServersGetByIdentifier)
}

func (s *Server) RefreshIIResourceServersList(ctx context.Context, q *pb.TenantScope) (*pb.ResourceServerList, error) {
	return withRefreshII(s, ctx, q, (*Server).ResourceServersList)
}

func (s *Server) RefreshIIRBACSnapshot(ctx context.Context, q *pb.RBACRequest) (*pb.RBACResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).RBACSnapshot)
}

func (s *Server) RefreshIIOrganizationsGet(ctx context.Context, q *pb.OrganizationsRequest) (*pb.OrganizationsResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).OrganizationsGet)
}

func (s *Server) RefreshIIOrganizationsGetByName(ctx context.Context, q *pb.OrganizationsRequest) (*pb.OrganizationsResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).OrganizationsGetByName)
}

func (s *Server) RefreshIIOrganizationsList(ctx context.Context, q *pb.OrganizationsRequest) (*pb.OrganizationsResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).OrganizationsList)
}

func (s *Server) RefreshIIOrganizationsUserOrganizations(ctx context.Context, q *pb.OrganizationsRequest) (*pb.OrganizationsResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).OrganizationsUserOrganizations)
}

func (s *Server) RefreshIIOrganizationsIIGrantOrganizations(ctx context.Context, q *pb.OrganizationsIIRequest) (*pb.OrganizationsIIResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).OrganizationsIIGrantOrganizations)
}

func (s *Server) RefreshIIOrganizationsIIDiscoverOrganizations(ctx context.Context, q *pb.OrganizationsIIRequest) (*pb.OrganizationsIIResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).OrganizationsIIDiscoverOrganizations)
}

func (s *Server) RefreshIIOrganizationsIISearch(ctx context.Context, q *pb.OrganizationsIIRequest) (*pb.OrganizationsIIResponse, error) {
	return withRefreshII(s, ctx, q, (*Server).OrganizationsIISearch)
}

func (s *Server) RefreshIISessionsGet(ctx context.Context, q *pb.ScopedKey) (*pb.SessionResult, error) {
	return withRefreshII(s, ctx, q, (*Server).SessionsGet)
}

func (s *Server) RefreshIISessionsGetByTokenHash(ctx context.Context, q *pb.ScopedKey) (*pb.SessionResult, error) {
	return withRefreshII(s, ctx, q, (*Server).SessionsGetByTokenHash)
}

func (s *Server) RefreshIISessionsListByUser(ctx context.Context, q *pb.ScopedKey) (*pb.SessionList, error) {
	return withRefreshII(s, ctx, q, (*Server).SessionsListByUser)
}

func (s *Server) RefreshIIAuthTransactionsGet(ctx context.Context, q *pb.ScopedKey) (*pb.AuthTransactionResult, error) {
	return withRefreshII(s, ctx, q, (*Server).AuthTransactionsGet)
}

func (s *Server) RefreshIIAuthCodesGet(ctx context.Context, q *pb.ScopedKey) (*pb.AuthCodeResult, error) {
	return withRefreshII(s, ctx, q, (*Server).AuthCodesGet)
}

func (s *Server) RefreshIIAuthCodesConsume(ctx context.Context, q *pb.ConsumeRequest) (*pb.AuthCodeResult, error) {
	return withRefreshII(s, ctx, q, (*Server).AuthCodesConsume)
}

func (s *Server) RefreshIIRefreshTokensGet(ctx context.Context, q *pb.ScopedKey) (*pb.RefreshTokenResult, error) {
	return withRefreshII(s, ctx, q, (*Server).RefreshTokensGet)
}

func (s *Server) RefreshIIRefreshTokensGetByTokenHash(ctx context.Context, q *pb.ScopedKey) (*pb.RefreshTokenResult, error) {
	return withRefreshII(s, ctx, q, (*Server).RefreshTokensGetByTokenHash)
}

func (s *Server) RefreshIIRefreshTokensListByUser(ctx context.Context, q *pb.ScopedKey) (*pb.RefreshTokenList, error) {
	return withRefreshII(s, ctx, q, (*Server).RefreshTokensListByUser)
}
