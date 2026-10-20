package grpcstore

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// This file holds the repository RPCs. Each one decodes its request, runs
// the store call through Server.with (the base store or a held
// transaction), and encodes the result. Domain errors travel in the
// response; a failure to encode the server's own values is a real fault and
// returns a gRPC Internal status.

var _ storev1.StoreServiceServer = (*Server)(nil)

func encodeFault(err error) error { return status.Error(codes.Internal, err.Error()) }

// write decodes pb and runs call with the decoded value.
func write[P, T any](s *Server, txID string, pb P, dec func(P) (*T, error), call func(store.Store, *T) error) *storev1.Result {
	v, err := dec(pb)
	if err == nil && v == nil {
		err = errMissingValue
	}
	if err == nil {
		err = s.with(txID, func(st store.Store) error { return call(st, v) })
	}
	return &storev1.Result{Error: errToPB(err)}
}

// errMissingValue answers a write request that carries no value.
var errMissingValue = errors.New("grpcstore: the request has no value")

// exec runs a call that returns only an error.
func exec(s *Server, txID string, call func(store.Store) error) *storev1.Result {
	return &storev1.Result{Error: errToPB(s.with(txID, call))}
}

// one runs a call that returns one value and encodes it. The value is
// encoded even when the call fails (Consume returns both).
func one[T, P any](s *Server, txID string, call func(store.Store) (*T, error), enc func(*T) (P, error)) (P, *storev1.Error, error) {
	var v *T
	err := s.with(txID, func(st store.Store) (e error) {
		v, e = call(st)
		return e
	})
	pb, encErr := enc(v)
	if encErr != nil {
		var zero P
		return zero, nil, encodeFault(encErr)
	}
	return pb, errToPB(err), nil
}

// many runs a call that returns a list and encodes every element.
func many[T, P any](s *Server, txID string, call func(store.Store) ([]*T, error), enc func(*T) (P, error)) ([]P, *storev1.Error, error) {
	var vs []*T
	err := s.with(txID, func(st store.Store) (e error) {
		vs, e = call(st)
		return e
	})
	var pbs []P
	if vs != nil {
		pbs = make([]P, 0, len(vs))
	}
	for _, v := range vs {
		pb, encErr := enc(v)
		if encErr != nil {
			return nil, nil, encodeFault(encErr)
		}
		pbs = append(pbs, pb)
	}
	return pbs, errToPB(err), nil
}

// count runs a call that returns a count.
func count(s *Server, txID string, call func(store.Store) (int, error)) *storev1.CountResult {
	var n int
	err := s.with(txID, func(st store.Store) (e error) {
		n, e = call(st)
		return e
	})
	return &storev1.CountResult{Error: errToPB(err), Count: int64(n)}
}

// ---- tenants ----

func (s *Server) TenantsCreate(ctx context.Context, r *storev1.TenantWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, tenantFromPB, func(st store.Store, t *store.Tenant) error {
		return st.Tenants().Create(ctx, t)
	}), nil
}

func (s *Server) TenantsGet(ctx context.Context, r *storev1.TenantsGetRequest) (*storev1.TenantResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.Tenant, error) { return st.Tenants().Get(ctx, r.Key) }, tenantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.TenantResult{Error: e, Value: v}, nil
}

func (s *Server) TenantsGetByName(ctx context.Context, r *storev1.TenantsGetRequest) (*storev1.TenantResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.Tenant, error) { return st.Tenants().GetByName(ctx, r.Key) }, tenantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.TenantResult{Error: e, Value: v}, nil
}

func (s *Server) TenantsGetByDomain(ctx context.Context, r *storev1.TenantsGetRequest) (*storev1.TenantResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.Tenant, error) { return st.Tenants().GetByDomain(ctx, r.Key) }, tenantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.TenantResult{Error: e, Value: v}, nil
}

func (s *Server) TenantsUpdate(ctx context.Context, r *storev1.TenantWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, tenantFromPB, func(st store.Store, t *store.Tenant) error {
		return st.Tenants().Update(ctx, t)
	}), nil
}

func (s *Server) TenantsList(ctx context.Context, r *storev1.TenantsListRequest) (*storev1.TenantList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) ([]*store.Tenant, error) { return st.Tenants().List(ctx) }, tenantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.TenantList{Error: e, Values: vs}, nil
}

func (s *Server) TenantsDelete(ctx context.Context, r *storev1.TenantsGetRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.Tenants().Delete(ctx, r.Key) }), nil
}

// ---- clients ----

func (s *Server) ClientsCreate(ctx context.Context, r *storev1.ClientWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, clientFromPB, func(st store.Store, c *store.Client) error {
		return st.Clients().Create(ctx, c)
	}), nil
}

func (s *Server) ClientsGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.ClientResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.Client, error) { return st.Clients().Get(ctx, r.TenantId, r.Key) }, clientToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ClientResult{Error: e, Value: v}, nil
}

func (s *Server) ClientsUpdate(ctx context.Context, r *storev1.ClientWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, clientFromPB, func(st store.Store, c *store.Client) error {
		return st.Clients().Update(ctx, c)
	}), nil
}

func (s *Server) ClientsDelete(ctx context.Context, r *storev1.ScopedKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.Clients().Delete(ctx, r.TenantId, r.Key) }), nil
}

func (s *Server) ClientsList(ctx context.Context, r *storev1.TenantScope) (*storev1.ClientList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) (out []*store.Client, e error) {
		out, _, e = st.Clients().List(ctx, r.TenantId, store.ClientFilter{}, store.Page{})
		return out, e
	}, clientToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ClientList{Error: e, Values: vs}, nil
}

func (s *Server) ClientsListPage(ctx context.Context, r *storev1.ClientsListPageRequest) (*storev1.ClientPage, error) {
	var total int
	vs, e, err := many(s, r.TxId, func(st store.Store) (out []*store.Client, e error) {
		f := store.ClientFilter{AppTypes: r.AppTypes}
		if r.HasIsFirstParty {
			v := r.IsFirstParty
			f.IsFirstParty = &v
		}
		out, total, e = st.Clients().List(ctx, r.TenantId, f, store.Page{Offset: int(r.Offset), Limit: int(r.Limit)})
		return out, e
	}, clientToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ClientPage{Error: e, Values: vs, Total: int64(total)}, nil
}

// ---- resource servers ----

func (s *Server) ResourceServersCreate(ctx context.Context, r *storev1.ResourceServerWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, resourceServerFromPB, func(st store.Store, rs *store.ResourceServer) error {
		return st.ResourceServers().Create(ctx, rs)
	}), nil
}

func (s *Server) ResourceServersGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.ResourceServerResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.ResourceServer, error) {
		return st.ResourceServers().Get(ctx, r.TenantId, r.Key)
	}, resourceServerToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ResourceServerResult{Error: e, Value: v}, nil
}

func (s *Server) ResourceServersGetByIdentifier(ctx context.Context, r *storev1.ScopedKey) (*storev1.ResourceServerResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.ResourceServer, error) {
		return st.ResourceServers().GetByIdentifier(ctx, r.TenantId, r.Key)
	}, resourceServerToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ResourceServerResult{Error: e, Value: v}, nil
}

func (s *Server) ResourceServersUpdate(ctx context.Context, r *storev1.ResourceServerWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, resourceServerFromPB, func(st store.Store, rs *store.ResourceServer) error {
		return st.ResourceServers().Update(ctx, rs)
	}), nil
}

func (s *Server) ResourceServersDelete(ctx context.Context, r *storev1.ScopedKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.ResourceServers().Delete(ctx, r.TenantId, r.Key) }), nil
}

// ---- client grants ----

func (s *Server) ResourceServersList(ctx context.Context, r *storev1.TenantScope) (*storev1.ResourceServerList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) ([]*store.ResourceServer, error) {
		return st.ResourceServers().List(ctx, r.TenantId)
	}, resourceServerToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ResourceServerList{Error: e, Values: vs}, nil
}

func (s *Server) ClientGrantsCreate(ctx context.Context, r *storev1.ClientGrantWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, clientGrantFromPB, func(st store.Store, g *store.ClientGrant) error {
		return st.ClientGrants().Create(ctx, g)
	}), nil
}

func (s *Server) ClientGrantsFind(ctx context.Context, r *storev1.ClientGrantsFindRequest) (*storev1.ClientGrantResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.ClientGrant, error) {
		// Hosts older than Plan 9 send no subject_type: a client grant.
		subjectType := r.SubjectType
		if subjectType == "" {
			subjectType = store.SubjectTypeClient
		}
		return st.ClientGrants().Find(ctx, r.TenantId, r.ClientId, r.Audience, subjectType)
	}, clientGrantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ClientGrantResult{Error: e, Value: v}, nil
}

func (s *Server) ClientGrantsUpdate(ctx context.Context, r *storev1.ClientGrantWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, clientGrantFromPB, func(st store.Store, g *store.ClientGrant) error {
		return st.ClientGrants().Update(ctx, g)
	}), nil
}

func (s *Server) ClientGrantsList(ctx context.Context, r *storev1.ClientGrantsListRequest) (*storev1.ClientGrantList, error) {
	var total int
	vs, e, err := many(s, r.TxId, func(st store.Store) (out []*store.ClientGrant, e error) {
		out, total, e = st.ClientGrants().List(ctx, r.TenantId,
			store.ClientGrantFilter{ClientID: r.ClientId, Audience: r.Audience, SubjectType: r.SubjectType, AfterID: r.AfterId, ID: r.Id},
			store.Page{Offset: int(r.Offset), Limit: int(r.Limit)})
		return out, e
	}, clientGrantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ClientGrantList{Error: e, Values: vs, Total: int64(total)}, nil
}

func (s *Server) ClientGrantsDelete(ctx context.Context, r *storev1.ScopedKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.ClientGrants().Delete(ctx, r.TenantId, r.Key) }), nil
}

// ---- user grants ----

func (s *Server) UserGrantsFind(ctx context.Context, r *storev1.UserGrantsFindRequest) (*storev1.UserGrantResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.UserGrant, error) {
		return st.UserGrants().Find(ctx, r.TenantId, r.ClientId, r.UserId, r.Audience)
	}, userGrantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserGrantResult{Error: e, Value: v}, nil
}

func (s *Server) UserGrantsUpsert(ctx context.Context, r *storev1.UserGrantWrite) (*storev1.UserGrantResult, error) {
	g, err := userGrantFromPB(r.Value)
	if err == nil && g == nil {
		err = errMissingValue
	}
	if err != nil {
		return &storev1.UserGrantResult{Error: errToPB(err)}, nil
	}
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.UserGrant, error) {
		return st.UserGrants().Upsert(ctx, g)
	}, userGrantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserGrantResult{Error: e, Value: v}, nil
}

func (s *Server) UserGrantsList(ctx context.Context, r *storev1.UserGrantsListRequest) (*storev1.UserGrantList, error) {
	var total int
	vs, e, err := many(s, r.TxId, func(st store.Store) (out []*store.UserGrant, e error) {
		out, total, e = st.UserGrants().List(ctx, r.TenantId,
			store.UserGrantFilter{UserID: r.UserId, ClientID: r.ClientId, Audience: r.Audience},
			store.Page{Offset: int(r.Offset), Limit: int(r.Limit)})
		return out, e
	}, userGrantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserGrantList{Error: e, Values: vs, Total: int64(total)}, nil
}

func (s *Server) UserGrantsListByUser(ctx context.Context, r *storev1.ScopedKey) (*storev1.UserGrantList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) ([]*store.UserGrant, error) {
		return st.UserGrants().ListByUser(ctx, r.TenantId, r.Key)
	}, userGrantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserGrantList{Error: e, Values: vs}, nil
}

func (s *Server) UserGrantsListByAudience(ctx context.Context, r *storev1.ScopedKey) (*storev1.UserGrantList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) ([]*store.UserGrant, error) {
		return st.UserGrants().ListByAudience(ctx, r.TenantId, r.Key)
	}, userGrantToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserGrantList{Error: e, Values: vs}, nil
}

func (s *Server) UserGrantsDelete(ctx context.Context, r *storev1.ScopedKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.UserGrants().Delete(ctx, r.TenantId, r.Key) }), nil
}

func (s *Server) UserGrantsDeleteByUser(ctx context.Context, r *storev1.ScopedKey) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) { return st.UserGrants().DeleteByUser(ctx, r.TenantId, r.Key) }), nil
}

// ---- signing keys ----

func (s *Server) SigningKeysCreate(ctx context.Context, r *storev1.SigningKeyWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, signingKeyFromPB, func(st store.Store, k *store.SigningKey) error {
		return st.SigningKeys().Create(ctx, k)
	}), nil
}

func (s *Server) SigningKeysList(ctx context.Context, r *storev1.TenantScope) (*storev1.SigningKeyList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) ([]*store.SigningKey, error) {
		return st.SigningKeys().List(ctx, r.TenantId)
	}, signingKeyToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.SigningKeyList{Error: e, Values: vs}, nil
}

func (s *Server) SigningKeysRotate(ctx context.Context, r *storev1.SigningKeysRotateRequest) (*storev1.Result, error) {
	return write(s, r.TxId, r.Next, signingKeyFromPB, func(st store.Store, k *store.SigningKey) error {
		return st.SigningKeys().Rotate(ctx, r.TenantId, k)
	}), nil
}

// ---- connections ----

func (s *Server) ConnectionsCreate(ctx context.Context, r *storev1.ConnectionWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, connectionFromPB, func(st store.Store, c *store.Connection) error {
		return st.Connections().Create(ctx, c)
	}), nil
}

func (s *Server) ConnectionsGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.ConnectionResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.Connection, error) {
		return st.Connections().Get(ctx, r.TenantId, r.Key)
	}, connectionToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ConnectionResult{Error: e, Value: v}, nil
}

func (s *Server) ConnectionsGetByName(ctx context.Context, r *storev1.ScopedKey) (*storev1.ConnectionResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.Connection, error) {
		return st.Connections().GetByName(ctx, r.TenantId, r.Key)
	}, connectionToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ConnectionResult{Error: e, Value: v}, nil
}

func (s *Server) ConnectionsUpdate(ctx context.Context, r *storev1.ConnectionWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, connectionFromPB, func(st store.Store, c *store.Connection) error {
		return st.Connections().Update(ctx, c)
	}), nil
}

func (s *Server) ConnectionsList(ctx context.Context, r *storev1.TenantScope) (*storev1.ConnectionList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) (out []*store.Connection, e error) {
		out, _, e = st.Connections().List(ctx, r.TenantId, store.ConnectionFilter{}, store.Page{})
		return out, e
	}, connectionToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ConnectionList{Error: e, Values: vs}, nil
}

func (s *Server) ConnectionsListPage(ctx context.Context, r *storev1.ConnectionsListPageRequest) (*storev1.ConnectionPage, error) {
	var total int
	vs, e, err := many(s, r.TxId, func(st store.Store) (out []*store.Connection, e error) {
		out, total, e = st.Connections().List(ctx, r.TenantId,
			store.ConnectionFilter{Name: r.Name, Strategies: r.Strategies},
			store.Page{Offset: int(r.Offset), Limit: int(r.Limit)})
		return out, e
	}, connectionToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.ConnectionPage{Error: e, Values: vs, Total: int64(total)}, nil
}

func (s *Server) ConnectionsDelete(ctx context.Context, r *storev1.ScopedKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.Connections().Delete(ctx, r.TenantId, r.Key) }), nil
}

func (s *Server) PasswordHistoriesAdd(ctx context.Context, r *storev1.PasswordHistoryAdd) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.PasswordHistories().Add(ctx, r.TenantId, r.UserId, r.Hash, int(r.Keep))
	}), nil
}

func (s *Server) PasswordHistoriesList(ctx context.Context, r *storev1.ScopedKey) (*storev1.PasswordHistoryList, error) {
	var hs [][]byte
	err := s.with(r.TxId, func(st store.Store) (e error) {
		hs, e = st.PasswordHistories().List(ctx, r.TenantId, r.Key)
		return e
	})
	var fault *storev1.Error
	if err != nil {
		fault = errToPB(err)
		hs = nil
	}
	return &storev1.PasswordHistoryList{Error: fault, Values: hs}, nil
}

// ---- users ----

func (s *Server) UsersCreate(ctx context.Context, r *storev1.UserWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, userFromPB, func(st store.Store, u *store.User) error {
		return st.Users().Create(ctx, u)
	}), nil
}

func (s *Server) UsersGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.UserResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.User, error) { return st.Users().Get(ctx, r.TenantId, r.Key) }, userToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserResult{Error: e, Value: v}, nil
}

func (s *Server) UsersFindByLogin(ctx context.Context, r *storev1.UsersFindByLoginRequest) (*storev1.UserResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.User, error) {
		return st.Users().FindByLogin(ctx, r.TenantId, r.Connection, r.Login)
	}, userToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserResult{Error: e, Value: v}, nil
}

func (s *Server) UsersUpdate(ctx context.Context, r *storev1.UserWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, userFromPB, func(st store.Store, u *store.User) error {
		return st.Users().Update(ctx, u)
	}), nil
}

func (s *Server) UsersRecordLogin(ctx context.Context, r *storev1.UsersRecordLoginRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.Users().RecordLogin(ctx, r.TenantId, r.UserId, tsFromPB(r.At), r.Ip)
	}), nil
}

func (s *Server) UsersSetPasswordHash(ctx context.Context, r *storev1.UsersSetPasswordHashRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.Users().SetPasswordHash(ctx, r.TenantId, r.UserId, r.Connection, r.Hash, tsFromPB(r.At))
	}), nil
}

func (s *Server) UsersSetPasswordHashIfEmpty(ctx context.Context, r *storev1.UsersSetPasswordHashRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.Users().SetPasswordHashIfEmpty(ctx, r.TenantId, r.UserId, r.Connection, r.Hash, tsFromPB(r.At))
	}), nil
}

func (s *Server) UsersBumpVersion(ctx context.Context, r *storev1.ScopedKey) (*storev1.VersionResult, error) {
	var v int64
	err := s.with(r.TxId, func(st store.Store) (e error) {
		v, e = st.Users().BumpVersion(ctx, r.TenantId, r.Key)
		return e
	})
	return &storev1.VersionResult{Error: errToPB(err), Value: v}, nil
}

func (s *Server) UsersFindByEmail(ctx context.Context, r *storev1.UsersFindByEmailRequest) (*storev1.UserListResult, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) ([]*store.User, error) {
		return st.Users().FindByEmail(ctx, r.TenantId, r.Email)
	}, userToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserListResult{Error: e, Values: vs}, nil
}

func (s *Server) UsersList(ctx context.Context, r *storev1.UsersListRequest) (*storev1.UserListResult, error) {
	var total int
	vs, e, err := many(s, r.TxId, func(st store.Store) (out []*store.User, e error) {
		out, total, e = st.Users().List(ctx, r.TenantId, userQueryFromPB(r.Query),
			store.UserSort{Field: r.SortField, Desc: r.SortDesc}, store.Page{Offset: int(r.Offset), Limit: int(r.Limit)})
		return out, e
	}, userToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.UserListResult{Error: e, Values: vs, Total: int64(total)}, nil
}

func (s *Server) UsersDelete(ctx context.Context, r *storev1.ScopedKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.Users().Delete(ctx, r.TenantId, r.Key)
	}), nil
}

// ---- sessions ----

func (s *Server) SessionsCreate(ctx context.Context, r *storev1.SessionWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, sessionFromPB, func(st store.Store, ls *store.LoginSession) error {
		return st.Sessions().Create(ctx, ls)
	}), nil
}

func (s *Server) SessionsGetByTokenHash(ctx context.Context, r *storev1.ScopedKey) (*storev1.SessionResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.LoginSession, error) {
		return st.Sessions().GetByTokenHash(ctx, r.TenantId, r.Key)
	}, sessionToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.SessionResult{Error: e, Value: v}, nil
}

func (s *Server) SessionsGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.SessionResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.LoginSession, error) {
		return st.Sessions().Get(ctx, r.TenantId, r.Key)
	}, sessionToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.SessionResult{Error: e, Value: v}, nil
}

func (s *Server) SessionsListByUser(ctx context.Context, r *storev1.ScopedKey) (*storev1.SessionList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) ([]*store.LoginSession, error) {
		return st.Sessions().ListByUser(ctx, r.TenantId, r.Key)
	}, sessionToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.SessionList{Error: e, Values: vs}, nil
}

func (s *Server) SessionsTouch(ctx context.Context, r *storev1.TouchRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.Sessions().Touch(ctx, r.TenantId, r.Id, tsFromPB(r.At), tsFromPB(r.IdleExpiresAt), r.Ip, r.UserAgent)
	}), nil
}

func (s *Server) SessionsAddClient(ctx context.Context, r *storev1.SessionsAddClientRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.Sessions().AddClient(ctx, r.TenantId, r.Id, r.ClientId)
	}), nil
}

func (s *Server) SessionsDelete(ctx context.Context, r *storev1.ScopedKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.Sessions().Delete(ctx, r.TenantId, r.Key) }), nil
}

func (s *Server) SessionsDeleteByUser(ctx context.Context, r *storev1.ScopedKey) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) { return st.Sessions().DeleteByUser(ctx, r.TenantId, r.Key) }), nil
}

func (s *Server) SessionsDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) { return st.Sessions().DeleteExpired(ctx, tsFromPB(r.Before)) }), nil
}

// ---- auth transactions ----

func (s *Server) AuthTransactionsCreate(ctx context.Context, r *storev1.AuthTransactionWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, authTransactionFromPB, func(st store.Store, a *store.AuthTransaction) error {
		return st.AuthTransactions().Create(ctx, a)
	}), nil
}

func (s *Server) AuthTransactionsGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.AuthTransactionResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.AuthTransaction, error) {
		return st.AuthTransactions().Get(ctx, r.TenantId, r.Key)
	}, authTransactionToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.AuthTransactionResult{Error: e, Value: v}, nil
}

func (s *Server) AuthTransactionsDelete(ctx context.Context, r *storev1.ScopedKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.AuthTransactions().Delete(ctx, r.TenantId, r.Key) }), nil
}

func (s *Server) AuthTransactionsDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.AuthTransactions().DeleteExpired(ctx, tsFromPB(r.Before))
	}), nil
}

// ---- auth codes ----

func (s *Server) AuthCodesCreate(ctx context.Context, r *storev1.AuthCodeWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, authCodeFromPB, func(st store.Store, c *store.AuthCode) error {
		return st.AuthCodes().Create(ctx, c)
	}), nil
}

// AuthCodesConsume returns the code together with ErrAlreadyUsed on replay.
func (s *Server) AuthCodesConsume(ctx context.Context, r *storev1.ConsumeRequest) (*storev1.AuthCodeResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.AuthCode, error) {
		return st.AuthCodes().Consume(ctx, r.TenantId, r.Hash, tsFromPB(r.At))
	}, authCodeToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.AuthCodeResult{Error: e, Value: v}, nil
}

func (s *Server) AuthCodesGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.AuthCodeResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.AuthCode, error) {
		return st.AuthCodes().Get(ctx, r.TenantId, r.Key)
	}, authCodeToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.AuthCodeResult{Error: e, Value: v}, nil
}

func (s *Server) AuthCodesDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) { return st.AuthCodes().DeleteExpired(ctx, tsFromPB(r.Before)) }), nil
}

// ---- pushed auth requests ----

func (s *Server) PushedAuthRequestsCreate(ctx context.Context, r *storev1.PushedAuthRequestWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, pushedAuthRequestFromPB, func(st store.Store, p *store.PushedAuthRequest) error {
		return st.PushedAuthRequests().Create(ctx, p)
	}), nil
}

// PushedAuthRequestsConsume returns the request together with ErrAlreadyUsed on reuse.
func (s *Server) PushedAuthRequestsConsume(ctx context.Context, r *storev1.ConsumeRequest) (*storev1.PushedAuthRequestResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.PushedAuthRequest, error) {
		return st.PushedAuthRequests().Consume(ctx, r.TenantId, r.Hash, tsFromPB(r.At))
	}, pushedAuthRequestToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.PushedAuthRequestResult{Error: e, Value: v}, nil
}

func (s *Server) PushedAuthRequestsGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.PushedAuthRequestResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.PushedAuthRequest, error) {
		return st.PushedAuthRequests().Get(ctx, r.TenantId, r.Key)
	}, pushedAuthRequestToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.PushedAuthRequestResult{Error: e, Value: v}, nil
}

func (s *Server) PushedAuthRequestsDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.PushedAuthRequests().DeleteExpired(ctx, tsFromPB(r.Before))
	}), nil
}

// ---- device codes ----

func (s *Server) DeviceCodesCreate(ctx context.Context, r *storev1.DeviceCodeWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, deviceCodeFromPB, func(st store.Store, d *store.DeviceCode) error {
		return st.DeviceCodes().Create(ctx, d)
	}), nil
}

func (s *Server) DeviceCodesGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.DeviceCodeResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.DeviceCode, error) {
		return st.DeviceCodes().Get(ctx, r.TenantId, r.Key)
	}, deviceCodeToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.DeviceCodeResult{Error: e, Value: v}, nil
}

func (s *Server) DeviceCodesGetByUserCode(ctx context.Context, r *storev1.ScopedKey) (*storev1.DeviceCodeResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.DeviceCode, error) {
		return st.DeviceCodes().GetByUserCode(ctx, r.TenantId, r.Key)
	}, deviceCodeToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.DeviceCodeResult{Error: e, Value: v}, nil
}

// DeviceCodesDecide returns the record together with ErrAlreadyUsed.
func (s *Server) DeviceCodesDecide(ctx context.Context, r *storev1.DeviceDecisionRequest) (*storev1.DeviceCodeResult, error) {
	dec := store.DeviceDecision{Status: store.DeviceCodeStatus(r.Status), UserID: r.UserId, GrantedScopes: stringsFromPB(r.GrantedScopes)}
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.DeviceCode, error) {
		return st.DeviceCodes().Decide(ctx, r.TenantId, r.DeviceCodeHash, dec)
	}, deviceCodeToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.DeviceCodeResult{Error: e, Value: v}, nil
}

func (s *Server) DeviceCodesPoll(ctx context.Context, r *storev1.DevicePollRequest) (*storev1.DevicePollResult, error) {
	var p store.DevicePoll
	err := s.with(r.TxId, func(st store.Store) (e error) {
		p, e = st.DeviceCodes().Poll(ctx, r.TenantId, r.DeviceCodeHash, tsFromPB(r.At))
		return e
	})
	if err != nil {
		return &storev1.DevicePollResult{Error: errToPB(err)}, nil
	}
	code, encErr := deviceCodeToPB(p.Code)
	if encErr != nil {
		return nil, encodeFault(encErr)
	}
	return &storev1.DevicePollResult{Code: code, Outcome: string(p.Outcome)}, nil
}

func (s *Server) DeviceCodesDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.DeviceCodes().DeleteExpired(ctx, tsFromPB(r.Before))
	}), nil
}

// ---- refresh tokens ----

func (s *Server) RefreshTokensCreate(ctx context.Context, r *storev1.RefreshTokenWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, refreshTokenFromPB, func(st store.Store, t *store.RefreshToken) error {
		return st.RefreshTokens().Create(ctx, t)
	}), nil
}

func (s *Server) RefreshTokensGetByTokenHash(ctx context.Context, r *storev1.ScopedKey) (*storev1.RefreshTokenResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.RefreshToken, error) {
		return st.RefreshTokens().GetByTokenHash(ctx, r.TenantId, r.Key)
	}, refreshTokenToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.RefreshTokenResult{Error: e, Value: v}, nil
}

func (s *Server) RefreshTokensGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.RefreshTokenResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.RefreshToken, error) {
		return st.RefreshTokens().Get(ctx, r.TenantId, r.Key)
	}, refreshTokenToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.RefreshTokenResult{Error: e, Value: v}, nil
}

func (s *Server) RefreshTokensListByUser(ctx context.Context, r *storev1.ScopedKey) (*storev1.RefreshTokenList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) ([]*store.RefreshToken, error) {
		return st.RefreshTokens().ListByUser(ctx, r.TenantId, r.Key)
	}, refreshTokenToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.RefreshTokenList{Error: e, Values: vs}, nil
}

func (s *Server) RefreshTokensRevoke(ctx context.Context, r *storev1.RevokeRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.RefreshTokens().Revoke(ctx, r.TenantId, r.Key, tsFromPB(r.At))
	}), nil
}

func (s *Server) RefreshTokensRotate(ctx context.Context, r *storev1.RefreshTokensRotateRequest) (*storev1.Result, error) {
	var leeway time.Duration
	if r.Leeway != nil { // an absent leeway is zero
		leeway = r.Leeway.AsDuration()
	}
	return write(s, r.TxId, r.Next, refreshTokenFromPB, func(st store.Store, t *store.RefreshToken) error {
		return st.RefreshTokens().Rotate(ctx, r.TenantId, r.OldId, t, tsFromPB(r.At), leeway)
	}), nil
}

func (s *Server) RefreshTokensTouch(ctx context.Context, r *storev1.TouchRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.RefreshTokens().Touch(ctx, r.TenantId, r.Id, tsFromPB(r.IdleExpiresAt))
	}), nil
}

func (s *Server) RefreshTokensRevokeFamily(ctx context.Context, r *storev1.RevokeRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		return st.RefreshTokens().RevokeFamily(ctx, r.TenantId, r.Key, tsFromPB(r.At))
	}), nil
}

func (s *Server) RefreshTokensRevokeByUser(ctx context.Context, r *storev1.RevokeRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.RefreshTokens().RevokeByUser(ctx, r.TenantId, r.Key, tsFromPB(r.At))
	}), nil
}

func (s *Server) RefreshTokensDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.RefreshTokens().DeleteExpired(ctx, tsFromPB(r.Before))
	}), nil
}

// ---- password-reset tickets ----

func (s *Server) PasswordResetTicketsCreate(ctx context.Context, r *storev1.PasswordResetTicketWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, passwordResetTicketFromPB, func(st store.Store, p *store.PasswordResetTicket) error {
		return st.PasswordResetTickets().Create(ctx, p)
	}), nil
}

func (s *Server) PasswordResetTicketsGetByTokenHash(ctx context.Context, r *storev1.ScopedKey) (*storev1.PasswordResetTicketResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.PasswordResetTicket, error) {
		return st.PasswordResetTickets().GetByTokenHash(ctx, r.TenantId, r.Key)
	}, passwordResetTicketToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.PasswordResetTicketResult{Error: e, Value: v}, nil
}

// PasswordResetTicketsConsume returns the ticket together with
// ErrAlreadyUsed when it was already used.
func (s *Server) PasswordResetTicketsConsume(ctx context.Context, r *storev1.ConsumeRequest) (*storev1.PasswordResetTicketResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.PasswordResetTicket, error) {
		return st.PasswordResetTickets().Consume(ctx, r.TenantId, r.Hash, tsFromPB(r.At))
	}, passwordResetTicketToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.PasswordResetTicketResult{Error: e, Value: v}, nil
}

func (s *Server) PasswordResetTicketsDeleteByUser(ctx context.Context, r *storev1.ScopedKey) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.PasswordResetTickets().DeleteByUser(ctx, r.TenantId, r.Key)
	}), nil
}

func (s *Server) PasswordResetTicketsDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.PasswordResetTickets().DeleteExpired(ctx, tsFromPB(r.Before))
	}), nil
}

// ---- email verification tickets ----

func (s *Server) EmailVerificationTicketsCreate(ctx context.Context, r *storev1.EmailVerificationTicketWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, emailVerificationTicketFromPB, func(st store.Store, p *store.EmailVerificationTicket) error {
		return st.EmailVerificationTickets().Create(ctx, p)
	}), nil
}

func (s *Server) EmailVerificationTicketsGetByTokenHash(ctx context.Context, r *storev1.ScopedKey) (*storev1.EmailVerificationTicketResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.EmailVerificationTicket, error) {
		return st.EmailVerificationTickets().GetByTokenHash(ctx, r.TenantId, r.Key)
	}, emailVerificationTicketToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.EmailVerificationTicketResult{Error: e, Value: v}, nil
}

// EmailVerificationTicketsConsume returns the ticket together with
// ErrAlreadyUsed when it was already used.
func (s *Server) EmailVerificationTicketsConsume(ctx context.Context, r *storev1.ConsumeRequest) (*storev1.EmailVerificationTicketResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.EmailVerificationTicket, error) {
		return st.EmailVerificationTickets().Consume(ctx, r.TenantId, r.Hash, tsFromPB(r.At))
	}, emailVerificationTicketToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.EmailVerificationTicketResult{Error: e, Value: v}, nil
}

func (s *Server) EmailVerificationTicketsDeleteByUser(ctx context.Context, r *storev1.ScopedKey) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.EmailVerificationTickets().DeleteByUser(ctx, r.TenantId, r.Key)
	}), nil
}

func (s *Server) EmailVerificationTicketsDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	return count(s, r.TxId, func(st store.Store) (int, error) {
		return st.EmailVerificationTickets().DeleteExpired(ctx, tsFromPB(r.Before))
	}), nil
}

// ---- operators ----

func (s *Server) OperatorsGet(ctx context.Context, r *storev1.ScopedKey) (*storev1.OperatorResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.Operator, error) { return st.Operators().Get(ctx, r.TenantId, r.Key) }, operatorToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.OperatorResult{Error: e, Value: v}, nil
}

func (s *Server) OperatorsUpsert(ctx context.Context, r *storev1.OperatorWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, operatorFromPB, func(st store.Store, o *store.Operator) error {
		return st.Operators().Upsert(ctx, o)
	}), nil
}

func (s *Server) OperatorsList(ctx context.Context, r *storev1.TenantScope) (*storev1.OperatorList, error) {
	vs, e, err := many(s, r.TxId, func(st store.Store) ([]*store.Operator, error) { return st.Operators().List(ctx, r.TenantId) }, operatorToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.OperatorList{Error: e, Values: vs}, nil
}

func (s *Server) OperatorsDelete(ctx context.Context, r *storev1.ScopedKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.Operators().Delete(ctx, r.TenantId, r.Key) }), nil
}
