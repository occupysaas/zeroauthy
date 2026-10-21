package grpcstore

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// This file holds the repository adapters. Each method encodes its
// arguments, makes one RPC with the view's transaction ID, and decodes the
// result. A gRPC error is a transport or server fault and is wrapped by
// rpcErr; a domain error arrives in the response's Error field and maps back
// to the store sentinel through errFromPB.

// result is implemented by the generated responses that carry only an Error.
type result interface{ GetError() *storev1.Error }

// put encodes v and sends it with call.
func put[T, P any](op string, v *T, enc func(*T) (P, error), call func(P) (result, error)) error {
	pb, err := enc(v)
	if err != nil {
		return err
	}
	r, err := call(pb)
	if err != nil {
		return rpcErr(op, err)
	}
	return errFromPB(r.GetError())
}

// do reports the outcome of a call that returns only an error.
func do(op string, r result, err error) error {
	if err != nil {
		return rpcErr(op, err)
	}
	return errFromPB(r.GetError())
}

// counted reports the outcome of a call that returns a count.
func counted(op string, r *storev1.CountResult, err error) (int, error) {
	if err != nil {
		return 0, rpcErr(op, err)
	}
	if e := errFromPB(r.GetError()); e != nil {
		return 0, e
	}
	return int(r.GetCount()), nil
}

// decOne decodes a single value. The value is returned together with a domain
// error, because Consume returns both.
func decOne[P, T any](op string, err error, e *storev1.Error, pb P, dec func(P) (*T, error)) (*T, error) {
	if err != nil {
		return nil, rpcErr(op, err)
	}
	v, derr := dec(pb)
	if derr != nil {
		return nil, derr
	}
	return v, errFromPB(e)
}

// decList decodes a list of values.
func decList[P, T any](op string, err error, e *storev1.Error, pbs []P, dec func(P) (*T, error)) ([]*T, error) {
	if err != nil {
		return nil, rpcErr(op, err)
	}
	if de := errFromPB(e); de != nil {
		return nil, de
	}
	if len(pbs) == 0 {
		return nil, nil
	}
	out := make([]*T, 0, len(pbs))
	for _, pb := range pbs {
		v, derr := dec(pb)
		if derr != nil {
			return nil, derr
		}
		out = append(out, v)
	}
	return out, nil
}

// ---- tenants ----

type clientTenants struct{ c *Client }

func (a clientTenants) Create(ctx context.Context, t *store.Tenant) error {
	return put("TenantsCreate", t, tenantToPB, func(pb *storev1.Tenant) (result, error) {
		return a.c.rpc.TenantsCreate(ctx, &storev1.TenantWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientTenants) get(ctx context.Context, op string, call func(context.Context, *storev1.TenantsGetRequest, ...grpc.CallOption) (*storev1.TenantResult, error), key string) (*store.Tenant, error) {
	r, err := call(ctx, &storev1.TenantsGetRequest{TxId: a.c.txID, Key: key})
	return decOne(op, err, r.GetError(), r.GetValue(), tenantFromPB)
}

func (a clientTenants) Get(ctx context.Context, id string) (*store.Tenant, error) {
	return a.get(ctx, "TenantsGet", a.c.rpc.TenantsGet, id)
}

func (a clientTenants) GetByName(ctx context.Context, name string) (*store.Tenant, error) {
	return a.get(ctx, "TenantsGetByName", a.c.rpc.TenantsGetByName, name)
}

func (a clientTenants) GetByDomain(ctx context.Context, domain string) (*store.Tenant, error) {
	return a.get(ctx, "TenantsGetByDomain", a.c.rpc.TenantsGetByDomain, domain)
}

func (a clientTenants) Update(ctx context.Context, t *store.Tenant) error {
	return put("TenantsUpdate", t, tenantToPB, func(pb *storev1.Tenant) (result, error) {
		return a.c.rpc.TenantsUpdate(ctx, &storev1.TenantWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientTenants) List(ctx context.Context) ([]*store.Tenant, error) {
	r, err := a.c.rpc.TenantsList(ctx, &storev1.TenantsListRequest{TxId: a.c.txID})
	return decList("TenantsList", err, r.GetError(), r.GetValues(), tenantFromPB)
}

// Delete needs a plugin built against Plan 13's protocol.
func (a clientTenants) Delete(ctx context.Context, id string) error {
	r, err := a.c.rpc.TenantsDelete(ctx, &storev1.TenantsGetRequest{TxId: a.c.txID, Key: id})
	return do("TenantsDelete", r, tooOld(err))
}

// ---- clients ----

type clientClients struct{ c *Client }

func (a clientClients) Create(ctx context.Context, v *store.Client) error {
	return put("ClientsCreate", v, clientToPB, func(pb *storev1.Client) (result, error) {
		return a.c.rpc.ClientsCreate(ctx, &storev1.ClientWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientClients) Get(ctx context.Context, tenantID, clientID string) (*store.Client, error) {
	r, err := a.c.rpc.ClientsGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: clientID})
	return decOne("ClientsGet", err, r.GetError(), r.GetValue(), clientFromPB)
}

func (a clientClients) Update(ctx context.Context, v *store.Client) error {
	return put("ClientsUpdate", v, clientToPB, func(pb *storev1.Client) (result, error) {
		return a.c.rpc.ClientsUpdate(ctx, &storev1.ClientWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientClients) Delete(ctx context.Context, tenantID, clientID string) error {
	r, err := a.c.rpc.ClientsDelete(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: clientID})
	return do("ClientsDelete", r, err)
}

func (a clientClients) List(ctx context.Context, tenantID string, f store.ClientFilter, p store.Page) ([]*store.Client, int, error) {
	if len(f.AppTypes) == 0 && f.IsFirstParty == nil && p == (store.Page{}) {
		// Everything, as every plugin can serve it.
		r, err := a.c.rpc.ClientsList(ctx, &storev1.TenantScope{TxId: a.c.txID, TenantId: tenantID})
		out, err := decList("ClientsList", err, r.GetError(), r.GetValues(), clientFromPB)
		sortClients(out)
		return out, len(out), err
	}
	req := &storev1.ClientsListPageRequest{TxId: a.c.txID, TenantId: tenantID, AppTypes: f.AppTypes,
		Offset: int64(p.Offset), Limit: int64(p.Limit)}
	if f.IsFirstParty != nil {
		req.HasIsFirstParty, req.IsFirstParty = true, *f.IsFirstParty
	}
	r, err := a.c.rpc.ClientsListPage(ctx, req)
	if status.Code(err) == codes.Unimplemented {
		// A plugin without ClientsListPage still serves GET /clients: list
		// everything and filter, order and page here.
		all, _, err := a.List(ctx, tenantID, store.ClientFilter{}, store.Page{})
		if err != nil {
			return nil, 0, err
		}
		return filterClients(all, f, p)
	}
	out, err := decList("ClientsListPage", err, r.GetError(), r.GetValues(), clientFromPB)
	if err != nil {
		return nil, 0, err
	}
	return out, int(r.GetTotal()), nil
}

// sortClients orders by CreatedAt, then ClientID, as Clients.List promises;
// a plugin that predates the order returns them by ClientID.
func sortClients(cs []*store.Client) {
	slices.SortStableFunc(cs, func(a, b *store.Client) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ClientID, b.ClientID))
	})
}

// filterClients applies f and p to all, which sortClients has ordered.
func filterClients(all []*store.Client, f store.ClientFilter, p store.Page) ([]*store.Client, int, error) {
	var kept []*store.Client
	for _, c := range all {
		if (len(f.AppTypes) == 0 || slices.Contains(f.AppTypes, string(c.AppType))) &&
			(f.IsFirstParty == nil || c.IsFirstParty == *f.IsFirstParty) {
			kept = append(kept, c)
		}
	}
	total := len(kept)
	kept = kept[min(max(p.Offset, 0), total):]
	if p.Limit > 0 && len(kept) > p.Limit {
		kept = kept[:p.Limit]
	}
	return kept, total, nil
}

// ---- resource servers ----

type clientResourceServers struct{ c *Client }

func (a clientResourceServers) Create(ctx context.Context, v *store.ResourceServer) error {
	return put("ResourceServersCreate", v, resourceServerToPB, func(pb *storev1.ResourceServer) (result, error) {
		return a.c.rpc.ResourceServersCreate(ctx, &storev1.ResourceServerWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientResourceServers) Get(ctx context.Context, tenantID, id string) (*store.ResourceServer, error) {
	r, err := a.c.rpc.ResourceServersGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return decOne("ResourceServersGet", err, r.GetError(), r.GetValue(), resourceServerFromPB)
}

func (a clientResourceServers) GetByIdentifier(ctx context.Context, tenantID, identifier string) (*store.ResourceServer, error) {
	r, err := a.c.rpc.ResourceServersGetByIdentifier(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: identifier})
	return decOne("ResourceServersGetByIdentifier", err, r.GetError(), r.GetValue(), resourceServerFromPB)
}

func (a clientResourceServers) Update(ctx context.Context, v *store.ResourceServer) error {
	return put("ResourceServersUpdate", v, resourceServerToPB, func(pb *storev1.ResourceServer) (result, error) {
		return a.c.rpc.ResourceServersUpdate(ctx, &storev1.ResourceServerWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientResourceServers) Delete(ctx context.Context, tenantID, id string) error {
	r, err := a.c.rpc.ResourceServersDelete(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return do("ResourceServersDelete", r, err)
}

func (a clientResourceServers) List(ctx context.Context, tenantID string) ([]*store.ResourceServer, error) {
	r, err := a.c.rpc.ResourceServersList(ctx, &storev1.TenantScope{TxId: a.c.txID, TenantId: tenantID})
	return decList("ResourceServersList", tooOld(err), r.GetError(), r.GetValues(), resourceServerFromPB)
}

// ---- client grants ----

type clientClientGrants struct{ c *Client }

func (a clientClientGrants) Create(ctx context.Context, v *store.ClientGrant) error {
	return put("ClientGrantsCreate", v, clientGrantToPB, func(pb *storev1.ClientGrant) (result, error) {
		return a.c.rpc.ClientGrantsCreate(ctx, &storev1.ClientGrantWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientClientGrants) Find(ctx context.Context, tenantID, clientID, audience, subjectType string) (*store.ClientGrant, error) {
	r, err := a.c.rpc.ClientGrantsFind(ctx, &storev1.ClientGrantsFindRequest{
		TxId: a.c.txID, TenantId: tenantID, ClientId: clientID, Audience: audience, SubjectType: subjectType})
	got, err := decOne("ClientGrantsFind", err, r.GetError(), r.GetValue(), clientGrantFromPB)
	if err != nil {
		return nil, err
	}
	// A plugin older than Plan 9 ignores subject_type and may return the
	// other type's grant.
	if got != nil && got.SubjectType != subjectType {
		return nil, store.ErrNotFound
	}
	return got, nil
}

func (a clientClientGrants) Update(ctx context.Context, v *store.ClientGrant) error {
	return put("ClientGrantsUpdate", v, clientGrantToPB, func(pb *storev1.ClientGrant) (result, error) {
		return a.c.rpc.ClientGrantsUpdate(ctx, &storev1.ClientGrantWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientClientGrants) Delete(ctx context.Context, tenantID, id string) error {
	r, err := a.c.rpc.ClientGrantsDelete(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return do("ClientGrantsDelete", r, err)
}

func (a clientClientGrants) List(ctx context.Context, tenantID string, f store.ClientGrantFilter, p store.Page) ([]*store.ClientGrant, int, error) {
	r, err := a.c.rpc.ClientGrantsList(ctx, &storev1.ClientGrantsListRequest{TxId: a.c.txID, TenantId: tenantID,
		ClientId: f.ClientID, Audience: f.Audience, SubjectType: f.SubjectType, AfterId: f.AfterID, Id: f.ID, Offset: int64(p.Offset), Limit: int64(p.Limit)})
	out, err := decList("ClientGrantsList", tooOld(err), r.GetError(), r.GetValues(), clientGrantFromPB)
	if err != nil {
		return nil, 0, err
	}
	return out, int(r.GetTotal()), nil
}

// ---- user grants ----

type clientUserGrants struct{ c *Client }

func (a clientUserGrants) Find(ctx context.Context, tenantID, clientID, userID, audience string) (*store.UserGrant, error) {
	r, err := a.c.rpc.UserGrantsFind(ctx, &storev1.UserGrantsFindRequest{
		TxId: a.c.txID, TenantId: tenantID, ClientId: clientID, UserId: userID, Audience: audience})
	return decOne("UserGrantsFind", err, r.GetError(), r.GetValue(), userGrantFromPB)
}

func (a clientUserGrants) Upsert(ctx context.Context, g *store.UserGrant) (*store.UserGrant, error) {
	pb, err := userGrantToPB(g)
	if err != nil {
		return nil, err
	}
	r, err := a.c.rpc.UserGrantsUpsert(ctx, &storev1.UserGrantWrite{TxId: a.c.txID, Value: pb})
	return decOne("UserGrantsUpsert", err, r.GetError(), r.GetValue(), userGrantFromPB)
}

func (a clientUserGrants) List(ctx context.Context, tenantID string, f store.UserGrantFilter, p store.Page) ([]*store.UserGrant, int, error) {
	r, err := a.c.rpc.UserGrantsList(ctx, &storev1.UserGrantsListRequest{TxId: a.c.txID, TenantId: tenantID,
		UserId: f.UserID, ClientId: f.ClientID, Audience: f.Audience, Offset: int64(p.Offset), Limit: int64(p.Limit)})
	out, err := decList("UserGrantsList", tooOld(err), r.GetError(), r.GetValues(), userGrantFromPB)
	if err != nil {
		return nil, 0, err
	}
	return out, int(r.GetTotal()), nil
}

func (a clientUserGrants) ListByUser(ctx context.Context, tenantID, userID string) ([]*store.UserGrant, error) {
	r, err := a.c.rpc.UserGrantsListByUser(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return decList("UserGrantsListByUser", err, r.GetError(), r.GetValues(), userGrantFromPB)
}

func (a clientUserGrants) ListByAudience(ctx context.Context, tenantID, audience string) ([]*store.UserGrant, error) {
	r, err := a.c.rpc.UserGrantsListByAudience(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: audience})
	return decList("UserGrantsListByAudience", err, r.GetError(), r.GetValues(), userGrantFromPB)
}

func (a clientUserGrants) Delete(ctx context.Context, tenantID, id string) error {
	r, err := a.c.rpc.UserGrantsDelete(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return do("UserGrantsDelete", r, err)
}

func (a clientUserGrants) DeleteByUser(ctx context.Context, tenantID, userID string) (int, error) {
	r, err := a.c.rpc.UserGrantsDeleteByUser(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return counted("UserGrantsDeleteByUser", r, err)
}

// ----  ----

type clientSigningKeys struct{ c *Client }

func (a clientSigningKeys) Create(ctx context.Context, v *store.SigningKey) error {
	return put("SigningKeysCreate", v, signingKeyToPB, func(pb *storev1.SigningKey) (result, error) {
		return a.c.rpc.SigningKeysCreate(ctx, &storev1.SigningKeyWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientSigningKeys) List(ctx context.Context, tenantID string) ([]*store.SigningKey, error) {
	r, err := a.c.rpc.SigningKeysList(ctx, &storev1.TenantScope{TxId: a.c.txID, TenantId: tenantID})
	return decList("SigningKeysList", err, r.GetError(), r.GetValues(), signingKeyFromPB)
}

func (a clientSigningKeys) Rotate(ctx context.Context, tenantID string, next *store.SigningKey) error {
	return put("SigningKeysRotate", next, signingKeyToPB, func(pb *storev1.SigningKey) (result, error) {
		return a.c.rpc.SigningKeysRotate(ctx, &storev1.SigningKeysRotateRequest{TxId: a.c.txID, TenantId: tenantID, Next: pb})
	})
}

// ---- connections ----

type clientConnections struct{ c *Client }

func (a clientConnections) Create(ctx context.Context, v *store.Connection) error {
	return put("ConnectionsCreate", v, connectionToPB, func(pb *storev1.Connection) (result, error) {
		return a.c.rpc.ConnectionsCreate(ctx, &storev1.ConnectionWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientConnections) Get(ctx context.Context, tenantID, id string) (*store.Connection, error) {
	r, err := a.c.rpc.ConnectionsGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return decOne("ConnectionsGet", err, r.GetError(), r.GetValue(), connectionFromPB)
}

func (a clientConnections) GetByName(ctx context.Context, tenantID, name string) (*store.Connection, error) {
	r, err := a.c.rpc.ConnectionsGetByName(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: name})
	return decOne("ConnectionsGetByName", err, r.GetError(), r.GetValue(), connectionFromPB)
}

func (a clientConnections) Update(ctx context.Context, v *store.Connection) error {
	return put("ConnectionsUpdate", v, connectionToPB, func(pb *storev1.Connection) (result, error) {
		return a.c.rpc.ConnectionsUpdate(ctx, &storev1.ConnectionWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientConnections) List(ctx context.Context, tenantID string, f store.ConnectionFilter, p store.Page) ([]*store.Connection, int, error) {
	if f.Name == "" && len(f.Strategies) == 0 && p == (store.Page{}) {
		// Everything, as plugins older than Plan 15 can serve it.
		r, err := a.c.rpc.ConnectionsList(ctx, &storev1.TenantScope{TxId: a.c.txID, TenantId: tenantID})
		out, err := decList("ConnectionsList", err, r.GetError(), r.GetValues(), connectionFromPB)
		return out, len(out), err
	}
	r, err := a.c.rpc.ConnectionsListPage(ctx, &storev1.ConnectionsListPageRequest{TxId: a.c.txID, TenantId: tenantID,
		Name: f.Name, Strategies: f.Strategies, Offset: int64(p.Offset), Limit: int64(p.Limit)})
	out, err := decList("ConnectionsListPage", tooOld(err), r.GetError(), r.GetValues(), connectionFromPB)
	if err != nil {
		return nil, 0, err
	}
	return out, int(r.GetTotal()), nil
}

func (a clientConnections) Delete(ctx context.Context, tenantID, id string) error {
	r, err := a.c.rpc.ConnectionsDelete(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return do("ConnectionsDelete", r, tooOld(err))
}

// ---- password histories ----

type clientPasswordHistories struct{ c *Client }

func (a clientPasswordHistories) Add(ctx context.Context, tenantID, userID string, hash []byte, keep int) error {
	r, err := a.c.rpc.PasswordHistoriesAdd(ctx, &storev1.PasswordHistoryAdd{TxId: a.c.txID, TenantId: tenantID,
		UserId: userID, Hash: hash, Keep: int64(keep)})
	return do("PasswordHistoriesAdd", r, tooOld(err))
}

func (a clientPasswordHistories) List(ctx context.Context, tenantID, userID string) ([][]byte, error) {
	r, err := a.c.rpc.PasswordHistoriesList(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	if err = tooOld(err); err != nil {
		return nil, rpcErr("PasswordHistoriesList", err)
	}
	if e := errFromPB(r.GetError()); e != nil {
		return nil, e
	}
	out := make([][]byte, 0, len(r.GetValues()))
	for _, h := range r.GetValues() {
		out = append(out, cloneBytes(h))
	}
	return out, nil
}

// ---- users ----

type clientUsers struct{ c *Client }

func (a clientUsers) Create(ctx context.Context, v *store.User) error {
	return put("UsersCreate", v, userToPB, func(pb *storev1.User) (result, error) {
		return a.c.rpc.UsersCreate(ctx, &storev1.UserWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientUsers) Get(ctx context.Context, tenantID, userID string) (*store.User, error) {
	r, err := a.c.rpc.UsersGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return decOne("UsersGet", err, r.GetError(), r.GetValue(), userFromPB)
}

// GetForUpdate runs in the plugin's transaction named by txID, so the
// plugin's driver takes the lock there.
func (a clientUsers) GetForUpdate(ctx context.Context, tenantID, userID string) (*store.User, error) {
	r, err := a.c.rpc.UsersGetForUpdate(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return decOne("UsersGetForUpdate", tooOld(err), r.GetError(), r.GetValue(), userFromPB)
}

func (a clientUsers) FindByLogin(ctx context.Context, tenantID, connection, login string) (*store.User, error) {
	r, err := a.c.rpc.UsersFindByLogin(ctx, &storev1.UsersFindByLoginRequest{TxId: a.c.txID, TenantId: tenantID, Connection: connection, Login: login})
	return decOne("UsersFindByLogin", err, r.GetError(), r.GetValue(), userFromPB)
}

func (a clientUsers) Update(ctx context.Context, v *store.User) error {
	return put("UsersUpdate", v, userToPB, func(pb *storev1.User) (result, error) {
		return a.c.rpc.UsersUpdate(ctx, &storev1.UserWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientUsers) RecordLogin(ctx context.Context, tenantID, userID string, at time.Time, ip string) error {
	r, err := a.c.rpc.UsersRecordLogin(ctx, &storev1.UsersRecordLoginRequest{TxId: a.c.txID, TenantId: tenantID, UserId: userID, At: tsToPB(at), Ip: ip})
	return do("UsersRecordLogin", r, err)
}

func (a clientUsers) SetPasswordHash(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error {
	r, err := a.c.rpc.UsersSetPasswordHash(ctx, &storev1.UsersSetPasswordHashRequest{
		TxId: a.c.txID, TenantId: tenantID, UserId: userID, Connection: connection, Hash: hash, At: tsToPB(at)})
	return do("UsersSetPasswordHash", r, err)
}

func (a clientUsers) SetPasswordHashIfEmpty(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error {
	r, err := a.c.rpc.UsersSetPasswordHashIfEmpty(ctx, &storev1.UsersSetPasswordHashRequest{
		TxId: a.c.txID, TenantId: tenantID, UserId: userID, Connection: connection, Hash: hash, At: tsToPB(at)})
	return do("UsersSetPasswordHashIfEmpty", r, tooOld(err))
}

func (a clientUsers) UpgradeImportedHash(ctx context.Context, tenantID, userID, connection, imported, hash string, at time.Time) error {
	r, err := a.c.rpc.UsersUpgradeImportedHash(ctx, &storev1.UsersUpgradeImportedHashRequest{
		TxId: a.c.txID, TenantId: tenantID, UserId: userID, Connection: connection, Imported: imported, Hash: hash, At: tsToPB(at)})
	return do("UsersUpgradeImportedHash", r, tooOld(err))
}

func (a clientUsers) BumpVersion(ctx context.Context, tenantID, userID string) (int64, error) {
	r, err := a.c.rpc.UsersBumpVersion(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	if err = tooOld(err); err != nil {
		return 0, rpcErr("UsersBumpVersion", err)
	}
	if e := errFromPB(r.GetError()); e != nil {
		return 0, e
	}
	return r.GetValue(), nil
}

func (a clientUsers) FindByEmail(ctx context.Context, tenantID, email string) ([]*store.User, error) {
	r, err := a.c.rpc.UsersFindByEmail(ctx, &storev1.UsersFindByEmailRequest{TxId: a.c.txID, TenantId: tenantID, Email: email})
	return decList("UsersFindByEmail", tooOld(err), r.GetError(), r.GetValues(), userFromPB)
}

func (a clientUsers) Delete(ctx context.Context, tenantID, userID string) error {
	r, err := a.c.rpc.UsersDelete(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return do("UsersDelete", r, tooOld(err))
}

// ---- sessions ----

type clientSessions struct{ c *Client }

func (a clientSessions) Create(ctx context.Context, v *store.LoginSession) error {
	return put("SessionsCreate", v, sessionToPB, func(pb *storev1.LoginSession) (result, error) {
		return a.c.rpc.SessionsCreate(ctx, &storev1.SessionWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientSessions) GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*store.LoginSession, error) {
	r, err := a.c.rpc.SessionsGetByTokenHash(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: tokenHash})
	return decOne("SessionsGetByTokenHash", err, r.GetError(), r.GetValue(), sessionFromPB)
}

func (a clientSessions) Get(ctx context.Context, tenantID, id string) (*store.LoginSession, error) {
	r, err := a.c.rpc.SessionsGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return decOne("SessionsGet", tooOld(err), r.GetError(), r.GetValue(), sessionFromPB)
}

func (a clientSessions) ListByUser(ctx context.Context, tenantID, userID string) ([]*store.LoginSession, error) {
	r, err := a.c.rpc.SessionsListByUser(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return decList("SessionsListByUser", tooOld(err), r.GetError(), r.GetValues(), sessionFromPB)
}

// Touch sends at, ip and userAgent as new TouchRequest fields: a plugin that
// predates them still extends the idle expiry and drops the rest.
func (a clientSessions) Touch(ctx context.Context, tenantID, id string, at, idleExpiresAt time.Time, ip, userAgent string) error {
	r, err := a.c.rpc.SessionsTouch(ctx, &storev1.TouchRequest{TxId: a.c.txID, TenantId: tenantID, Id: id,
		IdleExpiresAt: tsToPB(idleExpiresAt), At: tsToPB(at), Ip: ip, UserAgent: userAgent})
	return do("SessionsTouch", r, err)
}

func (a clientSessions) AddClient(ctx context.Context, tenantID, id, clientID string) error {
	r, err := a.c.rpc.SessionsAddClient(ctx, &storev1.SessionsAddClientRequest{TxId: a.c.txID, TenantId: tenantID, Id: id, ClientId: clientID})
	return do("SessionsAddClient", r, err)
}

func (a clientSessions) Delete(ctx context.Context, tenantID, id string) error {
	r, err := a.c.rpc.SessionsDelete(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return do("SessionsDelete", r, err)
}

func (a clientSessions) DeleteByUser(ctx context.Context, tenantID, userID string) (int, error) {
	r, err := a.c.rpc.SessionsDeleteByUser(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return counted("SessionsDeleteByUser", r, err)
}

func (a clientSessions) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.SessionsDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	return counted("SessionsDeleteExpired", r, err)
}

// ---- auth transactions ----

type clientAuthTransactions struct{ c *Client }

func (a clientAuthTransactions) Create(ctx context.Context, v *store.AuthTransaction) error {
	return put("AuthTransactionsCreate", v, authTransactionToPB, func(pb *storev1.AuthTransaction) (result, error) {
		return a.c.rpc.AuthTransactionsCreate(ctx, &storev1.AuthTransactionWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientAuthTransactions) Get(ctx context.Context, tenantID, id string) (*store.AuthTransaction, error) {
	r, err := a.c.rpc.AuthTransactionsGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return decOne("AuthTransactionsGet", err, r.GetError(), r.GetValue(), authTransactionFromPB)
}

func (a clientAuthTransactions) Delete(ctx context.Context, tenantID, id string) error {
	r, err := a.c.rpc.AuthTransactionsDelete(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return do("AuthTransactionsDelete", r, err)
}

func (a clientAuthTransactions) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.AuthTransactionsDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	return counted("AuthTransactionsDeleteExpired", r, err)
}

// ---- auth codes ----

type clientAuthCodes struct{ c *Client }

func (a clientAuthCodes) Create(ctx context.Context, v *store.AuthCode) error {
	return put("AuthCodesCreate", v, authCodeToPB, func(pb *storev1.AuthCode) (result, error) {
		return a.c.rpc.AuthCodesCreate(ctx, &storev1.AuthCodeWrite{TxId: a.c.txID, Value: pb})
	})
}

// Consume returns the code together with ErrAlreadyUsed on a replay.
func (a clientAuthCodes) Consume(ctx context.Context, tenantID, codeHash string, at time.Time) (*store.AuthCode, error) {
	r, err := a.c.rpc.AuthCodesConsume(ctx, &storev1.ConsumeRequest{TxId: a.c.txID, TenantId: tenantID, Hash: codeHash, At: tsToPB(at)})
	return decOne("AuthCodesConsume", err, r.GetError(), r.GetValue(), authCodeFromPB)
}

func (a clientAuthCodes) Get(ctx context.Context, tenantID, codeHash string) (*store.AuthCode, error) {
	r, err := a.c.rpc.AuthCodesGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: codeHash})
	return decOne("AuthCodesGet", err, r.GetError(), r.GetValue(), authCodeFromPB)
}

func (a clientAuthCodes) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.AuthCodesDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	return counted("AuthCodesDeleteExpired", r, err)
}

// ---- pushed auth requests ----

type clientPushedAuthRequests struct{ c *Client }

func (a clientPushedAuthRequests) Create(ctx context.Context, v *store.PushedAuthRequest) error {
	return put("PushedAuthRequestsCreate", v, pushedAuthRequestToPB, func(pb *storev1.PushedAuthRequest) (result, error) {
		return a.c.rpc.PushedAuthRequestsCreate(ctx, &storev1.PushedAuthRequestWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientPushedAuthRequests) Consume(ctx context.Context, tenantID, idHash string, at time.Time) (*store.PushedAuthRequest, error) {
	r, err := a.c.rpc.PushedAuthRequestsConsume(ctx, &storev1.ConsumeRequest{TxId: a.c.txID, TenantId: tenantID, Hash: idHash, At: tsToPB(at)})
	return decOne("PushedAuthRequestsConsume", err, r.GetError(), r.GetValue(), pushedAuthRequestFromPB)
}

func (a clientPushedAuthRequests) Get(ctx context.Context, tenantID, idHash string) (*store.PushedAuthRequest, error) {
	r, err := a.c.rpc.PushedAuthRequestsGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: idHash})
	return decOne("PushedAuthRequestsGet", err, r.GetError(), r.GetValue(), pushedAuthRequestFromPB)
}

// DeleteExpired treats a plugin that predates the RPC as holding no pushed
// requests: the sweeper calls it on every deployment.
func (a clientPushedAuthRequests) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.PushedAuthRequestsDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	if status.Code(err) == codes.Unimplemented {
		return 0, nil
	}
	return counted("PushedAuthRequestsDeleteExpired", r, err)
}

// ---- device codes ----

type clientDeviceCodes struct{ c *Client }

func (a clientDeviceCodes) Create(ctx context.Context, v *store.DeviceCode) error {
	return put("DeviceCodesCreate", v, deviceCodeToPB, func(pb *storev1.DeviceCode) (result, error) {
		return a.c.rpc.DeviceCodesCreate(ctx, &storev1.DeviceCodeWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientDeviceCodes) Get(ctx context.Context, tenantID, deviceCodeHash string) (*store.DeviceCode, error) {
	r, err := a.c.rpc.DeviceCodesGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: deviceCodeHash})
	return decOne("DeviceCodesGet", err, r.GetError(), r.GetValue(), deviceCodeFromPB)
}

func (a clientDeviceCodes) GetByUserCode(ctx context.Context, tenantID, userCodeHash string) (*store.DeviceCode, error) {
	r, err := a.c.rpc.DeviceCodesGetByUserCode(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userCodeHash})
	return decOne("DeviceCodesGetByUserCode", err, r.GetError(), r.GetValue(), deviceCodeFromPB)
}

// Decide returns the record together with ErrAlreadyUsed.
func (a clientDeviceCodes) Decide(ctx context.Context, tenantID, deviceCodeHash string, dec store.DeviceDecision) (*store.DeviceCode, error) {
	r, err := a.c.rpc.DeviceCodesDecide(ctx, &storev1.DeviceDecisionRequest{
		TxId: a.c.txID, TenantId: tenantID, DeviceCodeHash: deviceCodeHash,
		Status: string(dec.Status), UserId: dec.UserID, GrantedScopes: stringsToPB(dec.GrantedScopes),
	})
	return decOne("DeviceCodesDecide", err, r.GetError(), r.GetValue(), deviceCodeFromPB)
}

func (a clientDeviceCodes) Poll(ctx context.Context, tenantID, deviceCodeHash string, at time.Time) (store.DevicePoll, error) {
	r, err := a.c.rpc.DeviceCodesPoll(ctx, &storev1.DevicePollRequest{
		TxId: a.c.txID, TenantId: tenantID, DeviceCodeHash: deviceCodeHash, At: tsToPB(at),
	})
	if err != nil {
		return store.DevicePoll{}, rpcErr("DeviceCodesPoll", err)
	}
	if e := errFromPB(r.GetError()); e != nil {
		return store.DevicePoll{}, e
	}
	code, err := deviceCodeFromPB(r.GetCode())
	if err != nil {
		return store.DevicePoll{}, err
	}
	outcome, err := devicePollOutcomeFromPB(r.GetOutcome())
	if err != nil {
		return store.DevicePoll{}, err
	}
	return store.DevicePoll{Code: code, Outcome: outcome}, nil
}

// DeleteExpired treats a plugin that predates the RPC as holding no device
// codes: the sweeper calls it on every deployment.
func (a clientDeviceCodes) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.DeviceCodesDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	if status.Code(err) == codes.Unimplemented {
		return 0, nil
	}
	return counted("DeviceCodesDeleteExpired", r, err)
}

// ---- refresh tokens ----

type clientRefreshTokens struct{ c *Client }

func (a clientRefreshTokens) Create(ctx context.Context, v *store.RefreshToken) error {
	return put("RefreshTokensCreate", v, refreshTokenToPB, func(pb *storev1.RefreshToken) (result, error) {
		return a.c.rpc.RefreshTokensCreate(ctx, &storev1.RefreshTokenWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientRefreshTokens) GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*store.RefreshToken, error) {
	r, err := a.c.rpc.RefreshTokensGetByTokenHash(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: tokenHash})
	return decOne("RefreshTokensGetByTokenHash", err, r.GetError(), r.GetValue(), refreshTokenFromPB)
}

func (a clientRefreshTokens) Get(ctx context.Context, tenantID, id string) (*store.RefreshToken, error) {
	r, err := a.c.rpc.RefreshTokensGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return decOne("RefreshTokensGet", tooOld(err), r.GetError(), r.GetValue(), refreshTokenFromPB)
}

func (a clientRefreshTokens) ListByUser(ctx context.Context, tenantID, userID string) ([]*store.RefreshToken, error) {
	r, err := a.c.rpc.RefreshTokensListByUser(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return decList("RefreshTokensListByUser", tooOld(err), r.GetError(), r.GetValues(), refreshTokenFromPB)
}

func (a clientRefreshTokens) Revoke(ctx context.Context, tenantID, id string, at time.Time) error {
	r, err := a.c.rpc.RefreshTokensRevoke(ctx, &storev1.RevokeRequest{TxId: a.c.txID, TenantId: tenantID, Key: id, At: tsToPB(at)})
	return do("RefreshTokensRevoke", r, tooOld(err))
}

func (a clientRefreshTokens) Rotate(ctx context.Context, tenantID, oldID string, next *store.RefreshToken, at time.Time, leeway time.Duration) error {
	return put("RefreshTokensRotate", next, refreshTokenToPB, func(pb *storev1.RefreshToken) (result, error) {
		return a.c.rpc.RefreshTokensRotate(ctx, &storev1.RefreshTokensRotateRequest{
			TxId: a.c.txID, TenantId: tenantID, OldId: oldID, Next: pb, At: tsToPB(at), Leeway: durationpb.New(leeway)})
	})
}

func (a clientRefreshTokens) Touch(ctx context.Context, tenantID, id string, idleExpiresAt time.Time) error {
	r, err := a.c.rpc.RefreshTokensTouch(ctx, &storev1.TouchRequest{TxId: a.c.txID, TenantId: tenantID, Id: id, IdleExpiresAt: tsToPB(idleExpiresAt)})
	return do("RefreshTokensTouch", r, err)
}

func (a clientRefreshTokens) RevokeFamily(ctx context.Context, tenantID, familyID string, at time.Time) error {
	r, err := a.c.rpc.RefreshTokensRevokeFamily(ctx, &storev1.RevokeRequest{TxId: a.c.txID, TenantId: tenantID, Key: familyID, At: tsToPB(at)})
	return do("RefreshTokensRevokeFamily", r, err)
}

func (a clientRefreshTokens) RevokeByUser(ctx context.Context, tenantID, userID string, at time.Time) (int, error) {
	r, err := a.c.rpc.RefreshTokensRevokeByUser(ctx, &storev1.RevokeRequest{TxId: a.c.txID, TenantId: tenantID, Key: userID, At: tsToPB(at)})
	return counted("RefreshTokensRevokeByUser", r, err)
}

func (a clientRefreshTokens) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.RefreshTokensDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	return counted("RefreshTokensDeleteExpired", r, err)
}

// ---- password reset tickets ----

type clientPasswordResetTickets struct{ c *Client }

func (a clientPasswordResetTickets) Create(ctx context.Context, v *store.PasswordResetTicket) error {
	return put("PasswordResetTicketsCreate", v, passwordResetTicketToPB, func(pb *storev1.PasswordResetTicket) (result, error) {
		return a.c.rpc.PasswordResetTicketsCreate(ctx, &storev1.PasswordResetTicketWrite{TxId: a.c.txID, Value: pb})
	})
}

func (a clientPasswordResetTickets) GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*store.PasswordResetTicket, error) {
	r, err := a.c.rpc.PasswordResetTicketsGetByTokenHash(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: tokenHash})
	return decOne("PasswordResetTicketsGetByTokenHash", err, r.GetError(), r.GetValue(), passwordResetTicketFromPB)
}

// Consume returns the ticket together with ErrAlreadyUsed on a replay.
func (a clientPasswordResetTickets) Consume(ctx context.Context, tenantID, tokenHash string, at time.Time) (*store.PasswordResetTicket, error) {
	r, err := a.c.rpc.PasswordResetTicketsConsume(ctx, &storev1.ConsumeRequest{TxId: a.c.txID, TenantId: tenantID, Hash: tokenHash, At: tsToPB(at)})
	return decOne("PasswordResetTicketsConsume", err, r.GetError(), r.GetValue(), passwordResetTicketFromPB)
}

func (a clientPasswordResetTickets) DeleteByUser(ctx context.Context, tenantID, userID string) (int, error) {
	r, err := a.c.rpc.PasswordResetTicketsDeleteByUser(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return counted("PasswordResetTicketsDeleteByUser", r, err)
}

func (a clientPasswordResetTickets) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.PasswordResetTicketsDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	return counted("PasswordResetTicketsDeleteExpired", r, err)
}

// ---- email verification tickets ----

type clientEmailVerificationTickets struct{ c *Client }

func (a clientEmailVerificationTickets) Create(ctx context.Context, v *store.EmailVerificationTicket) error {
	return put("EmailVerificationTicketsCreate", v, emailVerificationTicketToPB, func(pb *storev1.EmailVerificationTicket) (result, error) {
		r, err := a.c.rpc.EmailVerificationTicketsCreate(ctx, &storev1.EmailVerificationTicketWrite{TxId: a.c.txID, Value: pb})
		return r, tooOld(err)
	})
}

func (a clientEmailVerificationTickets) GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*store.EmailVerificationTicket, error) {
	r, err := a.c.rpc.EmailVerificationTicketsGetByTokenHash(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: tokenHash})
	return decOne("EmailVerificationTicketsGetByTokenHash", tooOld(err), r.GetError(), r.GetValue(), emailVerificationTicketFromPB)
}

// Consume returns the ticket together with ErrAlreadyUsed on a replay.
func (a clientEmailVerificationTickets) Consume(ctx context.Context, tenantID, tokenHash string, at time.Time) (*store.EmailVerificationTicket, error) {
	r, err := a.c.rpc.EmailVerificationTicketsConsume(ctx, &storev1.ConsumeRequest{TxId: a.c.txID, TenantId: tenantID, Hash: tokenHash, At: tsToPB(at)})
	return decOne("EmailVerificationTicketsConsume", tooOld(err), r.GetError(), r.GetValue(), emailVerificationTicketFromPB)
}

func (a clientEmailVerificationTickets) DeleteByUser(ctx context.Context, tenantID, userID string) (int, error) {
	r, err := a.c.rpc.EmailVerificationTicketsDeleteByUser(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return counted("EmailVerificationTicketsDeleteByUser", r, tooOld(err))
}

// DeleteExpired treats a plugin that predates the RPC as holding no tickets:
// the sweeper calls it on every deployment.
func (a clientEmailVerificationTickets) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.EmailVerificationTicketsDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	if status.Code(err) == codes.Unimplemented {
		return 0, nil
	}
	return counted("EmailVerificationTicketsDeleteExpired", r, err)
}

// ---- operators ----

// errPluginTooOld wraps the Unimplemented status of a plugin that predates
// an RPC the host needs.
var errPluginTooOld = errors.New("the storage plugin is too old for this zeroauthy version (missing RPC); upgrade the plugin")

// tooOld turns Unimplemented into errPluginTooOld, keeping the status.
func tooOld(err error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("%w: %w", errPluginTooOld, err)
	}
	return err
}

type clientOperators struct{ c *Client }

func (a clientOperators) Get(ctx context.Context, tenantID, userID string) (*store.Operator, error) {
	r, err := a.c.rpc.OperatorsGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return decOne("OperatorsGet", tooOld(err), r.GetError(), r.GetValue(), operatorFromPB)
}

func (a clientOperators) Upsert(ctx context.Context, o *store.Operator) error {
	return put("OperatorsUpsert", o, operatorToPB, func(pb *storev1.Operator) (result, error) {
		r, err := a.c.rpc.OperatorsUpsert(ctx, &storev1.OperatorWrite{TxId: a.c.txID, Value: pb})
		return r, tooOld(err)
	})
}

func (a clientOperators) List(ctx context.Context, tenantID string) ([]*store.Operator, error) {
	r, err := a.c.rpc.OperatorsList(ctx, &storev1.TenantScope{TxId: a.c.txID, TenantId: tenantID})
	return decList("OperatorsList", tooOld(err), r.GetError(), r.GetValues(), operatorFromPB)
}

func (a clientOperators) Delete(ctx context.Context, tenantID, userID string) error {
	r, err := a.c.rpc.OperatorsDelete(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: userID})
	return do("OperatorsDelete", r, tooOld(err))
}

func (a clientUsers) List(ctx context.Context, tenantID string, q *store.UserQuery, s store.UserSort, p store.Page) ([]*store.User, int, error) {
	// The host validates first: a nil kid cannot cross the wire, and a bad
	// tree must fail the same way whatever the plugin does with it.
	if err := q.Validate(); err != nil {
		return nil, 0, err
	}
	if err := s.Validate(); err != nil {
		return nil, 0, err
	}
	r, err := a.c.rpc.UsersList(ctx, &storev1.UsersListRequest{TxId: a.c.txID, TenantId: tenantID, Query: userQueryToPB(q),
		SortField: s.Field, SortDesc: s.Desc, Offset: int64(p.Offset), Limit: int64(p.Limit)})
	out, err := decList("UsersList", tooOld(err), r.GetError(), r.GetValues(), userFromPB)
	if err != nil {
		return nil, 0, err
	}
	return out, int(r.GetTotal()), nil
}

// ---- jobs ----

type clientJobs struct{ c *Client }

func (a clientJobs) Create(ctx context.Context, j *store.Job) error {
	return put("JobsCreate", j, jobToPB, func(pb *storev1.Job) (result, error) {
		r, err := a.c.rpc.JobsCreate(ctx, &storev1.JobWrite{TxId: a.c.txID, Value: pb})
		return r, tooOld(err)
	})
}

func (a clientJobs) Get(ctx context.Context, tenantID, id string) (*store.Job, error) {
	r, err := a.c.rpc.JobsGet(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	return decOne("JobsGet", tooOld(err), r.GetError(), r.GetValue(), jobFromPB)
}

func (a clientJobs) List(ctx context.Context, tenantID string, p store.Page) ([]*store.Job, int, error) {
	r, err := a.c.rpc.JobsList(ctx, &storev1.JobsListRequest{TxId: a.c.txID, TenantId: tenantID, Offset: int64(p.Offset), Limit: int64(p.Limit)})
	out, err := decList("JobsList", tooOld(err), r.GetError(), r.GetValues(), jobFromPB)
	if err != nil {
		return nil, 0, err
	}
	return out, int(r.GetTotal()), nil
}

func (a clientJobs) CountActive(ctx context.Context, tenantID string, t store.JobType) (int, error) {
	r, err := a.c.rpc.JobsCountActive(ctx, &storev1.JobsCountActiveRequest{TxId: a.c.txID, TenantId: tenantID, Type: string(t)})
	return counted("JobsCountActive", r, tooOld(err))
}

func (a clientJobs) Claim(ctx context.Context, owner string, now time.Time, lease time.Duration) (*store.Job, error) {
	r, err := a.c.rpc.JobsClaim(ctx, &storev1.JobsClaimRequest{TxId: a.c.txID, Owner: owner, Now: tsToPB(now), Lease: durationpb.New(lease)})
	return decOne("JobsClaim", tooOld(err), r.GetError(), r.GetValue(), jobFromPB)
}

func (a clientJobs) Renew(ctx context.Context, tenantID, id, owner string, until time.Time) error {
	r, err := a.c.rpc.JobsRenew(ctx, &storev1.JobsRenewRequest{TxId: a.c.txID, TenantId: tenantID, Id: id, Owner: owner, Until: tsToPB(until)})
	return do("JobsRenew", r, tooOld(err))
}

func (a clientJobs) Checkpoint(ctx context.Context, tenantID, id, owner string, progress int, s store.JobSummary, errs []store.JobError) error {
	req := &storev1.JobsCheckpointRequest{TxId: a.c.txID, TenantId: tenantID, Id: id, Owner: owner,
		Progress: int64(progress), Summary: jobSummaryToPB(s), Errors: make([]*storev1.JobError, 0, len(errs))}
	for i := range errs {
		pb, err := jobErrorToPB(&errs[i])
		if err != nil {
			return err
		}
		req.Errors = append(req.Errors, pb)
	}
	r, err := a.c.rpc.JobsCheckpoint(ctx, req)
	return do("JobsCheckpoint", r, tooOld(err))
}

func (a clientJobs) Finish(ctx context.Context, tenantID, id, owner string, st store.JobStatus, details string, at time.Time) error {
	r, err := a.c.rpc.JobsFinish(ctx, &storev1.JobsFinishRequest{TxId: a.c.txID, TenantId: tenantID, Id: id, Owner: owner,
		Status: string(st), Details: details, At: tsToPB(at)})
	return do("JobsFinish", r, tooOld(err))
}

func (a clientJobs) Errors(ctx context.Context, tenantID, id string) ([]store.JobError, error) {
	r, err := a.c.rpc.JobsErrors(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	ptrs, err := decList("JobsErrors", tooOld(err), r.GetError(), r.GetValues(), jobErrorFromPB)
	if err != nil {
		return nil, err
	}
	var out []store.JobError
	for _, p := range ptrs {
		out = append(out, *p)
	}
	return out, nil
}

func (a clientJobs) AppendFile(ctx context.Context, tenantID, id, owner string, seq int, chunk []byte) error {
	r, err := a.c.rpc.JobsAppendFile(ctx, &storev1.JobsAppendFileRequest{TxId: a.c.txID, TenantId: tenantID, Id: id, Owner: owner,
		Seq: int64(seq), Chunk: chunk})
	return do("JobsAppendFile", r, tooOld(err))
}

func (a clientJobs) ReadFile(ctx context.Context, tenantID, id string, fn func(chunk []byte) error) error {
	// The stream is cancelled when fn stops early.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := a.c.rpc.JobsReadFile(ctx, &storev1.ScopedKey{TxId: a.c.txID, TenantId: tenantID, Key: id})
	if err != nil {
		return rpcErr("JobsReadFile", tooOld(err))
	}
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return rpcErr("JobsReadFile", tooOld(err))
		}
		if e := errFromPB(m.GetError()); e != nil {
			return e
		}
		if err := fn(m.GetData()); err != nil {
			return err
		}
	}
}

// DeleteExpired treats a plugin that predates the RPC as holding no jobs:
// the sweeper calls it on every deployment.
func (a clientJobs) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	r, err := a.c.rpc.JobsDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: a.c.txID, Before: tsToPB(before)})
	if status.Code(err) == codes.Unimplemented {
		return 0, nil
	}
	return counted("JobsDeleteExpired", r, err)
}
