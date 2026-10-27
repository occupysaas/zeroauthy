package grpcstore

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// Plan 24 federation. Every client call maps Unimplemented (an older plugin
// server) to store.ErrFederationUnavailable, so social login stays
// unavailable instead of falling back to non-atomic behavior.

func fedKeyToPB(k store.FederatedIdentityKey) *storev1.FederatedIdentityKey {
	return &storev1.FederatedIdentityKey{TenantId: k.TenantID, ConnectionId: k.ConnectionID, Subject: []byte(k.Subject)}
}

func fedKeyFromPB(pb *storev1.FederatedIdentityKey) store.FederatedIdentityKey {
	return store.FederatedIdentityKey{TenantID: pb.GetTenantId(), ConnectionID: pb.GetConnectionId(), Subject: string(pb.GetSubject())}
}

func attemptToPB(a *store.FederationAttempt) (*storev1.FederationAttempt, error) {
	if a == nil {
		return nil, nil
	}
	pb := &storev1.FederationAttempt{
		StateHash: a.StateHash, TenantId: a.TenantID, TransactionId: a.TransactionID, ConnectionId: a.ConnectionID,
		Revision: a.Revision, IdentityEpoch: a.IdentityEpoch, CookieHash: a.CookieHash, Origin: a.Origin,
		CallbackUrl: a.CallbackURL, Issuer: a.Issuer,
		Endpoints: &storev1.FederationEndpoints{
			AuthorizationUrl: a.Endpoints.AuthorizationURL, TokenUrl: a.Endpoints.TokenURL, JwksUrl: a.Endpoints.JWKSURL,
			UserinfoUrl: a.Endpoints.UserInfoURL, TokenAuthMethod: a.Endpoints.TokenAuthMethod,
		},
		ExpiresAt: tsToPB(a.ExpiresAt), Status: a.Status, Superseded: a.Superseded, CreatedAt: tsToPB(a.CreatedAt),
	}
	if len(a.SealedProof) > 0 {
		pb.SealedProof = cloneBytes(a.SealedProof)
	}
	return pb, nil
}

func attemptFromPB(pb *storev1.FederationAttempt) (*store.FederationAttempt, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.ExpiresAt); err != nil {
		return nil, err
	}
	if err := checkTS(pb.CreatedAt); err != nil {
		return nil, err
	}
	e := pb.GetEndpoints()
	a := &store.FederationAttempt{
		StateHash: pb.StateHash, TenantID: pb.TenantId, TransactionID: pb.TransactionId, ConnectionID: pb.ConnectionId,
		Revision: pb.Revision, IdentityEpoch: pb.IdentityEpoch, CookieHash: pb.CookieHash, Origin: pb.Origin,
		CallbackURL: pb.CallbackUrl, Issuer: pb.Issuer,
		Endpoints: store.FederationEndpoints{
			AuthorizationURL: e.GetAuthorizationUrl(), TokenURL: e.GetTokenUrl(), JWKSURL: e.GetJwksUrl(),
			UserInfoURL: e.GetUserinfoUrl(), TokenAuthMethod: e.GetTokenAuthMethod(),
		},
		ExpiresAt: tsFromPB(pb.ExpiresAt), Status: pb.Status, Superseded: pb.Superseded, CreatedAt: tsFromPB(pb.CreatedAt),
	}
	if len(pb.SealedProof) > 0 {
		a.SealedProof = cloneBytes(pb.SealedProof)
	}
	return a, nil
}

type clientFederation struct{ c *Client }

func (c *Client) Federation() store.Federation { return clientFederation{c} }

func fedErr(err error) error { return capabilityError(err, store.ErrFederationUnavailable) }

func (r clientFederation) IdentityEpoch(ctx context.Context, tenantID string) (int64, error) {
	res, err := r.c.rpc.FederationIdentityEpoch(ctx, &storev1.TenantScope{TxId: r.c.txID, TenantId: tenantID})
	if err := do("FederationIdentityEpoch", res, fedErr(err)); err != nil {
		return 0, err
	}
	return res.GetValue(), nil
}

func (r clientFederation) BumpIdentityEpoch(ctx context.Context, tenantID string) error {
	res, err := r.c.rpc.FederationBumpIdentityEpoch(ctx, &storev1.TenantScope{TxId: r.c.txID, TenantId: tenantID})
	return do("FederationBumpIdentityEpoch", res, fedErr(err))
}

func (r clientFederation) CreateAttempt(ctx context.Context, a *store.FederationAttempt) error {
	if a != nil {
		if err := requireMicrosoftKey(ctx, r.c, store.FederatedIdentityKey{TenantID: a.TenantID, ConnectionID: a.ConnectionID}); err != nil {
			return err
		}
	}
	pb, err := attemptToPB(a)
	if err != nil {
		return err
	}
	res, err := r.c.rpc.FederationCreateAttempt(ctx, &storev1.FederationAttemptWrite{TxId: r.c.txID, Value: pb})
	return do("FederationCreateAttempt", res, fedErr(err))
}

func (r clientFederation) GetAttempt(ctx context.Context, tenantID, stateHash string) (*store.FederationAttempt, error) {
	res, err := r.c.rpc.FederationGetAttempt(ctx, &storev1.FederationAttemptKey{TxId: r.c.txID, TenantId: tenantID, StateHash: stateHash})
	return decOne("FederationGetAttempt", fedErr(err), res.GetError(), res.GetValue(), attemptFromPB)
}

func (r clientFederation) ClaimAttempt(ctx context.Context, tenantID, stateHash, cookieHash, origin string, now time.Time) (*store.FederationAttempt, error) {
	res, err := r.c.rpc.FederationClaimAttempt(ctx, &storev1.FederationClaimRequest{TxId: r.c.txID, TenantId: tenantID, StateHash: stateHash,
		CookieHash: cookieHash, Origin: origin, Now: tsToPB(now)})
	return decOne("FederationClaimAttempt", fedErr(err), res.GetError(), res.GetValue(), attemptFromPB)
}

func (r clientFederation) FinishAttempt(ctx context.Context, tenantID, stateHash string) error {
	res, err := r.c.rpc.FederationFinishAttempt(ctx, &storev1.FederationAttemptKey{TxId: r.c.txID, TenantId: tenantID, StateHash: stateHash})
	return do("FederationFinishAttempt", res, fedErr(err))
}

func (r clientFederation) PutIdentity(ctx context.Context, k store.FederatedIdentityKey, userID string) error {
	if err := requireMicrosoftKey(ctx, r.c, k); err != nil {
		return err
	}
	res, err := r.c.rpc.FederationPutIdentity(ctx, &storev1.FederatedIdentityWrite{TxId: r.c.txID, Key: fedKeyToPB(k), UserId: userID})
	return do("FederationPutIdentity", res, fedErr(err))
}

func (r clientFederation) DeleteIdentity(ctx context.Context, k store.FederatedIdentityKey, expectedUserID string) error {
	if err := requireMicrosoftKey(ctx, r.c, k); err != nil {
		return err
	}
	res, err := r.c.rpc.FederationDeleteIdentity(ctx, &storev1.FederatedIdentityWrite{TxId: r.c.txID, Key: fedKeyToPB(k), UserId: expectedUserID})
	return do("FederationDeleteIdentity", res, fedErr(err))
}

func (r clientFederation) GetTokens(ctx context.Context, k store.FederatedIdentityKey) ([]byte, error) {
	res, err := r.c.rpc.FederationGetTokens(ctx, &storev1.FederatedIdentityRequest{TxId: r.c.txID, Key: fedKeyToPB(k)})
	if err := do("FederationGetTokens", res, fedErr(err)); err != nil {
		return nil, err
	}
	return cloneBytes(res.GetSealed()), nil
}

func (r clientFederation) PutTokens(ctx context.Context, k store.FederatedIdentityKey, sealed []byte) error {
	if err := requireMicrosoftKey(ctx, r.c, k); err != nil {
		return err
	}
	res, err := r.c.rpc.FederationPutTokens(ctx, &storev1.FederatedTokensWrite{TxId: r.c.txID, Key: fedKeyToPB(k), Sealed: cloneBytes(sealed)})
	return do("FederationPutTokens", res, fedErr(err))
}

func (r clientFederation) DeleteTokens(ctx context.Context, k store.FederatedIdentityKey) error {
	if err := requireMicrosoftKey(ctx, r.c, k); err != nil {
		return err
	}
	res, err := r.c.rpc.FederationDeleteTokens(ctx, &storev1.FederatedIdentityRequest{TxId: r.c.txID, Key: fedKeyToPB(k)})
	return do("FederationDeleteTokens", res, fedErr(err))
}

func (r clientFederation) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := r.c.rpc.FederationDeleteExpired(ctx, &storev1.DeleteExpiredRequest{TxId: r.c.txID, Before: tsToPB(before)})
	return counted("FederationDeleteExpired", res, fedErr(err))
}

func (a clientUsers) FindByIdentity(ctx context.Context, tenantID, connectionID, subject string) (*store.User, error) {
	key := store.FederatedIdentityKey{TenantID: tenantID, ConnectionID: connectionID, Subject: subject}
	res, err := a.c.rpc.UsersFindByIdentity(ctx, &storev1.UsersFindByIdentityRequest{TxId: a.c.txID, Key: fedKeyToPB(key)})
	return decOne("UsersFindByIdentity", fedErr(err), res.GetError(), res.GetValue(), userFromPB)
}

// Server side.

func (s *Server) FederationIdentityEpoch(ctx context.Context, r *storev1.TenantScope) (*storev1.VersionResult, error) {
	var v int64
	err := s.with(r.TxId, func(st store.Store) (e error) {
		v, e = st.Federation().IdentityEpoch(ctx, r.TenantId)
		return e
	})
	return &storev1.VersionResult{Error: errToPB(err), Value: v}, nil
}

func (s *Server) FederationBumpIdentityEpoch(ctx context.Context, r *storev1.TenantScope) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.Federation().BumpIdentityEpoch(ctx, r.TenantId) }), nil
}

func (s *Server) FederationCreateAttempt(ctx context.Context, r *storev1.FederationAttemptWrite) (*storev1.Result, error) {
	return write(s, r.TxId, r.Value, attemptFromPB, func(st store.Store, a *store.FederationAttempt) error {
		if err := requireMicrosoftKey(ctx, st, store.FederatedIdentityKey{TenantID: a.TenantID, ConnectionID: a.ConnectionID}); err != nil {
			return err
		}
		return st.Federation().CreateAttempt(ctx, a)
	}), nil
}

func (s *Server) FederationGetAttempt(ctx context.Context, r *storev1.FederationAttemptKey) (*storev1.FederationAttemptResult, error) {
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.FederationAttempt, error) {
		return st.Federation().GetAttempt(ctx, r.TenantId, r.StateHash)
	}, attemptToPB)
	return &storev1.FederationAttemptResult{Error: e, Value: v}, err
}

func (s *Server) FederationClaimAttempt(ctx context.Context, r *storev1.FederationClaimRequest) (*storev1.FederationAttemptResult, error) {
	if err := checkTS(r.Now); err != nil {
		return &storev1.FederationAttemptResult{Error: errToPB(err)}, nil
	}
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.FederationAttempt, error) {
		return st.Federation().ClaimAttempt(ctx, r.TenantId, r.StateHash, r.CookieHash, r.Origin, tsFromPB(r.Now))
	}, attemptToPB)
	return &storev1.FederationAttemptResult{Error: e, Value: v}, err
}

func (s *Server) FederationFinishAttempt(ctx context.Context, r *storev1.FederationAttemptKey) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return st.Federation().FinishAttempt(ctx, r.TenantId, r.StateHash) }), nil
}

func (s *Server) FederationPutIdentity(ctx context.Context, r *storev1.FederatedIdentityWrite) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		if err := requireMicrosoftKey(ctx, st, fedKeyFromPB(r.Key)); err != nil {
			return err
		}
		return st.Federation().PutIdentity(ctx, fedKeyFromPB(r.Key), r.UserId)
	}), nil
}

func (s *Server) FederationDeleteIdentity(ctx context.Context, r *storev1.FederatedIdentityWrite) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		if err := requireMicrosoftKey(ctx, st, fedKeyFromPB(r.Key)); err != nil {
			return err
		}
		return st.Federation().DeleteIdentity(ctx, fedKeyFromPB(r.Key), r.UserId)
	}), nil
}

func (s *Server) FederationGetTokens(ctx context.Context, r *storev1.FederatedIdentityRequest) (*storev1.FederatedTokensResult, error) {
	var v []byte
	err := s.with(r.TxId, func(st store.Store) (e error) {
		v, e = st.Federation().GetTokens(ctx, fedKeyFromPB(r.Key))
		return e
	})
	return &storev1.FederatedTokensResult{Error: errToPB(err), Sealed: v}, nil
}

func (s *Server) FederationPutTokens(ctx context.Context, r *storev1.FederatedTokensWrite) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		if err := requireMicrosoftKey(ctx, st, fedKeyFromPB(r.Key)); err != nil {
			return err
		}
		return st.Federation().PutTokens(ctx, fedKeyFromPB(r.Key), r.Sealed)
	}), nil
}

func (s *Server) FederationDeleteTokens(ctx context.Context, r *storev1.FederatedIdentityRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error {
		if err := requireMicrosoftKey(ctx, st, fedKeyFromPB(r.Key)); err != nil {
			return err
		}
		return st.Federation().DeleteTokens(ctx, fedKeyFromPB(r.Key))
	}), nil
}

func (s *Server) FederationDeleteExpired(ctx context.Context, r *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	if err := checkTS(r.Before); err != nil {
		return &storev1.CountResult{Error: errToPB(err)}, nil
	}
	var n int
	err := s.with(r.TxId, func(st store.Store) (e error) {
		n, e = st.Federation().DeleteExpired(ctx, tsFromPB(r.Before))
		return e
	})
	return &storev1.CountResult{Error: errToPB(err), Count: int64(n)}, nil
}

func (s *Server) UsersFindByIdentity(ctx context.Context, r *storev1.UsersFindByIdentityRequest) (*storev1.UserResult, error) {
	k := fedKeyFromPB(r.Key)
	v, e, err := one(s, r.TxId, func(st store.Store) (*store.User, error) {
		return st.Users().FindByIdentity(ctx, k.TenantID, k.ConnectionID, k.Subject)
	}, userToPB)
	return &storev1.UserResult{Error: e, Value: v}, err
}

// MicrosoftFederationSupported verifies the plugin and its selected backing
// transaction view implement canonical Microsoft identity ownership.
func (c *Client) MicrosoftFederationSupported(ctx context.Context) error {
	r, err := c.rpc.MicrosoftFederationSupported(ctx, &storev1.MicrosoftFederationCapabilitiesRequest{TxId: c.txID})
	return do("MicrosoftFederationSupported", r, fedErr(err))
}
func requireMicrosoftBacking(ctx context.Context, st store.Store) error {
	capability, ok := st.(store.MicrosoftFederationSupporter)
	if !ok {
		return store.ErrFederationUnavailable
	}
	return capability.MicrosoftFederationSupported(ctx)
}
func (s *Server) MicrosoftFederationSupported(ctx context.Context, r *storev1.MicrosoftFederationCapabilitiesRequest) (*storev1.Result, error) {
	return exec(s, r.TxId, func(st store.Store) error { return requireMicrosoftBacking(ctx, st) }), nil
}
func microsoftStrategy(strategy string) bool { return strategy == "windowslive" || strategy == "waad" }
func microsoftUser(u *store.User) bool {
	if u != nil {
		for _, id := range u.Identities {
			if microsoftStrategy(id.Provider) {
				return true
			}
		}
	}
	return false
}

func requireMicrosoftKey(ctx context.Context, st store.Store, key store.FederatedIdentityKey) error {
	c, err := st.Connections().Get(ctx, key.TenantID, key.ConnectionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} // retain predecessor repository semantics for orphan keys
	if err != nil {
		return err
	}
	if microsoftStrategy(c.Strategy) {
		return requireMicrosoftBacking(ctx, st)
	}
	return nil
}
