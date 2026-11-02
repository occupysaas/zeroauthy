package grpcstore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
	"time"
)

type clientMFA struct{ c *Client }

func (c *Client) MFA() store.MFA { return clientMFA{c} }
func (c *Client) CheckMFASupport(ctx context.Context) error {
	v, err := c.rpc.MFACapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("MFA capability", capabilityError(err, store.ErrMFAUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < 1 {
			err = store.ErrMFAUnavailable
		}
	}
	if errors.Is(err, store.ErrMFAUnavailable) {
		c.mfaCap.v.Store(2)
	} else if err == nil {
		c.mfaCap.v.Store(1)
	}
	return err
}
func (c *Client) MFASupported() bool {
	switch c.mfaCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckMFASupport(ctx) == nil
}
func (s *Server) MFACapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if c, ok := s.st.(store.MFASupporter); ok {
		if err := c.CheckMFASupport(ctx); err != nil {
			return &storev1.EventsCapabilitiesResult{Error: errToPB(err)}, nil
		}
		if !c.MFASupported() {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
	}
	switch s.st.MFA().(type) {
	case store.UnimplementedMFA, *store.UnimplementedMFA:
		return &storev1.EventsCapabilitiesResult{}, nil
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}
func mfaCall(ctx context.Context, c *Client, args any, rpc func(context.Context, *storev1.MFARequest, ...grpc.CallOption) (*storev1.MFAResponse, error), out any) error {
	if err := c.CheckMFASupport(ctx); err != nil {
		return err
	}
	b, err := json.Marshal(args)
	if err != nil {
		return err
	}
	v, err := rpc(ctx, &storev1.MFARequest{TxId: c.txID, ArgsJson: b})
	if err != nil {
		err = capabilityError(err, store.ErrMFAUnavailable)
		if errors.Is(err, store.ErrMFAUnavailable) {
			c.mfaCap.v.Store(2)
		}
		return rpcErr("MFA", err)
	}
	if err = errFromPB(v.Error); err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(v.ValueJson, out)
	}
	return nil
}
func (s *Server) mfaServe(q *storev1.MFARequest, args any, fn func(store.MFA) (any, error)) *storev1.MFAResponse {
	out := &storev1.MFAResponse{}
	if err := json.Unmarshal(q.ArgsJson, args); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := fn(st.MFA())
		if err != nil {
			return err
		}
		if v != nil {
			out.ValueJson, err = json.Marshal(v)
		}
		return err
	}))
	return out
}

type mfaGetGuardianArgs struct{ Tid string }

func (o clientMFA) GetGuardian(ctx context.Context, tid string) (*store.GuardianSettings, error) {
	var out *store.GuardianSettings
	err := mfaCall(ctx, o.c, mfaGetGuardianArgs{Tid: tid}, o.c.rpc.MFAGetGuardian, &out)
	return out, err
}
func (s *Server) MFAGetGuardian(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaGetGuardianArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { v, err := r.GetGuardian(ctx, a.Tid); return v, err }), nil
}

type mfaPutGuardianArgs struct {
	V       *store.GuardianSettings
	Version int
}

func (o clientMFA) PutGuardian(ctx context.Context, v *store.GuardianSettings, version int) error {
	return mfaCall(ctx, o.c, mfaPutGuardianArgs{V: v, Version: version}, o.c.rpc.MFAPutGuardian, nil)
}
func (s *Server) MFAPutGuardian(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaPutGuardianArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.PutGuardian(ctx, a.V, a.Version) }), nil
}

type mfaCreateAuthenticatorArgs struct{ V *store.Authenticator }

func (o clientMFA) CreateAuthenticator(ctx context.Context, v *store.Authenticator) error {
	return mfaCall(ctx, o.c, mfaCreateAuthenticatorArgs{V: v}, o.c.rpc.MFACreateAuthenticator, nil)
}
func (s *Server) MFACreateAuthenticator(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaCreateAuthenticatorArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.CreateAuthenticator(ctx, a.V) }), nil
}

type mfaGetAuthenticatorArgs struct {
	Tid string
	Uid string
	Id  string
}

func (o clientMFA) GetAuthenticator(ctx context.Context, tid string, uid string, id string) (*store.Authenticator, error) {
	var out *store.Authenticator
	err := mfaCall(ctx, o.c, mfaGetAuthenticatorArgs{Tid: tid, Uid: uid, Id: id}, o.c.rpc.MFAGetAuthenticator, &out)
	return out, err
}
func (s *Server) MFAGetAuthenticator(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaGetAuthenticatorArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { v, err := r.GetAuthenticator(ctx, a.Tid, a.Uid, a.Id); return v, err }), nil
}

type mfaListAuthenticatorsArgs struct {
	Tid string
	Uid string
}

func (o clientMFA) ListAuthenticators(ctx context.Context, tid string, uid string) ([]store.Authenticator, error) {
	var out []store.Authenticator
	err := mfaCall(ctx, o.c, mfaListAuthenticatorsArgs{Tid: tid, Uid: uid}, o.c.rpc.MFAListAuthenticators, &out)
	return out, err
}
func (s *Server) MFAListAuthenticators(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaListAuthenticatorsArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { v, err := r.ListAuthenticators(ctx, a.Tid, a.Uid); return v, err }), nil
}

type mfaUpdateAuthenticatorArgs struct{ V *store.Authenticator }

func (o clientMFA) UpdateAuthenticator(ctx context.Context, v *store.Authenticator) error {
	return mfaCall(ctx, o.c, mfaUpdateAuthenticatorArgs{V: v}, o.c.rpc.MFAUpdateAuthenticator, nil)
}
func (s *Server) MFAUpdateAuthenticator(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaUpdateAuthenticatorArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.UpdateAuthenticator(ctx, a.V) }), nil
}

type mfaDeleteAuthenticatorArgs struct {
	Tid string
	Uid string
	Id  string
}

func (o clientMFA) DeleteAuthenticator(ctx context.Context, tid string, uid string, id string) error {
	return mfaCall(ctx, o.c, mfaDeleteAuthenticatorArgs{Tid: tid, Uid: uid, Id: id}, o.c.rpc.MFADeleteAuthenticator, nil)
}
func (s *Server) MFADeleteAuthenticator(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaDeleteAuthenticatorArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.DeleteAuthenticator(ctx, a.Tid, a.Uid, a.Id) }), nil
}

type mfaDeleteUserAuthenticatorsArgs struct {
	Tid   string
	Uid   string
	Types []string
}

func (o clientMFA) DeleteUserAuthenticators(ctx context.Context, tid string, uid string, types []string) error {
	return mfaCall(ctx, o.c, mfaDeleteUserAuthenticatorsArgs{Tid: tid, Uid: uid, Types: types}, o.c.rpc.MFADeleteUserAuthenticators, nil)
}
func (s *Server) MFADeleteUserAuthenticators(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaDeleteUserAuthenticatorsArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.DeleteUserAuthenticators(ctx, a.Tid, a.Uid, a.Types) }), nil
}

type mfaAcceptTOTPStepArgs struct {
	Tid  string
	Uid  string
	Id   string
	Step int64
	At   time.Time
}

func (o clientMFA) AcceptTOTPStep(ctx context.Context, tid string, uid string, id string, step int64, at time.Time) error {
	return mfaCall(ctx, o.c, mfaAcceptTOTPStepArgs{Tid: tid, Uid: uid, Id: id, Step: step, At: at}, o.c.rpc.MFAAcceptTOTPStep, nil)
}
func (s *Server) MFAAcceptTOTPStep(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaAcceptTOTPStepArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.AcceptTOTPStep(ctx, a.Tid, a.Uid, a.Id, a.Step, a.At) }), nil
}

type mfaReplaceRecoveryCodeArgs struct {
	Tid     string
	Uid     string
	Oldhash string
	Newhash string
	At      time.Time
}

func (o clientMFA) ReplaceRecoveryCode(ctx context.Context, tid string, uid string, oldHash string, newHash string, at time.Time) error {
	return mfaCall(ctx, o.c, mfaReplaceRecoveryCodeArgs{Tid: tid, Uid: uid, Oldhash: oldHash, Newhash: newHash, At: at}, o.c.rpc.MFAReplaceRecoveryCode, nil)
}
func (s *Server) MFAReplaceRecoveryCode(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaReplaceRecoveryCodeArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) {
		return nil, r.ReplaceRecoveryCode(ctx, a.Tid, a.Uid, a.Oldhash, a.Newhash, a.At)
	}), nil
}

type mfaAcceptSignCountArgs struct {
	Tid   string
	Uid   string
	Id    string
	Count uint32
	At    time.Time
}

func (o clientMFA) AcceptSignCount(ctx context.Context, tid string, uid string, id string, count uint32, at time.Time) error {
	return mfaCall(ctx, o.c, mfaAcceptSignCountArgs{Tid: tid, Uid: uid, Id: id, Count: count, At: at}, o.c.rpc.MFAAcceptSignCount, nil)
}
func (s *Server) MFAAcceptSignCount(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaAcceptSignCountArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.AcceptSignCount(ctx, a.Tid, a.Uid, a.Id, a.Count, a.At) }), nil
}

type mfaCreateMFATokenArgs struct{ V *store.MFAToken }

func (o clientMFA) CreateMFAToken(ctx context.Context, v *store.MFAToken) error {
	return mfaCall(ctx, o.c, mfaCreateMFATokenArgs{V: v}, o.c.rpc.MFACreateMFAToken, nil)
}
func (s *Server) MFACreateMFAToken(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaCreateMFATokenArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.CreateMFAToken(ctx, a.V) }), nil
}

type mfaConsumeMFATokenArgs struct {
	Tid      string
	Hash     string
	Clientid string
	Now      time.Time
}

func (o clientMFA) ConsumeMFAToken(ctx context.Context, tid string, hash string, clientID string, now time.Time) (*store.MFAToken, error) {
	var out *store.MFAToken
	err := mfaCall(ctx, o.c, mfaConsumeMFATokenArgs{Tid: tid, Hash: hash, Clientid: clientID, Now: now}, o.c.rpc.MFAConsumeMFAToken, &out)
	return out, err
}
func (s *Server) MFAConsumeMFAToken(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaConsumeMFATokenArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) {
		v, err := r.ConsumeMFAToken(ctx, a.Tid, a.Hash, a.Clientid, a.Now)
		return v, err
	}), nil
}

type mfaPeekMFATokenArgs struct {
	Tid  string
	Hash string
	Now  time.Time
}

func (o clientMFA) PeekMFAToken(ctx context.Context, tid string, hash string, now time.Time) (*store.MFAToken, error) {
	var out *store.MFAToken
	err := mfaCall(ctx, o.c, mfaPeekMFATokenArgs{Tid: tid, Hash: hash, Now: now}, o.c.rpc.MFAPeekMFAToken, &out)
	return out, err
}
func (s *Server) MFAPeekMFAToken(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaPeekMFATokenArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { v, err := r.PeekMFAToken(ctx, a.Tid, a.Hash, a.Now); return v, err }), nil
}

type mfaCreateChallengeArgs struct{ V *store.MFAChallenge }

func (o clientMFA) CreateChallenge(ctx context.Context, v *store.MFAChallenge) error {
	return mfaCall(ctx, o.c, mfaCreateChallengeArgs{V: v}, o.c.rpc.MFACreateChallenge, nil)
}
func (s *Server) MFACreateChallenge(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaCreateChallengeArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.CreateChallenge(ctx, a.V) }), nil
}

type mfaGetChallengeArgs struct {
	Tid string
	Id  string
	Now time.Time
}

func (o clientMFA) GetChallenge(ctx context.Context, tid string, id string, now time.Time) (*store.MFAChallenge, error) {
	var out *store.MFAChallenge
	err := mfaCall(ctx, o.c, mfaGetChallengeArgs{Tid: tid, Id: id, Now: now}, o.c.rpc.MFAGetChallenge, &out)
	return out, err
}
func (s *Server) MFAGetChallenge(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaGetChallengeArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { v, err := r.GetChallenge(ctx, a.Tid, a.Id, a.Now); return v, err }), nil
}

type mfaFailChallengeArgs struct {
	Tid string
	Id  string
}

func (o clientMFA) FailChallenge(ctx context.Context, tid string, id string) (int, error) {
	var out int
	err := mfaCall(ctx, o.c, mfaFailChallengeArgs{Tid: tid, Id: id}, o.c.rpc.MFAFailChallenge, &out)
	return out, err
}
func (s *Server) MFAFailChallenge(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaFailChallengeArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { v, err := r.FailChallenge(ctx, a.Tid, a.Id); return v, err }), nil
}

type mfaConsumeChallengeArgs struct {
	Tid string
	Id  string
	Now time.Time
}

func (o clientMFA) ConsumeChallenge(ctx context.Context, tid string, id string, now time.Time) error {
	return mfaCall(ctx, o.c, mfaConsumeChallengeArgs{Tid: tid, Id: id, Now: now}, o.c.rpc.MFAConsumeChallenge, nil)
}
func (s *Server) MFAConsumeChallenge(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaConsumeChallengeArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.ConsumeChallenge(ctx, a.Tid, a.Id, a.Now) }), nil
}

type mfaCreateTicketArgs struct{ V *store.EnrollmentTicket }

func (o clientMFA) CreateTicket(ctx context.Context, v *store.EnrollmentTicket) error {
	return mfaCall(ctx, o.c, mfaCreateTicketArgs{V: v}, o.c.rpc.MFACreateTicket, nil)
}
func (s *Server) MFACreateTicket(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaCreateTicketArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.CreateTicket(ctx, a.V) }), nil
}

type mfaConsumeTicketArgs struct {
	Tid  string
	Hash string
	Now  time.Time
}

func (o clientMFA) ConsumeTicket(ctx context.Context, tid string, hash string, now time.Time) (*store.EnrollmentTicket, error) {
	var out *store.EnrollmentTicket
	err := mfaCall(ctx, o.c, mfaConsumeTicketArgs{Tid: tid, Hash: hash, Now: now}, o.c.rpc.MFAConsumeTicket, &out)
	return out, err
}
func (s *Server) MFAConsumeTicket(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaConsumeTicketArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { v, err := r.ConsumeTicket(ctx, a.Tid, a.Hash, a.Now); return v, err }), nil
}

type mfaPutBrowserArgs struct{ V *store.MFABrowser }

func (o clientMFA) PutBrowser(ctx context.Context, v *store.MFABrowser) error {
	return mfaCall(ctx, o.c, mfaPutBrowserArgs{V: v}, o.c.rpc.MFAPutBrowser, nil)
}
func (s *Server) MFAPutBrowser(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaPutBrowserArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.PutBrowser(ctx, a.V) }), nil
}

type mfaGetBrowserArgs struct {
	Tid  string
	Hash string
	Now  time.Time
}

func (o clientMFA) GetBrowser(ctx context.Context, tid string, hash string, now time.Time) (*store.MFABrowser, error) {
	var out *store.MFABrowser
	err := mfaCall(ctx, o.c, mfaGetBrowserArgs{Tid: tid, Hash: hash, Now: now}, o.c.rpc.MFAGetBrowser, &out)
	return out, err
}
func (s *Server) MFAGetBrowser(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaGetBrowserArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { v, err := r.GetBrowser(ctx, a.Tid, a.Hash, a.Now); return v, err }), nil
}

type mfaBumpRememberEpochArgs struct {
	Tid string
	Uid string
}

func (o clientMFA) BumpRememberEpoch(ctx context.Context, tid string, uid string) error {
	return mfaCall(ctx, o.c, mfaBumpRememberEpochArgs{Tid: tid, Uid: uid}, o.c.rpc.MFABumpRememberEpoch, nil)
}
func (s *Server) MFABumpRememberEpoch(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaBumpRememberEpochArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.BumpRememberEpoch(ctx, a.Tid, a.Uid) }), nil
}

type mfaPurgeMFAArgs struct {
	Before time.Time
	Limit  int
}

func (o clientMFA) PurgeMFA(ctx context.Context, before time.Time, limit int) (int, error) {
	var out int
	err := mfaCall(ctx, o.c, mfaPurgeMFAArgs{Before: before, Limit: limit}, o.c.rpc.MFAPurgeMFA, &out)
	return out, err
}
func (s *Server) MFAPurgeMFA(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaPurgeMFAArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { v, err := r.PurgeMFA(ctx, a.Before, a.Limit); return v, err }), nil
}

type mfaDeleteUserMFAArgs struct {
	Tid string
	Uid string
}

func (o clientMFA) DeleteUserMFA(ctx context.Context, tid string, uid string) error {
	return mfaCall(ctx, o.c, mfaDeleteUserMFAArgs{Tid: tid, Uid: uid}, o.c.rpc.MFADeleteUserMFA, nil)
}
func (s *Server) MFADeleteUserMFA(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaDeleteUserMFAArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.DeleteUserMFA(ctx, a.Tid, a.Uid) }), nil
}

type mfaDeleteTenantMFAArgs struct{ Tid string }

func (o clientMFA) DeleteTenantMFA(ctx context.Context, tid string) error {
	return mfaCall(ctx, o.c, mfaDeleteTenantMFAArgs{Tid: tid}, o.c.rpc.MFADeleteTenantMFA, nil)
}
func (s *Server) MFADeleteTenantMFA(ctx context.Context, q *storev1.MFARequest) (*storev1.MFAResponse, error) {
	var a mfaDeleteTenantMFAArgs
	return s.mfaServe(q, &a, func(r store.MFA) (any, error) { return nil, r.DeleteTenantMFA(ctx, a.Tid) }), nil
}
