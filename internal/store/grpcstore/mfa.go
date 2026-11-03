package grpcstore

import (
	"context"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"reflect"
	"strings"
	"time"
)

type clientMFA struct{ c *Client }

func (c *Client) MFA() store.MFA { return clientMFA{c} }

// Phone is the unimplemented stub until the phone.v1 capability lands (Plan 34 Task 6).
func (c *Client) Phone() store.Phone { return store.UnimplementedPhone{} }

// A definitive unsupported operation remains latched for the connection lifetime.
// A newly connected client negotiates again; transient transport errors do not latch.
func (c *Client) CheckMFASupport(ctx context.Context) error {
	if c.mfaCap.v.Load() == 2 {
		return store.ErrMFAUnavailable
	}
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
		c.mfaCap.v.CompareAndSwap(0, 1)
	}
	if c.mfaCap.v.Load() == 2 {
		return store.ErrMFAUnavailable
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
func mfaRPCError(c *Client, err error, e *storev1.Error) error {
	if err != nil {
		err = capabilityError(err, store.ErrMFAUnavailable)
		if errors.Is(err, store.ErrMFAUnavailable) {
			c.mfaCap.v.Store(2)
		}
		return rpcErr("MFA", err)
	}
	err = errFromPB(e)
	if errors.Is(err, store.ErrMFAUnavailable) {
		c.mfaCap.v.Store(2)
	}
	return err
}

// copyMFA maps the explicitly defined protobuf record fields to their store counterparts.
func copyMFA(dst, src any) error {
	return copyMFAValue(reflect.ValueOf(dst).Elem(), reflect.ValueOf(src))
}

var mfaTimeType = reflect.TypeOf(time.Time{})

func copyMFAValue(d, s reflect.Value) error {
	if !s.IsValid() {
		return nil
	}
	if s.Kind() == reflect.Interface {
		if s.IsNil() {
			return nil
		}
		s = s.Elem()
	}
	if s.Kind() == reflect.Pointer {
		if s.IsNil() {
			return nil
		}
		s = s.Elem()
	}
	if d.Kind() == reflect.Pointer {
		d.Set(reflect.New(d.Type().Elem()))
		return copyMFAValue(d.Elem(), s)
	}
	if s.Type() == mfaTimeType {
		v := s.Interface().(time.Time)
		if !v.IsZero() {
			d.SetString(v.Format(time.RFC3339Nano))
		}
		return nil
	}
	if d.Type() == mfaTimeType {
		if s.String() == "" {
			return nil
		}
		v, err := time.Parse(time.RFC3339Nano, s.String())
		if err != nil {
			return store.ErrInvalid
		}
		d.Set(reflect.ValueOf(v))
		return nil
	}
	switch d.Kind() {
	case reflect.Struct:
		if s.Kind() != reflect.Struct {
			return store.ErrInvalid
		}
		// Both records must have the same exported fields; protobuf runtime internals are unexported.
		matched := make(map[int]bool)
		for i := 0; i < d.NumField(); i++ {
			f := d.Type().Field(i)
			if f.PkgPath != "" {
				continue
			}
			name := strings.ReplaceAll(strings.ToLower(f.Name), "_", "")
			found := false
			for j := 0; j < s.NumField(); j++ {
				sf := s.Type().Field(j)
				if sf.PkgPath != "" {
					continue
				}
				if strings.ReplaceAll(strings.ToLower(sf.Name), "_", "") == name {
					if matched[j] {
						return store.ErrInvalid
					}
					matched[j] = true
					found = true
					if err := copyMFAValue(d.Field(i), s.Field(j)); err != nil {
						return err
					}
					break
				}
			}
			if !found {
				return fmt.Errorf("MFA: missing field %s: %w", f.Name, store.ErrInvalid)
			}
		}
		for j := 0; j < s.NumField(); j++ {
			if s.Type().Field(j).PkgPath == "" && !matched[j] {
				return fmt.Errorf("MFA: extra field %s: %w", s.Type().Field(j).Name, store.ErrInvalid)
			}
		}
		return nil
	case reflect.Slice:
		if s.Kind() != reflect.Slice {
			return store.ErrInvalid
		}
		if s.IsNil() {
			return nil
		}
		d.Set(reflect.MakeSlice(d.Type(), s.Len(), s.Len()))
		for i := 0; i < s.Len(); i++ {
			if err := copyMFAValue(d.Index(i), s.Index(i)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		if s.Kind() != reflect.Map {
			return store.ErrInvalid
		}
		if s.IsNil() {
			return nil
		}
		d.Set(reflect.MakeMap(d.Type()))
		it := s.MapRange()
		for it.Next() {
			v := reflect.New(d.Type().Elem()).Elem()
			if err := copyMFAValue(v, it.Value()); err != nil {
				return err
			}
			d.SetMapIndex(it.Key(), v)
		}
		return nil
	default:
		if s.Type().ConvertibleTo(d.Type()) {
			d.Set(s.Convert(d.Type()))
			return nil
		}
		return fmt.Errorf("MFA: incompatible %s and %s: %w", s.Type(), d.Type(), store.ErrInvalid)
	}
}

func (o clientMFA) GetGuardian(ctx context.Context, tid string) (*store.GuardianSettings, error) {
	var out *store.GuardianSettings
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAGetGuardianRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAGetGuardian(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	if out != nil && out.Policies == nil {
		out.Policies = []string{}
	}
	return out, err
}
func (s *Server) MFAGetGuardian(ctx context.Context, q *storev1.MFAGetGuardianRequest) (*storev1.MFAGetGuardianResponse, error) {
	out := &storev1.MFAGetGuardianResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().GetGuardian(ctx, tid)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) PutGuardian(ctx context.Context, v *store.GuardianSettings, version int) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	if v == nil {
		return store.ErrInvalid
	}
	q := &storev1.MFAPutGuardianRequest{TxId: o.c.txID}
	if err := copyMFA(&q.V, v); err != nil {
		return err
	}
	if err := copyMFA(&q.Version, version); err != nil {
		return err
	}
	response, err := o.c.rpc.MFAPutGuardian(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFAPutGuardian(ctx context.Context, q *storev1.MFAPutGuardianRequest) (*storev1.MFAPutGuardianResponse, error) {
	out := &storev1.MFAPutGuardianResponse{}
	if q == nil || q.V == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var v *store.GuardianSettings
	if err := copyMFA(&v, q.V); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var version int
	if err := copyMFA(&version, q.Version); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().PutGuardian(ctx, v, version)
	}))
	return out, nil
}

func (o clientMFA) CreateAuthenticator(ctx context.Context, v *store.Authenticator) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	if v == nil {
		return store.ErrInvalid
	}
	q := &storev1.MFACreateAuthenticatorRequest{TxId: o.c.txID}
	if err := copyMFA(&q.V, v); err != nil {
		return err
	}
	response, err := o.c.rpc.MFACreateAuthenticator(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFACreateAuthenticator(ctx context.Context, q *storev1.MFACreateAuthenticatorRequest) (*storev1.MFACreateAuthenticatorResponse, error) {
	out := &storev1.MFACreateAuthenticatorResponse{}
	if q == nil || q.V == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var v *store.Authenticator
	if err := copyMFA(&v, q.V); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().CreateAuthenticator(ctx, v)
	}))
	return out, nil
}

func (o clientMFA) GetAuthenticator(ctx context.Context, tid string, uid string, id string) (*store.Authenticator, error) {
	var out *store.Authenticator
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAGetAuthenticatorRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Uid, uid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Id, id); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAGetAuthenticator(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAGetAuthenticator(ctx context.Context, q *storev1.MFAGetAuthenticatorRequest) (*storev1.MFAGetAuthenticatorResponse, error) {
	out := &storev1.MFAGetAuthenticatorResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var uid string
	if err := copyMFA(&uid, q.Uid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var id string
	if err := copyMFA(&id, q.Id); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().GetAuthenticator(ctx, tid, uid, id)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) GetAuthenticatorByEnrollmentID(ctx context.Context, tid string, enrollmentID string) (*store.Authenticator, error) {
	var out *store.Authenticator
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAGetAuthenticatorByEnrollmentIDRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.EnrollmentId, enrollmentID); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAGetAuthenticatorByEnrollmentID(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAGetAuthenticatorByEnrollmentID(ctx context.Context, q *storev1.MFAGetAuthenticatorByEnrollmentIDRequest) (*storev1.MFAGetAuthenticatorByEnrollmentIDResponse, error) {
	out := &storev1.MFAGetAuthenticatorByEnrollmentIDResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var enrollmentID string
	if err := copyMFA(&enrollmentID, q.EnrollmentId); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().GetAuthenticatorByEnrollmentID(ctx, tid, enrollmentID)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) ListAuthenticators(ctx context.Context, tid string, uid string) ([]store.Authenticator, error) {
	var out []store.Authenticator
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAListAuthenticatorsRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Uid, uid); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAListAuthenticators(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAListAuthenticators(ctx context.Context, q *storev1.MFAListAuthenticatorsRequest) (*storev1.MFAListAuthenticatorsResponse, error) {
	out := &storev1.MFAListAuthenticatorsResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var uid string
	if err := copyMFA(&uid, q.Uid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().ListAuthenticators(ctx, tid, uid)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) UpdateAuthenticator(ctx context.Context, v *store.Authenticator) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	if v == nil {
		return store.ErrInvalid
	}
	q := &storev1.MFAUpdateAuthenticatorRequest{TxId: o.c.txID}
	if err := copyMFA(&q.V, v); err != nil {
		return err
	}
	response, err := o.c.rpc.MFAUpdateAuthenticator(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFAUpdateAuthenticator(ctx context.Context, q *storev1.MFAUpdateAuthenticatorRequest) (*storev1.MFAUpdateAuthenticatorResponse, error) {
	out := &storev1.MFAUpdateAuthenticatorResponse{}
	if q == nil || q.V == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var v *store.Authenticator
	if err := copyMFA(&v, q.V); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().UpdateAuthenticator(ctx, v)
	}))
	return out, nil
}

func (o clientMFA) DeleteAuthenticator(ctx context.Context, tid string, uid string, id string) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	q := &storev1.MFADeleteAuthenticatorRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return err
	}
	if err := copyMFA(&q.Uid, uid); err != nil {
		return err
	}
	if err := copyMFA(&q.Id, id); err != nil {
		return err
	}
	response, err := o.c.rpc.MFADeleteAuthenticator(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFADeleteAuthenticator(ctx context.Context, q *storev1.MFADeleteAuthenticatorRequest) (*storev1.MFADeleteAuthenticatorResponse, error) {
	out := &storev1.MFADeleteAuthenticatorResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var uid string
	if err := copyMFA(&uid, q.Uid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var id string
	if err := copyMFA(&id, q.Id); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().DeleteAuthenticator(ctx, tid, uid, id)
	}))
	return out, nil
}

func (o clientMFA) DeleteUserAuthenticators(ctx context.Context, tid string, uid string, types []string) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	q := &storev1.MFADeleteUserAuthenticatorsRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return err
	}
	if err := copyMFA(&q.Uid, uid); err != nil {
		return err
	}
	q.Types = stringsToPB(types)
	response, err := o.c.rpc.MFADeleteUserAuthenticators(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFADeleteUserAuthenticators(ctx context.Context, q *storev1.MFADeleteUserAuthenticatorsRequest) (*storev1.MFADeleteUserAuthenticatorsResponse, error) {
	out := &storev1.MFADeleteUserAuthenticatorsResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var uid string
	if err := copyMFA(&uid, q.Uid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	types := stringsFromPB(q.Types)
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().DeleteUserAuthenticators(ctx, tid, uid, types)
	}))
	return out, nil
}

func (o clientMFA) AcceptTOTPStep(ctx context.Context, tid string, uid string, id string, step int64, at time.Time) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	q := &storev1.MFAAcceptTOTPStepRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return err
	}
	if err := copyMFA(&q.Uid, uid); err != nil {
		return err
	}
	if err := copyMFA(&q.Id, id); err != nil {
		return err
	}
	if err := copyMFA(&q.Step, step); err != nil {
		return err
	}
	if err := copyMFA(&q.At, at); err != nil {
		return err
	}
	response, err := o.c.rpc.MFAAcceptTOTPStep(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFAAcceptTOTPStep(ctx context.Context, q *storev1.MFAAcceptTOTPStepRequest) (*storev1.MFAAcceptTOTPStepResponse, error) {
	out := &storev1.MFAAcceptTOTPStepResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var uid string
	if err := copyMFA(&uid, q.Uid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var id string
	if err := copyMFA(&id, q.Id); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var step int64
	if err := copyMFA(&step, q.Step); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var at time.Time
	if err := copyMFA(&at, q.At); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().AcceptTOTPStep(ctx, tid, uid, id, step, at)
	}))
	return out, nil
}

func (o clientMFA) ReplaceRecoveryCode(ctx context.Context, tid string, uid string, oldHash string, newHash string, at time.Time) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	q := &storev1.MFAReplaceRecoveryCodeRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return err
	}
	if err := copyMFA(&q.Uid, uid); err != nil {
		return err
	}
	if err := copyMFA(&q.OldHash, oldHash); err != nil {
		return err
	}
	if err := copyMFA(&q.NewHash, newHash); err != nil {
		return err
	}
	if err := copyMFA(&q.At, at); err != nil {
		return err
	}
	response, err := o.c.rpc.MFAReplaceRecoveryCode(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFAReplaceRecoveryCode(ctx context.Context, q *storev1.MFAReplaceRecoveryCodeRequest) (*storev1.MFAReplaceRecoveryCodeResponse, error) {
	out := &storev1.MFAReplaceRecoveryCodeResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var uid string
	if err := copyMFA(&uid, q.Uid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var oldHash string
	if err := copyMFA(&oldHash, q.OldHash); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var newHash string
	if err := copyMFA(&newHash, q.NewHash); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var at time.Time
	if err := copyMFA(&at, q.At); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().ReplaceRecoveryCode(ctx, tid, uid, oldHash, newHash, at)
	}))
	return out, nil
}

func (o clientMFA) AcceptSignCount(ctx context.Context, tid string, uid string, id string, count uint32, at time.Time) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	q := &storev1.MFAAcceptSignCountRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return err
	}
	if err := copyMFA(&q.Uid, uid); err != nil {
		return err
	}
	if err := copyMFA(&q.Id, id); err != nil {
		return err
	}
	if err := copyMFA(&q.Count, count); err != nil {
		return err
	}
	if err := copyMFA(&q.At, at); err != nil {
		return err
	}
	response, err := o.c.rpc.MFAAcceptSignCount(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFAAcceptSignCount(ctx context.Context, q *storev1.MFAAcceptSignCountRequest) (*storev1.MFAAcceptSignCountResponse, error) {
	out := &storev1.MFAAcceptSignCountResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var uid string
	if err := copyMFA(&uid, q.Uid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var id string
	if err := copyMFA(&id, q.Id); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var count uint32
	if err := copyMFA(&count, q.Count); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var at time.Time
	if err := copyMFA(&at, q.At); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().AcceptSignCount(ctx, tid, uid, id, count, at)
	}))
	return out, nil
}

func (o clientMFA) CreateMFAToken(ctx context.Context, v *store.MFAToken) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	if v == nil {
		return store.ErrInvalid
	}
	q := &storev1.MFACreateMFATokenRequest{TxId: o.c.txID}
	if err := copyMFA(&q.V, v); err != nil {
		return err
	}
	response, err := o.c.rpc.MFACreateMFAToken(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFACreateMFAToken(ctx context.Context, q *storev1.MFACreateMFATokenRequest) (*storev1.MFACreateMFATokenResponse, error) {
	out := &storev1.MFACreateMFATokenResponse{}
	if q == nil || q.V == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var v *store.MFAToken
	if err := copyMFA(&v, q.V); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().CreateMFAToken(ctx, v)
	}))
	return out, nil
}

func (o clientMFA) ConsumeMFAToken(ctx context.Context, tid string, hash string, clientID string, now time.Time) (*store.MFAToken, error) {
	var out *store.MFAToken
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAConsumeMFATokenRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Hash, hash); err != nil {
		return out, err
	}
	if err := copyMFA(&q.ClientID, clientID); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Now, now); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAConsumeMFAToken(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAConsumeMFAToken(ctx context.Context, q *storev1.MFAConsumeMFATokenRequest) (*storev1.MFAConsumeMFATokenResponse, error) {
	out := &storev1.MFAConsumeMFATokenResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var hash string
	if err := copyMFA(&hash, q.Hash); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var clientID string
	if err := copyMFA(&clientID, q.ClientID); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var now time.Time
	if err := copyMFA(&now, q.Now); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().ConsumeMFAToken(ctx, tid, hash, clientID, now)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) PeekMFAToken(ctx context.Context, tid string, hash string, now time.Time) (*store.MFAToken, error) {
	var out *store.MFAToken
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAPeekMFATokenRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Hash, hash); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Now, now); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAPeekMFAToken(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAPeekMFAToken(ctx context.Context, q *storev1.MFAPeekMFATokenRequest) (*storev1.MFAPeekMFATokenResponse, error) {
	out := &storev1.MFAPeekMFATokenResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var hash string
	if err := copyMFA(&hash, q.Hash); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var now time.Time
	if err := copyMFA(&now, q.Now); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().PeekMFAToken(ctx, tid, hash, now)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) CreateChallenge(ctx context.Context, v *store.MFAChallenge) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	if v == nil {
		return store.ErrInvalid
	}
	q := &storev1.MFACreateChallengeRequest{TxId: o.c.txID}
	if err := copyMFA(&q.V, v); err != nil {
		return err
	}
	response, err := o.c.rpc.MFACreateChallenge(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFACreateChallenge(ctx context.Context, q *storev1.MFACreateChallengeRequest) (*storev1.MFACreateChallengeResponse, error) {
	out := &storev1.MFACreateChallengeResponse{}
	if q == nil || q.V == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var v *store.MFAChallenge
	if err := copyMFA(&v, q.V); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().CreateChallenge(ctx, v)
	}))
	return out, nil
}

func (o clientMFA) GetChallenge(ctx context.Context, tid string, id string, now time.Time) (*store.MFAChallenge, error) {
	var out *store.MFAChallenge
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAGetChallengeRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Id, id); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Now, now); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAGetChallenge(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAGetChallenge(ctx context.Context, q *storev1.MFAGetChallengeRequest) (*storev1.MFAGetChallengeResponse, error) {
	out := &storev1.MFAGetChallengeResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var id string
	if err := copyMFA(&id, q.Id); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var now time.Time
	if err := copyMFA(&now, q.Now); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().GetChallenge(ctx, tid, id, now)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) FailChallenge(ctx context.Context, tid string, id string) (int, error) {
	var out int
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAFailChallengeRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Id, id); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAFailChallenge(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAFailChallenge(ctx context.Context, q *storev1.MFAFailChallengeRequest) (*storev1.MFAFailChallengeResponse, error) {
	out := &storev1.MFAFailChallengeResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var id string
	if err := copyMFA(&id, q.Id); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().FailChallenge(ctx, tid, id)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) ConsumeChallenge(ctx context.Context, tid string, id string, now time.Time) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	q := &storev1.MFAConsumeChallengeRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return err
	}
	if err := copyMFA(&q.Id, id); err != nil {
		return err
	}
	if err := copyMFA(&q.Now, now); err != nil {
		return err
	}
	response, err := o.c.rpc.MFAConsumeChallenge(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFAConsumeChallenge(ctx context.Context, q *storev1.MFAConsumeChallengeRequest) (*storev1.MFAConsumeChallengeResponse, error) {
	out := &storev1.MFAConsumeChallengeResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var id string
	if err := copyMFA(&id, q.Id); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var now time.Time
	if err := copyMFA(&now, q.Now); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().ConsumeChallenge(ctx, tid, id, now)
	}))
	return out, nil
}

func (o clientMFA) CreateTicket(ctx context.Context, v *store.EnrollmentTicket) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	if v == nil {
		return store.ErrInvalid
	}
	q := &storev1.MFACreateTicketRequest{TxId: o.c.txID}
	if err := copyMFA(&q.V, v); err != nil {
		return err
	}
	response, err := o.c.rpc.MFACreateTicket(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFACreateTicket(ctx context.Context, q *storev1.MFACreateTicketRequest) (*storev1.MFACreateTicketResponse, error) {
	out := &storev1.MFACreateTicketResponse{}
	if q == nil || q.V == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var v *store.EnrollmentTicket
	if err := copyMFA(&v, q.V); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().CreateTicket(ctx, v)
	}))
	return out, nil
}

func (o clientMFA) ConsumeTicket(ctx context.Context, tid string, hash string, now time.Time) (*store.EnrollmentTicket, error) {
	var out *store.EnrollmentTicket
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAConsumeTicketRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Hash, hash); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Now, now); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAConsumeTicket(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAConsumeTicket(ctx context.Context, q *storev1.MFAConsumeTicketRequest) (*storev1.MFAConsumeTicketResponse, error) {
	out := &storev1.MFAConsumeTicketResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var hash string
	if err := copyMFA(&hash, q.Hash); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var now time.Time
	if err := copyMFA(&now, q.Now); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().ConsumeTicket(ctx, tid, hash, now)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) PeekTicket(ctx context.Context, tid string, hash string, now time.Time) (*store.EnrollmentTicket, error) {
	var out *store.EnrollmentTicket
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAPeekTicketRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Hash, hash); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Now, now); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAPeekTicket(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAPeekTicket(ctx context.Context, q *storev1.MFAPeekTicketRequest) (*storev1.MFAPeekTicketResponse, error) {
	out := &storev1.MFAPeekTicketResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var hash string
	if err := copyMFA(&hash, q.Hash); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var now time.Time
	if err := copyMFA(&now, q.Now); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().PeekTicket(ctx, tid, hash, now)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) PutBrowser(ctx context.Context, v *store.MFABrowser) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	if v == nil {
		return store.ErrInvalid
	}
	q := &storev1.MFAPutBrowserRequest{TxId: o.c.txID}
	if err := copyMFA(&q.V, v); err != nil {
		return err
	}
	response, err := o.c.rpc.MFAPutBrowser(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFAPutBrowser(ctx context.Context, q *storev1.MFAPutBrowserRequest) (*storev1.MFAPutBrowserResponse, error) {
	out := &storev1.MFAPutBrowserResponse{}
	if q == nil || q.V == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var v *store.MFABrowser
	if err := copyMFA(&v, q.V); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().PutBrowser(ctx, v)
	}))
	return out, nil
}

func (o clientMFA) GetBrowser(ctx context.Context, tid string, hash string, now time.Time) (*store.MFABrowser, error) {
	var out *store.MFABrowser
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAGetBrowserRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Hash, hash); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Now, now); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAGetBrowser(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAGetBrowser(ctx context.Context, q *storev1.MFAGetBrowserRequest) (*storev1.MFAGetBrowserResponse, error) {
	out := &storev1.MFAGetBrowserResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var hash string
	if err := copyMFA(&hash, q.Hash); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var now time.Time
	if err := copyMFA(&now, q.Now); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().GetBrowser(ctx, tid, hash, now)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) BumpRememberEpoch(ctx context.Context, tid string, uid string) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	q := &storev1.MFABumpRememberEpochRequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return err
	}
	if err := copyMFA(&q.Uid, uid); err != nil {
		return err
	}
	response, err := o.c.rpc.MFABumpRememberEpoch(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFABumpRememberEpoch(ctx context.Context, q *storev1.MFABumpRememberEpochRequest) (*storev1.MFABumpRememberEpochResponse, error) {
	out := &storev1.MFABumpRememberEpochResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var uid string
	if err := copyMFA(&uid, q.Uid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().BumpRememberEpoch(ctx, tid, uid)
	}))
	return out, nil
}

func (o clientMFA) PurgeMFA(ctx context.Context, before time.Time, limit int) (int, error) {
	var out int
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return out, err
	}
	q := &storev1.MFAPurgeMFARequest{TxId: o.c.txID}
	if err := copyMFA(&q.Before, before); err != nil {
		return out, err
	}
	if err := copyMFA(&q.Limit, limit); err != nil {
		return out, err
	}
	response, err := o.c.rpc.MFAPurgeMFA(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return out, err
	}
	err = copyMFA(&out, response.GetValue())
	return out, err
}
func (s *Server) MFAPurgeMFA(ctx context.Context, q *storev1.MFAPurgeMFARequest) (*storev1.MFAPurgeMFAResponse, error) {
	out := &storev1.MFAPurgeMFAResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var before time.Time
	if err := copyMFA(&before, q.Before); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var limit int
	if err := copyMFA(&limit, q.Limit); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		v, err := st.MFA().PurgeMFA(ctx, before, limit)
		if err != nil {
			return err
		}
		return copyMFA(&out.Value, v)
	}))
	return out, nil
}

func (o clientMFA) DeleteUserMFA(ctx context.Context, tid string, uid string) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	q := &storev1.MFADeleteUserMFARequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return err
	}
	if err := copyMFA(&q.Uid, uid); err != nil {
		return err
	}
	response, err := o.c.rpc.MFADeleteUserMFA(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFADeleteUserMFA(ctx context.Context, q *storev1.MFADeleteUserMFARequest) (*storev1.MFADeleteUserMFAResponse, error) {
	out := &storev1.MFADeleteUserMFAResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var uid string
	if err := copyMFA(&uid, q.Uid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().DeleteUserMFA(ctx, tid, uid)
	}))
	return out, nil
}

func (o clientMFA) DeleteTenantMFA(ctx context.Context, tid string) error {
	if err := o.c.CheckMFASupport(ctx); err != nil {
		return err
	}
	q := &storev1.MFADeleteTenantMFARequest{TxId: o.c.txID}
	if err := copyMFA(&q.Tid, tid); err != nil {
		return err
	}
	response, err := o.c.rpc.MFADeleteTenantMFA(ctx, q)
	if err = mfaRPCError(o.c, err, response.GetError()); err != nil {
		return err
	}
	return nil
}
func (s *Server) MFADeleteTenantMFA(ctx context.Context, q *storev1.MFADeleteTenantMFARequest) (*storev1.MFADeleteTenantMFAResponse, error) {
	out := &storev1.MFADeleteTenantMFAResponse{}
	if q == nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	var tid string
	if err := copyMFA(&tid, q.Tid); err != nil {
		out.Error = errToPB(store.ErrInvalid)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		return st.MFA().DeleteTenantMFA(ctx, tid)
	}))
	return out, nil
}
