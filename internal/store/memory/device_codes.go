package memory

import (
	"context"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type deviceCodes struct{ s *Store }

func (r deviceCodes) Create(_ context.Context, d *store.DeviceCode) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.deviceCodes[key{d.TenantID, d.DeviceCodeHash}]; ok {
		return store.ErrConflict
	}
	for _, o := range r.s.deviceCodes {
		if o.TenantID == d.TenantID && o.UserCodeHash == d.UserCodeHash {
			return store.ErrConflict
		}
	}
	r.s.deviceCodes[key{d.TenantID, d.DeviceCodeHash}] = cloneDeviceCode(d)
	return nil
}

func (r deviceCodes) Get(_ context.Context, tenantID, deviceCodeHash string) (*store.DeviceCode, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	d, ok := r.s.deviceCodes[key{tenantID, deviceCodeHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneDeviceCode(d), nil
}

func (r deviceCodes) GetByUserCode(_ context.Context, tenantID, userCodeHash string) (*store.DeviceCode, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for _, d := range r.s.deviceCodes {
		if d.TenantID == tenantID && d.UserCodeHash == userCodeHash {
			return cloneDeviceCode(d), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r deviceCodes) Decide(_ context.Context, tenantID, deviceCodeHash string, dec store.DeviceDecision) (*store.DeviceCode, error) {
	r.s.lock()
	defer r.s.unlock()
	d, ok := r.s.deviceCodes[key{tenantID, deviceCodeHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	if d.Status != store.DeviceCodePending {
		return cloneDeviceCode(d), store.ErrAlreadyUsed
	}
	d.Status = dec.Status
	d.UserID = dec.UserID
	d.GrantedScopes = append([]string(nil), dec.GrantedScopes...)
	d.ActionEffects = slices.Clone(dec.ActionEffects)
	return cloneDeviceCode(d), nil
}

func (r deviceCodes) Poll(_ context.Context, tenantID, deviceCodeHash string, at time.Time) (store.DevicePoll, error) {
	r.s.lock()
	defer r.s.unlock()
	d, ok := r.s.deviceCodes[key{tenantID, deviceCodeHash}]
	if !ok {
		return store.DevicePoll{}, store.ErrNotFound
	}
	out := func(o store.DevicePollOutcome) (store.DevicePoll, error) {
		return store.DevicePoll{Code: cloneDeviceCode(d), Outcome: o}, nil
	}
	switch {
	case d.Status == store.DeviceCodeConsumed:
		return out(store.PollInvalid)
	case !at.Before(d.ExpiresAt):
		// Expiry is checked before consumption, so an approval the device
		// did not collect before expiry is lost: RFC 8628 treats an expired
		// device code as invalid (Auth0's behaviour here is unobserved).
		if d.ExpiredReportedAt != nil {
			return out(store.PollInvalid)
		}
		t := at
		d.ExpiredReportedAt = &t
		return out(store.PollExpired)
	case d.LastPolledAt != nil && at.Sub(*d.LastPolledAt) < store.MinPollGap:
		return out(store.PollSlowDown)
	}
	t := at
	d.LastPolledAt = &t
	switch d.Status {
	case store.DeviceCodeApproved:
		d.Status = store.DeviceCodeConsumed
		return out(store.PollApproved)
	case store.DeviceCodeDenied:
		d.Status = store.DeviceCodeConsumed
		return out(store.PollDenied)
	}
	return out(store.PollPending)
}

func (r deviceCodes) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, d := range r.s.deviceCodes {
		if !d.ExpiresAt.After(before) {
			delete(r.s.deviceCodes, k)
			n++
		}
	}
	return n, nil
}
