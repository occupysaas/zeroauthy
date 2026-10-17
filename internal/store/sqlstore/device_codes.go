package sqlstore

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// errDeviceCodesNotImplemented is returned until the device codes repository
// is implemented for this driver.
var errDeviceCodesNotImplemented = errors.New("device codes: not implemented")

type deviceCodes struct{ s *Store }

func (s *Store) DeviceCodes() store.DeviceCodes { return deviceCodes{s} }

func (deviceCodes) Create(context.Context, *store.DeviceCode) error {
	return errDeviceCodesNotImplemented
}

func (deviceCodes) Get(context.Context, string, string) (*store.DeviceCode, error) {
	return nil, errDeviceCodesNotImplemented
}

func (deviceCodes) GetByUserCode(context.Context, string, string) (*store.DeviceCode, error) {
	return nil, errDeviceCodesNotImplemented
}

func (deviceCodes) Decide(context.Context, string, string, store.DeviceDecision) (*store.DeviceCode, error) {
	return nil, errDeviceCodesNotImplemented
}

func (deviceCodes) Poll(context.Context, string, string, time.Time) (store.DevicePoll, error) {
	return store.DevicePoll{}, errDeviceCodesNotImplemented
}

func (deviceCodes) DeleteExpired(context.Context, time.Time) (int, error) {
	return 0, errDeviceCodesNotImplemented
}
