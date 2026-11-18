package store

import (
	"bytes"
	"context"
	"errors"
	"time"
)

type ConnectionKey struct {
	TenantID, ConnectionID, KID, Use, Alg, State string
	CertDER, PrivateSealed                       []byte
	CurrentSince                                 *time.Time
	CreatedAt                                    time.Time
}

func (k *ConnectionKey) Clone() *ConnectionKey {
	if k == nil {
		return nil
	}
	c := *k
	c.CertDER = bytes.Clone(k.CertDER)
	c.PrivateSealed = bytes.Clone(k.PrivateSealed)
	if k.CurrentSince != nil {
		v := *k.CurrentSince
		c.CurrentSince = &v
	}
	return &c
}

var ErrConnectionKeysUnavailable = errors.New("store: connection keys unavailable")

type ConnectionKeysSupporter interface{ ConnectionKeysSupported() bool }
type ConnectionKeys interface {
	List(context.Context, string, string) ([]*ConnectionKey, error)
	Create(context.Context, string, string, string, *ConnectionKey, *ConnectionKey) error
	Rotate(context.Context, string, string, string, *ConnectionKey, time.Time) (*ConnectionKey, error)
}
type UnimplementedConnectionKeys struct{}

func (UnimplementedConnectionKeys) List(context.Context, string, string) ([]*ConnectionKey, error) {
	return nil, ErrConnectionKeysUnavailable
}
func (UnimplementedConnectionKeys) Create(context.Context, string, string, string, *ConnectionKey, *ConnectionKey) error {
	return ErrConnectionKeysUnavailable
}
func (UnimplementedConnectionKeys) Rotate(context.Context, string, string, string, *ConnectionKey, time.Time) (*ConnectionKey, error) {
	return nil, ErrConnectionKeysUnavailable
}

// ValidateConnectionKeyPair prevents mismatched ownership and key-id collisions
// before any repository mutation.
func ValidateConnectionKeyPair(tid, cid, use string, current, next *ConnectionKey) error {
	if current == nil || next == nil || current.KID == next.KID || (use != "signing" && use != "encryption") {
		return ErrInvalid
	}
	for _, k := range []*ConnectionKey{current, next} {
		if k.TenantID != tid || k.ConnectionID != cid || k.Use != use || k.KID == "" {
			return ErrInvalid
		}
	}
	return nil
}
