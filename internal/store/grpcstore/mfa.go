package grpcstore

import "github.com/zeroauthy/zeroauthy/internal/store"

func (*Client) MFA() store.MFA { return store.UnimplementedMFA{} }
