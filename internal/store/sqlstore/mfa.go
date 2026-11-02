package sqlstore

import "github.com/zeroauthy/zeroauthy/internal/store"

func (*Store) MFA() store.MFA { return store.UnimplementedMFA{} }
