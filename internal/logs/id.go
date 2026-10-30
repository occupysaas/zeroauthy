package logs

import "github.com/zeroauthy/zeroauthy/internal/store"

func FormatID(seq int64) string       { return store.FormatLogID(seq) }
func ParseID(id string) (int64, bool) { seq, err := store.ParseLogID(id); return seq, err == nil }
