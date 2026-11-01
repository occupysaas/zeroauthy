package sqlstore

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/zeroauthy/zeroauthy/internal/logsearch"
)

// logSearchBody keeps only searchable strings as ASCII hex JSON. Database JSON
// implementations cannot all represent the accepted Body Unicode/numeric domain.
// Hex preserves byte equality and prefixes, including embedded NUL; Body is kept
// untouched for GET and stream delivery.
func logSearchBody(body []byte) string {
	fields := logsearch.BodyFields(body)
	if fields == nil {
		return "{}"
	}
	for k, v := range fields {
		fields[k] = hex.EncodeToString([]byte(v))
	}
	encoded, _ := json.Marshal(fields) // string-only maps always marshal successfully
	return string(encoded)
}

// Backfill in bounded pages, including sequence gaps. Original bodies and all
// runtime state remain unchanged. The migration runner commits the data step and
// version marker together; MySQL's column DDL can be resumed independently.
func (s *Store) backfillLogSearch(ctx context.Context) error {
	var after int64
	for {
		rows, err := s.query(ctx, `SELECT seq,body FROM tenant_logs WHERE seq>? ORDER BY seq LIMIT 100`, after)
		if err != nil {
			return err
		}
		type item struct {
			seq  int64
			body []byte
		}
		batch := make([]item, 0, 100)
		for rows.Next() {
			var e item
			if err := rows.Scan(&e.seq, &e.body); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, e := range batch {
			if _, err := s.exec(ctx, `UPDATE tenant_logs SET searchable_body=? WHERE seq=?`, logSearchBody(e.body), e.seq); err != nil {
				return err
			}
			after = e.seq
		}
	}
}
