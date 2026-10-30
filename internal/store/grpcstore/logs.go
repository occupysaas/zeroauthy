package grpcstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/logsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
	"time"
)

const logsCapability = 1

var _ store.LogsSupporter = (*Client)(nil)

type clientLogs struct{ c *Client }

func (c *Client) Logs() store.Logs { return clientLogs{c} }

// Only definitive answers are cached by the cheap predicate. Active operations
// re-probe so reconnects and capability upgrades cannot retain a stale answer.
func (c *Client) CheckLogsSupport(ctx context.Context) error {
	v, err := c.rpc.LogsCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("Logs capability", capabilityError(err, store.ErrLogsUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < logsCapability {
			err = store.ErrLogsUnavailable
		}
	}
	if errors.Is(err, store.ErrLogsUnavailable) {
		c.logsCap.v.Store(2)
	} else if err == nil {
		c.logsCap.v.Store(1)
	}
	return err
}
func (c *Client) LogsSupported() bool {
	switch c.logsCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckLogsSupport(ctx) == nil
}
func (s *Server) LogsCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.LogsCapabilitiesResult, error) {
	if c, ok := s.st.(store.LogsSupporter); ok {
		if err := c.CheckLogsSupport(ctx); err != nil {
			return &storev1.LogsCapabilitiesResult{Error: errToPB(err)}, nil
		}
	}
	// Do not call repository methods here: a held memory transaction owns its
	// outer lock. An explicit unavailable stub is the driver's declaration.
	switch s.st.Logs().(type) {
	case store.UnimplementedLogs, *store.UnimplementedLogs:
		return &storev1.LogsCapabilitiesResult{}, nil
	}
	return &storev1.LogsCapabilitiesResult{Version: logsCapability}, nil
}
func logsCall(c *Client, ctx context.Context, q *storev1.LogsRequest, rpc func(context.Context, *storev1.LogsRequest, ...grpc.CallOption) (*storev1.LogsResponse, error)) (*storev1.LogsResponse, error) {
	if err := c.CheckLogsSupport(ctx); err != nil {
		return nil, err
	}
	q.TxId = c.txID
	v, err := rpc(ctx, q)
	if err != nil {
		err = capabilityError(err, store.ErrLogsUnavailable)
		if errors.Is(err, store.ErrLogsUnavailable) {
			c.logsCap.v.Store(2)
		}
		return nil, rpcErr("Logs", err)
	}
	if err = errFromPB(v.GetError()); err != nil {
		return nil, err
	}
	return v, nil
}
func (s *Server) logsServe(tx string, fn func(store.Logs, *storev1.LogsResponse) error) *storev1.LogsResponse {
	out := &storev1.LogsResponse{}
	out.Error = errToPB(s.with(tx, func(st store.Store) error { return fn(st.Logs(), out) }))
	return out
}

func (o clientLogs) AppendLogs(ctx context.Context, events []store.LogEvent, stats []store.DailyStatDelta) error {
	es, err := logsEncodeMany(events, logEventToPB)
	if err != nil {
		return err
	}
	ds, err := logsEncodeMany(stats, dailyStatDeltaToPB)
	if err != nil {
		return err
	}
	_, err = logsCall(o.c, ctx, &storev1.LogsRequest{Events: es, Deltas: ds}, o.c.rpc.AppendLogs)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) AppendLogs(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		es, err := logsDecodeMany(q.Events, logEventFromPB)
		if err != nil {
			return err
		}
		ds, err := logsDecodeMany(q.Deltas, dailyStatDeltaFromPB)
		if err != nil {
			return err
		}
		return r.AppendLogs(ctx, es, ds)
	}), nil
}

func (o clientLogs) GetLog(ctx context.Context, tid, id string) (*store.LogEvent, error) {
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid, Id: id}, o.c.rpc.GetLog)
	if err != nil {
		return nil, err
	}
	return logEventFromPB(v.Event)
}
func (s *Server) GetLog(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		v, err := r.GetLog(ctx, q.TenantId, q.Id)
		if err != nil {
			return err
		}
		out.Event, err = logEventToPB(v)
		return err
	}), nil
}

func (o clientLogs) SearchLogs(ctx context.Context, tid string, query *store.LogQuery, p store.LogPage) ([]store.LogEvent, int, error) {
	if err := logsearch.Validate(query); err != nil {
		return nil, 0, err
	}
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid, Query: logQueryToPB(query), Page: logPageToPB(p)}, o.c.rpc.SearchLogs)
	if err != nil {
		return nil, 0, err
	}
	es, e := logsDecodeMany(v.Events, logEventFromPB)
	return es, int(v.Total), e
}
func (s *Server) SearchLogs(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		vs, total, err := r.SearchLogs(ctx, q.TenantId, logQueryFromPB(q.Query), logPageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(total)
		out.Events, err = logsEncodeMany(vs, logEventToPB)
		return err
	}), nil
}

func (o clientLogs) LogsAfter(ctx context.Context, tid string, afterSeq int64, query *store.LogQuery, take int, settled time.Time) ([]store.LogEvent, error) {
	if err := logsearch.Validate(query); err != nil {
		return nil, err
	}
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid, AfterSeq: afterSeq, Query: logQueryToPB(query), Take: int64(take), Settled: settled.UTC().Format(store.LogTimeLayout)}, o.c.rpc.LogsAfter)
	if err != nil {
		return nil, err
	}
	return logsDecodeMany(v.Events, logEventFromPB)
}
func (s *Server) LogsAfter(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		var settled time.Time
		if err := logTimesFromPB([]string{q.Settled}, &settled); err != nil {
			return err
		}
		vs, err := r.LogsAfter(ctx, q.TenantId, q.AfterSeq, logQueryFromPB(q.Query), int(q.Take), settled)
		if err != nil {
			return err
		}
		out.Events, err = logsEncodeMany(vs, logEventToPB)
		return err
	}), nil
}

func (o clientLogs) LatestLogs(ctx context.Context, tid string, query *store.LogQuery, take int, settled time.Time) ([]store.LogEvent, error) {
	if err := logsearch.Validate(query); err != nil {
		return nil, err
	}
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid, Query: logQueryToPB(query), Take: int64(take), Settled: settled.UTC().Format(store.LogTimeLayout)}, o.c.rpc.LatestLogs)
	if err != nil {
		return nil, err
	}
	return logsDecodeMany(v.Events, logEventFromPB)
}
func (s *Server) LatestLogs(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		var settled time.Time
		if err := logTimesFromPB([]string{q.Settled}, &settled); err != nil {
			return err
		}
		vs, err := r.LatestLogs(ctx, q.TenantId, logQueryFromPB(q.Query), int(q.Take), settled)
		if err != nil {
			return err
		}
		out.Events, err = logsEncodeMany(vs, logEventToPB)
		return err
	}), nil
}

func (o clientLogs) PurgeLogs(ctx context.Context, before time.Time, limit int) (int, error) {
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{Before: before.UTC().Format(store.LogTimeLayout), Limit: int64(limit)}, o.c.rpc.PurgeLogs)
	if err != nil {
		return 0, err
	}
	return int(v.Count), nil
}
func (s *Server) PurgeLogs(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		var before time.Time
		if err := logTimesFromPB([]string{q.Before}, &before); err != nil {
			return err
		}
		n, err := r.PurgeLogs(ctx, before, int(q.Limit))
		out.Count = int64(n)
		return err
	}), nil
}

func (o clientLogs) DeleteTenantLogs(ctx context.Context, tid string) error {
	_, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid}, o.c.rpc.DeleteTenantLogs)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) DeleteTenantLogs(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		return r.DeleteTenantLogs(ctx, q.TenantId)
	}), nil
}

func (o clientLogs) CreateLogStream(ctx context.Context, in *store.LogStream) error {
	pb, err := logStreamToPB(in)
	if err != nil {
		return err
	}
	_, err = logsCall(o.c, ctx, &storev1.LogsRequest{Stream: pb}, o.c.rpc.CreateLogStream)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) CreateLogStream(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		v, err := logStreamFromPB(q.Stream)
		if err != nil {
			return err
		}
		if v == nil {
			return store.ErrInvalid
		}
		return r.CreateLogStream(ctx, v)
	}), nil
}

func (o clientLogs) GetLogStream(ctx context.Context, tid, id string) (*store.LogStream, error) {
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid, Id: id}, o.c.rpc.GetLogStream)
	if err != nil {
		return nil, err
	}
	return logStreamFromPB(v.Stream)
}
func (s *Server) GetLogStream(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		v, err := r.GetLogStream(ctx, q.TenantId, q.Id)
		if err != nil {
			return err
		}
		out.Stream, err = logStreamToPB(v)
		return err
	}), nil
}

func (o clientLogs) ListLogStreams(ctx context.Context, tid string) ([]store.LogStream, error) {
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid}, o.c.rpc.ListLogStreams)
	if err != nil {
		return nil, err
	}
	return logsDecodeMany(v.Streams, logStreamFromPB)
}
func (s *Server) ListLogStreams(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		vs, err := r.ListLogStreams(ctx, q.TenantId)
		if err != nil {
			return err
		}
		out.Streams, err = logsEncodeMany(vs, logStreamToPB)
		return err
	}), nil
}

func (o clientLogs) UpdateLogStream(ctx context.Context, in *store.LogStream, version int) error {
	pb, err := logStreamToPB(in)
	if err != nil {
		return err
	}
	_, err = logsCall(o.c, ctx, &storev1.LogsRequest{Stream: pb, Version: int64(version)}, o.c.rpc.UpdateLogStream)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) UpdateLogStream(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		v, err := logStreamFromPB(q.Stream)
		if err != nil {
			return err
		}
		if v == nil {
			return store.ErrInvalid
		}
		return r.UpdateLogStream(ctx, v, int(q.Version))
	}), nil
}

func (o clientLogs) DeleteLogStream(ctx context.Context, tid, id string) error {
	_, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid, Id: id}, o.c.rpc.DeleteLogStream)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) DeleteLogStream(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		return r.DeleteLogStream(ctx, q.TenantId, q.Id)
	}), nil
}

func (o clientLogs) LeaseLogStream(ctx context.Context, owner string, now, until time.Time) (*store.LogStream, error) {
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{Owner: owner, Now: now.UTC().Format(store.LogTimeLayout), Until: until.UTC().Format(store.LogTimeLayout)}, o.c.rpc.LeaseLogStream)
	if err != nil {
		return nil, err
	}
	return logStreamFromPB(v.Stream)
}
func (s *Server) LeaseLogStream(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		var now, until time.Time
		if err := logTimesFromPB([]string{q.Now, q.Until}, &now, &until); err != nil {
			return err
		}
		v, err := r.LeaseLogStream(ctx, q.Owner, now, until)
		if err != nil {
			return err
		}
		out.Stream, err = logStreamToPB(v)
		return err
	}), nil
}

func (o clientLogs) RecordDelivery(ctx context.Context, tid, id, owner string, d store.LogStreamDelivery) error {
	pb, err := logStreamDeliveryToPB(&d)
	if err != nil {
		return err
	}
	_, err = logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid, Id: id, Owner: owner, Delivery: pb}, o.c.rpc.RecordDelivery)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) RecordDelivery(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		v, err := logStreamDeliveryFromPB(q.Delivery)
		if err != nil {
			return err
		}
		if v == nil {
			return store.ErrInvalid
		}
		return r.RecordDelivery(ctx, q.TenantId, q.Id, q.Owner, *v)
	}), nil
}

func (o clientLogs) DailyStats(ctx context.Context, tid string, from, to time.Time) ([]store.DailyStat, error) {
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid, From: from.UTC().Format(store.LogTimeLayout), To: to.UTC().Format(store.LogTimeLayout)}, o.c.rpc.DailyStats)
	if err != nil {
		return nil, err
	}
	return logsDecodeMany(v.Stats, dailyStatFromPB)
}
func (s *Server) DailyStats(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		var from, to time.Time
		if err := logTimesFromPB([]string{q.From, q.To}, &from, &to); err != nil {
			return err
		}
		vs, err := r.DailyStats(ctx, q.TenantId, from, to)
		if err != nil {
			return err
		}
		out.Stats, err = logsEncodeMany(vs, dailyStatToPB)
		return err
	}), nil
}

func (o clientLogs) ActiveUsers(ctx context.Context, tid string, since time.Time) (int, error) {
	v, err := logsCall(o.c, ctx, &storev1.LogsRequest{TenantId: tid, Since: since.UTC().Format(store.LogTimeLayout)}, o.c.rpc.ActiveUsers)
	if err != nil {
		return 0, err
	}
	return int(v.Count), nil
}
func (s *Server) ActiveUsers(ctx context.Context, q *storev1.LogsRequest) (*storev1.LogsResponse, error) {
	return s.logsServe(q.TxId, func(r store.Logs, out *storev1.LogsResponse) error {
		var since time.Time
		if err := logTimesFromPB([]string{q.Since}, &since); err != nil {
			return err
		}
		n, err := r.ActiveUsers(ctx, q.TenantId, since)
		out.Count = int64(n)
		return err
	}), nil
}
