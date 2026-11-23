package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

func requestLog(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.InfoContext(r.Context(), "request",
				"method", r.Method,
				"host", r.Host,
				"path", logPath(r.URL.Path),
				"status", ww.Status(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}

// logPath hides path segments that are secrets: the AD/LDAP Connector
// provisioning ticket (Plan 38a).
func logPath(path string) string {
	if rest, ok := strings.CutPrefix(path, "/p/ad/"); ok {
		if strings.HasSuffix(rest, "/info") {
			return "/p/ad/" + logscrub.Marker + "/info"
		}
		return "/p/ad/" + logscrub.Marker
	}
	return path
}

// recoverer turns a handler panic into a logged JSON 500.
func recoverer(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				log.ErrorContext(r.Context(), "panic in handler",
					"panic", fmt.Sprint(rec),
					"stack", string(debug.Stack()),
					"request_id", middleware.GetReqID(r.Context()),
				)
				httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
			}()
			next.ServeHTTP(w, r)
		})
	}
}
