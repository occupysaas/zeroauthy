package mgmt

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

// managementWriter observes only bytes the transport accepted. Every optional
// HTTP writer interface is retained only when the transport supports it.
type managementWriter struct {
	http.ResponseWriter
	status     int
	capture    managementCapture
	resource   string
	secretRead bool
}

func (w *managementWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ResponseController prefers FlushError to Flush. Keep transport failures and
// leave headers writable when a failed flush sent nothing.
func (w *managementWriter) FlushError() error {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err == nil && w.status == 0 {
		w.status = http.StatusOK
	}
	return err
}
func (w *managementWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != 101 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status != 0 {
		return
	}
	w.ResponseWriter.WriteHeader(status)
	w.status = status
}
func (w *managementWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(body)
	w.capture.Write(body[:n])
	return n, err
}
func (w *managementWriter) observeManagementJSON(value any) {
	w.secretRead = w.secretRead || managementSecretRead(w.resource, value)
}

type managementFlush struct{ w *managementWriter }

func (f managementFlush) Flush() {
	if f.w.status == 0 {
		f.w.WriteHeader(200)
	}
	f.w.ResponseWriter.(http.Flusher).Flush()
}

type managementHijack struct{ w *managementWriter }

func (f managementHijack) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return f.w.ResponseWriter.(http.Hijacker).Hijack()
}

type managementPush struct{ w *managementWriter }

func (f managementPush) Push(target string, options *http.PushOptions) error {
	return f.w.ResponseWriter.(http.Pusher).Push(target, options)
}

type managementReadFrom struct{ w *managementWriter }

func (f managementReadFrom) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{f.w}, r)
}

type managementCloseNotify struct{ w *managementWriter }

func (f managementCloseNotify) CloseNotify() <-chan bool {
	return f.w.ResponseWriter.(http.CloseNotifier).CloseNotify()
}
func wrapManagementWriter(w *managementWriter) http.ResponseWriter {
	flags := 0
	if _, ok := w.ResponseWriter.(http.Flusher); ok {
		flags |= 1
	}
	if _, ok := w.ResponseWriter.(http.Hijacker); ok {
		flags |= 2
	}
	if _, ok := w.ResponseWriter.(http.Pusher); ok {
		flags |= 4
	}
	if _, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		flags |= 8
	}
	if _, ok := w.ResponseWriter.(http.CloseNotifier); ok {
		flags |= 16
	}
	switch flags {
	case 1:
		return struct {
			*managementWriter
			http.Flusher
		}{w, managementFlush{w}}
	case 2:
		return struct {
			*managementWriter
			http.Hijacker
		}{w, managementHijack{w}}
	case 3:
		return struct {
			*managementWriter
			http.Flusher
			http.Hijacker
		}{w, managementFlush{w}, managementHijack{w}}
	case 4:
		return struct {
			*managementWriter
			http.Pusher
		}{w, managementPush{w}}
	case 5:
		return struct {
			*managementWriter
			http.Flusher
			http.Pusher
		}{w, managementFlush{w}, managementPush{w}}
	case 6:
		return struct {
			*managementWriter
			http.Hijacker
			http.Pusher
		}{w, managementHijack{w}, managementPush{w}}
	case 7:
		return struct {
			*managementWriter
			http.Flusher
			http.Hijacker
			http.Pusher
		}{w, managementFlush{w}, managementHijack{w}, managementPush{w}}
	case 8:
		return struct {
			*managementWriter
			io.ReaderFrom
		}{w, managementReadFrom{w}}
	case 9:
		return struct {
			*managementWriter
			http.Flusher
			io.ReaderFrom
		}{w, managementFlush{w}, managementReadFrom{w}}
	case 10:
		return struct {
			*managementWriter
			http.Hijacker
			io.ReaderFrom
		}{w, managementHijack{w}, managementReadFrom{w}}
	case 11:
		return struct {
			*managementWriter
			http.Flusher
			http.Hijacker
			io.ReaderFrom
		}{w, managementFlush{w}, managementHijack{w}, managementReadFrom{w}}
	case 12:
		return struct {
			*managementWriter
			http.Pusher
			io.ReaderFrom
		}{w, managementPush{w}, managementReadFrom{w}}
	case 13:
		return struct {
			*managementWriter
			http.Flusher
			http.Pusher
			io.ReaderFrom
		}{w, managementFlush{w}, managementPush{w}, managementReadFrom{w}}
	case 14:
		return struct {
			*managementWriter
			http.Hijacker
			http.Pusher
			io.ReaderFrom
		}{w, managementHijack{w}, managementPush{w}, managementReadFrom{w}}
	case 15:
		return struct {
			*managementWriter
			http.Flusher
			http.Hijacker
			http.Pusher
			io.ReaderFrom
		}{w, managementFlush{w}, managementHijack{w}, managementPush{w}, managementReadFrom{w}}
	case 16:
		return struct {
			*managementWriter
			http.CloseNotifier
		}{w, managementCloseNotify{w}}
	case 17:
		return struct {
			*managementWriter
			http.Flusher
			http.CloseNotifier
		}{w, managementFlush{w}, managementCloseNotify{w}}
	case 18:
		return struct {
			*managementWriter
			http.Hijacker
			http.CloseNotifier
		}{w, managementHijack{w}, managementCloseNotify{w}}
	case 19:
		return struct {
			*managementWriter
			http.Flusher
			http.Hijacker
			http.CloseNotifier
		}{w, managementFlush{w}, managementHijack{w}, managementCloseNotify{w}}
	case 20:
		return struct {
			*managementWriter
			http.Pusher
			http.CloseNotifier
		}{w, managementPush{w}, managementCloseNotify{w}}
	case 21:
		return struct {
			*managementWriter
			http.Flusher
			http.Pusher
			http.CloseNotifier
		}{w, managementFlush{w}, managementPush{w}, managementCloseNotify{w}}
	case 22:
		return struct {
			*managementWriter
			http.Hijacker
			http.Pusher
			http.CloseNotifier
		}{w, managementHijack{w}, managementPush{w}, managementCloseNotify{w}}
	case 23:
		return struct {
			*managementWriter
			http.Flusher
			http.Hijacker
			http.Pusher
			http.CloseNotifier
		}{w, managementFlush{w}, managementHijack{w}, managementPush{w}, managementCloseNotify{w}}
	case 24:
		return struct {
			*managementWriter
			io.ReaderFrom
			http.CloseNotifier
		}{w, managementReadFrom{w}, managementCloseNotify{w}}
	case 25:
		return struct {
			*managementWriter
			http.Flusher
			io.ReaderFrom
			http.CloseNotifier
		}{w, managementFlush{w}, managementReadFrom{w}, managementCloseNotify{w}}
	case 26:
		return struct {
			*managementWriter
			http.Hijacker
			io.ReaderFrom
			http.CloseNotifier
		}{w, managementHijack{w}, managementReadFrom{w}, managementCloseNotify{w}}
	case 27:
		return struct {
			*managementWriter
			http.Flusher
			http.Hijacker
			io.ReaderFrom
			http.CloseNotifier
		}{w, managementFlush{w}, managementHijack{w}, managementReadFrom{w}, managementCloseNotify{w}}
	case 28:
		return struct {
			*managementWriter
			http.Pusher
			io.ReaderFrom
			http.CloseNotifier
		}{w, managementPush{w}, managementReadFrom{w}, managementCloseNotify{w}}
	case 29:
		return struct {
			*managementWriter
			http.Flusher
			http.Pusher
			io.ReaderFrom
			http.CloseNotifier
		}{w, managementFlush{w}, managementPush{w}, managementReadFrom{w}, managementCloseNotify{w}}
	case 30:
		return struct {
			*managementWriter
			http.Hijacker
			http.Pusher
			io.ReaderFrom
			http.CloseNotifier
		}{w, managementHijack{w}, managementPush{w}, managementReadFrom{w}, managementCloseNotify{w}}
	case 31:
		return struct {
			*managementWriter
			http.Flusher
			http.Hijacker
			http.Pusher
			io.ReaderFrom
			http.CloseNotifier
		}{w, managementFlush{w}, managementHijack{w}, managementPush{w}, managementReadFrom{w}, managementCloseNotify{w}}
	default:
		return w
	}
}
