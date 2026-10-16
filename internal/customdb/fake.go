package customdb

import (
	"context"
	"encoding/json"
	"sync"
)

// FuncExecutor is an Executor for tests: Funcs[script](args) returns the
// callback value or an error (a *ScriptError, ErrTimeout, …).
type FuncExecutor struct {
	Funcs map[string]func(args []any) (any, error)
	Calls []Request // recorded under a mutex; read with Requests()

	mu sync.Mutex
}

// Execute records req and runs Funcs[req.Script].
func (f *FuncExecutor) Execute(_ context.Context, req Request) (json.RawMessage, error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, req)
	f.mu.Unlock()
	fn := f.Funcs[req.Script]
	if fn == nil {
		return nil, ErrNoScript
	}
	v, err := fn(req.Args)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// Requests returns a copy of the recorded calls.
func (f *FuncExecutor) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.Calls...)
}

// Close does nothing.
func (f *FuncExecutor) Close() error { return nil }
