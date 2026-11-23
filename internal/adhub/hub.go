package adhub

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/net/websocket"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Hub limits and timings.
const (
	// RequestTimeout bounds a request to a connector (LR38a-11).
	RequestTimeout = 10 * time.Second
	// MaxInFlight bounds the requests in flight per connection (LR38a-11).
	MaxInFlight = 64
	// authWait bounds the wait for the connector's authenticate message.
	authWait = 10 * time.Second
	// heartbeat refreshes the session row (SessionLiveness is 90 s).
	heartbeat = 30 * time.Second
	// maxTokenLifetime bounds the exp of a connector token (LR38a-7).
	maxTokenLifetime = 5 * time.Minute
	maxFrameBytes    = 1 << 20
)

// idleTimeout closes a socket that sent nothing (the connector pings every
// 5 s) for this long; writeTimeout bounds one frame write. Tests shorten
// them per hub.
const (
	idleTimeout  = 30 * time.Second
	writeTimeout = RequestTimeout
)

// Errors of Call.
var (
	ErrTimeout  = errors.New("adhub: connector did not answer in time")
	ErrBusy     = errors.New("adhub: too many requests in flight")
	ErrDetached = errors.New("adhub: connector disconnected")
)

type connKey struct{ tenantID, connectionID string }

// Hub holds this replica's connector sockets. Set Service before use.
type Hub struct {
	Service *Service
	// ReplicaID names this replica in session rows; ReplicaURL is its
	// internal forwarding endpoint, empty on a single replica.
	ReplicaID, ReplicaURL string
	// Forward, when set, sends a request for a connection without a local
	// connector to the replica that holds sess.
	Forward func(ctx context.Context, sess *store.ADHubSession, op Op, claims map[string]any) (*Reply, error)

	// idle and write override idleTimeout and writeTimeout (tests).
	idle, write time.Duration

	mu       sync.Mutex
	agents   map[connKey]map[string]*agent
	inFlight map[connKey]int
	next     map[connKey]int
}

// agent is one authenticated connector socket.
type agent struct {
	hub        *Hub
	id         string
	key        connKey
	thumbprint string
	ws         *websocket.Conn
	writeMu    sync.Mutex
	mu         sync.Mutex
	pending    map[string]*pendingCall
	done       chan struct{}
	closeOnce  sync.Once
}

type pendingCall struct {
	suffix string
	ch     chan *Reply
}

func (h *Hub) now() time.Time { return h.Service.now() }

func (h *Hub) idleTimeout() time.Duration {
	if h.idle > 0 {
		return h.idle
	}
	return idleTimeout
}

func (h *Hub) writeTimeout() time.Duration {
	if h.write > 0 {
		return h.write
	}
	return writeTimeout
}

// tlsOK is LR38a-2: the hub accepts sockets only over TLS, directly or
// through a trusted proxy that says so.
func (h *Hub) tlsOK(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return h.Service.TrustProxyHeaders && strings.EqualFold(proto, "https")
}

// ServeHTTP accepts a connector socket on GET /ad-hub.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "unknown tenant")
		return
	}
	if !h.tlsOK(r) {
		httpx.WriteError(w, http.StatusForbidden, "tls_required", "the AD/LDAP hub requires TLS")
		return
	}
	// Origin is not checked: a page could open a socket but never
	// authenticate without a provisioned connector key.
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "not an AD/LDAP Connector WebSocket")
		return
	}
	ip := httpx.ClientIP(r, h.Service.TrustProxyHeaders)
	ctx := context.WithoutCancel(r.Context())
	srv := websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler: func(ws *websocket.Conn) {
			ws.MaxPayloadBytes = maxFrameBytes
			h.serve(ctx, res, ws, ip)
		},
	}
	srv.ServeHTTP(idleWriter{ResponseWriter: w, idle: h.idleTimeout()}, r)
}

// serve authenticates a socket and runs it until it closes.
func (h *Hub) serve(ctx context.Context, res tenant.Resolved, ws *websocket.Conn, ip string) {
	defer ws.Close()
	_ = ws.SetReadDeadline(time.Now().Add(authWait))
	var f frame
	if err := readFrame(ws, &f); err != nil || f.N != evAuthenticate {
		h.reject(ws)
		return
	}
	var p tokenPayload
	if json.Unmarshal(f.P, &p) != nil || p.JWT == "" || len(p.JWT) > 16<<10 {
		h.reject(ws)
		return
	}
	conn, thumbprint, err := h.authenticate(ctx, res, p.JWT)
	if err != nil {
		h.Service.log().WarnContext(ctx, "ad connector rejected", "tenant", res.Tenant.ID, "reason", err.Error())
		h.reject(ws)
		return
	}
	_ = ws.SetReadDeadline(time.Now().Add(h.idleTimeout()))
	a := &agent{hub: h, id: secrets.RandomHex(16), key: connKey{conn.TenantID, conn.ID}, thumbprint: thumbprint, ws: ws,
		pending: map[string]*pendingCall{}, done: make(chan struct{})}
	if err := a.send(frame{N: evAuthenticated}); err != nil {
		return
	}
	h.attach(ctx, a, ip)
	defer h.detach(a)
	h.Service.log().InfoContext(ctx, "ad connector connected", "tenant", conn.TenantID, "connection", conn.Name)
	go a.heartbeat(ctx, ip)
	a.readLoop()
}

func (h *Hub) reject(ws *websocket.Conn) {
	b, _ := json.Marshal(frame{N: evAuthenticationFailure})
	_ = ws.SetWriteDeadline(time.Now().Add(h.writeTimeout()))
	ws.PayloadType = websocket.TextFrame
	_, _ = ws.Write(b)
}

// authenticate verifies the connector's hub token (LR38a-7) and returns its
// connection and the thumbprint of the certificate that signed it.
func (h *Hub) authenticate(ctx context.Context, res tenant.Resolved, raw string) (*store.Connection, string, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, "", fmt.Errorf("token: %w", err)
	}
	var unverified jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, "", fmt.Errorf("claims: %w", err)
	}
	if unverified.Issuer == "" || len(unverified.Issuer) > 128 {
		return nil, "", errors.New("issuer")
	}
	conn, err := h.Service.Store.Connections().GetByName(ctx, res.Tenant.ID, unverified.Issuer)
	if err != nil || conn.Strategy != store.StrategyAD || conn.Name != unverified.Issuer {
		return nil, "", errors.New("unknown connection")
	}
	var claims jwt.Claims
	thumbprint := ""
	for _, c := range anyStrings(conn.Extra["certs"]) {
		cert, err := rules.ParseADCert(c)
		if err != nil {
			continue
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if tok.Claims(pub, &claims) == nil {
			thumbprint, _ = rules.ADFSThumbprints(cert.Raw)
			break
		}
	}
	if thumbprint == "" {
		return nil, "", errors.New("signature does not match a provisioned certificate")
	}
	now := h.now()
	if claims.Expiry == nil || claims.Expiry.Time().After(now.Add(maxTokenLifetime)) {
		return nil, "", errors.New("exp missing or too far ahead")
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: conn.Name, AnyAudience: jwt.Audience{RealmName(res.Tenant, conn)}, Time: now}, 30*time.Second); err != nil {
		return nil, "", fmt.Errorf("claims: %w", err)
	}
	replay, ok := h.Service.Store.(store.SAMLReplayStore)
	if !ok {
		return nil, "", errors.New("no replay store")
	}
	sum := sha256.Sum256([]byte(raw))
	exp := claims.Expiry.Time().Add(30 * time.Second)
	if !exp.After(now) {
		exp = now.Add(time.Second)
	}
	if err := replay.UseSAMLAssertion(ctx, conn.TenantID, conn.ID, "adhub:"+hex.EncodeToString(sum[:]), exp, now); err != nil {
		return nil, "", fmt.Errorf("replayed token: %w", err)
	}
	return conn, thumbprint, nil
}

func (h *Hub) attach(ctx context.Context, a *agent, ip string) {
	h.mu.Lock()
	if h.agents == nil {
		h.agents = map[connKey]map[string]*agent{}
	}
	if h.agents[a.key] == nil {
		h.agents[a.key] = map[string]*agent{}
	}
	h.agents[a.key][a.id] = a
	h.mu.Unlock()
	h.putSession(ctx, a, ip, h.now())
	h.recordAgentIP(ctx, a.key, ip)
}

func (h *Hub) detach(a *agent) {
	h.mu.Lock()
	if m := h.agents[a.key]; m != nil {
		delete(m, a.id)
		if len(m) == 0 {
			delete(h.agents, a.key)
		}
	}
	h.mu.Unlock()
	a.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if repo, err := store.ADHub(ctx, h.Service.Store); err == nil {
		_ = repo.DeleteADHubSession(ctx, a.key.tenantID, a.key.connectionID, a.id)
	}
}

func (h *Hub) putSession(ctx context.Context, a *agent, ip string, connected time.Time) {
	repo, err := store.ADHub(ctx, h.Service.Store)
	if err != nil {
		return
	}
	if err := repo.PutADHubSession(ctx, &store.ADHubSession{TenantID: a.key.tenantID, ConnectionID: a.key.connectionID, SessionID: a.id,
		ReplicaID: h.ReplicaID, ReplicaURL: h.ReplicaURL, CertThumbprint: a.thumbprint, AgentIP: ip, ConnectedAt: connected, LastSeenAt: h.now()}); err != nil {
		h.Service.log().WarnContext(ctx, "ad hub session", "err", err)
	}
}

// recordAgentIP keeps options.agentIP (connector-managed) current.
func (h *Hub) recordAgentIP(ctx context.Context, key connKey, ip string) {
	if ip == "" {
		return
	}
	_ = h.Service.Store.WithTx(ctx, func(tx store.Store) error {
		cur, err := tx.Connections().Get(ctx, key.tenantID, key.connectionID)
		if err != nil || cur.Extra["agentIP"] == ip {
			return err
		}
		next := *cur
		next.Extra = cloneExtra(cur.Extra)
		next.Extra["agentIP"] = ip
		return tx.Connections().Update(ctx, &next)
	})
}

// Evict closes the connection's sockets whose certificate thumbprint is not
// in keep (LR38a-5).
func (h *Hub) Evict(tenantID, connectionID string, keep []string) {
	h.mu.Lock()
	var gone []*agent
	for _, a := range h.agents[connKey{tenantID, connectionID}] {
		found := false
		for _, k := range keep {
			if k == a.thumbprint {
				found = true
			}
		}
		if !found {
			gone = append(gone, a)
		}
	}
	h.mu.Unlock()
	for _, a := range gone {
		a.close()
	}
}

// Connected reports whether this replica holds a socket for the connection.
func (h *Hub) Connected(tenantID, connectionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.agents[connKey{tenantID, connectionID}]) > 0
}

// localAgents returns the connection's sockets on this replica, starting
// with the next in turn.
func (h *Hub) localAgents(key connKey) []*agent {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.agents[key]
	out := make([]*agent, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	if len(out) > 1 {
		if h.next == nil {
			h.next = map[connKey]int{}
		}
		i := h.next[key] % len(out)
		h.next[key]++
		out = append(out[i:], out[:i]...)
	}
	return out
}

func (h *Hub) acquire(key connKey) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inFlight == nil {
		h.inFlight = map[connKey]int{}
	}
	if h.inFlight[key] >= MaxInFlight {
		return false
	}
	h.inFlight[key]++
	return true
}

func (h *Hub) release(key connKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.inFlight[key]--
	if h.inFlight[key] <= 0 {
		delete(h.inFlight, key)
	}
}

// Call sends op with claims to a connector of the connection and waits for
// its reply: a local socket first (the next in turn, failing over to the
// others when one disconnects), else a replica holding one.
func (h *Hub) Call(ctx context.Context, tenantID, connectionID string, op Op, claims map[string]any) (*Reply, error) {
	return h.call(ctx, tenantID, connectionID, op, claims, true)
}

// LocalCall is Call restricted to this replica's sockets: the forwarding
// endpoint answers with it, so a request is never forwarded twice.
func (h *Hub) LocalCall(ctx context.Context, tenantID, connectionID string, op Op, claims map[string]any) (*Reply, error) {
	return h.call(ctx, tenantID, connectionID, op, claims, false)
}

func (h *Hub) call(ctx context.Context, tenantID, connectionID string, op Op, claims map[string]any, forward bool) (*Reply, error) {
	if !op.valid() {
		return nil, fmt.Errorf("adhub: unknown op %q", op)
	}
	key := connKey{tenantID, connectionID}
	if !h.acquire(key) {
		return nil, ErrBusy
	}
	defer h.release(key)
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	signingKey, err := h.Service.SigningKey(ctx, tenantID, connectionID)
	if err != nil {
		return nil, err
	}
	for _, a := range h.localAgents(key) {
		reply, err := a.call(ctx, signingKey, op, claims)
		if errors.Is(err, ErrDetached) {
			continue
		}
		return reply, err
	}
	if !forward {
		return nil, ErrDetached
	}
	if h.Forward != nil {
		repo, err := store.ADHub(ctx, h.Service.Store)
		if err != nil {
			return nil, err
		}
		sessions, err := repo.ListADHubSessions(ctx, tenantID, connectionID, h.now().Add(-SessionLiveness))
		if err != nil {
			return nil, err
		}
		for _, s := range sessions {
			if s.ReplicaID == h.ReplicaID || s.ReplicaURL == "" {
				continue
			}
			reply, err := h.Forward(ctx, s, op, claims)
			if errors.Is(err, ErrDetached) {
				continue
			}
			return reply, err
		}
	}
	return nil, ErrUnavailable
}

func (a *agent) send(f frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	// The deadline is cleared again: x/net/websocket answers the
	// connector's pings with pongs on the same connection, and a stale
	// deadline would fail them and drop the socket (found by make e2e-ad).
	_ = a.ws.SetWriteDeadline(time.Now().Add(a.hub.writeTimeout()))
	defer a.ws.SetWriteDeadline(time.Time{})
	a.ws.PayloadType = websocket.TextFrame
	_, err = a.ws.Write(b)
	return err
}

func (a *agent) close() {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		close(a.done)
		for pid, p := range a.pending {
			close(p.ch)
			delete(a.pending, pid)
		}
		a.mu.Unlock()
		_ = a.ws.Close()
	})
}

// call sends one request on this socket and waits for its reply. A reply
// for another pid, or with another op's suffix, is never taken for it.
func (a *agent) call(ctx context.Context, signingKey []byte, op Op, claims map[string]any) (*Reply, error) {
	pid := secrets.RandomHex(16)
	now := a.hub.now()
	payload := map[string]any{}
	for k, v := range claims {
		payload[k] = v
	}
	payload["pid"] = pid
	payload["iat"] = now.Unix()
	payload["exp"] = now.Add(time.Minute).Unix()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: signingKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	token, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		return nil, err
	}
	p := &pendingCall{suffix: op.replySuffix(), ch: make(chan *Reply, 1)}
	a.mu.Lock()
	select {
	case <-a.done:
		a.mu.Unlock()
		return nil, ErrDetached
	default:
	}
	a.pending[pid] = p
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, pid)
		a.mu.Unlock()
	}()
	body, _ := json.Marshal(tokenPayload{JWT: token})
	if err := a.send(frame{N: string(op), P: body}); err != nil {
		a.close()
		return nil, ErrDetached
	}
	select {
	case reply, ok := <-p.ch:
		if !ok {
			return nil, ErrDetached
		}
		return reply, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrTimeout
		}
		return nil, ctx.Err()
	}
}

// readLoop delivers replies until the socket closes.
func (a *agent) readLoop() {
	defer a.close()
	for {
		var f frame
		if err := readFrame(a.ws, &f); err != nil {
			if errors.Is(err, errBadFrame) {
				continue // the connector ignores what it cannot parse, too
			}
			return
		}
		pid, suffix, ok := splitReply(f.N)
		if !ok {
			continue
		}
		var reply Reply
		if len(f.P) > 0 && json.Unmarshal(f.P, &reply) != nil {
			continue
		}
		a.mu.Lock()
		if p := a.pending[pid]; p != nil && p.suffix == suffix {
			delete(a.pending, pid)
			p.ch <- &reply
		}
		a.mu.Unlock()
	}
}

func (a *agent) heartbeat(ctx context.Context, ip string) {
	connected := a.hub.now()
	t := time.NewTicker(heartbeat)
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case <-t.C:
			a.hub.putSession(ctx, a, ip, connected)
		}
	}
}

var errBadFrame = errors.New("adhub: unparseable frame")

// readFrame reads one message; unparseable text is errBadFrame, a closed or
// failed socket another error.
func readFrame(ws *websocket.Conn, f *frame) error {
	var raw []byte
	if err := websocket.Message.Receive(ws, &raw); err != nil {
		return err
	}
	if json.Unmarshal(raw, f) != nil || f.N == "" {
		return errBadFrame
	}
	return nil
}

// idleWriter makes the hijacked connection fail reads after idleTimeout
// without any bytes from the connector (it pings every 5 s), so a vanished
// connector frees its session.
type idleWriter struct {
	http.ResponseWriter
	idle time.Duration
}

func (w idleWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("adhub: hijacking unsupported")
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	pre, _ := brw.Reader.Peek(brw.Reader.Buffered())
	ic := &idleConn{Conn: c, idle: w.idle}
	r := bufio.NewReader(io.MultiReader(bytes.NewReader(bytes.Clone(pre)), ic))
	return ic, bufio.NewReadWriter(r, bufio.NewWriter(ic)), nil
}

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

// NewReplicaID names this process in hub session rows.
func NewReplicaID() string {
	host, _ := os.Hostname()
	if len(host) > 64 {
		host = host[:64]
	}
	return host + "-" + secrets.RandomHex(6)
}
