package adhub

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Replica-to-replica forwarding (Plan 38a §6, LR38a-3): a login on a
// replica without a socket for the connection is sent over HTTPS to the
// replica whose session row holds one. Requests are authenticated with an
// HMAC under a key derived from the connection's signing key, which every
// replica opens with the master key; a forwarded request is answered from
// the receiving replica's own sockets only.

// ForwardPath is the internal endpoint on every host of a replica.
const ForwardPath = "/internal/ad-hub/forward"

const (
	forwardHeader   = "X-Zeroauthy-Ad-Signature"
	forwardLabel    = "zeroauthy/ad-forward/v1"
	forwardSkew     = time.Minute
	maxForwardBytes = 64 << 10
)

type forwardRequest struct {
	TenantID     string         `json:"tenant_id"`
	ConnectionID string         `json:"connection_id"`
	Op           Op             `json:"op"`
	Claims       map[string]any `json:"claims"`
	Time         int64          `json:"time"`
	Nonce        string         `json:"nonce"`
}

func forwardMAC(signingKey, body []byte) []byte {
	k := hmac.New(sha256.New, signingKey)
	k.Write([]byte(forwardLabel))
	mac := hmac.New(sha256.New, k.Sum(nil))
	mac.Write(body)
	return mac.Sum(nil)
}

// ReplicaClient is the HTTPS client for other replicas' internal URLs:
// certificates verified against caFile (PEM) or the system roots, no proxy,
// no redirects.
func ReplicaClient(caFile string) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("adhub: %s holds no PEM certificate", caFile)
		}
		cfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:       RequestTimeout + 2*time.Second,
		Transport:     &http.Transport{TLSClientConfig: cfg, Proxy: nil, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 8},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// ForwardOver returns a Hub.Forward that posts to the replica of a session
// with client.
func (h *Hub) ForwardOver(client *http.Client) func(context.Context, *store.ADHubSession, Op, map[string]any) (*Reply, error) {
	return func(ctx context.Context, sess *store.ADHubSession, op Op, claims map[string]any) (*Reply, error) {
		if !strings.HasPrefix(sess.ReplicaURL, "https://") {
			return nil, ErrDetached
		}
		key, err := h.Service.SigningKey(ctx, sess.TenantID, sess.ConnectionID)
		if err != nil {
			return nil, err
		}
		body, err := json.Marshal(forwardRequest{TenantID: sess.TenantID, ConnectionID: sess.ConnectionID, Op: op, Claims: claims,
			Time: h.now().Unix(), Nonce: secrets.RandomHex(16)})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(sess.ReplicaURL, "/")+ForwardPath, bytes.NewReader(body))
		if err != nil {
			return nil, ErrDetached
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(forwardHeader, hex.EncodeToString(forwardMAC(key, body)))
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ErrTimeout
			}
			return nil, ErrDetached // the replica is gone: try the next one
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFrameBytes))
		if err != nil {
			return nil, ErrDetached
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var reply Reply
			if err := json.Unmarshal(raw, &reply); err != nil {
				return nil, fmt.Errorf("adhub: forwarded reply: %w", err)
			}
			return &reply, nil
		case http.StatusConflict:
			return nil, ErrDetached
		case http.StatusTooManyRequests:
			return nil, ErrBusy
		case http.StatusGatewayTimeout:
			return nil, ErrTimeout
		}
		return nil, fmt.Errorf("adhub: forwarding answered %d", resp.StatusCode)
	}
}

// ServeForward answers POST /internal/ad-hub/forward from another replica.
func (h *Hub) ServeForward(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		httpx.WriteError(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	if r.TLS == nil {
		httpx.WriteError(w, http.StatusForbidden, "tls_required", "forwarding requires TLS")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxForwardBytes))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return
	}
	var fr forwardRequest
	if json.Unmarshal(body, &fr) != nil || fr.TenantID == "" || fr.ConnectionID == "" || !fr.Op.valid() || len(fr.Nonce) != 32 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed forwarding request")
		return
	}
	ctx := r.Context()
	sig, err := hex.DecodeString(r.Header.Get(forwardHeader))
	key, kerr := h.Service.SigningKey(ctx, fr.TenantID, fr.ConnectionID)
	if err != nil || kerr != nil || !hmac.Equal(sig, forwardMAC(key, body)) {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_signature", "forwarding request not authenticated")
		return
	}
	now := h.now()
	at := time.Unix(fr.Time, 0)
	if at.Before(now.Add(-forwardSkew)) || at.After(now.Add(forwardSkew)) {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_signature", "forwarding request expired")
		return
	}
	replay, ok := h.Service.Store.(store.SAMLReplayStore)
	if !ok || replay.UseSAMLAssertion(ctx, fr.TenantID, fr.ConnectionID, "adfwd:"+fr.Nonce, now.Add(2*forwardSkew), now) != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_signature", "forwarding request replayed")
		return
	}
	reply, err := h.LocalCall(ctx, fr.TenantID, fr.ConnectionID, fr.Op, fr.Claims)
	switch {
	case errors.Is(err, ErrDetached):
		httpx.WriteError(w, http.StatusConflict, "not_connected", "no connector on this replica")
	case errors.Is(err, ErrBusy):
		httpx.WriteError(w, http.StatusTooManyRequests, "busy", "too many requests in flight")
	case errors.Is(err, ErrTimeout):
		httpx.WriteError(w, http.StatusGatewayTimeout, "timeout", "the connector did not answer")
	case err != nil:
		h.Service.log().ErrorContext(ctx, "ad forwarding", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "forwarding failed")
	default:
		httpx.WriteJSON(w, http.StatusOK, reply)
	}
}
