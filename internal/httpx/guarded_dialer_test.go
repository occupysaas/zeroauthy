package httpx

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

type answerResolver struct{ answers []netip.Addr }

func (r *answerResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.answers, nil
}
func TestGuardedDialerBlocks(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "fc00::1", "::ffff:127.0.0.1"} {
		t.Run(ip, func(t *testing.T) {
			_, err := GuardedDialer(false)(context.Background(), "tcp", net.JoinHostPort(ip, "80"))
			if !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("got %v", err)
			}
		})
	}
	r := &answerResolver{answers: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	calls := 0
	dial := guardedDialer(false, r, func(_ context.Context, _, addr string) (net.Conn, error) {
		calls++
		if addr != "8.8.8.8:80" {
			t.Fatal(addr)
		}
		return nil, errors.New("fixture")
	})
	_, _ = dial(context.Background(), "tcp", "rebind.test:80")
	r.answers = []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}
	if _, err := dial(context.Background(), "tcp", "rebind.test:80"); !errors.Is(err, ErrBlockedAddress) || calls != 1 {
		t.Fatalf("mixed/rebound answers dialed: %d %v", calls, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := GuardedDialer(false)(context.Background(), "tcp", listener.Addr().String()); !errors.Is(err, ErrBlockedAddress) {
		t.Fatal(err)
	}
	conn, err := GuardedDialer(true)(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
