package websocket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// newTestClient returns a bare Client suitable for exercising conn
// bookkeeping directly, without dialing a real server. isDisconnected is set
// so reconnect() performs its compare-and-clear but never spawns a
// connectWithRetry goroutine.
func newTestClient() *Client {
	return &Client{
		done:           make(chan struct{}),
		isDisconnected: true,
	}
}

// dialTestConn spins up a throwaway websocket server and returns a live
// client-side *websocket.Conn, for tests that need a real connection (i.e.
// one that survives a Close() call without panicking).
func dialTestConn(t *testing.T) *websocket.Conn {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		select {}
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial test server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestClearConnIfCurrentClearsMatchingConnection(t *testing.T) {
	c := newTestClient()
	a := dialTestConn(t)
	c.setConn(a)

	if !c.clearConnIfCurrent(a) {
		t.Fatal("expected clearConnIfCurrent(a) to succeed when a is the active connection")
	}
	if got := c.getConn(); got != nil {
		t.Fatalf("expected conn to be nil after clearing, got %v", got)
	}
}

func TestClearConnIfCurrentIgnoresStaleConnection(t *testing.T) {
	c := newTestClient()
	a := dialTestConn(t)
	b := dialTestConn(t)
	c.setConn(a)

	// Simulate a concurrent winner already having replaced a with b.
	c.setConn(b)

	if c.clearConnIfCurrent(a) {
		t.Fatal("expected clearConnIfCurrent(a) to fail once b has replaced a as the active connection")
	}
	if got := c.getConn(); got != b {
		t.Fatalf("stale clearConnIfCurrent(a) must not clobber the newer connection: got %v, want %v", got, b)
	}
}

// TestReconnectIgnoresStaleConnection is the direct regression test for
// fosrl/olm#139: the read pump and sendPing can both react to the same dead
// connection and call reconnect() independently. Once one of them has
// already replaced c.conn with a newer connection, the other's reconnect
// call (carrying the old, now-stale connection) must be a no-op rather than
// tearing down or nulling out the newer connection out from under its own
// read pump.
func TestReconnectIgnoresStaleConnection(t *testing.T) {
	c := newTestClient()
	a := dialTestConn(t)
	b := dialTestConn(t)
	c.setConn(a)

	// A winning concurrent reconnect already replaced a with b.
	c.setConn(b)

	// The stale report for `a` must not touch b, and must not attempt to
	// close `a` a second time or otherwise panic.
	c.reconnect(a)

	if got := c.getConn(); got != b {
		t.Fatalf("stale reconnect(a) must not clobber the newer connection: got %v, want %v", got, b)
	}
}

func TestReconnectClearsCurrentConnection(t *testing.T) {
	c := newTestClient()
	a := dialTestConn(t)
	c.setConn(a)

	c.reconnect(a)

	if got := c.getConn(); got != nil {
		t.Fatalf("expected conn to be cleared after reconnect(a) when a was still current, got %v", got)
	}
}
