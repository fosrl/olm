package monitor

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/fosrl/newt/bind"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

// listenLoopback opens a UDP socket on 127.0.0.1 that is closed when the test ends.
func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen on loopback: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// startReachableEndpoint returns the address of a loopback endpoint that answers holepunch
// test requests the way a site does.
func startReachableEndpoint(t *testing.T) string {
	t.Helper()
	conn := listenLoopback(t)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < bind.MagicTestRequestLen || !bytes.HasPrefix(buf[:n], bind.MagicTestRequest) {
				continue
			}
			resp := make([]byte, bind.MagicTestResponseLen)
			copy(resp, bind.MagicTestResponse)
			copy(resp[len(bind.MagicTestResponse):], buf[len(bind.MagicTestRequest):bind.MagicTestRequestLen])
			_, _ = conn.WriteToUDP(resp, addr)
		}
	}()
	return conn.LocalAddr().String()
}

// startUnreachableEndpoint returns the address of a loopback endpoint that never answers,
// standing in for an endpoint that can't be reached from this client.
func startUnreachableEndpoint(t *testing.T) string {
	t.Helper()
	return listenLoopback(t).LocalAddr().String()
}

// newTestPeerMonitor returns a PeerMonitor whose holepunch tester sends its probes from a
// loopback SharedBind. Only the tester is started, not the monitor loops, so the test drives
// the monitor by hand.
func newTestPeerMonitor(t *testing.T) *PeerMonitor {
	t.Helper()

	sharedBind, err := bind.New(listenLoopback(t))
	if err != nil {
		t.Fatalf("failed to create SharedBind: %v", err)
	}
	t.Cleanup(func() { sharedBind.Close() })

	// SharedBind only delivers test responses to the tester from its receive path, which
	// WireGuard would normally be calling.
	recvFuncs, _, err := sharedBind.Open(0)
	if err != nil {
		t.Fatalf("failed to open SharedBind: %v", err)
	}
	go func() {
		bufs := [][]byte{make([]byte, 1500)}
		sizes := make([]int, 1)
		eps := make([]wgConn.Endpoint, 1)
		for {
			if _, err := recvFuncs[0](bufs, sizes, eps); err != nil {
				return
			}
		}
	}()

	pm := NewPeerMonitor(nil, nil, "", sharedBind, nil, nil)
	pm.rapidTestTimeout = 500 * time.Millisecond
	pm.rapidTestInterval = 10 * time.Millisecond
	pm.rapidTestMaxAttempts = 1

	if err := pm.holepunchTester.Start(); err != nil {
		t.Fatalf("failed to start holepunch tester: %v", err)
	}
	t.Cleanup(pm.holepunchTester.Stop)

	return pm
}

// A site's active local endpoint stopped answering, the public endpoint is unreachable too
// (e.g. the client is on the site's LAN and the router doesn't hairpin), but another local
// candidate answers. The WireGuard peer has to be moved to that candidate.
func TestRapidTestOnLocalFallbackSwitchesToLocalWinner(t *testing.T) {
	const siteID = 1

	pm := newTestPeerMonitor(t)

	deadLocal := startUnreachableEndpoint(t)
	liveLocal := startReachableEndpoint(t)
	public := startUnreachableEndpoint(t)

	localEndpoints := []string{deadLocal, liveLocal}
	// The monitor address is inside the tunnel; it isn't dialed since the monitor isn't started.
	if err := pm.AddPeer(siteID, "100.90.128.1:21821", public, localEndpoints); err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}

	var switchedTo []string
	pm.SetLocalConnectionCallbacks(
		func(_ int, endpoint string) { switchedTo = append(switchedTo, endpoint) },
		func(int) {},
	)

	// State right after checkLocalEndpoints gave up on deadLocal: no local endpoint active,
	// the WireGuard peer back on the public endpoint.
	pm.rapidTestOnLocalFallback(siteID, public, remainingLocalCandidates(localEndpoints, deadLocal))

	if len(switchedTo) != 1 || switchedTo[0] != liveLocal {
		t.Fatalf("local switch callback calls = %q, want [%q] (monitor's active local endpoint: %q)",
			switchedTo, liveLocal, pm.localActiveEndpoint[siteID])
	}
}
