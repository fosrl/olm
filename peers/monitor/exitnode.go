package monitor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/fosrl/newt/logger"
	"golang.org/x/net/icmp"
	xipv4 "golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip"
	gipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gicmp "gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	exitNodePingInterval    = 3 * time.Second
	exitNodePingTimeout     = 1 * time.Second
	exitNodePingMaxAttempts = 3
)

// SetExitNode starts (or, if the server address changed, restarts) ICMP
// connectivity monitoring of the exit node at serverIP. serverIP must be a
// bare IP address (no CIDR suffix).
func (pm *PeerMonitor) SetExitNode(serverIP string) {
	pm.exitNodeMu.Lock()
	if pm.exitNodeCancel != nil && pm.exitNodeServerIP == serverIP {
		pm.exitNodeMu.Unlock()
		return
	}
	if pm.exitNodeCancel != nil {
		pm.exitNodeCancel()
	}
	pm.exitNodeServerIP = serverIP
	ctx, cancel := context.WithCancel(context.Background())
	pm.exitNodeCancel = cancel
	pm.exitNodeMu.Unlock()

	logger.Info("Started exit node connectivity monitor for %s", serverIP)
	go pm.runExitNodeMonitor(ctx, serverIP)
}

// ClearExitNode stops ICMP monitoring of the exit node and clears its status
// from the API.
func (pm *PeerMonitor) ClearExitNode() {
	pm.exitNodeMu.Lock()
	if pm.exitNodeCancel != nil {
		pm.exitNodeCancel()
		pm.exitNodeCancel = nil
	}
	pm.exitNodeServerIP = ""
	pm.exitNodeMu.Unlock()

	if pm.apiServer != nil {
		pm.apiServer.ClearExitNodeStatus()
	}

	logger.Info("Stopped exit node connectivity monitor")
}

// runExitNodeMonitor periodically pings the exit node and reports its status
// to the API server until ctx is cancelled.
func (pm *PeerMonitor) runExitNodeMonitor(ctx context.Context, serverIP string) {
	check := func() {
		var (
			connected bool
			rtt       time.Duration
		)
		for attempt := 0; attempt < exitNodePingMaxAttempts; attempt++ {
			if d, err := pm.pingExitNode(serverIP, exitNodePingTimeout); err == nil {
				connected = true
				rtt = d
				break
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
		if pm.apiServer != nil {
			pm.apiServer.SetExitNodeStatus(connected, rtt, serverIP)
		}
	}

	check()

	ticker := time.NewTicker(exitNodePingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// pingExitNode sends a single ICMP echo request to dst and waits up to timeout
// for the matching reply. The request is built and read directly on the peer
// monitor's gvisor netstack, so it's injected into (and intercepted from) the
// WireGuard device via MiddleDevice - it never touches the host's real
// network stack, matching how the UDP peer tests above work.
func (pm *PeerMonitor) pingExitNode(dst string, timeout time.Duration) (time.Duration, error) {
	pm.mutex.Lock()
	st := pm.stack
	localIPStr := pm.localIP
	pm.mutex.Unlock()

	if st == nil {
		return 0, fmt.Errorf("netstack not initialized")
	}

	dstAddr, err := netip.ParseAddr(dst)
	if err != nil {
		return 0, fmt.Errorf("invalid destination address: %w", err)
	}
	localAddr, err := netip.ParseAddr(localIPStr)
	if err != nil {
		return 0, fmt.Errorf("invalid local address: %w", err)
	}

	var wq waiter.Queue
	ep, tcpipErr := st.NewEndpoint(gicmp.ProtocolNumber4, gipv4.ProtocolNumber, &wq)
	if tcpipErr != nil {
		return 0, fmt.Errorf("failed to create ICMP endpoint: %s", tcpipErr)
	}
	defer ep.Close()

	if tcpipErr := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(localAddr.AsSlice())}); tcpipErr != nil {
		return 0, fmt.Errorf("failed to bind ICMP endpoint: %s", tcpipErr)
	}
	if tcpipErr := ep.Connect(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dstAddr.AsSlice())}); tcpipErr != nil {
		return 0, fmt.Errorf("failed to connect ICMP endpoint: %s", tcpipErr)
	}

	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return 0, fmt.Errorf("failed to generate echo ID: %w", err)
	}
	echoID := int(binary.BigEndian.Uint16(idBuf[:]))

	requestPing := icmp.Echo{
		ID:   echoID,
		Seq:  1,
		Data: []byte("olmping"),
	}
	icmpBytes, err := (&icmp.Message{Type: xipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	start := time.Now()

	if _, tcpipErr := ep.Write(bytes.NewReader(icmpBytes), tcpip.WriteOptions{}); tcpipErr != nil {
		return 0, fmt.Errorf("failed to write ICMP echo request: %s", tcpipErr)
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	readBuf := make([]byte, 1500)
	for {
		select {
		case <-deadline.C:
			return 0, fmt.Errorf("ping to %s timed out", dst)
		case <-notifyCh:
			w := tcpip.SliceWriter(readBuf)
			res, tcpipErr := ep.Read(&w, tcpip.ReadOptions{})
			if tcpipErr != nil {
				continue
			}

			reply, err := icmp.ParseMessage(1, readBuf[:res.Count])
			if err != nil {
				continue
			}
			replyEcho, ok := reply.Body.(*icmp.Echo)
			if !ok || replyEcho.ID != echoID || replyEcho.Seq != requestPing.Seq {
				continue
			}

			return time.Since(start), nil
		}
	}
}
